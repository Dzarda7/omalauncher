"""omausb: USB devices for the Linux guest (see UsbBridge.kt).

Android only lets apps open USB devices, so the launcher opens them for us and
passes the device's usbfs file descriptor over $XDG_RUNTIME_DIR/usb.sock. With
that fd we speak USB ourselves: `run` hands it to a program, and `attach`
serves the device's serial ports with userspace drivers (CDC-ACM, FTDI,
CP210x, CH34x, PL2303), each as a pty and a local RFC 2217 port. A pty can't
carry DTR/RTS, and Android denies apps the modem-line ioctls on one, which
pyserial fails to open a port over; pyserial programs (esptool, monitors)
take the RFC 2217 URL instead, which carries everything.
"""

import ctypes
import errno
import fcntl
import importlib.util
import json
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import time

RUNTIME_DIR = os.environ.get("XDG_RUNTIME_DIR", "/run/user/0")
BRIDGE = os.path.join(RUNTIME_DIR, "usb.sock")
PORTS_DIR = os.path.join(RUNTIME_DIR, "usb")
HOOK = os.path.expanduser("~/.config/omausb/hook")

# RFC 2217 ports: ttyACM<n> listens on 4000+n, ttyUSB<n> on 4100+n.
RFC2217_BASE = {"ttyACM": 4000, "ttyUSB": 4100}

# --- the launcher's socket ---------------------------------------------------


def request(line):
    """Sends one request line; returns the reply text and any fd passed along."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(BRIDGE)
    except OSError as e:
        sys.exit(f"omausb: can't reach the launcher at {BRIDGE}: {e.strerror}")
    with s:
        s.sendall(line.encode() + b"\n")
        data, fds = b"", []
        while True:
            chunk, got, _, _ = socket.recv_fds(s, 65536, 4)
            fds += got
            if not chunk:
                break
            data += chunk
    return data.decode(errors="replace"), fds


def devices():
    """Devices the phone sees: dicts with name, vid, pid, granted, manufacturer, product, serial."""
    text, _ = request("list")
    out = []
    for line in text.splitlines():
        f = line.split("\t")
        if len(f) < 7:
            continue
        out.append(
            dict(name=f[0], vid=int(f[1], 16), pid=int(f[2], 16), granted=f[3] == "1", manufacturer=f[4], product=f[5], serial=f[6])
        )
    return out


def find(spec):
    """A device by its Android name (/dev/bus/usb/001/002), vid:pid, or a word of its product name."""
    found = devices()
    if spec is None:
        if len(found) == 1:
            return found[0]
        sys.exit("omausb: " + ("no USB device connected" if not found else "several devices connected; name one (omausb list)"))
    for d in found:
        if spec in (d["name"], f"{d['vid']:04x}:{d['pid']:04x}"):
            return d
    matches = [d for d in found if spec.lower() in (d["manufacturer"] + " " + d["product"]).lower()]
    if len(matches) == 1:
        return matches[0]
    sys.exit(f"omausb: no single device matches {spec!r} (omausb list)")


def open_fd(dev):
    """The device's usbfs fd; the launcher asks for permission first if needed."""
    reply, fds = request("open " + dev["name"])
    if not reply.startswith("ok") or not fds:
        for fd in fds:
            os.close(fd)
        sys.exit(f"omausb: can't open {dev['name']}: {reply.strip().removeprefix('error ') or 'no answer'}")
    return fds[0]


# --- usbfs -------------------------------------------------------------------

libc = ctypes.CDLL(None, use_errno=True)
libc.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]


class CtrlTransfer(ctypes.Structure):
    _fields_ = [
        ("bRequestType", ctypes.c_uint8),
        ("bRequest", ctypes.c_uint8),
        ("wValue", ctypes.c_uint16),
        ("wIndex", ctypes.c_uint16),
        ("wLength", ctypes.c_uint16),
        ("timeout", ctypes.c_uint32),
        ("data", ctypes.c_void_p),
    ]


class BulkTransfer(ctypes.Structure):
    _fields_ = [("ep", ctypes.c_uint), ("len", ctypes.c_uint), ("timeout", ctypes.c_uint), ("data", ctypes.c_void_p)]


class UsbIoctl(ctypes.Structure):
    _fields_ = [("ifno", ctypes.c_int), ("ioctl_code", ctypes.c_int), ("data", ctypes.c_void_p)]


def _ioc(direction, nr, size):
    return direction << 30 | size << 16 | ord("U") << 8 | nr


USBDEVFS_CONTROL = _ioc(3, 0, ctypes.sizeof(CtrlTransfer))
USBDEVFS_BULK = _ioc(3, 2, ctypes.sizeof(BulkTransfer))
USBDEVFS_CLAIMINTERFACE = _ioc(2, 15, ctypes.sizeof(ctypes.c_uint))
USBDEVFS_RELEASEINTERFACE = _ioc(2, 16, ctypes.sizeof(ctypes.c_uint))
USBDEVFS_IOCTL = _ioc(3, 18, ctypes.sizeof(UsbIoctl))
USBDEVFS_DISCONNECT = _ioc(0, 22, 0)

# Errors that mean the device is gone.
UNPLUGGED = {errno.ENODEV, errno.ESHUTDOWN, errno.EPROTO, errno.EPIPE, errno.EIO}


def _ioctl(fd, request, arg):
    r = libc.ioctl(fd, request, ctypes.byref(arg))
    if r < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return r


class Interface:
    def __init__(self, number, cls, subclass, protocol):
        self.number, self.cls, self.subclass, self.protocol = number, cls, subclass, protocol
        self.bulk_in = self.bulk_out = None
        self.max_packet = 64
        # CDC union: the data interface this communication interface controls.
        self.union_data = None


class Device:
    """An opened USB device: its descriptors, and control and bulk transfers on its usbfs fd."""

    def __init__(self, fd):
        self.fd = fd
        try:
            raw = os.pread(fd, 65536, 0)
        except OSError:
            os.lseek(fd, 0, os.SEEK_SET)
            raw = os.read(fd, 65536)
        if len(raw) < 18:
            raise OSError(errno.EIO, "no device descriptor")
        self.vid, self.pid, self.bcd = struct.unpack_from("<HHH", raw, 8)
        self.interfaces = {}
        self._parse(raw)

    def _parse(self, raw):
        """Alternate setting 0 of each interface of the first configuration, which is the active one here."""
        i, configs, current = 18, 0, None
        while i + 2 <= len(raw):
            length, kind = raw[i], raw[i + 1]
            if length < 2:
                break
            d = raw[i : i + length]
            if kind == 2:  # configuration
                configs += 1
                if configs > 1:
                    break
            elif kind == 4 and len(d) >= 9:  # interface
                current = None
                if d[3] == 0:
                    current = self.interfaces[d[2]] = Interface(d[2], d[5], d[6], d[7])
            elif kind == 5 and current and len(d) >= 7 and d[3] & 3 == 2:  # bulk endpoint
                if d[2] & 0x80:
                    current.bulk_in = d[2]
                    current.max_packet = struct.unpack_from("<H", d, 4)[0] & 0x7FF or 64
                else:
                    current.bulk_out = d[2]
            elif kind == 0x24 and current and len(d) >= 5 and d[2] == 6:  # CDC union
                current.union_data = d[4]
            i += length

    def control(self, request_type, request, value=0, index=0, data=b"", length=0, timeout=1000):
        """A control transfer; returns what an IN transfer read."""
        size = length if request_type & 0x80 else len(data)
        buf = ctypes.create_string_buffer(bytes(data), max(size, 1))
        t = CtrlTransfer(request_type, request, value & 0xFFFF, index & 0xFFFF, size, timeout, ctypes.cast(buf, ctypes.c_void_p))
        n = _ioctl(self.fd, USBDEVFS_CONTROL, t)
        return buf.raw[:n]

    def read(self, ep, size, timeout=0):
        buf = ctypes.create_string_buffer(size)
        n = _ioctl(self.fd, USBDEVFS_BULK, BulkTransfer(ep, size, timeout, ctypes.cast(buf, ctypes.c_void_p)))
        return buf.raw[:n]

    def write(self, ep, data, timeout=5000):
        for start in range(0, len(data), 16384):
            chunk = data[start : start + 16384]
            buf = ctypes.create_string_buffer(chunk, len(chunk))
            _ioctl(self.fd, USBDEVFS_BULK, BulkTransfer(ep, len(chunk), timeout, ctypes.cast(buf, ctypes.c_void_p)))

    def claim(self, number):
        """Claims an interface, detaching a kernel driver that holds it first."""
        n = ctypes.c_uint(number)
        try:
            _ioctl(self.fd, USBDEVFS_CLAIMINTERFACE, n)
        except OSError as e:
            if e.errno != errno.EBUSY:
                raise
            _ioctl(self.fd, USBDEVFS_IOCTL, UsbIoctl(number, USBDEVFS_DISCONNECT, None))
            _ioctl(self.fd, USBDEVFS_CLAIMINTERFACE, n)


# --- serial drivers ----------------------------------------------------------


class SerialPort:
    """
    One serial port of a device. The attributes are pyserial's, which is
    what RFC 2217's PortManager drives; setting one reconfigures the chip.
    """

    kind = "ttyUSB"
    driver = "?"

    def __init__(self, dev, intf):
        self.dev, self.intf = dev, intf
        self._baudrate, self._bytesize, self._parity, self._stopbits = 115200, 8, "N", 1
        self._dtr = self._rts = self._break = False
        self.xonxoff = self.rtscts = False
        self.cts = self.dsr = self.ri = self.cd = False
        self.lock = threading.Lock()

    def open(self):
        self.dev.claim(self.intf.number)
        self.init()
        self.set_line()
        self.set_modem()

    # pyserial's settings
    baudrate = property(lambda s: s._baudrate, lambda s, v: s._set("_baudrate", int(v), s.set_line))
    bytesize = property(lambda s: s._bytesize, lambda s, v: s._set("_bytesize", int(v), s.set_line))
    parity = property(lambda s: s._parity, lambda s, v: s._set("_parity", v, s.set_line))
    stopbits = property(lambda s: s._stopbits, lambda s, v: s._set("_stopbits", v, s.set_line))
    dtr = property(lambda s: s._dtr, lambda s, v: s._set("_dtr", bool(v), s.set_modem))
    rts = property(lambda s: s._rts, lambda s, v: s._set("_rts", bool(v), s.set_modem))
    break_condition = property(lambda s: s._break, lambda s, v: s._set("_break", bool(v), s.set_break))

    def _set(self, attr, value, apply):
        with self.lock:
            if getattr(self, attr) == value:
                return
            setattr(self, attr, value)
            apply()

    def lines(self, dtr, rts):
        """Sets DTR and RTS at once, as a tty's open and close do; one after the other can reset an ESP."""
        with self.lock:
            if (self._dtr, self._rts) != (dtr, rts):
                self._dtr, self._rts = dtr, rts
                self.set_modem()

    def reset_input_buffer(self):
        pass

    def reset_output_buffer(self):
        pass

    # what each chip implements
    def init(self):
        pass

    def set_line(self):
        pass

    def set_modem(self):
        pass

    def set_break(self):
        pass

    def read(self):
        return self.dev.read(self.intf.bulk_in, self.intf.max_packet * 32)

    def write(self, data):
        self.dev.write(self.intf.bulk_out, data)


CDC_PARITY = {"N": 0, "O": 1, "E": 2, "M": 3, "S": 4}
CDC_STOP = {1: 0, 1.5: 1, 2: 2}


class CdcAcm(SerialPort):
    """The USB standard: ESP32-S3/C3/C6 USB-Serial-JTAG, RP2040, Arduino, STM32, nRF, CH9102 and many more."""

    kind = "ttyACM"
    driver = "cdc-acm"

    def __init__(self, dev, comm, data):
        super().__init__(dev, data)
        self.comm = comm

    def open(self):
        if self.comm:
            self.dev.claim(self.comm.number)
        super().open()

    def _request(self, request, value=0, data=b""):
        if self.comm:
            self.dev.control(0x21, request, value, self.comm.number, data)

    def set_line(self):
        self._request(0x20, data=struct.pack("<IBBB", self._baudrate, CDC_STOP[self._stopbits], CDC_PARITY[self._parity], self._bytesize))

    def set_modem(self):
        self._request(0x22, self._dtr | self._rts << 1)

    def set_break(self):
        self._request(0x23, 0xFFFF if self._break else 0)


class Ftdi(SerialPort):
    """FT232R, FT230X, FT2232/4232/232H. Every IN packet starts with two status bytes."""

    driver = "ftdi"

    @property
    def _index(self):
        return self.intf.number + 1

    def _request(self, request, value, index=None):
        self.dev.control(0x40, request, value, self._index if index is None else index)

    def init(self):
        self._request(0, 0)  # reset
        self._request(2, 0)  # no flow control
        self._request(9, 2)  # 2 ms latency timer: answers come back fast (esptool)

    def set_line(self):
        hi_speed = self.dev.bcd in (0x700, 0x800, 0x900)  # 2232H, 4232H, 232H
        if hi_speed and self._baudrate >= 1200:
            div3 = (8 * 120_000_000 + 5 * self._baudrate) // (10 * self._baudrate)
            extra = 0x20000
        else:
            div3 = (48_000_000 + self._baudrate) // (2 * self._baudrate)
            extra = 0
        divisor = div3 >> 3 | (0, 3, 2, 4, 1, 5, 6, 7)[div3 & 7] << 14
        divisor = {1: 0, 0x4001: 1}.get(divisor, divisor) | extra
        index = divisor >> 16 & 0xFFFF
        if self.dev.bcd in (0x500, 0x700, 0x800, 0x900, 0x1000):  # 2232C, H series, X series: the port goes in the low byte
            index = index << 8 | self._index
        self._request(3, divisor & 0xFFFF, index)
        stop = {1: 0, 1.5: 1, 2: 2}[self._stopbits]
        self._request(4, self._bytesize | CDC_PARITY[self._parity] << 8 | stop << 11 | (0x4000 if self._break else 0))

    def set_modem(self):
        self._request(1, 0x0300 | self._dtr | self._rts << 1)

    def set_break(self):
        self.set_line()

    def read(self):
        size = self.intf.max_packet
        raw = self.dev.read(self.intf.bulk_in, size * 32)
        return b"".join(raw[i + 2 : i + size] for i in range(0, len(raw), size))


class Cp210x(SerialPort):
    """Silicon Labs CP2102/CP2104/CP2105: most ESP32 DevKits."""

    driver = "cp210x"

    def _request(self, request, value=0, data=b""):
        self.dev.control(0x41, request, value, self.intf.number, data)

    def init(self):
        self._request(0x00, 1)  # enable the interface
        self._request(0x12, 0x0F)  # purge

    def set_line(self):
        self._request(0x1E, data=struct.pack("<I", self._baudrate))
        stop = {1: 0, 1.5: 1, 2: 2}[self._stopbits]
        self._request(0x03, stop | CDC_PARITY[self._parity] << 4 | self._bytesize << 8)

    def set_modem(self):
        self._request(0x07, 0x0300 | self._dtr | self._rts << 1)

    def set_break(self):
        self._request(0x05, int(self._break))


class Ch341(SerialPort):
    """WCH CH340/CH341: cheap ESP and Arduino boards. Follows Linux's ch341.c."""

    driver = "ch341"
    CLOCK = 48_000_000

    def _out(self, request, value=0, index=0):
        self.dev.control(0x40, request, value, index)

    def init(self):
        self.version = self.dev.control(0xC0, 0x5F, length=2)[0]
        self._out(0xA1)  # serial init

    @classmethod
    def divisor(cls, speed):
        speed = max(46, min(speed, 3_000_000))
        clk_div = lambda ps, fact: 1 << (12 - 3 * ps - fact)  # noqa: E731
        ps = next(ps for ps in (3, 2, 1, 0) if ps == 0 or speed > cls.CLOCK // (clk_div(ps, 1) * 512))
        fact = 1
        div_clk = clk_div(ps, fact)
        div = cls.CLOCK // (div_clk * speed)
        if div < 9 or div > 255:
            div //= 2
            div_clk *= 2
            fact = 0
        if 16 * cls.CLOCK // (div_clk * div) - 16 * speed >= 16 * speed - 16 * cls.CLOCK // (div_clk * (div + 1)):
            div += 1
        if fact == 1 and div % 2 == 0:
            div //= 2
            fact = 0
        return (0x100 - div) << 8 | fact << 2 | ps

    def set_line(self):
        value = self.divisor(self._baudrate)
        if self.version >= 0x30:
            value |= 0x80  # don't buffer until full
        self._out(0x9A, 0x1312, value)
        if self.version < 0x30:
            return
        lcr = 0xC0 | (self._bytesize - 5)
        if self._parity != "N":
            lcr |= 0x08 | {"O": 0, "E": 0x10, "M": 0x20, "S": 0x30}[self._parity]
        if self._stopbits == 2:
            lcr |= 0x04
        self._out(0x9A, 0x2518, lcr)

    def set_modem(self):
        self._out(0xA4, ~(self._dtr << 5 | self._rts << 6) & 0xFFFF)

    def set_break(self):
        reg = self.dev.control(0xC0, 0x95, 0x1805, length=2)
        on = self._break
        self._out(0x9A, 0x1805, (reg[0] & ~0x01 if on else reg[0] | 0x01) | (reg[1] & ~0x40 if on else reg[1] | 0x40) << 8)


class Pl2303(SerialPort):
    """Prolific PL2303: older cables. Line settings are CDC requests after a vendor init."""

    driver = "pl2303"
    HXN = {0x23A3, 0x23B3, 0x23C3, 0x23D3, 0x23E3, 0x23F3}

    def init(self):
        if self.dev.pid in self.HXN:
            return
        # Linux's pl2303.c start-up sequence: (value, index) writes, value-only reads.
        for step in (0x8484, (0x0404, 0), 0x8484, 0x8383, 0x8484, (0x0404, 1), 0x8484, 0x8383, (0, 1), (1, 0), (2, 0x44)):
            if isinstance(step, tuple):
                self.dev.control(0x40, 0x01, *step)
            else:
                self.dev.control(0xC0, 0x01, step, 0, length=1)

    def set_line(self):
        data = struct.pack("<IBBB", self._baudrate, CDC_STOP[self._stopbits], CDC_PARITY[self._parity], self._bytesize)
        self.dev.control(0x21, 0x20, 0, 0, data)

    def set_modem(self):
        self.dev.control(0x21, 0x22, self._dtr | self._rts << 1, 0)

    def set_break(self):
        self.dev.control(0x21, 0x23, 0xFFFF if self._break else 0, 0)


CH341_IDS = {(0x1A86, 0x7523), (0x1A86, 0x5523), (0x1A86, 0x7522), (0x1A86, 0xE523)}


def serial_ports(dev):
    """The serial ports a device has, or none if it isn't a serial device we know."""
    bulk = [i for i in dev.interfaces.values() if i.bulk_in and i.bulk_out]
    vendor = [i for i in bulk if i.cls == 0xFF]
    if dev.vid == 0x0403:
        return [Ftdi(dev, i) for i in vendor]
    if dev.vid == 0x10C4:
        return [Cp210x(dev, i) for i in vendor]
    if (dev.vid, dev.pid) in CH341_IDS:
        return [Ch341(dev, i) for i in vendor[:1]]
    if dev.vid == 0x067B:
        return [Pl2303(dev, i) for i in vendor[:1]]
    ports = []
    for comm in dev.interfaces.values():
        if comm.cls == 2 and comm.subclass == 2:
            data = dev.interfaces.get(comm.union_data) or dev.interfaces.get(comm.number + 1)
            if data and data.cls == 0x0A and data.bulk_in and data.bulk_out:
                ports.append(CdcAcm(dev, comm, data))
    if not ports:  # a bare CDC data interface, no control
        ports = [CdcAcm(dev, None, i) for i in bulk if i.cls == 0x0A]
    return ports


# --- serving a port ----------------------------------------------------------

TCGETS2 = 2 << 30 | 44 << 16 | ord("T") << 8 | 0x2A
CBAUD, BOTHER = 0o10017, 0o10000
# The speeds of the Bxxx codes in c_cflag; the kernel fills c_ospeed only for BOTHER on a pty.
# fmt: off
SPEEDS = [0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400,
          0, 57600, 115200, 230400, 460800, 500000, 576000, 921600, 1000000, 1152000, 1500000,
          2000000, 2500000, 3000000, 3500000, 4000000]
# fmt: on


class Served:
    """A port as /run/user/0/usb/<name> (a pty) and rfc2217://localhost:<n>."""

    def __init__(self, port, info, gone):
        self.port, self.gone = port, gone
        self.name = self._claim_name(port.kind)
        self.link = os.path.join(PORTS_DIR, self.name)
        self.master, slave = os.openpty()
        attrs = termios.tcgetattr(slave)
        attrs[0] = attrs[1] = attrs[3] = 0  # raw
        attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
        attrs[4] = attrs[5] = termios.B115200
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        pts = os.ttyname(slave)
        # Closed, so the pty hangs up until a program opens it: that's how we see opens and closes.
        os.close(slave)
        os.set_blocking(self.master, False)
        os.replace(self._tmp_link(pts), self.link)
        self.client = None
        self.termios = None
        self.url = self._listen()
        self.info = dict(info, port=self.link, pts=pts, rfc2217=self.url, driver=port.driver, pid=os.getpid())
        with open(self.link + ".json.tmp", "w") as f:
            json.dump(self.info, f)
        os.replace(self.link + ".json.tmp", self.link + ".json")

    @staticmethod
    def _claim_name(kind):
        os.makedirs(PORTS_DIR, exist_ok=True)
        n = 0
        while True:
            name = f"{kind}{n}"
            try:
                # The lock file makes the name ours; a stale one from a killed attach is taken over.
                fd = os.open(os.path.join(PORTS_DIR, name + ".lock"), os.O_CREAT | os.O_RDWR, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return name
            except BlockingIOError:
                os.close(fd)
                n += 1

    def _tmp_link(self, target):
        tmp = self.link + ".tmp"
        if os.path.lexists(tmp):
            os.unlink(tmp)
        os.symlink(target, tmp)
        return tmp

    def _listen(self):
        if importlib.util.find_spec("serial") is None:
            log("pyserial isn't installed, so no RFC 2217 port: pacman -S python-pyserial")
            return None
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        n = int(self.name.removeprefix(self.port.kind))
        try:
            self.server.bind(("127.0.0.1", RFC2217_BASE[self.port.kind] + n))
        except OSError:
            self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        return f"rfc2217://localhost:{self.server.getsockname()[1]}"

    def start(self):
        for target in (self._usb_reader, self._pty_loop) + ((self._rfc2217_server,) if self.url else ()):
            threading.Thread(target=self._guard(target), daemon=True).start()

    def _guard(self, target):
        def run():
            try:
                target()
            except OSError as e:
                if e.errno not in UNPLUGGED:
                    log(f"{self.name}: {e}")
            self.gone.set()

        return run

    def remove(self):
        for path in (self.link, self.link + ".json", self.link + ".lock"):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def _usb_reader(self):
        while True:
            data = self.port.read()
            if not data:
                continue
            try:
                os.write(self.master, data)
            except (BlockingIOError, OSError):
                pass  # nobody has the pty open, or isn't reading: dropped, like a real UART's overrun
            client = self.client
            if client:
                client.send(b"".join(client.manager.escape(data)))

    def _pty_loop(self):
        """Copies the pty to the device; its termios become line settings, and opening it raises DTR and RTS."""
        poller = select.poll()
        poller.register(self.master, select.POLLIN)
        is_open = False
        while not self.gone.is_set():
            events = poller.poll(200)
            hangup = any(ev & select.POLLHUP for _, ev in events)
            if hangup:
                if is_open:
                    is_open = False
                    self.port.lines(False, False)
                time.sleep(0.1)
                continue
            if not is_open:
                is_open = True
                self.termios = None
                self.port.lines(True, True)
            self._follow_termios()
            if any(ev & select.POLLIN for _, ev in events):
                try:
                    data = os.read(self.master, 16384)
                except (BlockingIOError, OSError):
                    continue
                self.port.write(data)

    def _follow_termios(self):
        """
        Applies the pty's speed and stop bits when a program changes them, so they don't undo an
        RFC 2217 client's. Linux keeps a pty at 8 data bits without parity whatever is set.
        """
        buf = bytearray(44)
        fcntl.ioctl(self.master, TCGETS2, buf)
        cflag = struct.unpack_from("<I", buf, 8)[0]
        code = cflag & CBAUD
        speed = struct.unpack_from("<I", buf, 40)[0] if code == BOTHER else SPEEDS[(code & 0o17) | (16 if code & BOTHER else 0)]
        if (cflag, speed) == self.termios:
            return
        self.termios = (cflag, speed)
        stop = 2 if cflag & termios.CSTOPB else 1
        for attr, value in (("baudrate", speed), ("stopbits", stop)):
            if speed and getattr(self.port, attr) != value:
                setattr(self.port, attr, value)

    def _rfc2217_server(self):
        while True:
            sock, _ = self.server.accept()
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self.client:
                self.client.close()
            self.client = Rfc2217Client(self, sock)
            threading.Thread(target=self.client.run, daemon=True).start()


class Rfc2217Client:
    def __init__(self, served, sock):
        import serial.rfc2217

        self.served, self.sock = served, sock
        self.lock = threading.Lock()
        self.manager = serial.rfc2217.PortManager(served.port, self)

    def write(self, data):
        """For PortManager's replies."""
        self.send(data)

    def send(self, data):
        with self.lock:
            try:
                self.sock.sendall(data)
            except OSError:
                pass

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def run(self):
        try:
            while data := self.sock.recv(16384):
                out = b"".join(self.manager.filter(data))
                if out:
                    self.served.port.write(out)
        except OSError as e:
            if e.errno in UNPLUGGED:
                self.served.gone.set()
        finally:
            if self.served.client is self:
                self.served.client = None
            self.sock.close()


def log(message):
    print(f"omausb: {message}", file=sys.stderr, flush=True)


def hook(*args):
    if os.access(HOOK, os.X_OK):
        subprocess.run([HOOK, *args], check=False)


# --- commands ----------------------------------------------------------------


def served_ports():
    """Info of the ports attach is serving now, by device name."""
    out = {}
    if os.path.isdir(PORTS_DIR):
        for entry in sorted(os.listdir(PORTS_DIR)):
            if entry.endswith(".json"):
                try:
                    with open(os.path.join(PORTS_DIR, entry)) as f:
                        info = json.load(f)
                    os.kill(info["pid"], 0)
                except (OSError, ValueError, KeyError):
                    continue
                out.setdefault(info["dev"], []).append(info)
    return out


def cmd_list(args):
    found = devices()
    if not found:
        print("No USB devices connected.")
        return
    served = served_ports()
    for d in found:
        name = " ".join(x for x in (d["manufacturer"], d["product"]) if x) or "USB device"
        access = "" if d["granted"] else "  (not allowed yet; asks when opened)"
        print(f"{d['name']}  {d['vid']:04x}:{d['pid']:04x}  {name}{access}")
        for info in served.get(d["name"], []):
            print(f"    {info['port']}  {info['rfc2217'] or ''}  [{info['driver']}]")


def cmd_run(args):
    if "--" not in args:
        sys.exit("usage: omausb run [device] -- <command>...")
    split = args.index("--")
    spec, command = (args[0] if split else None), args[split + 1 :]
    if not command:
        sys.exit("usage: omausb run [device] -- <command>...")
    dev = find(spec)
    fd = open_fd(dev)
    os.set_inheritable(fd, True)
    os.environ.update(OMAUSB_FD=str(fd), OMAUSB_DEVICE=dev["name"], OMAUSB_ID=f"{dev['vid']:04x}:{dev['pid']:04x}")
    try:
        os.execvp(command[0], command)
    except OSError as e:
        sys.exit(f"omausb: {command[0]}: {e.strerror}")


def cmd_attach(args):
    dev_info = find(args[0] if args else None)
    if dev_info["name"] in served_ports():
        log(f"{dev_info['name']} is already attached")
        return
    fd = open_fd(dev_info)
    dev = Device(fd)
    ports = serial_ports(dev)
    if not ports:
        log(f"{dev_info['name']} ({dev.vid:04x}:{dev.pid:04x}) has no serial port we know; omausb run gives programs its fd")
        return
    gone = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: gone.set())
    signal.signal(signal.SIGHUP, lambda *_: gone.set())
    served = []
    try:
        for port in ports:
            port.open()
            s = Served(port, dict(dev=dev_info["name"], vid=dev.vid, pid=dev.pid, product=dev_info["product"]), gone)
            served.append(s)
            s.start()
            log(f"{s.name}: {s.link}  {s.url or ''}  [{port.driver}]")
            hook("add", s.name, s.link, s.url or "", dev_info["name"])
        while not gone.wait(1):
            pass
    except KeyboardInterrupt:
        pass
    finally:
        for s in served:
            s.remove()
            hook("remove", s.name, s.link, s.url or "", dev_info["name"])


USAGE = """usage: omausb <command>

  list                        USB devices on the phone, and the ports served for them
  attach [device]             serves a device's serial ports until it's unplugged:
                                /run/user/0/usb/ttyACM0 (a pty), rfc2217://localhost:4000
                              the launcher runs this by itself when a serial device is plugged in
  run [device] -- <command>   runs a command with the device opened; its usbfs fd is in $OMAUSB_FD

A device is its name (/dev/bus/usb/001/002), vid:pid, or a word of its name;
it can be left out when only one is connected.

Programs using pyserial take the RFC 2217 URL, which carries DTR/RTS (esptool
resets the chip with them), baud rate and line settings:

  esptool.py --port rfc2217://localhost:4000 write_flash 0x0 firmware.bin
  python -m serial.tools.miniterm rfc2217://localhost:4000 115200

The pty is for terminal programs (picocom, screen, minicom); it carries data
and the baud rate, and opening it raises DTR and RTS. pyserial can't open it:
Android denies the modem-line ioctls on ptys.

An executable ~/.config/omausb/hook runs as `hook add|remove <name> <port> <rfc2217 url> <device>`.
"""


def main():
    commands = {"list": cmd_list, "attach": cmd_attach, "run": cmd_run}
    if len(sys.argv) < 2 or sys.argv[1] not in commands:
        sys.exit(USAGE)
    commands[sys.argv[1]](sys.argv[2:])


if __name__ == "__main__":
    main()
