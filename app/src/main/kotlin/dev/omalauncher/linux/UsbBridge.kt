package dev.omalauncher.linux

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import android.util.Log
import dev.omalauncher.upgrade.Managed
import dev.omalauncher.upgrade.Policy
import dev.omalauncher.wayland.Native
import java.io.File
import java.nio.ByteBuffer
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

private const val TAG = "usb"
private const val PERMISSION_ACTION = "dev.omalauncher.USB_PERMISSION"

/** How long an open waits for the user to answer Android's permission dialog. */
private const val PERMISSION_TIMEOUT_S = 60L

/**
 * USB devices for the guest. Only apps can open them, through [UsbManager], so the
 * guest asks us over a socket in the shared runtime dir and gets the opened device's
 * usbfs fd (SCM_RIGHTS, as Wayland passes buffers). The guest's omausb (assets/usb)
 * speaks USB over it: its own serial drivers behind a pty and an RFC 2217 port, or
 * any program it hands the fd to. One request line per connection:
 *
 *   list         one line per device: name, vid, pid (hex), allowed (1/0), manufacturer, product, serial; tab-separated
 *   open <name>  "ok" with the device's fd attached, after Android's permission dialog if needed; or "error <why>"
 *
 * Plugged-in devices the launcher may open start `omausb attach`, which serves their
 * serial ports; "Always open" in Android's dialog for [dev.omalauncher.UsbAttachActivity]
 * makes that permission stick.
 */
class UsbBridge(
    private val context: Context,
    private val proot: Proot,
    /** Runs a command in the guest, if Linux is up. */
    private val launch: (String) -> Unit,
) {
    private val usb = context.getSystemService(UsbManager::class.java)
    private val socket = File(proot.runtimeDir, "usb.sock")

    /** Devices `omausb attach` was started for, until they're unplugged. */
    private val attached = ConcurrentHashMap.newKeySet<String>()

    /** Permission dialogs being answered, by device name. */
    private val pending = ConcurrentHashMap<String, CompletableFuture<Boolean>>()

    private var listening = false

    private val receiver =
        object : BroadcastReceiver() {
            override fun onReceive(
                context: Context,
                intent: Intent,
            ) {
                val device = intent.device() ?: return
                when (intent.action) {
                    UsbManager.ACTION_USB_DEVICE_ATTACHED -> if (usb.hasPermission(device)) attach(device)
                    UsbManager.ACTION_USB_DEVICE_DETACHED -> attached.remove(device.deviceName)
                    PERMISSION_ACTION -> pending.remove(device.deviceName)?.complete(intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false))
                }
            }
        }

    /** Starts serving the guest, and attaches what's plugged in already; again whenever Linux comes up. */
    fun start() {
        if (usb == null) return
        if (!listening) {
            val filter =
                IntentFilter().apply {
                    addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
                    addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
                    addAction(PERMISSION_ACTION)
                }
            if (Build.VERSION.SDK_INT >= 33) context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED) else context.registerReceiver(receiver, filter)
            val listenFd = Native.listen(socket.path)
            if (listenFd < 0) return Log.e(TAG, "cannot listen on $socket: errno ${-listenFd}")
            listening = true
            thread(name = "usb-bridge", isDaemon = true) {
                while (true) {
                    val fd = Native.accept(listenFd)
                    if (fd < 0) return@thread Log.e(TAG, "accept failed: errno ${-fd}")
                    // Its own thread: an open may wait on the permission dialog.
                    thread(name = "usb-request", isDaemon = true) { serve(fd) }
                }
            }
        }
        // A new guest: the attaches of one before it ended with it.
        attached.clear()
        usb.deviceList.values.filter(usb::hasPermission).forEach(::attach)
    }

    /** A device Android started [dev.omalauncher.UsbAttachActivity] for, which grants us it. */
    fun attached(intent: Intent) {
        val device = intent.device() ?: return
        if (usb?.hasPermission(device) == true) attach(device)
    }

    private fun attach(device: UsbDevice) {
        // omausb attach leaves devices without a serial port alone.
        if (listening && attached.add(device.deviceName)) launch("omausb attach ${shellQuote(device.deviceName)}")
    }

    private fun serve(fd: Int) {
        try {
            val line = readLine(fd) ?: return
            val command = line.substringBefore(' ')
            val arg = line.substringAfter(' ', "")
            when (command) {
                "list" -> reply(fd, list())
                "open" -> open(fd, arg)
                else -> reply(fd, "error unknown request $command\n")
            }
        } catch (e: Exception) {
            Log.w(TAG, "request failed", e)
        } finally {
            Native.close(fd)
        }
    }

    private fun list(): String =
        usb.deviceList.values.sortedBy { it.deviceName }.joinToString("") { d ->
            // The serial number needs permission to read.
            val serial = if (usb.hasPermission(d)) runCatching { d.serialNumber }.getOrNull() else null
            listOf(
                d.deviceName,
                "%04x".format(d.vendorId),
                "%04x".format(d.productId),
                if (usb.hasPermission(d)) "1" else "0",
                d.manufacturerName,
                d.productName,
                serial,
            ).joinToString("\t") { it.orEmpty().replace(Regex("[\t\n]"), " ") } + "\n"
        }

    private fun open(
        fd: Int,
        name: String,
    ) {
        val device = usb.deviceList[name] ?: return reply(fd, "error no such device\n")
        if (!usb.hasPermission(device) && !askPermission(device)) return reply(fd, "error not allowed\n")
        val connection = usb.openDevice(device) ?: return reply(fd, "error Android couldn't open it\n")
        // The guest gets its own copy of the fd; ours closes with the connection.
        try {
            reply(fd, "ok\n", connection.fileDescriptor)
        } finally {
            connection.close()
        }
    }

    /** Shows Android's dialog for [device]; true once allowed. Concurrent opens of a device share one dialog. */
    private fun askPermission(device: UsbDevice): Boolean {
        val answer =
            pending.computeIfAbsent(device.deviceName) {
                CompletableFuture<Boolean>().also {
                    val intent = Intent(PERMISSION_ACTION).setPackage(context.packageName)
                    // Mutable: Android adds the device and the answer to it.
                    val flags = if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0
                    usb.requestPermission(device, PendingIntent.getBroadcast(context, 0, intent, flags))
                }
            }
        return runCatching { answer.get(PERMISSION_TIMEOUT_S, TimeUnit.SECONDS) }.getOrDefault(false)
    }

    /** The request line, up to the newline; null if the guest hung up first. */
    private fun readLine(fd: Int): String? {
        val buf = ByteBuffer.allocateDirect(1024)
        val fds = IntArray(32)
        var len = 0
        while (len < buf.capacity()) {
            val n = Native.recv(fd, buf, len, fds)
            for (i in 1..fds[0]) Native.close(fds[i])
            if (n <= 0) return null
            len += n
            val bytes = ByteArray(len).also { buf.duplicate().get(it) }
            val end = bytes.indexOf('\n'.code.toByte())
            if (end >= 0) return bytes.decodeToString(0, end)
        }
        return null
    }

    private fun reply(
        fd: Int,
        text: String,
        passFd: Int = -1,
    ) {
        val bytes = text.toByteArray()
        val buf = ByteBuffer.allocateDirect(bytes.size).put(bytes)
        val n = Native.send(fd, buf, bytes.size, intArrayOf(passFd), if (passFd >= 0) 1 else 0)
        if (n < 0) Log.w(TAG, "reply failed: errno ${-n}")
    }

    /** omausb: the script (assets/usb) and the command that runs it, or says what to install. */
    fun managed(): List<Managed> =
        listOf(
            Managed(File(proot.rootfs, "usr/local/lib/omausb/omausb.py"), Policy.Owned) { context.assets.open("usb/omausb.py").use { it.readBytes() } },
            Managed.text(File(proot.rootfs, "usr/local/bin/omausb"), Policy.Owned, executable = true) {
                """
                #!/bin/sh
                # omalauncher: USB devices for Linux (see UsbBridge.kt)
                if ! command -v python3 >/dev/null; then
                  echo "omausb needs Python: pacman -S python python-pyserial" >&2
                  exit 1
                fi
                exec python3 -I /usr/local/lib/omausb/omausb.py "${'$'}@"
                """.trimIndent() + "\n"
            },
        )

    private fun Intent.device(): UsbDevice? =
        if (Build.VERSION.SDK_INT >= 33) {
            getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
        } else {
            @Suppress("DEPRECATION")
            getParcelableExtra(UsbManager.EXTRA_DEVICE)
        }
}
