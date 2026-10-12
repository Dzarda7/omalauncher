package dev.omalauncher

import android.app.Activity
import android.os.Bundle

/**
 * Android offers this when a serial or vendor USB device is plugged in
 * (res/xml/usb_devices.xml); opening it, or "Always" in that dialog, grants
 * the launcher the device. Hands it to Linux (linux/UsbBridge.kt) and goes.
 */
class UsbAttachActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        (application as App).runtime.usb.attached(intent)
        finish()
    }
}
