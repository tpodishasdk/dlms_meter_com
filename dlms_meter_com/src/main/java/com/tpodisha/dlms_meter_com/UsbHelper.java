package com.tpodisha.dlms_meter_com;


import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;

public class UsbHelper {

    private static final String ACTION_USB_PERMISSION = "com.tpodisha.dlms_smart_lib.USB_PERMISSION";

    private final Context context;
    public final UsbManager usbManager;
    private UsbPermissionListener listener;

    public UsbHelper(Context context) {
        this.context = context.getApplicationContext();
        this.usbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
    }

    public void setUsbPermissionListener(UsbPermissionListener listener) {
        this.listener = listener;
    }

    public void requestPermission(UsbDevice device) {
        PendingIntent permissionIntent = PendingIntent.getBroadcast(
                context,
                0,
                new Intent(ACTION_USB_PERMISSION),
                PendingIntent.FLAG_IMMUTABLE
        );

        IntentFilter filter = new IntentFilter(ACTION_USB_PERMISSION);
        context.registerReceiver(usbReceiver, filter,context.RECEIVER_EXPORTED);

        usbManager.requestPermission(device, permissionIntent);
    }

    private final BroadcastReceiver usbReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context ctx, Intent intent) {
            if (ACTION_USB_PERMISSION.equals(intent.getAction())) {
                UsbDevice device = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);

                if (intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) {
                    if (listener != null) listener.onPermissionGranted(device);
                } else {
                    if (listener != null) listener.onPermissionDenied(device);
                }

                // unregister after handling
                context.unregisterReceiver(this);
            }
        }
    };

    // Callback interface
    public interface UsbPermissionListener {
        void onPermissionGranted(UsbDevice device);
        void onPermissionDenied(UsbDevice device);
    }
}
