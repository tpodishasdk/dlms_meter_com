package com.tpodisha.dlms_meter_com;

import static com.tpodisha.dlms_meter_com.Utility.hexStringToByteArray;
import static java.time.MonthDay.now;
import static gurux.common.GXCommon.bytesToHex;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbManager;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;

import com.hoho.android.usbserial.driver.UsbSerialDriver;
import com.hoho.android.usbserial.driver.UsbSerialPort;
import com.hoho.android.usbserial.driver.UsbSerialProber;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import gurux.common.IGXMedia;
import gurux.common.ReceiveParameters;
import gurux.dlms.GXByteBuffer;
import gurux.dlms.GXDLMSException;
import gurux.dlms.GXDLMSTranslator;
import gurux.dlms.GXReplyData;
import gurux.dlms.enums.Authentication;
import gurux.dlms.enums.DataType;
import gurux.dlms.enums.ErrorCode;
import gurux.dlms.enums.InterfaceType;
import gurux.dlms.enums.RequestTypes;
import gurux.dlms.enums.Security;
import gurux.dlms.objects.GXDLMSData;
import gurux.dlms.objects.GXDLMSDisconnectControl;
import gurux.dlms.objects.GXDLMSObject;
import gurux.dlms.secure.GXDLMSSecureClient;
import gurux.io.BaudRate;
import gurux.io.Parity;
import gurux.io.StopBits;
import gurux.serial.GXSerial;

public class SmartDLMS {
    Context ctx;
    private static final String ACTION_USB_PERMISSION = "com.example.USB_PERMISSION";
    CustomProgressDialog progressDialog;
    private UsbManager usbManager;
    private PendingIntent permissionIntent;
    private UsbSerialPort serialPort;
    GXDLMSSecureClient client;
    GXDevice mDevice = new GXDevice();

    UsbSerialDriver driver;
    UsbHelper usbHelper;
    Boolean meterMatched=true;
    SmartDLMSActionListener smartDLMSActionListener;
    String meterSerialNumber;
    public SmartDLMS(Context ctx,String meterSerialNumber,SmartDLMSActionListener smartDLMSActionListener) {
        this.ctx=ctx;
        this.smartDLMSActionListener=smartDLMSActionListener;
        this.meterSerialNumber=meterSerialNumber;
        setupClient();
        checkUSB();
    }

    private void checkUSB() {
        usbHelper = new UsbHelper(ctx);

        usbHelper.setUsbPermissionListener(new UsbHelper.UsbPermissionListener() {
            @Override
            public void onPermissionGranted(UsbDevice device) {
                Toast.makeText(ctx, "USB Permission Granted!", Toast.LENGTH_SHORT).show();
                openSerialPort(driver);
                //smartDLMSActionListener.onPortConfigSuccess(driver);
            }

            @Override
            public void onPermissionDenied(UsbDevice device) {
                Toast.makeText(ctx, "USB Permission Denied!", Toast.LENGTH_SHORT).show();
            }
        });

        for (UsbDevice device : usbHelper.usbManager.getDeviceList().values()) {
            driver = UsbSerialProber.getDefaultProber().probeDevice(device);
            if (!usbHelper.usbManager.hasPermission(device)) {
                usbHelper.requestPermission(device);
            }else{
                openSerialPort(driver);
                //smartDLMSActionListener.onPortConfigSuccess(driver);
            }
        }

    }

    private void setupClient() {
        /*usbManager = (UsbManager) ctx.getSystemService(Context.USB_SERVICE);
        this.permissionIntent = PendingIntent.getBroadcast(ctx, 0,
                new Intent(ACTION_USB_PERMISSION), PendingIntent.FLAG_IMMUTABLE);
        IntentFilter filter = new IntentFilter(ACTION_USB_PERMISSION);
        filter.addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED);
        ctx.registerReceiver(usbReceiver, filter, Context.RECEIVER_EXPORTED);

        HashMap<String, UsbDevice> deviceList = usbManager.getDeviceList();
        for (UsbDevice device : deviceList.values()) {
            driver = UsbSerialProber.getDefaultProber().probeDevice(device);
            if (driver != null && !driver.getPorts().isEmpty()) {
                if (!usbManager.hasPermission(device)) {
                    usbManager.requestPermission(device, permissionIntent);
                }
            }
        }*/

        client = new GXDLMSSecureClient();
        mDevice.setMedia(new GXSerial(ctx));

        client.setUseLogicalNameReferencing(true);
        client.setClientAddress(48);//for US
        //client.setClientAddress(32);//for MR
        //client.setClientAddress(20);//if issue persist
        client.setServerAddress(1);
        client.getCiphering().setSecurity(Security.AUTHENTICATION_ENCRYPTION);
        client.setAuthentication(Authentication.HIGH);
        client.setInterfaceType(InterfaceType.HDLC);
        client.getCiphering().setAuthenticationKey(hexStringToByteArray("31323334414243443132333441424344")); // 16 bytes
        client.getCiphering().setBlockCipherKey(hexStringToByteArray("31323334414243443132333441424344"));   // 16 bytes
        client.getCiphering().setDedicatedKey(hexStringToByteArray("31323334414243443132333441424344"));
        client.getCiphering().setSystemTitle(hexStringToByteArray("48504C3732393938"));
        client.setPassword("8888888888888888".getBytes());//for US
        //client.setPassword("111111111111111".getBytes());//for MR
    }

    private final BroadcastReceiver usbReceiver = new BroadcastReceiver() {
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (ACTION_USB_PERMISSION.equals(action)) {
                synchronized (this) {
                    UsbDevice device = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);

                    if (intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) {
                        Toast.makeText(context, "USB Device connected: " , Toast.LENGTH_LONG).show();
                        openSerialPort(driver);
                    } else {
                        Log.d("USB", "Permission denied for device");
                        //  Toast.makeText(context, "Permission denied for device " + device.getDeviceName(), Toast.LENGTH_LONG).show();
                    }
                }
            }
        }
    };

    private void openSerialPort(UsbSerialDriver driver) {
        UsbDeviceConnection connection = usbManager.openDevice(driver.getDevice());
        if (connection == null) {
            Log.e("USB", "Cannot open connection.");
            Toast.makeText(ctx, "Cannot open connection.", Toast.LENGTH_LONG).show();
            return;
        }

        serialPort = driver.getPorts().get(0);
        try {

            serialPort.open(connection);
            serialPort.setParameters(9600, 8, UsbSerialPort.STOPBITS_1, UsbSerialPort.PARITY_NONE);

            // Example read
            byte[] buffer = new byte[64];
            int len = serialPort.read(buffer, 2000);
            String received = new String(buffer, 0, len);
            Log.d("USB", "Received: " + received);
            //Toast.makeText(this, "Received: " + received, Toast.LENGTH_LONG).show();

            try (AutoCloseableExecutor executor = new AutoCloseableExecutor(Executors.newSingleThreadExecutor())) {
                Handler handler = new Handler(Looper.getMainLooper());
                executor.getExecutor().submit(() -> {
                    try {

                        handler.post(() -> {
                            try {
                                initializeConnection();
                                Toast.makeText(ctx, "Connected.", Toast.LENGTH_SHORT).show();
                                if (client.getObjects().isEmpty()) {
                                    new AlertDialog.Builder(ctx)
                                            .setTitle("Import association view")
                                            .setMessage("You need to read Association view to see all objects what the meter can offer. Do you want to do it now?")
                                            .setPositiveButton(android.R.string.ok, (dialog, which) -> {
                                                readAssociationView();
                                            })
                                            .setNegativeButton(android.R.string.cancel, (dialog, which) -> {
                                            })
                                            .show();
                                }/* else {
                                    toggleStatusButton();
                                }*/
                            } catch (Exception ex) {
                                Toast.makeText(ctx, "Error reading Association."+ex.getMessage(), Toast.LENGTH_SHORT).show();
                            }
                        });
                    } catch (Exception e) {
                        Toast.makeText(ctx, "Error reading Association.", Toast.LENGTH_SHORT).show();
                    }
                });
            }


        } catch (IOException e) {
            Log.e("USB", "Error: " + e.getMessage());
            Toast.makeText(ctx, "Error: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void initializeConnection() throws Exception {

        GXSerial serial = (GXSerial) mDevice.getMedia();
        if (serial.getPorts().length != 0) {
            serial.setPort(serial.getPorts()[0]);
        }
        //IGXMedia media =new GXSerial(MainActivity.this,serialPort.getDevice().getDeviceName(), BaudRate.BAUD_RATE_9600,8,Parity.NONE, StopBits.ONE);
        IGXMedia media = mDevice.getMedia();
        media.open();
        updateFrameCounter(media);
        initializeOpticalHead(media);
        GXReplyData reply = new GXReplyData();
        byte[] data = client.snrmRequest();
        if (data.length != 0) {
            readDLMSPacket(data, reply);
            client.parseUAResponse(reply.getData());
        }
        reply.clear();
        // Generate AARQ request.
        // Split requests to multiple packets if needed.
        // If password is used all data might not fit to one packet.
        for (byte[] it : client.aarqRequest()) {
            readDLMSPacket(it, reply);
        }
        // Parse reply.
        client.parseAareResponse(reply.getData());
        reply.clear();
        // Get challenge Is HLS authentication is used.
        if (client.getAuthentication().getValue() > Authentication.LOW.getValue()) {
            for (byte[] it : client.getApplicationAssociationRequest()) {
                readDLMSPacket(it, reply);
            }
            client.parseApplicationAssociationResponse(reply.getData());
        }
    }

    private void updateFrameCounter(IGXMedia media) throws Exception {
        // Read frame counter if GeneralProtection is used.
        if (client.getCiphering() != null
                && client.getCiphering().getSecurity() != Security.NONE) {
            // Media settings are saved and they are restored when HDLC with
            // mode E is used.
            String mediaSettings = media.getSettings();
            initializeOpticalHead(media);
            byte[] data;
            GXReplyData reply = new GXReplyData();
            reply.clear();
            int add = client.getClientAddress();
            int serverAdd = client.getServerAddress();
            byte[] serverSt = client.getServerSystemTitle();
            Authentication auth = client.getAuthentication();
            Security security = client.getCiphering().getSecurity();
            byte[] challenge = client.getCtoSChallenge();
            try {
                client.setServerSystemTitle(null);
                client.setClientAddress(16);
                client.setAuthentication(Authentication.NONE);
                client.getCiphering().setSecurity(Security.NONE);
                data = client.snrmRequest();
                if (data.length != 0) {
                    readDLMSPacket(data, reply);
                    // Has server accepted client.
                    client.parseUAResponse(reply.getData());
                }
                // Generate AARQ request.
                // Split requests to multiple packets if needed.
                // If password is used all data might not fit to one packet.
                try {
                    if (!client.isPreEstablishedConnection()) {
                        reply.clear();
                        readDataBlock(client.aarqRequest(), reply);
                        // Parse reply.
                        client.parseAareResponse(reply.getData());
                    }
                    reply.clear();

                    //Meter Serial number validation
                    GXDLMSData d1 = new GXDLMSData("0.0.96.1.0.255");
                    readObject(d1, 2);
                    //long iv1 = ((Number) d1.getValue()).longValue();
                    System.out.println("Meter Serial no: " + String.valueOf(d1.getValue()));
                    reply.clear();
                    if(!meterSerialNumber.equalsIgnoreCase(String.valueOf(d1.getValue()))){
                        meterMatched=false;
                    }

                    GXDLMSData d = new GXDLMSData("0.0.43.1.3.255");
                    readObject(d, 2);
                    long iv = ((Number) d.getValue()).longValue();
                    iv += 1;
                    client.getCiphering().setInvocationCounter(iv);
                    System.out.println("Invocation counter: " + String.valueOf(iv));
                    reply.clear();
                    disconnect();
                    // Reset media settings back to default.
                    if (client.getInterfaceType() == InterfaceType.HDLC_WITH_MODE_E) {
                        media.close();
                        media.setSettings(mediaSettings);
                    }
                } catch (Exception Ex) {
                    disconnect();
                    throw Ex;
                }
            } finally {
                client.setServerSystemTitle(serverSt);
                client.setClientAddress(add);
                client.setServerAddress(serverAdd);
                client.setAuthentication(auth);
                client.getCiphering().setSecurity(security);
                client.setCtoSChallenge(challenge);
            }
        }
    }

    void initializeOpticalHead(IGXMedia media) throws Exception {
        if (media instanceof GXSerial) {
            GXSerial serial = (GXSerial) media;
            if (client.getInterfaceType() == InterfaceType.HDLC_WITH_MODE_E) {
                ReceiveParameters<byte[]> p =
                        new ReceiveParameters<byte[]>(byte[].class);
                p.setAllData(false);
                p.setEop((byte) '\n');
                p.setWaitTime(30 * 1000);
                String data;
                String replyStr;
                synchronized (media.getSynchronous()) {
                    data = "/?!\r\n";
                    System.out.println("<- " + now() + "\t"
                            + bytesToHex(data.getBytes("ASCII")));
                    media.send(data, null);
                    if (!media.receive(p)) {
                        throw new Exception("Invalid meter type.");
                    }
                    System.out.println("->" + now() + "\t"
                            + bytesToHex(p.getReply()));
                    // If echo is used.
                    replyStr = new String(p.getReply());
                    if (data.equals(replyStr)) {
                        p.setReply(null);
                        if (!media.receive(p)) {
                            throw new Exception("Invalid meter type.");
                        }
                        System.out.println("-> " + now() + "\t"
                                + bytesToHex(p.getReply()));
                        replyStr = new String(p.getReply());
                    }
                }
                if (replyStr.length() == 0 || replyStr.charAt(0) != '/') {
                    throw new Exception("Invalid responce.");
                }
                String manufactureID = replyStr.substring(1, 4);
                int bitrate = 0;
                char baudrate = replyStr.charAt(4);
                switch (baudrate) {
                    case '0':
                        bitrate = 300;
                        break;
                    case '1':
                        bitrate = 600;
                        break;
                    case '2':
                        bitrate = 1200;
                        break;
                    case '3':
                        bitrate = 2400;
                        break;
                    case '4':
                        bitrate = 4800;
                        break;
                    case '5':
                        bitrate = 9600;
                        break;
                    case '6':
                        bitrate = 19200;
                        break;
                    default:
                        throw new Exception("Unknown baud rate.");
                }
                // Send ACK
                // Send Protocol control character
                byte controlCharacter = (byte) '2';// "2" HDLC protocol
                // procedure (Mode E)
                // Send Baudrate character
                // Mode control character
                byte ModeControlCharacter = (byte) '2';// "2" //(HDLC protocol
                // procedure) (Binary
                // mode)
                // Set mode E.
                byte[] tmp = new byte[]{0x06, controlCharacter,
                        (byte) baudrate, ModeControlCharacter, 13, 10};
                p.setReply(null);
                synchronized (media.getSynchronous()) {
                    media.send(tmp, null);
                    System.out.println("<- " + now() + "\t" + bytesToHex(tmp));
                    p.setWaitTime(30 * 1000);
                    if (media.receive(p)) {
                        System.out.println("-> " + now() + "\t"
                                + bytesToHex(p.getReply()));
                    }
                    media.close();
                    serial.setDataBits(8);
                    serial.setParity(Parity.NONE);
                    serial.setStopBits(StopBits.ONE);
                    serial.setBaudRate(BaudRate.forValue(bitrate));
                    media.open();
                    // This sleep make sure that all meters can be read.
                    Thread.sleep(500);
                }
            }
        }
    }

    public void readDLMSPacket(byte[] data, GXReplyData reply)
            throws Exception {
        if (data == null || data.length == 0) {
            return;
        }
        GXReplyData notify = new GXReplyData();
        IGXMedia media = (GXSerial) mDevice.getMedia();
        reply.setError((short) 0);
        Object eop = (byte) 0x7E;
        //In network connection terminator is not used.
        if (client.getInterfaceType() != InterfaceType.HDLC &&
                client.getInterfaceType() != InterfaceType.HDLC_WITH_MODE_E) {
            eop = null;
        }
        GXByteBuffer rd = new GXByteBuffer();
        int pos = 0;
        boolean succeeded = false;
        ReceiveParameters<byte[]> p =
                new ReceiveParameters<byte[]>(byte[].class);
        p.setEop(eop);
        p.setCount(client.getFrameSize(rd));
        p.setWaitTime(30 * 1000);
        synchronized (media.getSynchronous()) {
            while (!succeeded) {
                System.out.println("<- " + now() + "\t" + bytesToHex(data));
                media.send(data, null);
                if (p.getEop() == null) {
                    p.setCount(1);
                }
                succeeded = media.receive(p);
                if (!succeeded) {
                    // Try to read again...
                    if (pos++ == 3) {
                        throw new RuntimeException(
                                "Failed to receive reply from the device in given time.");
                    }
                    System.out.println("Data send failed. Try to resend " + pos + "/3");
                }
            }
            // Loop until whole DLMS packet is received.
            rd = new GXByteBuffer(p.getReply());
            int msgPos = 0;
            try {
                while (!client.getData(rd, reply, notify)) {
                    p.setReply(null);
                    if (notify.getData().getData() != null) {
                        // Handle notify.
                        if (!notify.isMoreData()) {
                            // Show received push message as XML.
                            GXDLMSTranslator t = new GXDLMSTranslator();
                            String xml = t.dataToXml(notify.getData());
                            System.out.println(xml);
                            notify.clear();
                            msgPos = rd.position();
                        }
                        continue;
                    }

                    if (p.getEop() == null) {
                        p.setCount(client.getFrameSize(rd));
                    }
                    if (!media.receive(p)) {
                        // If echo.
                        if (reply.isEcho()) {
                            media.send(data, null);
                        }
                        // Try to read again...
                        if (++pos == 3) {
                            throw new Exception(
                                    "Failed to receive reply from the device in given time.");
                        }
                        System.out.println("Data send failed. Try to resend " + pos + "/3");
                    }
                    rd.position(msgPos);
                    rd.set(p.getReply());
                }
            } catch (Exception e) {
                System.out.println("-> " + now() + "\t"
                        + bytesToHex(p.getReply()));
                throw e;
            }
        }
        System.out.println("-> " + now() + "\t" + bytesToHex(p.getReply()));
        if (reply.getError() != 0) {
            if (reply.getError() == ErrorCode.REJECTED.getValue()) {
                Thread.sleep(1000);
                readDLMSPacket(data, reply);
            } else {
                throw new GXDLMSException(reply.getError());
            }
        }
    }

    void readDataBlock(byte[][] data, GXReplyData reply) throws Exception {
        for (byte[] it : data) {
            reply.clear();
            readDataBlock(it, reply);
        }
    }

    /**
     * Reads next data block.
     *
     * @param data  Send data.
     * @param reply Reply data.
     */
    void readDataBlock(byte[] data, GXReplyData reply) throws Exception {
        Set<RequestTypes> rt;
        if (data.length != 0) {
            readDLMSPacket(data, reply);
            while (reply.isMoreData()) {
                rt = reply.getMoreData();
                data = client.receiverReady(reply);
                readDLMSPacket(data, reply);
            }
        }
    }

    void disconnect() throws Exception {
        IGXMedia media = (GXSerial) mDevice.getMedia();
        if (media != null && media.isOpen() && !client.isPreEstablishedConnection()) {
            GXReplyData reply = new GXReplyData();
            readDLMSPacket(client.disconnectRequest(), reply);
        }
    }

    public Object readObject(
            GXDLMSObject item,
            int attributeIndex)
            throws Exception {
        try {
            byte[][] data = client.read(item, attributeIndex);
            GXReplyData reply = new GXReplyData();
            readDataBlock(data, reply);
            // Update data type on read.
            if (item.getDataType(attributeIndex) == DataType.NONE) {
                item.setDataType(attributeIndex, reply.getValueType());
            }
            return client.updateValue(item, attributeIndex, reply.getValue());
        } finally {

        }
    }

    public void refresh() throws Exception {
        // Get Association view from the meter.
        GXReplyData reply = new GXReplyData();
        readDataBlock(client.getObjectsRequest(), reply);
        mDevice.setObjects(client.parseObjects(reply.getData(), true));
    }

    private void readAssociationView() {
        progressDialog = new CustomProgressDialog(ctx, "Association working...");
        progressDialog.show();

        Handler handler = new Handler(Looper.getMainLooper());
        try (AutoCloseableExecutor associationExecutor = new AutoCloseableExecutor(Executors.newSingleThreadExecutor())) {
            associationExecutor.getExecutor().submit(() -> {
                try {
                    refresh();
                    handler.post(() -> {
                        try {
                            //Notify activity that association has read again.
                            Toast.makeText(ctx, "Refresh done.", Toast.LENGTH_SHORT).show();
                            //toggleStatusButton();
                            progressDialog.dismiss();
                            if(meterMatched){
                                toggleStatusButton();
                            }else{
                                smartDLMSActionListener.onAssociationComplete(false,0,"Meter not matched");
                            }
                        } catch (Exception ex) {
                            Toast.makeText(ctx, "Refresh error."+ex.getMessage(), Toast.LENGTH_SHORT).show();
                            smartDLMSActionListener.onAssociationComplete(false,0,ex.getMessage());
                        }
                    });
                } catch (Exception e) {
                    Toast.makeText(ctx, "Refresh error.", Toast.LENGTH_SHORT).show();
                }
            });
        }
    }

    private void toggleStatusButton() {
        if(meterMatched){
            try {
                GXDLMSObject oo=new GXDLMSObject();
                GXReplyData rgg=new GXReplyData();
                GXDLMSDisconnectControl fff=new GXDLMSDisconnectControl();
                fff.setLogicalName("0.0.96.3.10.255");
                readDataBlock(client.read(fff,2),rgg);
                System.out.println("Relay Output State: " + rgg.getValue().toString());
                if(rgg.getValue().toString().equalsIgnoreCase("true")){
                    //smartDLMSActionListener.relayStatus(2);
                    smartDLMSActionListener.onAssociationComplete(true,2,"Meter matched");
                }else if(rgg.getValue().toString().equalsIgnoreCase("false")){
                    //smartDLMSActionListener.relayStatus(1);
                    smartDLMSActionListener.onAssociationComplete(true,1,"Meter matched");
                }else{
                    //smartDLMSActionListener.relayStatus(3);
                    smartDLMSActionListener.onAssociationComplete(true,3,"Meter matched");
                }
                //smartDLMSActionListener.onAssociationComplete(true,client);
                //System.out.println("Current Relay status: " + relayStatus);
                //Toast.makeText(this, "Current Relay status: " + relayStatus, Toast.LENGTH_LONG).show();
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }else{
            Toast.makeText(ctx, "Meter Number not matched: " , Toast.LENGTH_LONG).show();
        }


    }

    public void onInvoke(byte[][] frames) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Handler h = new Handler(Looper.getMainLooper());
        executor.execute(() -> h.post(() -> {
            try {
                GXReplyData reply = new GXReplyData();
                readDataBlock(frames, reply);
                Toast.makeText(ctx, "Action completed.", Toast.LENGTH_SHORT).show();
                toggleStatusButton();
                smartDLMSActionListener.onActionComplete(true);
            } catch (Exception e) {
                Toast.makeText(ctx, e.getMessage() + "getString(R.string.error)", Toast.LENGTH_SHORT).show();
                smartDLMSActionListener.onActionComplete(false);
            }
        }));
    }

    public void smartDisconnect(GXDLMSSecureClient c){
        GXDLMSDisconnectControl dc = new GXDLMSDisconnectControl();
        byte[][] frames = null;
        //dc.setLogicalName("0.0.96.3.10.255");
        try {
            //client.method(dc, 1, 0, DataType.INT8);
            frames = dc.remoteDisconnect(c);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } finally {
            onInvoke(frames);
        }
    }

    public void smartReconnect(GXDLMSSecureClient c){
        GXDLMSDisconnectControl dc = new GXDLMSDisconnectControl();
        byte[][] frames = null;
        //dc.setLogicalName("0.0.96.3.10.255");
        try {
            //client.method(dc, 1, 0, DataType.INT8);
            frames = dc.remoteReconnect(c);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } finally {
            onInvoke(frames);
        }
    }

}
