package com.tpodisha.dlms_meter_com;

public interface SmartDLMSActionListener {
    void onActionComplete(boolean status);
    //void relayStatus(int i);
    void onAssociationComplete(boolean status,int relayStatus,String message);
    //void onError(String message);
    //void onPortConfigSuccess(boolean status);
}
