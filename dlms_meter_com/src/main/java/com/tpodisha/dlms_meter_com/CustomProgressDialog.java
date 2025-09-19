package com.tpodisha.dlms_meter_com;

import android.app.Dialog;
import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

public class CustomProgressDialog extends Dialog {
    private TextView messageTextView;

    public CustomProgressDialog(Context context, String message) {
        super(context);
        // Set up the dialog
        setContentView(createDialogView(context, message));
        getWindow().setLayout(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        getWindow().setBackgroundDrawable(new ColorDrawable(Color.WHITE)); // Transparent background
        setCancelable(false); // Prevent dismissing by tapping outside or back button
    }

    private LinearLayout createDialogView(Context context, String message) {
        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setGravity(Gravity.CENTER);
        layout.setPadding(50, 50, 50, 50); // Add padding

        ProgressBar progressBar = new ProgressBar(context);
        layout.addView(progressBar);

        messageTextView = new TextView(context);
        messageTextView.setText(message);
        messageTextView.setPadding(0, 30, 0, 0); // Add padding above text
        layout.addView(messageTextView);

        return layout;
    }

    public void setMessage(String message) {
        if (messageTextView != null) {
            messageTextView.setText(message);
        }
    }
}
