package com.example.arttipoc;

import android.app.Activity;
import android.hardware.biometrics.BiometricPrompt;
import android.os.CancellationSignal;
import android.util.Log;

/**
 * Invokes the platform android.hardware.biometrics.BiometricPrompt API.
 *
 * Without our ART TI hook, calling triggerBiometricPrompt() delegates to Android's system
 * IBiometricService (showing the system biometric prompt or returning BIOMETRIC_ERROR_NO_BIOMETRICS
 * if no biometrics are enrolled).
 * With our ART TI hook (JVMTI SetBreakpoint + GetLocalObject + ForceEarlyReturnVoid at offset 0 of
 * BiometricPrompt.authenticate), the system service is never called and the user is shown an in-app
 * Pass / Fail / Cancel simulation popup that drives the AuthenticationCallback below.
 */
public final class BiometricAuthController {

    private static final String TAG = "ARTTI_POC";

    public interface OutcomeListener {
        void onOutcome(String status, String detail);
    }

    private BiometricAuthController() {}

    public static CancellationSignal triggerBiometricPrompt(
            Activity activity,
            final OutcomeListener listener) {

        CancellationSignal cancellationSignal = new CancellationSignal();
        BiometricPrompt prompt = new BiometricPrompt.Builder(activity)
                .setTitle("Verify Your Identity")
                .setSubtitle("BrowserStack App Live Biometric PoC")
                .setDescription("Authenticate to approve corporate transfer #4821")
                .setNegativeButton("Use Password", activity.getMainExecutor(), (dialog, which) -> {
                    Log.i(TAG, "[BiometricAuthController] Negative button clicked");
                    if (listener != null) {
                        listener.onOutcome("NEGATIVE_BUTTON", "User clicked negative button");
                    }
                })
                .build();

        BiometricPrompt.AuthenticationCallback callback = new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                int authType = result != null ? result.getAuthenticationType() : -1;
                String detail = "AuthenticationResult(type=" + authType
                        + ", crypto=" + (result != null ? result.getCryptoObject() : null) + ")";
                Log.i(TAG, "[BiometricCallback] onAuthenticationSucceeded: " + detail);
                if (listener != null) {
                    listener.onOutcome("PASS (onAuthenticationSucceeded)", detail);
                }
            }

            @Override
            public void onAuthenticationFailed() {
                String detail = "Biometric recognized as invalid (onAuthenticationFailed)";
                Log.i(TAG, "[BiometricCallback] onAuthenticationFailed: " + detail);
                if (listener != null) {
                    listener.onOutcome("FAIL (onAuthenticationFailed)", detail);
                }
            }

            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                String detail = "errorCode=" + errorCode + " errString='" + errString + "'";
                Log.i(TAG, "[BiometricCallback] onAuthenticationError: " + detail);
                if (listener != null) {
                    listener.onOutcome("CANCEL/ERROR (onAuthenticationError)", detail);
                }
            }
        };

        Log.i(TAG, "[BiometricAuthController] Calling BiometricPrompt.authenticate(...)");
        prompt.authenticate(cancellationSignal, activity.getMainExecutor(), callback);
        return cancellationSignal;
    }
}
