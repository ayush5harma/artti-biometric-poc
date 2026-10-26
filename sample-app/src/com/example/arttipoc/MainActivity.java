package com.example.arttipoc;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.lang.reflect.Method;

/**
 * Interactive UI and automated E2E harness for the ART TI + LSPatch BiometricPrompt PoC.
 */
public class MainActivity extends Activity {

    private static final String TAG = "ARTTI_POC";
    private final Handler mHandler = new Handler(Looper.getMainLooper());

    private TextView mStatusView;
    private TextView mLogView;
    private final StringBuilder mLogBuffer = new StringBuilder();

    public static native String nativeControl(int mode, Class<?> targetWorkClass, Class<?> inlinedCalleeClass);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Ensure the Activity and its in-app BiometricPrompt simulation AlertDialog
        // render in the foreground during automated E2E runs even if the device
        // display has timed out onto the keyguard (measured 2026-10-26).
        setShowWhenLocked(true);
        setTurnScreenOn(true);
        buildUi();
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = Math.round(16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);

        TextView header = new TextView(this);
        header.setText("ART TI + LSPatch BiometricPrompt PoC");
        header.setTextSize(18f);
        header.setTypeface(Typeface.DEFAULT_BOLD);
        header.setTextColor(Color.parseColor("#0D47A1"));
        root.addView(header);

        mStatusView = new TextView(this);
        mStatusView.setTextSize(13f);
        mStatusView.setTypeface(Typeface.MONOSPACE);
        mStatusView.setPadding(0, pad / 2, 0, pad / 2);
        root.addView(mStatusView);

        Button bioBtn = new Button(this);
        bioBtn.setText("Trigger BiometricPrompt.authenticate()");
        bioBtn.setOnClickListener(v -> triggerBiometricFlow(null));
        root.addView(bioBtn);

        Button hookTestBtn = new Button(this);
        hookTestBtn.setText("Run Plain + AOT-Inlined Method Hook Test");
        hookTestBtn.setOnClickListener(v -> runMethodHookVerification());
        root.addView(hookTestBtn);

        mLogView = new TextView(this);
        mLogView.setTextSize(12f);
        mLogView.setTypeface(Typeface.MONOSPACE);
        mLogView.setTextColor(Color.parseColor("#212121"));
        mLogView.setPadding(0, pad, 0, pad);
        root.addView(mLogView);

        scroll.addView(root);
        setContentView(scroll);
        refreshStatusBanner("READY");
    }

    private void refreshStatusBanner(String latestBioOutcome) {
        boolean appSeesDebuggable = (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        String bootstrapSummary = queryLoaderMethod("org.lsposed.lspatch.loader.LSPApplication", "getBootstrapSummary");
        String hookTelemetry = queryLoaderMethod("org.lsposed.lspatch.loader.BiometricPromptHookDialog", "getHookTelemetry");
        String status = "Package           : " + getPackageName() + "\n"
                + "App sees debuggable: " + appSeesDebuggable + "\n"
                + "LSPatch bootstrap : " + bootstrapSummary + "\n"
                + "Biometric hook    : " + hookTelemetry + "\n"
                + "Latest Bio Outcome: " + latestBioOutcome;
        mStatusView.setText(status);
    }

    private void appendLog(String line) {
        Log.i(TAG, line);
        mLogBuffer.append(line).append("\n");
        if (mLogView != null) {
            mLogView.setText(mLogBuffer.toString());
        }
    }

    private void handleIntent(Intent intent) {
        if (intent == null) return;
        String action = intent.getStringExtra("e2e_action");
        String bioChoice = intent.getStringExtra("bio_choice");
        if (action == null) return;

        appendLog("=== E2E Intent Action: " + action + " (bioChoice=" + bioChoice + ") ===");
        if ("run_all".equals(action)) {
            runMethodHookVerification();
            triggerBiometricFlow(bioChoice);
        } else if ("biometric".equals(action)) {
            triggerBiometricFlow(bioChoice);
        } else if ("fingerprint".equals(action)) {
            triggerLegacyFingerprintFlow(bioChoice);
        } else if ("hooks".equals(action)) {
            runMethodHookVerification();
        }
    }

    @SuppressWarnings("deprecation")
    private void runMethodHookVerification() {
        try {
            boolean appSeesDebuggable = (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
            boolean pmSeesDebuggable = false;
            try {
                ApplicationInfo pmInfo = getPackageManager().getApplicationInfo(getPackageName(), 0);
                pmSeesDebuggable = (pmInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
            } catch (Throwable ignored) {
            }
            boolean origFactoryDelegated = SampleOriginalAppComponentFactory.didDelegateActivity();

            int canAuth = -999;
            try {
                android.hardware.biometrics.BiometricManager bm =
                        getSystemService(android.hardware.biometrics.BiometricManager.class);
                if (bm != null) {
                    canAuth = bm.canAuthenticate(
                            android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG);
                }
            } catch (Throwable ignored) {
            }

            String fpReady = "N/A";
            try {
                android.hardware.fingerprint.FingerprintManager fpm =
                        getSystemService(android.hardware.fingerprint.FingerprintManager.class);
                if (fpm != null) {
                    fpReady = fpm.isHardwareDetected() + "/" + fpm.hasEnrolledFingerprints();
                }
            } catch (Throwable ignored) {
            }

            int allocFallbackType = -1;
            try {
                Class<?> dlgCls = Class.forName(
                        "org.lsposed.lspatch.loader.BiometricPromptHookDialog", false, getClassLoader());
                Method createMid = dlgCls.getDeclaredMethod(
                        "nativeCreateAuthenticationResult", Object.class, int.class);
                android.hardware.biometrics.BiometricPrompt.AuthenticationResult fallbackRes =
                        (android.hardware.biometrics.BiometricPrompt.AuthenticationResult)
                                createMid.invoke(null, null, -99);
                if (fallbackRes != null) {
                    allocFallbackType = fallbackRes.getAuthenticationType();
                }
            } catch (Throwable ignored) {
            }

            String setupBp = nativeControl(1, TargetWork.class, InlinedCallee.class);
            String setupMe = nativeControl(2, TargetWork.class, InlinedCallee.class);
            nativeControl(0, TargetWork.class, InlinedCallee.class);

            // Invoke both direct static calls (which dex2oat -m speed inlines into MainActivity unless
            // compiled with -m verify or --debuggable) and polymorphic WorkRunner calls.
            int directPlain = TargetWork.plainMethod(7);
            int directCaller = TargetWork.callerMethod(10);
            String afterDirect = nativeControl(99, TargetWork.class, InlinedCallee.class);

            nativeControl(0, TargetWork.class, InlinedCallee.class);
            int polyPlain = TargetWork.sRunner.plainMethod(7);
            int polyCaller = TargetWork.sRunner.callerMethod(10);
            String afterPoly = nativeControl(99, TargetWork.class, InlinedCallee.class);

            String retransformRes = nativeControl(31, TargetWork.class, InlinedCallee.class);
            nativeControl(0, TargetWork.class, InlinedCallee.class);
            int postRtPlain = TargetWork.sRunner.plainMethod(7);
            int postRtCaller = TargetWork.sRunner.callerMethod(10);
            String afterRetransform = nativeControl(99, TargetWork.class, InlinedCallee.class);

            appendLog("[HOOK_VERIFY] appSeesDebuggable=" + appSeesDebuggable
                    + " pmSeesDebuggable=" + pmSeesDebuggable
                    + " origFactoryDelegated=" + origFactoryDelegated
                    + " canAuth=" + canAuth
                    + " fpReady=" + fpReady
                    + " allocFallbackType=" + allocFallbackType
                    + " | setupBp={" + setupBp + "}"
                    + " | setupMe={" + setupMe + "}"
                    + " | DirectCall={" + afterDirect + "} (plain=" + directPlain + ", caller=" + directCaller + ")"
                    + " | PolyCall={" + afterPoly + "} (plain=" + polyPlain + ", caller=" + polyCaller + ")"
                    + " | Retransform={" + retransformRes + "}"
                    + " | PostRetransform={" + afterRetransform + "} (plain=" + postRtPlain + ", caller=" + postRtCaller + ")");
            refreshStatusBanner("HOOK_VERIFY_DONE");
        } catch (UnsatisfiedLinkError ule) {
            appendLog("[HOOK_VERIFY] Unpatched build (native agent not loaded): " + ule.getMessage());
            int directPlain = TargetWork.plainMethod(7);
            int directCaller = TargetWork.callerMethod(10);
            appendLog("[UNPATCHED_BASELINE] plain=" + directPlain + " caller=" + directCaller);
            refreshStatusBanner("UNPATCHED_BASELINE");
        }
    }

    private void triggerBiometricFlow(final String autoClickChoice) {
        appendLog("[BIO_FLOW] Calling BiometricAuthController.triggerBiometricPrompt(...)");
        BiometricAuthController.triggerBiometricPrompt(this, (status, detail) -> {
            String summary = status + " -> " + detail;
            appendLog("[BIO_OUTCOME] " + summary);
            refreshStatusBanner(summary);
        });

        if (autoClickChoice != null && !autoClickChoice.isEmpty()) {
            // Wait 600ms so the AlertDialog is rendered in the window hierarchy (allowing dumpsys/uiautomator
            // inspection too), then verify popupShowing==true and click the requested button (PASS/FAIL/CANCEL).
            mHandler.postDelayed(() -> {
                String telemetryBeforeClick = queryLoaderMethod(
                        "org.lsposed.lspatch.loader.BiometricPromptHookDialog", "getHookTelemetry");
                boolean clicked = invokeDialogClick(autoClickChoice);
                appendLog("[BIO_AUTO_CLICK] choice=" + autoClickChoice
                        + " clicked=" + clicked
                        + " telemetryBeforeClick={" + telemetryBeforeClick + "}");
            }, 600);
        }
    }

    @SuppressWarnings("deprecation")
    private void triggerLegacyFingerprintFlow(final String autoClickChoice) {
        appendLog("[FP_FLOW] Calling legacy FingerprintManager.authenticate(...)");
        android.hardware.fingerprint.FingerprintManager fpm =
                getSystemService(android.hardware.fingerprint.FingerprintManager.class);
        if (fpm != null) {
            fpm.authenticate(
                    null,
                    new android.os.CancellationSignal(),
                    0,
                    new android.hardware.fingerprint.FingerprintManager.AuthenticationCallback() {
                        @Override
                        public void onAuthenticationSucceeded(
                                android.hardware.fingerprint.FingerprintManager.AuthenticationResult result) {
                            String summary = "FP_PASS (onAuthenticationSucceeded) -> result=" + result;
                            appendLog("[BIO_OUTCOME] " + summary);
                            refreshStatusBanner(summary);
                        }

                        @Override
                        public void onAuthenticationFailed() {
                            String summary = "FP_FAIL (onAuthenticationFailed)";
                            appendLog("[BIO_OUTCOME] " + summary);
                            refreshStatusBanner(summary);
                        }

                        @Override
                        public void onAuthenticationError(int errMsgId, CharSequence errString) {
                            String summary = "FP_CANCEL/ERROR (onAuthenticationError) -> errorCode="
                                    + errMsgId + " errString='" + errString + "'";
                            appendLog("[BIO_OUTCOME] " + summary);
                            refreshStatusBanner(summary);
                        }
                    },
                    mHandler);
        }
        if (autoClickChoice != null && !autoClickChoice.isEmpty()) {
            mHandler.postDelayed(() -> {
                String telemetryBeforeClick = queryLoaderMethod(
                        "org.lsposed.lspatch.loader.BiometricPromptHookDialog", "getHookTelemetry");
                boolean clicked = invokeDialogClick(autoClickChoice);
                appendLog("[BIO_AUTO_CLICK] choice=" + autoClickChoice
                        + " clicked=" + clicked
                        + " telemetryBeforeClick={" + telemetryBeforeClick + "}");
            }, 600);
        }
    }

    private String queryLoaderMethod(String className, String methodName) {
        try {
            Class<?> cls = Class.forName(className, false, getClassLoader());
            Method m = cls.getDeclaredMethod(methodName);
            m.setAccessible(true);
            Object res = m.invoke(null);
            return String.valueOf(res);
        } catch (Throwable t) {
            return "UNAVAILABLE (" + t.getClass().getSimpleName() + ")";
        }
    }

    private boolean invokeDialogClick(String choice) {
        try {
            Class<?> cls = Class.forName("org.lsposed.lspatch.loader.BiometricPromptHookDialog", false, getClassLoader());
            Method m = cls.getDeclaredMethod("performDialogButtonClick", String.class);
            m.setAccessible(true);
            Object res = m.invoke(null, choice);
            return Boolean.TRUE.equals(res);
        } catch (Throwable t) {
            Log.e(TAG, "Failed to invoke performDialogButtonClick", t);
            return false;
        }
    }
}
