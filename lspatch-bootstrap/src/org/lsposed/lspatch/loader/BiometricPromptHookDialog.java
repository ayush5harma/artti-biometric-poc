package org.lsposed.lspatch.loader;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.graphics.Color;
import android.graphics.Typeface;
import android.hardware.biometrics.BiometricPrompt;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.lang.reflect.Field;
import java.util.Map;
import java.util.concurrent.Executor;

/**
 * In-app BiometricPrompt replacement popup driven by ART TI (JVMTI) method interception.
 *
 * When the target application calls android.hardware.biometrics.BiometricPrompt.authenticate(...),
 * our JVMTI Breakpoint callback in libarttipoc.so fires at bytecode offset 0, extracts the
 * BiometricPrompt, CryptoObject, CancellationSignal, Executor, and AuthenticationCallback
 * references from the frame's DEX registers via jvmtiEnv::GetLocalObject, invokes
 * onAuthenticateIntercepted(...), and calls jvmtiEnv::ForceEarlyReturnVoid so the system
 * BiometricService is never contacted.
 */
public final class BiometricPromptHookDialog {

    private static final String TAG = "ARTTI_BIOMETRIC";
    private static final Handler MAIN_HANDLER = new Handler(Looper.getMainLooper());

    private static volatile AlertDialog sCurrentDialog;
    private static volatile int sInterceptCount = 0;
    private static volatile String sLastInterceptedTitle = "";
    private static volatile String sLastUserAction = "NONE";

    private BiometricPromptHookDialog() {}

    public static native String nativeAttachAgentNonDebuggable(ClassLoader classLoader);
    public static native String nativeInstallBiometricHook(Class<?> dialogHelperClass, Class<?> biometricPromptClass);
    public static native Object nativeCreateAuthenticationResult(Object cryptoObject, int authenticationType);
    public static native Object nativeCreateFingerprintAuthResult(Object cryptoObject);
    public static native void nativeRegisterAppNatives(Class<?> mainActivityClass);

    public static String installHooks() {
        return nativeInstallBiometricHook(BiometricPromptHookDialog.class, BiometricPrompt.class);
    }

    /**
     * Called from libarttipoc.so OnBreakpoint at bytecode location 0 of
     * android.hardware.fingerprint.FingerprintManager.authenticate(...) (legacy API 23-28 path)
     * immediately before ForceEarlyReturnVoid aborts the system FingerprintService call.
     */
    @SuppressWarnings({"unused", "deprecation"})
    public static void onFingerprintAuthenticateIntercepted(
            final android.hardware.fingerprint.FingerprintManager.CryptoObject crypto,
            final CancellationSignal cancelSignal,
            final android.hardware.fingerprint.FingerprintManager.AuthenticationCallback fpCallback,
            final Handler handler) {

        sInterceptCount++;
        final CharSequence title = "Legacy FingerprintManager Auth";
        final CharSequence subtitle = "android.hardware.fingerprint.FingerprintManager";
        final CharSequence description = "Intercepted via ART TI SetBreakpoint + ForceEarlyReturnVoid";
        sLastInterceptedTitle = title.toString();

        Log.i(TAG, "[INTERCEPTED] FingerprintManager.authenticate intercepted via ART TI! "
                + "count=" + sInterceptCount + " crypto=" + crypto
                + " cancelSignal=" + cancelSignal + " callback=" + fpCallback);

        final Executor executor = r -> {
            if (handler != null) {
                handler.post(r);
            } else {
                MAIN_HANDLER.post(r);
            }
        };

        final BiometricPrompt.AuthenticationCallback adapter = new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult ignored) {
                if (fpCallback != null) {
                    android.hardware.fingerprint.FingerprintManager.AuthenticationResult fpRes =
                            (android.hardware.fingerprint.FingerprintManager.AuthenticationResult)
                                    nativeCreateFingerprintAuthResult(crypto);
                    fpCallback.onAuthenticationSucceeded(fpRes);
                }
            }

            @Override
            public void onAuthenticationFailed() {
                if (fpCallback != null) {
                    fpCallback.onAuthenticationFailed();
                }
            }

            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                if (fpCallback != null) {
                    fpCallback.onAuthenticationError(errorCode, errString);
                }
            }
        };

        if (cancelSignal != null) {
            cancelSignal.setOnCancelListener(() -> MAIN_HANDLER.post(() -> {
                AlertDialog dlg = sCurrentDialog;
                if (dlg != null && dlg.isShowing()) {
                    sCurrentDialog = null;
                    dlg.dismiss();
                }
                sLastUserAction = "CANCELED_BY_SIGNAL";
                dispatchCancel(executor, adapter, BiometricPrompt.BIOMETRIC_ERROR_CANCELED,
                        "Fingerprint authentication canceled by app CancellationSignal");
            }));
        }

        MAIN_HANDLER.post(() -> showPopupDialog(title, subtitle, description, null, executor, adapter));
    }

    /**
     * Called from libarttipoc.so OnBreakpoint at bytecode location 0 of BiometricPrompt.authenticate
     * immediately before ForceEarlyReturnVoid aborts the real system call.
     */
    @SuppressWarnings("unused")
    public static void onAuthenticateIntercepted(
            final BiometricPrompt prompt,
            final BiometricPrompt.CryptoObject crypto,
            final CancellationSignal cancelSignal,
            final Executor executor,
            final BiometricPrompt.AuthenticationCallback callback) {

        sInterceptCount++;
        final CharSequence title = prompt != null && prompt.getTitle() != null
                ? prompt.getTitle() : "Biometric Authentication";
        final CharSequence subtitle = prompt != null && prompt.getSubtitle() != null
                ? prompt.getSubtitle() : "";
        final CharSequence description = prompt != null && prompt.getDescription() != null
                ? prompt.getDescription() : "";
        sLastInterceptedTitle = title.toString();

        Log.i(TAG, "[INTERCEPTED] BiometricPrompt.authenticate intercepted via ART TI! "
                + "count=" + sInterceptCount
                + " title='" + title + "' subtitle='" + subtitle + "' crypto=" + crypto
                + " cancelSignal=" + cancelSignal + " callback=" + callback);

        if (cancelSignal != null) {
            cancelSignal.setOnCancelListener(() -> MAIN_HANDLER.post(() -> {
                AlertDialog dlg = sCurrentDialog;
                if (dlg != null && dlg.isShowing()) {
                    sCurrentDialog = null;
                    dlg.dismiss();
                }
                sLastUserAction = "CANCELED_BY_SIGNAL";
                dispatchCancel(executor, callback, BiometricPrompt.BIOMETRIC_ERROR_CANCELED,
                        "Biometric authentication canceled by app CancellationSignal");
            }));
        }

        MAIN_HANDLER.post(() -> showPopupDialog(title, subtitle, description, crypto, executor, callback));
    }

    private static void showPopupDialog(
            CharSequence title,
            CharSequence subtitle,
            CharSequence description,
            BiometricPrompt.CryptoObject crypto,
            Executor executor,
            BiometricPrompt.AuthenticationCallback callback) {

        Activity activity = findTopResumedActivity();
        if (activity == null || activity.isFinishing()) {
            Log.e(TAG, "No active Activity found to display BiometricPrompt replacement popup");
            dispatchCancel(executor, callback, BiometricPrompt.BIOMETRIC_ERROR_HW_UNAVAILABLE,
                    "No foreground Activity for ART TI biometric popup");
            return;
        }

        AlertDialog existing = sCurrentDialog;
        if (existing != null && existing.isShowing()) {
            existing.dismiss();
        }

        LinearLayout container = new LinearLayout(activity);
        container.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(activity, 20);
        container.setPadding(pad, pad / 2, pad, pad / 2);

        TextView badgeView = new TextView(activity);
        badgeView.setText("ART TI (JVMTI) INTERCEPTED PROMPT");
        badgeView.setTextSize(12f);
        badgeView.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        badgeView.setTextColor(Color.parseColor("#1B5E20"));
        badgeView.setBackgroundColor(Color.parseColor("#E8F5E9"));
        badgeView.setPadding(dp(activity, 8), dp(activity, 6), dp(activity, 8), dp(activity, 6));
        badgeView.setGravity(Gravity.CENTER);
        container.addView(badgeView);

        if (subtitle != null && subtitle.length() > 0) {
            TextView subView = new TextView(activity);
            subView.setText(subtitle);
            subView.setTextSize(15f);
            subView.setTypeface(Typeface.DEFAULT_BOLD);
            subView.setPadding(0, dp(activity, 12), 0, dp(activity, 4));
            container.addView(subView);
        }

        if (description != null && description.length() > 0) {
            TextView descView = new TextView(activity);
            descView.setText(description);
            descView.setTextSize(14f);
            descView.setPadding(0, dp(activity, 4), 0, dp(activity, 8));
            container.addView(descView);
        }

        TextView noteView = new TextView(activity);
        noteView.setText("System BiometricPrompt was bypassed at bytecode offset 0 via JVMTI "
                + "SetBreakpoint + ForceEarlyReturnVoid.\nSelect simulated outcome:");
        noteView.setTextSize(13f);
        noteView.setTextColor(Color.parseColor("#424242"));
        noteView.setPadding(0, dp(activity, 8), 0, 0);
        container.addView(noteView);

        AlertDialog dialog = new AlertDialog.Builder(activity)
                .setTitle("[Biometric Sim] " + title)
                .setView(container)
                .setCancelable(false)
                .setPositiveButton("PASS", (d, which) -> {
                    sCurrentDialog = null;
                    sLastUserAction = "PASS";
                    Log.i(TAG, "[POPUP_ACTION] User clicked PASS -> invoking onAuthenticationSucceeded");
                    dispatchPass(crypto, executor, callback);
                })
                .setNeutralButton("FAIL", (d, which) -> {
                    sCurrentDialog = null;
                    sLastUserAction = "FAIL";
                    Log.i(TAG, "[POPUP_ACTION] User clicked FAIL -> invoking onAuthenticationFailed");
                    dispatchFail(executor, callback);
                })
                .setNegativeButton("CANCEL", (d, which) -> {
                    sCurrentDialog = null;
                    sLastUserAction = "CANCEL";
                    Log.i(TAG, "[POPUP_ACTION] User clicked CANCEL -> invoking onAuthenticationError(USER_CANCELED)");
                    dispatchCancel(executor, callback,
                            BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED,
                            "User canceled biometric authentication via ART TI popup");
                })
                .create();

        sCurrentDialog = dialog;
        dialog.show();
        Log.i(TAG, "[POPUP_SHOWN] Displayed in-app Pass/Fail/Cancel biometric popup on Activity="
                + activity.getClass().getName());
    }

    /**
     * Allows automated E2E tests or UI instrumentation to click the live AlertDialog button
     * ("PASS", "FAIL", or "CANCEL") on the main thread and verify that the dialog is actually showing.
     */
    public static boolean performDialogButtonClick(String action) {
        final AlertDialog dialog = sCurrentDialog;
        if (dialog == null || !dialog.isShowing()) {
            Log.e(TAG, "[performDialogButtonClick] No active biometric popup dialog is showing!");
            return false;
        }
        final int whichButton;
        if ("PASS".equalsIgnoreCase(action)) {
            whichButton = DialogInterface.BUTTON_POSITIVE;
        } else if ("FAIL".equalsIgnoreCase(action)) {
            whichButton = DialogInterface.BUTTON_NEUTRAL;
        } else if ("CANCEL".equalsIgnoreCase(action)) {
            whichButton = DialogInterface.BUTTON_NEGATIVE;
        } else {
            return false;
        }
        MAIN_HANDLER.post(() -> {
            if (dialog.isShowing() && dialog.getButton(whichButton) != null) {
                dialog.getButton(whichButton).performClick();
            }
        });
        return true;
    }

    public static boolean isPopupShowing() {
        AlertDialog dialog = sCurrentDialog;
        return dialog != null && dialog.isShowing();
    }

    public static String getHookTelemetry() {
        return "interceptCount=" + sInterceptCount
                + " popupShowing=" + isPopupShowing()
                + " lastTitle='" + sLastInterceptedTitle + "'"
                + " lastAction=" + sLastUserAction;
    }

    private static void dispatchPass(
            BiometricPrompt.CryptoObject crypto,
            Executor executor,
            BiometricPrompt.AuthenticationCallback callback) {
        Runnable r = () -> {
            try {
                BiometricPrompt.AuthenticationResult result =
                        (BiometricPrompt.AuthenticationResult) nativeCreateAuthenticationResult(
                                crypto, BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC);
                callback.onAuthenticationSucceeded(result);
            } catch (Throwable t) {
                Log.e(TAG, "Failed to dispatch onAuthenticationSucceeded", t);
            }
        };
        if (executor != null) {
            executor.execute(r);
        } else {
            MAIN_HANDLER.post(r);
        }
    }

    private static void dispatchFail(
            Executor executor,
            BiometricPrompt.AuthenticationCallback callback) {
        Runnable r = () -> {
            try {
                callback.onAuthenticationFailed();
            } catch (Throwable t) {
                Log.e(TAG, "Failed to dispatch onAuthenticationFailed", t);
            }
        };
        if (executor != null) {
            executor.execute(r);
        } else {
            MAIN_HANDLER.post(r);
        }
    }

    private static void dispatchCancel(
            Executor executor,
            BiometricPrompt.AuthenticationCallback callback,
            int errorCode,
            String errString) {
        Runnable r = () -> {
            try {
                callback.onAuthenticationError(errorCode, errString);
            } catch (Throwable t) {
                Log.e(TAG, "Failed to dispatch onAuthenticationError", t);
            }
        };
        if (executor != null) {
            executor.execute(r);
        } else {
            MAIN_HANDLER.post(r);
        }
    }

    @SuppressWarnings("unchecked")
    private static Activity findTopResumedActivity() {
        try {
            Class<?> atCls = Class.forName("android.app.ActivityThread");
            java.lang.reflect.Method curAtMid = atCls.getDeclaredMethod("currentActivityThread");
            curAtMid.setAccessible(true);
            Object at = curAtMid.invoke(null);
            Field mActivitiesField = atCls.getDeclaredField("mActivities");
            mActivitiesField.setAccessible(true);
            Map<Object, Object> activities = (Map<Object, Object>) mActivitiesField.get(at);
            if (activities == null) return null;
            Activity fallback = null;
            for (Object record : activities.values()) {
                Class<?> acrClass = record.getClass();
                Field activityField = acrClass.getDeclaredField("activity");
                activityField.setAccessible(true);
                Activity act = (Activity) activityField.get(record);
                if (act == null) continue;
                fallback = act;
                Field pausedField = acrClass.getDeclaredField("paused");
                pausedField.setAccessible(true);
                if (!pausedField.getBoolean(record)) {
                    return act;
                }
            }
            return fallback;
        } catch (Throwable t) {
            Log.e(TAG, "Failed to inspect ActivityThread.mActivities", t);
            return null;
        }
    }

    private static int dp(Activity activity, int dp) {
        float density = activity.getResources().getDisplayMetrics().density;
        return Math.round(dp * density);
    }
}
