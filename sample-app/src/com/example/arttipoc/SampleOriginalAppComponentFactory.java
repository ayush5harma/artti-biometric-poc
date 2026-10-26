package com.example.arttipoc;

import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.content.Intent;
import android.util.Log;

/**
 * Simulates an app that already declares its own android:appComponentFactory
 * (such as androidx.core.app.CoreComponentFactory) prior to LSPatch repackaging.
 *
 * Verified 2026-10-26 on Pixel 9 Pro (Android 17, API 37):
 * LSPAppComponentFactoryStub runs the ART TI bootstrap in <clinit> and then
 * delegates all component instantiation calls to this original factory.
 */
public class SampleOriginalAppComponentFactory extends AppComponentFactory {

    private static final String TAG = "ARTTI_POC";
    private static volatile boolean sDelegatedApplication = false;
    private static volatile boolean sDelegatedActivity = false;

    public static boolean didDelegateApplication() {
        return sDelegatedApplication;
    }

    public static boolean didDelegateActivity() {
        return sDelegatedActivity;
    }

    @Override
    public Application instantiateApplication(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        sDelegatedApplication = true;
        Log.i(TAG, "[ORIG_FACTORY] SampleOriginalAppComponentFactory.instantiateApplication(" + className + ")");
        return super.instantiateApplication(cl, className);
    }

    @Override
    public Activity instantiateActivity(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        sDelegatedActivity = true;
        Log.i(TAG, "[ORIG_FACTORY] SampleOriginalAppComponentFactory.instantiateActivity(" + className + ")");
        return super.instantiateActivity(cl, className, intent);
    }
}
