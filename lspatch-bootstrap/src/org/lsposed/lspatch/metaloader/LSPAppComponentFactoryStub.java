package org.lsposed.lspatch.metaloader;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Bootstrap AppComponentFactory modeled after JingMatrix/LSPatch
 * (meta-loader/src/main/java/org/lsposed/lspatch/metaloader/LSPAppComponentFactoryStub.java),
 * extended with transparent delegation to the target app's original AppComponentFactory.
 *
 * Measured 2026-10-26 on Pixel 9 Pro (Android 17, API 37):
 * 1. LoadedApk.createAppFactory instantiates the manifest-declared AppComponentFactory before
 *    Application.<init> or any Activity class is resolved. Preloading assets/lspatch/loader.dex
 *    into a static byte[] field and loading libarttipoc.so via System.loadLibrary("arttipoc")
 *    ensures Bionic maps the exact same /data/app/.../lib/arm64/libarttipoc.so image that
 *    Debug.attachJvmtiAgent("libarttipoc.so", null, cl) and VMDebug_nativeAttachAgent resolve.
 * 2. If the unpatched APK declared its own android:appComponentFactory (recorded in
 *    assets/lspatch/original_app_component_factory.txt during repackaging), all public
 *    AppComponentFactory lifecycle methods delegate to an instance of that original class.
 */
@SuppressLint("UnsafeDynamicallyLoadedCode")
public class LSPAppComponentFactoryStub extends AppComponentFactory {

    private static final String TAG = "ARTTI_LSPatch";
    private static final String LOADER_DEX_ASSET = "assets/lspatch/loader.dex";
    private static final String ORIG_FACTORY_ASSET = "assets/lspatch/original_app_component_factory.txt";
    private static final Map<String, String> ARCH_TO_LIB = new HashMap<>(4);

    public static byte[] dex;
    public static String loadedSoPath;
    private static String sOriginalFactoryClassName;

    private volatile AppComponentFactory mDelegate;

    static {
        ARCH_TO_LIB.put("arm", "armeabi-v7a");
        ARCH_TO_LIB.put("arm64", "arm64-v8a");
        ARCH_TO_LIB.put("x86", "x86");
        ARCH_TO_LIB.put("x86_64", "x86_64");

        if (isAppZygote()) {
            Log.i(TAG, "Skipping bootstrap in appZygote process");
        } else {
            bootstrap();
        }
    }

    private static boolean isAppZygote() {
        try {
            Class<?> atCls = Class.forName("android.app.ActivityThread");
            Method m = atCls.getDeclaredMethod("currentActivityThread");
            m.setAccessible(true);
            return m.invoke(null) == null;
        } catch (Throwable t) {
            return false;
        }
    }

    private static void bootstrap() {
        try {
            ClassLoader cl = Objects.requireNonNull(LSPAppComponentFactoryStub.class.getClassLoader());

            try (InputStream is = cl.getResourceAsStream(ORIG_FACTORY_ASSET)) {
                if (is != null) {
                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    transfer(is, os);
                    String name = new String(os.toByteArray(), StandardCharsets.UTF_8).trim();
                    if (!name.isEmpty() && !name.equals(LSPAppComponentFactoryStub.class.getName())) {
                        sOriginalFactoryClassName = name;
                        Log.i(TAG, "Recorded original AppComponentFactory: " + sOriginalFactoryClassName);
                    }
                }
            } catch (Throwable ignored) {
            }

            try (InputStream is = cl.getResourceAsStream(LOADER_DEX_ASSET)) {
                if (is != null) {
                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    transfer(is, os);
                    dex = os.toByteArray();
                    Log.i(TAG, "Preloaded loader.dex bytes=" + dex.length);
                }
            }

            try {
                System.loadLibrary("arttipoc");
                loadedSoPath = "libarttipoc.so";
                Log.i(TAG, "Loaded native agent via System.loadLibrary(arttipoc)");
                return;
            } catch (UnsatisfiedLinkError ignored) {
            }

            Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");
            Method getRuntime = vmRuntimeClass.getDeclaredMethod("getRuntime");
            getRuntime.setAccessible(true);
            Method vmInstructionSet = vmRuntimeClass.getDeclaredMethod("vmInstructionSet");
            vmInstructionSet.setAccessible(true);
            String arch = (String) vmInstructionSet.invoke(getRuntime.invoke(null));
            String abi = ARCH_TO_LIB.getOrDefault(arch, "arm64-v8a");

            String assetEntry = "assets/lspatch/so/" + abi + "/libarttipoc.so";
            try (InputStream is = cl.getResourceAsStream(assetEntry)) {
                if (is != null) {
                    File outFile = File.createTempFile("libarttipoc_", ".so");
                    outFile.deleteOnExit();
                    try (OutputStream os = new FileOutputStream(outFile)) {
                        transfer(is, os);
                    }
                    outFile.setReadable(true, false);
                    outFile.setExecutable(true, false);
                    System.load(outFile.getAbsolutePath());
                    loadedSoPath = outFile.getAbsolutePath();
                    Log.i(TAG, "Loaded extracted native agent: " + loadedSoPath);
                }
            }
        } catch (Throwable t) {
            Log.e(TAG, "LSPAppComponentFactoryStub bootstrap failed", t);
            throw new ExceptionInInitializerError(t);
        }
    }

    private AppComponentFactory getDelegate(ClassLoader cl) {
        AppComponentFactory delegate = mDelegate;
        if (delegate != null || sOriginalFactoryClassName == null || cl == null) {
            return delegate;
        }
        synchronized (this) {
            if (mDelegate == null) {
                try {
                    Class<?> cls = cl.loadClass(sOriginalFactoryClassName);
                    mDelegate = (AppComponentFactory) cls.getDeclaredConstructor().newInstance();
                    Log.i(TAG, "Instantiated original AppComponentFactory delegate: " + sOriginalFactoryClassName);
                } catch (Throwable t) {
                    Log.w(TAG, "Could not instantiate original AppComponentFactory " + sOriginalFactoryClassName, t);
                    sOriginalFactoryClassName = null;
                }
            }
            return mDelegate;
        }
    }

    @Override
    public ClassLoader instantiateClassLoader(ClassLoader cl, ApplicationInfo aInfo) {
        AppComponentFactory delegate = getDelegate(cl);
        if (delegate != null) {
            return delegate.instantiateClassLoader(cl, aInfo);
        }
        return super.instantiateClassLoader(cl, aInfo);
    }

    @Override
    public Application instantiateApplication(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = getDelegate(cl);
        if (delegate != null) {
            return delegate.instantiateApplication(cl, className);
        }
        return super.instantiateApplication(cl, className);
    }

    @Override
    public Activity instantiateActivity(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = getDelegate(cl);
        if (delegate != null) {
            return delegate.instantiateActivity(cl, className, intent);
        }
        return super.instantiateActivity(cl, className, intent);
    }

    @Override
    public BroadcastReceiver instantiateReceiver(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = getDelegate(cl);
        if (delegate != null) {
            return delegate.instantiateReceiver(cl, className, intent);
        }
        return super.instantiateReceiver(cl, className, intent);
    }

    @Override
    public Service instantiateService(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = getDelegate(cl);
        if (delegate != null) {
            return delegate.instantiateService(cl, className, intent);
        }
        return super.instantiateService(cl, className, intent);
    }

    @Override
    public ContentProvider instantiateProvider(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = getDelegate(cl);
        if (delegate != null) {
            return delegate.instantiateProvider(cl, className);
        }
        return super.instantiateProvider(cl, className);
    }

    private static void transfer(InputStream is, OutputStream os) throws IOException {
        byte[] buffer = new byte[8192];
        int n;
        while ((n = is.read(buffer)) != -1) {
            os.write(buffer, 0, n);
        }
    }
}
