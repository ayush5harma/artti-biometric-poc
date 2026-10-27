package org.lsposed.lspatch.loader;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.Debug;
import android.system.Os;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Second-stage loader modeled on JingMatrix/LSPatch
 * (patch-loader/src/main/java/org/lsposed/lspatch/loader/LSPApplication.java).
 *
 * Measured 2026-10-26 on Pixel 9 Pro (Android 17, API 37):
 * 1. Stock LSPatch v0.6 and JingMatrix/LSPatch v1.2 fail at LSPApplication.createLoadedApkWithContext
 *    with NoSuchFieldError: android.app.ActivityThread$AppBindData#compatInfo because compatInfo is
 *    marked hiddenapi MAX-TARGET-P (0x0004). We exempt hidden APIs in JNI before entering onLoad()
 *    and provide a fallback to CompatibilityInfo.DEFAULT_COMPATIBILITY_INFO.
 * 2. Locking /data/misc/profiles/cur/<userId>/<pkg>/primary.prof to mode 0400 (0 bytes) prevents
 *    ART's ProfileSaver and background dexopt from AOT-inlining app methods after installation.
 * 3. When packaged with android:debuggable="true" (LSPatch --debuggable mode), Debug.attachJvmtiAgent
 *    initializes libopenjdkjvmti.so officially without touching private libart.so offsets, and
 *    scrubDebuggableFlag() clears ApplicationInfo.FLAG_DEBUGGABLE immediately afterward so the app
 *    observes debuggable == false.
 */
public final class LSPApplication {

    private static final String TAG = "ARTTI_LSPatch";
    private static final String ORIGINAL_APK_ASSET_PATH = "assets/lspatch/origin.apk";
    private static final int PER_USER_RANGE = 100000;

    private static Object sActivityThread;
    private static Object sStubLoadedApk;
    private static Object sAppLoadedApk;
    private static ClassLoader sStubClassLoader;
    private static boolean sWasManifestDebuggable;
    private static boolean sScrubbedDebuggableFlag;
    private static String sAttachMechanism = "NOT_ATTACHED";

    private LSPApplication() {}

    public static void onLoad() {
        try {
            Class<?> atCls = Class.forName("android.app.ActivityThread");
            Method currentAt = atCls.getDeclaredMethod("currentActivityThread");
            currentAt.setAccessible(true);
            sActivityThread = currentAt.invoke(null);
            if (sActivityThread == null) {
                Log.e(TAG, "ActivityThread.currentActivityThread() is null");
                return;
            }

            Context context = setupLoadedApkAndContext(atCls);
            if (context == null) {
                Log.e(TAG, "Failed to create application context");
                return;
            }

            disableProfile(context);
            attachArtTiAgent(context);
            scrubDebuggableFlag(atCls);
            bindMainActivityNatives(context.getClassLoader());

            String hookStatus = BiometricPromptHookDialog.installHooks();
            String camHookStatus = CameraInjectionHook.installHooks(
                    context.getFilesDir(), context.getClassLoader());
            Log.i(TAG, "LSPApplication bootstrap complete: attach=" + sAttachMechanism
                    + " manifestDebuggable=" + sWasManifestDebuggable
                    + " scrubbedDebuggable=" + sScrubbedDebuggableFlag
                    + " biometricHook=" + hookStatus
                    + " cameraHook=" + camHookStatus);
        } catch (Throwable t) {
            Log.e(TAG, "LSPApplication.onLoad failed", t);
        }
    }

    private static Context setupLoadedApkAndContext(Class<?> atCls) throws Exception {
        Class<?> loadedApkCls = Class.forName("android.app.LoadedApk");
        Field boundAppField = findField(atCls, "mBoundApplication");
        Object mBoundApplication = boundAppField.get(sActivityThread);

        Field infoField = findField(mBoundApplication.getClass(), "info");
        Field appInfoField = findField(mBoundApplication.getClass(), "appInfo");

        sStubLoadedApk = infoField.get(mBoundApplication);
        ApplicationInfo appInfo = (ApplicationInfo) appInfoField.get(mBoundApplication);
        sWasManifestDebuggable = (appInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;

        Method getClassLoaderMid = loadedApkCls.getDeclaredMethod("getClassLoader");
        getClassLoaderMid.setAccessible(true);
        ClassLoader baseClassLoader = (ClassLoader) getClassLoaderMid.invoke(sStubLoadedApk);
        sStubClassLoader = baseClassLoader;

        boolean hasNestedOrigin = false;
        try (ZipFile sourceZip = new ZipFile(appInfo.sourceDir)) {
            ZipEntry originEntry = sourceZip.getEntry(ORIGINAL_APK_ASSET_PATH);
            if (originEntry != null) {
                hasNestedOrigin = true;
                Path originDir = Paths.get(appInfo.dataDir, "cache/lspatch/origin/");
                Path cacheApkPath = originDir.resolve(originEntry.getCrc() + ".apk");
                if (!Files.exists(cacheApkPath)) {
                    deleteDirectoryContents(originDir.toFile());
                    Files.createDirectories(originDir);
                    try (InputStream is = baseClassLoader.getResourceAsStream(ORIGINAL_APK_ASSET_PATH)) {
                        Files.copy(is, cacheApkPath);
                    }
                }
                cacheApkPath.toFile().setWritable(false);

                appInfo.sourceDir = cacheApkPath.toString();
                appInfo.publicSourceDir = cacheApkPath.toString();
                appInfo.appComponentFactory = null;

                Class<?> compatInfoCls = Class.forName("android.content.res.CompatibilityInfo");
                Object compatInfo = resolveCompatInfo(mBoundApplication, sStubLoadedApk, loadedApkCls, compatInfoCls);
                Map<?, ?> mPackages = (Map<?, ?>) findField(atCls, "mPackages").get(sActivityThread);
                mPackages.remove(appInfo.packageName);

                Method getPkgInfoNoCheck = atCls.getDeclaredMethod(
                        "getPackageInfoNoCheck", ApplicationInfo.class, compatInfoCls);
                getPkgInfoNoCheck.setAccessible(true);
                sAppLoadedApk = getPkgInfoNoCheck.invoke(sActivityThread, appInfo, compatInfo);
                infoField.set(mBoundApplication, sAppLoadedApk);

                ClassLoader appCl = (ClassLoader) getClassLoaderMid.invoke(sAppLoadedApk);
                bridgeLoaderClassesIntoAppClassLoader(appCl);
                switchAllClassLoader(loadedApkCls, sStubLoadedApk, sAppLoadedApk);
                repointActivityClientRecords(atCls);
                Log.i(TAG, "Swapped LoadedApk from nested origin.apk: " + cacheApkPath);
            }
        }

        if (!hasNestedOrigin) {
            sAppLoadedApk = sStubLoadedApk;
            ClassLoader appCl = (ClassLoader) getClassLoaderMid.invoke(sAppLoadedApk);
            bridgeLoaderClassesIntoAppClassLoader(appCl);
        }

        Method createAppContext = Class.forName("android.app.ContextImpl")
                .getDeclaredMethod("createAppContext", atCls, loadedApkCls);
        createAppContext.setAccessible(true);
        return (Context) createAppContext.invoke(null, sActivityThread, sStubLoadedApk);
    }

    private static Object resolveCompatInfo(
            Object mBoundApplication,
            Object stubLoadedApk,
            Class<?> loadedApkCls,
            Class<?> compatInfoCls) {
        try {
            Field compatField = findField(mBoundApplication.getClass(), "compatInfo");
            Object val = compatField.get(mBoundApplication);
            if (val != null) return val;
        } catch (Throwable ignored) {
        }
        try {
            Method getCompat = loadedApkCls.getDeclaredMethod("getCompatibilityInfo");
            getCompat.setAccessible(true);
            Object val = getCompat.invoke(stubLoadedApk);
            if (val != null) return val;
        } catch (Throwable ignored) {
        }
        try {
            Field defaultCompat = findField(compatInfoCls, "DEFAULT_COMPATIBILITY_INFO");
            return defaultCompat.get(null);
        } catch (Throwable t) {
            return null;
        }
    }

    private static void bridgeLoaderClassesIntoAppClassLoader(ClassLoader appClassLoader) {
        try {
            final ClassLoader loaderCl = LSPApplication.class.getClassLoader();
            if (appClassLoader == loaderCl) {
                return;
            }
            ClassLoader realParent = appClassLoader.getParent();
            ClassLoader bridge = new ClassLoader(realParent) {
                @Override
                protected Class<?> findClass(String name) throws ClassNotFoundException {
                    if (name.startsWith("org.lsposed.lspatch.loader.")) {
                        return loaderCl.loadClass(name);
                    }
                    throw new ClassNotFoundException(name);
                }
            };
            Field parentField = findField(ClassLoader.class, "parent");
            parentField.set(appClassLoader, bridge);
        } catch (Throwable t) {
            Log.w(TAG, "Failed to bridge loader ClassLoader", t);
        }
    }

    private static void attachArtTiAgent(Context context) {
        ClassLoader cl = sStubClassLoader != null ? sStubClassLoader : context.getClassLoader();
        if (sWasManifestDebuggable) {
            try {
                Debug.attachJvmtiAgent("libarttipoc.so", null, cl);
                sAttachMechanism = "PUBLIC_SDK_DEBUG_ATTACH_JVMTI_AGENT";
                Log.i(TAG, "Attached ART TI agent via public Debug.attachJvmtiAgent");
                return;
            } catch (Throwable t) {
                Log.w(TAG, "Debug.attachJvmtiAgent threw despite debuggable flag; falling back to native attach", t);
            }
        }

        try {
            Debug.attachJvmtiAgent("libarttipoc.so", null, cl);
            sAttachMechanism = "PUBLIC_SDK_DEBUG_ATTACH_JVMTI_AGENT";
            return;
        } catch (SecurityException se) {
            Log.i(TAG, "Verified Gate 3: public Debug.attachJvmtiAgent rejected on non-debuggable app: " + se.getMessage());
        } catch (Throwable ignored) {
        }

        String nativeRes = BiometricPromptHookDialog.nativeAttachAgentNonDebuggable(cl);
        sAttachMechanism = "NATIVE_MEM_PATCH(" + nativeRes + ")";
    }

    private static void scrubDebuggableFlag(Class<?> atCls) {
        try {
            Class<?> loadedApkCls = Class.forName("android.app.LoadedApk");
            Field boundAppField = findField(atCls, "mBoundApplication");
            Object mBoundApplication = boundAppField.get(sActivityThread);
            Field appInfoField = findField(mBoundApplication.getClass(), "appInfo");
            ApplicationInfo boundAppInfo = (ApplicationInfo) appInfoField.get(mBoundApplication);
            if (boundAppInfo != null) {
                boundAppInfo.flags &= ~ApplicationInfo.FLAG_DEBUGGABLE;
            }
            Field loadedAppInfoField = findField(loadedApkCls, "mApplicationInfo");
            if (sStubLoadedApk != null) {
                ApplicationInfo stubInfo = (ApplicationInfo) loadedAppInfoField.get(sStubLoadedApk);
                if (stubInfo != null) {
                    stubInfo.flags &= ~ApplicationInfo.FLAG_DEBUGGABLE;
                }
            }
            if (sAppLoadedApk != null && sAppLoadedApk != sStubLoadedApk) {
                ApplicationInfo realInfo = (ApplicationInfo) loadedAppInfoField.get(sAppLoadedApk);
                if (realInfo != null) {
                    realInfo.flags &= ~ApplicationInfo.FLAG_DEBUGGABLE;
                }
            }
            installPackageManagerDebuggableScrubProxy(atCls, boundAppInfo != null ? boundAppInfo.packageName : null);
            sScrubbedDebuggableFlag = true;
        } catch (Throwable t) {
            Log.w(TAG, "Failed to scrub FLAG_DEBUGGABLE", t);
        }
    }

    private static void installPackageManagerDebuggableScrubProxy(Class<?> atCls, final String selfPkg) {
        try {
            try {
                Class<?> apmCls = Class.forName("android.app.ApplicationPackageManager");
                Method disableCache = apmCls.getDeclaredMethod("disableGetApplicationInfoCache");
                disableCache.setAccessible(true);
                disableCache.invoke(null);
            } catch (Throwable ignored) {
            }
            Method getPmMethod = atCls.getDeclaredMethod("getPackageManager");
            getPmMethod.setAccessible(true);
            final Object origPm = getPmMethod.invoke(null);
            if (origPm == null) return;

            Class<?> iPmInterface = Class.forName("android.content.pm.IPackageManager");
            Object proxyPm = java.lang.reflect.Proxy.newProxyInstance(
                    iPmInterface.getClassLoader(),
                    new Class<?>[]{iPmInterface},
                    (proxy, method, args) -> {
                        Object result;
                        try {
                            result = method.invoke(origPm, args);
                        } catch (java.lang.reflect.InvocationTargetException ite) {
                            throw ite.getTargetException();
                        }
                        if (result instanceof ApplicationInfo) {
                            ApplicationInfo ai = (ApplicationInfo) result;
                            if (selfPkg == null || selfPkg.equals(ai.packageName)) {
                                ai.flags &= ~ApplicationInfo.FLAG_DEBUGGABLE;
                            }
                        } else if (result instanceof android.content.pm.PackageInfo) {
                            android.content.pm.PackageInfo pi = (android.content.pm.PackageInfo) result;
                            if (pi.applicationInfo != null && (selfPkg == null || selfPkg.equals(pi.packageName))) {
                                pi.applicationInfo.flags &= ~ApplicationInfo.FLAG_DEBUGGABLE;
                            }
                        }
                        return result;
                    });
            Field sPmField = findField(atCls, "sPackageManager");
            sPmField.set(null, proxyPm);
        } catch (Throwable t) {
            Log.w(TAG, "Failed to install IPackageManager FLAG_DEBUGGABLE scrub proxy", t);
        }
    }

    public static void disableProfile(Context context) {
        final ArrayList<String> codePaths = new ArrayList<>();
        ApplicationInfo appInfo = context.getApplicationInfo();
        String pkgName = context.getPackageName();
        if (appInfo == null) return;
        if ((appInfo.flags & ApplicationInfo.FLAG_HAS_CODE) != 0) {
            codePaths.add(appInfo.sourceDir);
        }
        if (appInfo.splitSourceDirs != null) {
            Collections.addAll(codePaths, appInfo.splitSourceDirs);
        }
        if (codePaths.isEmpty()) return;

        File profileDir = new File("/data/misc/profiles/cur/" + (appInfo.uid / PER_USER_RANGE) + "/" + pkgName);
        var attrs = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("r--------"));

        for (int i = codePaths.size() - 1; i >= 0; i--) {
            String splitName = i == 0 ? null : appInfo.splitNames[i - 1];
            File curProfileFile = new File(profileDir, splitName == null ? "primary.prof" : splitName + ".split.prof").getAbsoluteFile();
            try {
                if (!curProfileFile.exists()) {
                    Files.createFile(curProfileFile.toPath(), attrs);
                    continue;
                }
                if (!curProfileFile.canWrite() && Files.size(curProfileFile.toPath()) == 0) {
                    continue;
                }
                if (curProfileFile.exists() && !curProfileFile.delete()) {
                    try (FileOutputStream ignored = new FileOutputStream(curProfileFile)) {
                        // Truncate profile file to 0 bytes.
                    }
                    Os.chmod(curProfileFile.getAbsolutePath(), 00400);
                }
            } catch (Throwable e) {
                Log.w(TAG, "Failed to lock profile file " + curProfileFile.getAbsolutePath(), e);
            }
        }
    }

    private static void switchAllClassLoader(Class<?> loadedApkCls, Object from, Object to) throws Exception {
        for (Field field : loadedApkCls.getDeclaredFields()) {
            if (field.getType() == ClassLoader.class) {
                field.setAccessible(true);
                field.set(from, field.get(to));
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static void repointActivityClientRecords(Class<?> atCls) throws Exception {
        Class<?> acrClass = Class.forName("android.app.ActivityThread$ActivityClientRecord", false, atCls.getClassLoader());
        Field pkgInfoField = findField(acrClass, "packageInfo");
        BiConsumer<Object, Object> fixer = (k, v) -> {
            if (acrClass.isInstance(v)) {
                try {
                    if (pkgInfoField.get(v) == sStubLoadedApk) {
                        pkgInfoField.set(v, sAppLoadedApk);
                    }
                } catch (Throwable ignored) {
                }
            }
        };
        Map<Object, Object> mActivities = (Map<Object, Object>) findField(atCls, "mActivities").get(sActivityThread);
        mActivities.forEach(fixer);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                Map<Object, Object> mLaunching = (Map<Object, Object>) findField(atCls, "mLaunchingActivities").get(sActivityThread);
                mLaunching.forEach(fixer);
            } catch (Throwable ignored) {
            }
        }
    }

    private static Field findField(Class<?> clazz, String name) throws NoSuchFieldException {
        Class<?> curr = clazz;
        while (curr != null) {
            try {
                Field f = curr.getDeclaredField(name);
                f.setAccessible(true);
                return f;
            } catch (NoSuchFieldException ignored) {
                curr = curr.getSuperclass();
            }
        }
        throw new NoSuchFieldException(clazz.getName() + "#" + name);
    }

    private static void deleteDirectoryContents(File dir) {
        if (dir == null || !dir.exists()) return;
        File[] children = dir.listFiles();
        if (children != null) {
            for (File child : children) {
                if (child.isDirectory()) {
                    deleteDirectoryContents(child);
                }
                child.delete();
            }
        }
    }

    private static void bindMainActivityNatives(ClassLoader appCl) {
        try {
            Class<?> mainActCls = appCl.loadClass("com.example.arttipoc.MainActivity");
            BiometricPromptHookDialog.nativeRegisterAppNatives(mainActCls);
        } catch (Throwable t) {
            Log.w(TAG, "Failed to bind MainActivity native methods", t);
        }
    }

    public static String getBootstrapSummary() {
        return "attach=" + sAttachMechanism
                + " manifestDbg=" + sWasManifestDebuggable
                + " scrubbedDbg=" + sScrubbedDebuggableFlag;
    }
}
