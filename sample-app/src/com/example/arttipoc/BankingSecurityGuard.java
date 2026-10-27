package com.example.arttipoc;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Simulates a production Banking / Fintech RASP (Runtime Application Self-Protection) security
 * suite (such as Promon Shield, DexGuard, GuardSquare) that runs 5 anti-debug / anti-tamper
 * checks before allowing Camera KYC check deposit and BiometricPrompt wire transfer approval:
 *
 * 1. Java ApplicationInfo.FLAG_DEBUGGABLE check on Context.getApplicationInfo().
 * 2. Binder IPackageManager.getApplicationInfo(pkg, 0) check against system_server.
 * 3. Native Linux kernel prctl(PR_GET_DUMPABLE) check (must be 0 on production non-debuggable apps).
 * 4. Native /proc/self/status TracerPid check (must be 0, ensuring no ptrace/Frida attach).
 * 5. Binary AndroidManifest.xml (AXML) parser inside base.apk checking resource ID 0x0101000f
 *    (android:debuggable) to verify the packaged manifest itself has debuggable=false.
 *
 * Verified 2026-10-27 on Google Pixel 9 Pro (Android 17, API 37, user build, ro.debuggable=0).
 */
public final class BankingSecurityGuard {

    private static final String TAG = "ARTTI_POC";
    private static final int ATTR_ANDROID_DEBUGGABLE = 0x0101000f;

    private BankingSecurityGuard() {}

    public static native int nativeGetPrctlDumpable();
    public static native int nativeGetTracerPid();

    public static String runBankingRaspAudit(Context context) {
        boolean javaFlagDbg = (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;

        boolean binderPmDbg = false;
        try {
            ApplicationInfo pmInfo = context.getPackageManager()
                    .getApplicationInfo(context.getPackageName(), 0);
            binderPmDbg = (pmInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        } catch (Throwable ignored) {
        }

        int prctlDumpable = -1;
        int tracerPid = -1;
        try {
            prctlDumpable = nativeGetPrctlDumpable();
            tracerPid = nativeGetTracerPid();
        } catch (UnsatisfiedLinkError ignored) {
        }

        boolean manifestAxmldbg = isBinaryManifestDebuggable(context.getApplicationInfo().sourceDir);

        int passed = 0;
        if (!javaFlagDbg) passed++;
        if (!binderPmDbg) passed++;
        if (prctlDumpable == 0) passed++;
        if (tracerPid == 0) passed++;
        if (!manifestAxmldbg) passed++;

        String verdict = (passed == 5)
                ? "BANKING_RASP_PASS(5/5_STEALTH_CLEAN)"
                : "BANKING_RASP_PARTIAL(" + passed + "/5_CLEAN)";

        String report = verdict
                + " [javaDbg=" + javaFlagDbg
                + " binderPmDbg=" + binderPmDbg
                + " prctlDumpable=" + prctlDumpable
                + " tracerPid=" + tracerPid
                + " binaryManifestDbg=" + manifestAxmldbg + "]";
        Log.i(TAG, "[BANKING_RASP_AUDIT] " + report);
        return report;
    }

    /**
     * Parses the compiled binary AndroidManifest.xml (AXML) inside the APK on disk and inspects
     * the resource ID table + attribute chunks for android:debuggable (0x0101000f).
     */
    public static boolean isBinaryManifestDebuggable(String apkPath) {
        if (apkPath == null) return false;
        try (ZipFile zip = new ZipFile(apkPath)) {
            ZipEntry entry = zip.getEntry("AndroidManifest.xml");
            if (entry == null) return false;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (InputStream is = zip.getInputStream(entry)) {
                byte[] buf = new byte[4096];
                int n;
                while ((n = is.read(buf)) != -1) {
                    baos.write(buf, 0, n);
                }
            }
            byte[] axml = baos.toByteArray();
            ByteBuffer bb = ByteBuffer.wrap(axml).order(ByteOrder.LITTLE_ENDIAN);
            if (axml.length < 8 || bb.getInt(0) != 0x00080003) {
                return false;
            }

            int offset = 8;
            int[] resourceIds = null;

            while (offset + 8 <= axml.length) {
                int chunkType = bb.getShort(offset) & 0xFFFF;
                int headerSize = bb.getShort(offset + 2) & 0xFFFF;
                int chunkSize = bb.getInt(offset + 4);
                if (chunkSize <= 0 || offset + chunkSize > axml.length) {
                    break;
                }

                if (chunkType == 0x0180) { // RES_XML_RESOURCE_MAP_TYPE
                    int count = (chunkSize - headerSize) / 4;
                    resourceIds = new int[count];
                    for (int i = 0; i < count; i++) {
                        resourceIds[i] = bb.getInt(offset + headerSize + (i * 4));
                    }
                } else if (chunkType == 0x0102 && resourceIds != null) { // RES_XML_START_ELEMENT_TYPE
                    int attrExtOffset = offset + headerSize;
                    if (attrExtOffset + 20 <= offset + chunkSize) {
                        int attrStart = bb.getShort(attrExtOffset + 8) & 0xFFFF;
                        int attrSize = bb.getShort(attrExtOffset + 10) & 0xFFFF;
                        int attrCount = bb.getShort(attrExtOffset + 12) & 0xFFFF;
                        int attrBase = attrExtOffset + attrStart;
                        for (int i = 0; i < attrCount; i++) {
                            int aOff = attrBase + (i * attrSize);
                            if (aOff + 20 <= offset + chunkSize) {
                                int nameIdx = bb.getInt(aOff + 4);
                                int dataType = bb.get(aOff + 15) & 0xFF;
                                int dataVal = bb.getInt(aOff + 16);
                                if (nameIdx >= 0 && nameIdx < resourceIds.length
                                        && resourceIds[nameIdx] == ATTR_ANDROID_DEBUGGABLE) {
                                    // TYPE_INT_BOOLEAN (0x12): dataVal != 0 means true
                                    if (dataType == 0x12 && dataVal != 0) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
                offset += chunkSize;
            }
        } catch (Throwable t) {
            Log.w(TAG, "Failed to inspect binary AndroidManifest.xml", t);
        }
        return false;
    }
}
