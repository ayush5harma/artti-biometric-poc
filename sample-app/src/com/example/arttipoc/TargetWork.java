package com.example.arttipoc;

import android.util.Log;

/**
 * Target methods for verifying plain vs AOT-inlined method hooking under ART TI.
 */
public final class TargetWork {
    private static final String TAG = "ARTTI_POC";

    private TargetWork() {}

    /**
     * Native JNI method used to verify JVMTI_EVENT_NATIVE_METHOD_BIND
     * (can_generate_native_method_bind_events) hooking without ShadowHook.
     */
    public static native String nativeSecretToken(String challenge);

    public static int inlinedTarget(int a, int b) {
        return (a * 31) + (b ^ 0x5A) + 7;
    }

    public static int callerMethod(int x) {
        int cross = InlinedCallee.crossClassInlined(x);
        return inlinedTarget(x + 13, cross);
    }

    public static int plainMethod(int seed) {
        int acc = seed;
        for (int i = 1; i <= 8; i++) {
            acc = (acc * 17) ^ (i * 131);
            if ((acc & 3) == 0) {
                acc += Integer.bitCount(acc ^ seed);
            }
        }
        Log.i(TAG, "[TargetWork.plainMethod] seed=" + seed + " -> acc=" + acc);
        return acc;
    }

    public interface WorkRunner {
        int plainMethod(int seed);
        int callerMethod(int x);
    }

    public static final class RealRunner implements WorkRunner {
        @Override
        public int plainMethod(int seed) {
            return TargetWork.plainMethod(seed);
        }

        @Override
        public int callerMethod(int x) {
            return TargetWork.callerMethod(x);
        }
    }

    public static final class AltRunner implements WorkRunner {
        @Override
        public int plainMethod(int seed) {
            return seed;
        }

        @Override
        public int callerMethod(int x) {
            return x;
        }
    }

    public static volatile WorkRunner sRunner =
            System.currentTimeMillis() > 0 ? new RealRunner() : new AltRunner();
}
