package com.example.arttipoc;

/**
 * Cross-class tiny method that dex2oat (-m speed) AOT-inlines into TargetWork.callerMethod.
 * Measured 2026-10-26 on Pixel 9 Pro (Android 17, API 37): oatdump confirms this method compiles
 * to 3 inline ARM64 instructions (mov w16, #0x5a; eor w1, w1, w16; add w1, w1, #0xd) inside
 * TargetWork.callerMethod with no bl instruction when compiled with -m speed.
 */
public final class InlinedCallee {
    private InlinedCallee() {}

    public static int crossClassInlined(int x) {
        return (x ^ 0x5A) + 13;
    }
}
