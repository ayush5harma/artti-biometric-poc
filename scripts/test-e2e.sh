#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
PKG="com.example.arttipoc"

"$PROJECT_ROOT/scripts/build.sh"

echo "========================================================================"
echo "Device Under Test:"
adb shell "echo model=\$(getprop ro.product.model) android=\$(getprop ro.build.version.release) sdk=\$(getprop ro.build.version.sdk) build_type=\$(getprop ro.build.type) debuggable=\$(getprop ro.debuggable)"
echo "========================================================================"

install_fresh() {
    local apk="$1"
    adb uninstall "$PKG" >/dev/null 2>&1 || true
    adb install --no-incremental -r "$apk" >/dev/null
}

echo ""
echo "--- [SCENARIO 1] Unpatched Baseline (debuggable=false, -m speed) ---"
install_fresh "$BUILD_DIR/unpatched-sample.apk"
adb shell cmd package compile -m speed -f "$PKG" >/dev/null
adb logcat -c
adb shell am start -W -n "$PKG/.MainActivity" --es e2e_action run_all >/dev/null
sleep 2
adb logcat -d -s ARTTI_POC:I ARTTI_LSPatch:I ARTTI_BIOMETRIC:I | grep -E "UNPATCHED_BASELINE|BiometricAuthController|BiometricCallback|HOOK_VERIFY" || true

echo ""
echo "--- [SCENARIO 2] Non-Debuggable Manifest + AOT '-m speed' (lspatch-nondebuggable.apk) ---"
install_fresh "$BUILD_DIR/lspatch-nondebuggable.apk"
adb shell cmd package compile -m speed -f "$PKG" >/dev/null
adb logcat -c
adb shell am start -W -n "$PKG/.MainActivity" --es e2e_action run_all --es bio_choice PASS >/dev/null
sleep 2
adb logcat -d -s ARTTI_POC:I ARTTI_LSPatch:I ARTTI_BIOMETRIC:I | grep -E "JNI_OnLoad|Verified Gate|Upgraded runtime_debug_state_|LSPApplication bootstrap|HOOK_VERIFY|INTERCEPTED|POPUP_SHOWN|BIO_AUTO_CLICK|BIO_OUTCOME" || true

echo ""
echo "--- [SCENARIO 3] Rootless Package-Install Layer #1: Non-Debuggable Manifest + 'cmd package compile -m verify' ---"
# Without root, shell UID (2000) can force compiler-filter=verify so base.odex has zero AOT inlining.
adb shell am force-stop "$PKG"
adb shell cmd package compile -m verify -f "$PKG" >/dev/null
ODEX_PATH="$(adb shell pm path "$PKG" | sed 's/package://;s/base.apk/oat\/arm64\/base.odex/' | tr -d '\r')"
echo "base.odex compiler filter status:"
adb shell "oatdump --oat-file=$ODEX_PATH --header-only" | grep -E "compiler-filter =|dex2oat-cmdline =" || true
adb logcat -c
adb shell am start -W -n "$PKG/.MainActivity" --es e2e_action run_all --es bio_choice PASS >/dev/null
sleep 2
adb logcat -d -s ARTTI_POC:I ARTTI_LSPatch:I ARTTI_BIOMETRIC:I | grep -E "LSPApplication bootstrap|HOOK_VERIFY|BIO_OUTCOME" || true

echo ""
echo "--- [SCENARIO 4] Rootless Package-Install Layer #2: JingMatrix/LSPatch Nested origin.apk (even under '-m speed') ---"
install_fresh "$BUILD_DIR/lspatch-nested-origin.apk"
adb shell cmd package compile -m speed -f "$PKG" >/dev/null
adb logcat -c
adb shell am start -W -n "$PKG/.MainActivity" --es e2e_action run_all --es bio_choice PASS >/dev/null
sleep 2
adb logcat -d -s ARTTI_POC:I ARTTI_LSPatch:I ARTTI_BIOMETRIC:I | grep -E "Swapped LoadedApk|LSPApplication bootstrap|HOOK_VERIFY|BIO_OUTCOME" || true

echo ""
echo "--- [SCENARIO 5] Rootless Package-Install Layer #3: APK-Packaging debuggable=true + Runtime FLAG_DEBUGGABLE Scrub (even under '-m speed') ---"
install_fresh "$BUILD_DIR/lspatch-debuggable-scrubbed.apk"
adb shell cmd package compile -m speed -f "$PKG" >/dev/null
adb logcat -c
adb shell am start -W -n "$PKG/.MainActivity" --es e2e_action run_all --es bio_choice PASS >/dev/null
sleep 2
echo "[5A: Biometric Popup -> PASS]"
adb logcat -d -s ARTTI_POC:I ARTTI_LSPatch:I ARTTI_BIOMETRIC:I | grep -E "Attached ART TI agent|LSPApplication bootstrap|HOOK_VERIFY|INTERCEPTED|ForceEarlyReturnVoid|POPUP_SHOWN|POPUP_ACTION|BIO_AUTO_CLICK|BIO_OUTCOME" || true

echo ""
echo "[5B: Biometric Popup -> FAIL]"
adb logcat -c
adb shell am start -S -W -n "$PKG/.MainActivity" --es e2e_action biometric --es bio_choice FAIL >/dev/null
sleep 2
adb logcat -d -s ARTTI_POC:I ARTTI_LSPatch:I ARTTI_BIOMETRIC:I | grep -E "INTERCEPTED|ForceEarlyReturnVoid|POPUP_SHOWN|POPUP_ACTION|BIO_AUTO_CLICK|BIO_OUTCOME" || true

echo ""
echo "[5C: Biometric Popup -> CANCEL]"
adb logcat -c
adb shell am start -S -W -n "$PKG/.MainActivity" --es e2e_action biometric --es bio_choice CANCEL >/dev/null
sleep 2
adb logcat -d -s ARTTI_POC:I ARTTI_LSPatch:I ARTTI_BIOMETRIC:I | grep -E "INTERCEPTED|ForceEarlyReturnVoid|POPUP_SHOWN|POPUP_ACTION|BIO_AUTO_CLICK|BIO_OUTCOME" || true

echo ""
echo "[5D: Legacy FingerprintManager.authenticate -> PASS]"
adb logcat -c
adb shell am start -S -W -n "$PKG/.MainActivity" --es e2e_action fingerprint --es bio_choice PASS >/dev/null
sleep 2
adb logcat -d -s ARTTI_POC:I ARTTI_LSPatch:I ARTTI_BIOMETRIC:I | grep -E "INTERCEPTED|ForceEarlyReturnVoid|POPUP_SHOWN|POPUP_ACTION|BIO_AUTO_CLICK|BIO_OUTCOME" || true

echo ""
echo "[5E: Interactive Popup Window Hierarchy Check (leaving Pass/Fail/Cancel popup visible for uiautomator inspection)]"
adb logcat -c
adb shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1 || true
adb shell am start -S -W -n "$PKG/.MainActivity" --es e2e_action biometric >/dev/null
sleep 1
adb shell uiautomator dump /data/local/tmp/uidump.xml >/dev/null
adb shell "grep -o 'text=\"[^\"]*\"' /data/local/tmp/uidump.xml | grep -v 'text=\"\"' && rm -f /data/local/tmp/uidump.xml"
echo "========================================================================"
