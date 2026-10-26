#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
mkdir -p "$BUILD_DIR"
find "$BUILD_DIR" -mindepth 1 -maxdepth 1 ! -name 'poc-debug.keystore' -exec rm -rf {} +

SDK_ROOT="${ANDROID_HOME:-/nix/store/x6s8sdh2gab3bx5v2c5h794h539m7fbf-androidsdk/libexec/android-sdk}"
BUILD_TOOLS="$SDK_ROOT/build-tools/36.0.0"
PLATFORM_JAR="$SDK_ROOT/platforms/android-36/android.jar"
NDK_ROOT="$SDK_ROOT/ndk/29.0.14206865"
CLANGXX="$NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang++"

echo "[1/6] Compiling native ART TI / JVMTI agent (libarttipoc.so)..."
mkdir -p "$BUILD_DIR/lib/arm64-v8a"
"$CLANGXX" -shared -fPIC -O2 -Wall -Wextra \
    -I"$PROJECT_ROOT/native" \
    -static-libstdc++ \
    -Wl,-z,max-page-size=16384 \
    "$PROJECT_ROOT/native/agent.cpp" \
    -llog -ldl \
    -o "$BUILD_DIR/lib/arm64-v8a/libarttipoc.so"

echo "[2/6] Compiling sample app Java classes and classes.dex..."
mkdir -p "$BUILD_DIR/classes_app" "$BUILD_DIR/dex_app"
javac -source 11 -target 11 -cp "$PLATFORM_JAR" \
    -d "$BUILD_DIR/classes_app" \
    "$PROJECT_ROOT/sample-app/src/com/example/arttipoc/InlinedCallee.java" \
    "$PROJECT_ROOT/sample-app/src/com/example/arttipoc/TargetWork.java" \
    "$PROJECT_ROOT/sample-app/src/com/example/arttipoc/SampleOriginalAppComponentFactory.java" \
    "$PROJECT_ROOT/sample-app/src/com/example/arttipoc/BiometricAuthController.java" \
    "$PROJECT_ROOT/sample-app/src/com/example/arttipoc/MainActivity.java"

"$BUILD_TOOLS/d8" --min-api 29 --lib "$PLATFORM_JAR" \
    --output "$BUILD_DIR/dex_app" \
    "$BUILD_DIR/classes_app/com/example/arttipoc/"*.class

echo "[3/6] Compiling LSPatch bootstrap (metaloader.dex + loader.dex)..."
mkdir -p "$BUILD_DIR/classes_meta" "$BUILD_DIR/dex_meta" \
         "$BUILD_DIR/classes_loader" "$BUILD_DIR/dex_loader"

javac -source 11 -target 11 -cp "$PLATFORM_JAR" \
    -d "$BUILD_DIR/classes_meta" \
    "$PROJECT_ROOT/lspatch-bootstrap/src/org/lsposed/lspatch/metaloader/LSPAppComponentFactoryStub.java"

"$BUILD_TOOLS/d8" --min-api 29 --lib "$PLATFORM_JAR" \
    --output "$BUILD_DIR/dex_meta" \
    "$BUILD_DIR/classes_meta/org/lsposed/lspatch/metaloader/"*.class

javac -source 11 -target 11 -cp "$PLATFORM_JAR" \
    -d "$BUILD_DIR/classes_loader" \
    "$PROJECT_ROOT/lspatch-bootstrap/src/org/lsposed/lspatch/loader/BiometricPromptHookDialog.java" \
    "$PROJECT_ROOT/lspatch-bootstrap/src/org/lsposed/lspatch/loader/LSPApplication.java"

"$BUILD_TOOLS/d8" --min-api 29 --lib "$PLATFORM_JAR" \
    --output "$BUILD_DIR/dex_loader" \
    "$BUILD_DIR/classes_loader/org/lsposed/lspatch/loader/"*.class

# Also build a combined dex (app + metaloader) for non-nested LSPatch modes.
mkdir -p "$BUILD_DIR/dex_combined"
"$BUILD_TOOLS/d8" --min-api 29 --lib "$PLATFORM_JAR" \
    --output "$BUILD_DIR/dex_combined" \
    "$BUILD_DIR/classes_app/com/example/arttipoc/"*.class \
    "$BUILD_DIR/classes_meta/org/lsposed/lspatch/metaloader/"*.class

KEYSTORE="$BUILD_DIR/poc-debug.keystore"
if [[ ! -f "$KEYSTORE" ]]; then
    keytool -genkeypair -v -keystore "$KEYSTORE" \
        -storepass android -keypass android \
        -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=Android Debug,O=Android,C=US" >/dev/null 2>&1
fi

package_and_sign_apk() {
    local manifest_xml="$1"
    local dex_file="$2"
    local include_agent="$3"
    local nested_origin_apk="$4"
    local out_apk="$5"

    local stage_dir
    stage_dir="$BUILD_DIR/stage_$(basename "$out_apk" .apk)"
    rm -rf "$stage_dir"
    mkdir -p "$stage_dir"
    cp "$manifest_xml" "$stage_dir/AndroidManifest.xml"

    "$BUILD_TOOLS/aapt" package -f -M "$stage_dir/AndroidManifest.xml" -I "$PLATFORM_JAR" -F "$stage_dir/unsigned.apk"
    cp "$dex_file" "$stage_dir/classes.dex"
    (cd "$stage_dir" && zip -q unsigned.apk classes.dex)

    if [[ "$include_agent" == "true" ]]; then
        mkdir -p "$stage_dir/lib/arm64-v8a" "$stage_dir/assets/lspatch/so/arm64-v8a"
        cp "$BUILD_DIR/lib/arm64-v8a/libarttipoc.so" "$stage_dir/lib/arm64-v8a/libarttipoc.so"
        cp "$BUILD_DIR/lib/arm64-v8a/libarttipoc.so" "$stage_dir/assets/lspatch/so/arm64-v8a/libarttipoc.so"
        cp "$BUILD_DIR/dex_loader/classes.dex" "$stage_dir/assets/lspatch/loader.dex"
        printf '%s\n' 'com.example.arttipoc.SampleOriginalAppComponentFactory' \
            > "$stage_dir/assets/lspatch/original_app_component_factory.txt"
        if [[ -n "$nested_origin_apk" ]]; then
            cp "$nested_origin_apk" "$stage_dir/assets/lspatch/origin.apk"
            (cd "$stage_dir" && zip -q -0 unsigned.apk \
                lib/arm64-v8a/libarttipoc.so \
                assets/lspatch/so/arm64-v8a/libarttipoc.so \
                assets/lspatch/loader.dex \
                assets/lspatch/original_app_component_factory.txt \
                assets/lspatch/origin.apk)
        else
            (cd "$stage_dir" && zip -q -0 unsigned.apk \
                lib/arm64-v8a/libarttipoc.so \
                assets/lspatch/so/arm64-v8a/libarttipoc.so \
                assets/lspatch/loader.dex \
                assets/lspatch/original_app_component_factory.txt)
        fi
    fi

    "$BUILD_TOOLS/zipalign" -f -p 4 "$stage_dir/unsigned.apk" "$stage_dir/aligned.apk"
    "$BUILD_TOOLS/apksigner" sign --ks "$KEYSTORE" \
        --ks-pass pass:android --key-pass pass:android \
        --out "$out_apk" "$stage_dir/aligned.apk"
}

echo "[4/6] Packaging 1) build/unpatched-sample.apk (debuggable=false, no agent)..."
package_and_sign_apk \
    "$PROJECT_ROOT/sample-app/AndroidManifest.xml" \
    "$BUILD_DIR/dex_app/classes.dex" \
    "false" \
    "" \
    "$BUILD_DIR/unpatched-sample.apk"

echo "[5/6] Packaging 2) build/lspatch-nondebuggable.apk and 3) build/lspatch-nested-origin.apk (debuggable=false)..."
MANIFEST_NONDBG="$BUILD_DIR/AndroidManifest.nondebuggable.xml"
sed 's|android:extractNativeLibs="true"|android:extractNativeLibs="true" android:appComponentFactory="org.lsposed.lspatch.metaloader.LSPAppComponentFactoryStub"|' \
    "$PROJECT_ROOT/sample-app/AndroidManifest.xml" > "$MANIFEST_NONDBG"

package_and_sign_apk \
    "$MANIFEST_NONDBG" \
    "$BUILD_DIR/dex_combined/classes.dex" \
    "true" \
    "" \
    "$BUILD_DIR/lspatch-nondebuggable.apk"

package_and_sign_apk \
    "$MANIFEST_NONDBG" \
    "$BUILD_DIR/dex_meta/classes.dex" \
    "true" \
    "$BUILD_DIR/unpatched-sample.apk" \
    "$BUILD_DIR/lspatch-nested-origin.apk"

echo "[6/6] Packaging 4) build/lspatch-debuggable-scrubbed.apk (LSPatch --debuggable + runtime FLAG_DEBUGGABLE scrub)..."
MANIFEST_DBG="$BUILD_DIR/AndroidManifest.debuggable.xml"
sed -e 's|android:debuggable="false"|android:debuggable="true"|' \
    -e 's|android:extractNativeLibs="true"|android:extractNativeLibs="true" android:appComponentFactory="org.lsposed.lspatch.metaloader.LSPAppComponentFactoryStub"|' \
    "$PROJECT_ROOT/sample-app/AndroidManifest.xml" > "$MANIFEST_DBG"

package_and_sign_apk \
    "$MANIFEST_DBG" \
    "$BUILD_DIR/dex_combined/classes.dex" \
    "true" \
    "" \
    "$BUILD_DIR/lspatch-debuggable-scrubbed.apk"

echo "Build complete. Artifacts in $BUILD_DIR:"
ls -lh "$BUILD_DIR"/*.apk "$BUILD_DIR/lib/arm64-v8a/libarttipoc.so"
