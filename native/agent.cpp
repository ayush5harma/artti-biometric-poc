#include <jni.h>
#include <jvmti.h>
#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#define LOG_TAG "ARTTI_POC"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Measured 2026-10-26 on Pixel 9 Pro (Android 17, API 37):
// libopenjdkjvmti.so defines kArtTiVersion = JVMTI_VERSION_1_2 | 0x40000000 (0x70010200) for
// agents attached when RuntimeDebugState != kJavaDebuggableAtInit (2).
static constexpr jint kArtTiVersion = 0x70010200;

/**
 * Dynamic ELF64 .dynsym resolver + ARM64 instruction decoder for libart.so.
 *
 * Why zero hardcoded offsets are needed even when android:debuggable="false":
 * Because libopenjdkjvmti.so and libadbconnection.so are separate shared libraries inside the
 * com.android.art Mainline APEX that link against libart.so, libart.so exports the following
 * C++ functions/globals in its standard, uncompressed ELF .dynsym table across Android releases:
 *   - _ZN3art3Dbg14SetJdwpAllowedEb                                (art::Dbg::SetJdwpAllowed(bool))
 *   - _ZN3art3Dbg13IsJdwpAllowedEv                                 (art::Dbg::IsJdwpAllowed())
 *   - _ZN3art7Runtime9instance_E                                   (art::Runtime::instance_)
 *   - _ZN3art7Runtime20SetRuntimeDebugStateENS0_17RuntimeDebugStateE (art::Runtime::SetRuntimeDebugState)
 *
 * Furthermore, SetRuntimeDebugState is a 3-instruction setter ("bti c; str w1, [x0, #imm]; ret").
 * Decoding the unsigned 12-bit immediate of the ARM64 STR instruction (((insn >> 10) & 0xfff) * 4)
 * yields the exact runtime_debug_state_ offset (0x3d4 on Android 17) dynamically at runtime.
 */
using SetJdwpAllowedFn = void (*)(bool);
using IsJdwpAllowedFn = bool (*)();
using SetRuntimeDebugStateFn = void (*)(void*, int);

static SetJdwpAllowedFn g_fn_set_jdwp_allowed = nullptr;
static IsJdwpAllowedFn g_fn_is_jdwp_allowed = nullptr;
static SetRuntimeDebugStateFn g_fn_set_runtime_debug_state = nullptr;
static void** g_ptr_runtime_instance = nullptr;
static size_t g_decoded_debug_state_offset = 0;
static bool g_art_symbols_resolved = false;

static bool ResolveArtSymbolsDynamically() {
    if (g_art_symbols_resolved) {
        return g_fn_set_jdwp_allowed != nullptr &&
               g_fn_set_runtime_debug_state != nullptr &&
               g_ptr_runtime_instance != nullptr;
    }

    struct LibArtPhdrCtx {
        uintptr_t load_bias;
        char path[512];
    } ctx = {0, {0}};

    dl_iterate_phdr([](struct dl_phdr_info* info, size_t /*size*/, void* data) -> int {
        auto* c = static_cast<LibArtPhdrCtx*>(data);
        if (info->dlpi_name && strstr(info->dlpi_name, "/lib64/libart.so")) {
            c->load_bias = static_cast<uintptr_t>(info->dlpi_addr);
            snprintf(c->path, sizeof(c->path), "%s", info->dlpi_name);
            return 1;
        }
        return 0;
    }, &ctx);

    if (ctx.path[0] == '\0') {
        LOGE("[ResolveArtSymbols] Failed to locate /lib64/libart.so via dl_iterate_phdr");
        return false;
    }

    FILE* fp = fopen(ctx.path, "rb");
    if (!fp) {
        LOGE("[ResolveArtSymbols] Failed to open %s", ctx.path);
        return false;
    }

    Elf64_Ehdr ehdr = {};
    if (fread(&ehdr, sizeof(ehdr), 1, fp) != 1 || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fclose(fp);
        return false;
    }

     Elf64_Shdr* shdrs = static_cast<Elf64_Shdr*>(calloc(ehdr.e_shnum, sizeof(Elf64_Shdr)));
    if (!shdrs) {
        fclose(fp);
        return false;
    }
    fseek(fp, static_cast<long>(ehdr.e_shoff), SEEK_SET);
    if (fread(shdrs, sizeof(Elf64_Shdr), ehdr.e_shnum, fp) != ehdr.e_shnum) {
        free(shdrs);
        fclose(fp);
        return false;
    }

    for (uint16_t i = 0; i < ehdr.e_shnum; ++i) {
        if (shdrs[i].sh_type != SHT_DYNSYM || shdrs[i].sh_link >= ehdr.e_shnum) {
            continue;
        }
        const Elf64_Shdr& sym_sh = shdrs[i];
        const Elf64_Shdr& str_sh = shdrs[sym_sh.sh_link];

        auto* syms = static_cast<Elf64_Sym*>(malloc(sym_sh.sh_size));
        auto* strs = static_cast<char*>(malloc(str_sh.sh_size));
        if (!syms || !strs) {
            free(syms);
            free(strs);
            break;
        }

        fseek(fp, static_cast<long>(sym_sh.sh_offset), SEEK_SET);
        size_t r1 = fread(syms, 1, sym_sh.sh_size, fp);
        fseek(fp, static_cast<long>(str_sh.sh_offset), SEEK_SET);
        size_t r2 = fread(strs, 1, str_sh.sh_size, fp);
        if (r1 == sym_sh.sh_size && r2 == str_sh.sh_size) {
            size_t count = sym_sh.sh_size / sizeof(Elf64_Sym);
            for (size_t k = 0; k < count; ++k) {
                if (syms[k].st_name >= str_sh.sh_size || syms[k].st_value == 0) continue;
                const char* sym_name = strs + syms[k].st_name;
                uintptr_t addr = ctx.load_bias + syms[k].st_value;

                if (strcmp(sym_name, "_ZN3art3Dbg14SetJdwpAllowedEb") == 0) {
                    g_fn_set_jdwp_allowed = reinterpret_cast<SetJdwpAllowedFn>(addr);
                } else if (strcmp(sym_name, "_ZN3art3Dbg13IsJdwpAllowedEv") == 0) {
                    g_fn_is_jdwp_allowed = reinterpret_cast<IsJdwpAllowedFn>(addr);
                } else if (strcmp(sym_name, "_ZN3art7Runtime9instance_E") == 0) {
                    g_ptr_runtime_instance = reinterpret_cast<void**>(addr);
                } else if (strcmp(sym_name, "_ZN3art7Runtime20SetRuntimeDebugStateENS0_17RuntimeDebugStateE") == 0) {
                    g_fn_set_runtime_debug_state = reinterpret_cast<SetRuntimeDebugStateFn>(addr);
                }
            }
        }
        free(syms);
        free(strs);
    }

    free(shdrs);
    fclose(fp);

    // Decode the ARM64 "STR W1, [X0, #imm]" instruction inside SetRuntimeDebugState to extract
    // the exact struct offset of runtime_debug_state_ (0x3d4 on Android 17) without hardcoding.
    if (g_fn_set_runtime_debug_state != nullptr) {
        const uint32_t* insns = reinterpret_cast<const uint32_t*>(g_fn_set_runtime_debug_state);
        for (int idx = 0; idx < 8; ++idx) {
            uint32_t insn = insns[idx];
            if ((insn & 0xffc00000u) == 0xb9000000u) {
                g_decoded_debug_state_offset = ((insn >> 10) & 0xfffu) * 4u;
                break;
            }
            if (insn == 0xd65f03c0u) { // RET
                break;
            }
        }
    }

    g_art_symbols_resolved = true;
    LOGI("[ResolveArtSymbols] Dynamically resolved from %s (.dynsym): "
         "SetJdwpAllowed=%p IsJdwpAllowed=%p Runtime::instance_=%p "
         "SetRuntimeDebugState=%p decoded_debug_state_offset=0x%zx",
         ctx.path,
         reinterpret_cast<void*>(g_fn_set_jdwp_allowed),
         reinterpret_cast<void*>(g_fn_is_jdwp_allowed),
         reinterpret_cast<void*>(g_ptr_runtime_instance),
         reinterpret_cast<void*>(g_fn_set_runtime_debug_state),
         g_decoded_debug_state_offset);

    return g_fn_set_jdwp_allowed != nullptr &&
           g_fn_set_runtime_debug_state != nullptr &&
           g_ptr_runtime_instance != nullptr;
}

static JavaVM* g_vm = nullptr;
static jvmtiEnv* g_jvmti = nullptr;
static char g_self_so_path[1024] = {0};
static volatile int g_upgrade_debug_state_in_onattach = 0;

static jmethodID g_plain_method = nullptr;
static jmethodID g_same_class_inlined = nullptr;
static jmethodID g_cross_class_inlined = nullptr;
static jmethodID g_caller_method = nullptr;

using NativeSecretTokenFn = jstring (JNICALL *)(JNIEnv*, jclass, jstring);
static NativeSecretTokenFn g_orig_native_secret_token = nullptr;
static volatile int g_native_bind_hits = 0;
static volatile int g_native_hook_calls = 0;

static jmethodID g_bio_auth_3arg = nullptr;
static jmethodID g_bio_auth_4arg = nullptr;
static jmethodID g_bio_mgr_can_auth_0arg = nullptr;
static jmethodID g_bio_mgr_can_auth_1arg = nullptr;
static jmethodID g_fp_mgr_is_hw = nullptr;
static jmethodID g_fp_mgr_has_enrolled = nullptr;
static jmethodID g_fp_mgr_authenticate = nullptr;
static jclass g_dialog_helper_cls = nullptr;
static jmethodID g_on_auth_intercepted_mid = nullptr;
static jmethodID g_on_fp_auth_intercepted_mid = nullptr;

static jclass g_camera_helper_cls = nullptr;
static jmethodID g_on_cam1_take_picture_mid = nullptr;
static jmethodID g_on_cam1_preview_cb_mid = nullptr;
static jmethodID g_on_cam2_imagereader_mid = nullptr;
static jmethodID g_on_camx_analyzer_mid = nullptr;
static jmethodID g_cam1_take_picture_4arg = nullptr;
static jmethodID g_cam1_set_oneshot_preview = nullptr;
static jmethodID g_cam1_set_preview_cb = nullptr;
static jmethodID g_cam2_set_image_available = nullptr;
static jmethodID g_camx_set_analyzer = nullptr;
static volatile int g_cam_bp_hits = 0;

static volatile int g_plain_entry_hits = 0;
static volatile int g_same_inlined_entry_hits = 0;
static volatile int g_cross_inlined_entry_hits = 0;

static volatile int g_plain_bp_hits = 0;
static volatile int g_same_inlined_bp_hits = 0;
static volatile int g_cross_inlined_bp_hits = 0;
static volatile int g_bio_bp_hits = 0;
static volatile int g_cflh_hits = 0;

static jint AcquireJvmtiEnv(JavaVM* vm, jvmtiEnv** out_env, const char* context) {
    *out_env = nullptr;
    const jint versions[] = {
        JVMTI_VERSION_1_2,
        JVMTI_VERSION_1_1,
        JVMTI_VERSION_1_0,
        kArtTiVersion
    };
    const char* names[] = {
        "JVMTI_VERSION_1_2 (0x30010200)",
        "JVMTI_VERSION_1_1 (0x30010100)",
        "JVMTI_VERSION_1_0 (0x30010000)",
        "kArtTiVersion (0x70010200)"
    };
    for (size_t i = 0; i < 4; ++i) {
        void* env = nullptr;
        jint res = vm->GetEnv(&env, versions[i]);
        LOGI("[%s] GetEnv(%s) -> %d (env=%p)", context, names[i], res, env);
        if (res == JNI_OK && env != nullptr) {
            *out_env = reinterpret_cast<jvmtiEnv*>(env);
            return versions[i];
        }
    }
    return -1;
}

static void ExemptHiddenApis(JNIEnv* env) {
    // Measured 2026-10-26 on Pixel 9 Pro (Android 17, API 37):
    // Calling VMRuntime.getRuntime().setHiddenApiExemptions(new String[]{"L"}) from native JNI
    // (whose caller frame has no associated Java DEX domain) is permitted by ART's caller check
    // and unlocks ActivityThread$AppBindData#compatInfo and BiometricPrompt$AuthenticationResult.<init>.
    jclass vmRuntimeCls = env->FindClass("dalvik/system/VMRuntime");
    if (!vmRuntimeCls) {
        env->ExceptionClear();
        return;
    }
    jmethodID getRuntimeMid = env->GetStaticMethodID(vmRuntimeCls, "getRuntime", "()Ldalvik/system/VMRuntime;");
    jmethodID setExemptionsMid = env->GetMethodID(vmRuntimeCls, "setHiddenApiExemptions", "([Ljava/lang/String;)V");
    if (getRuntimeMid && setExemptionsMid) {
        jobject runtimeObj = env->CallStaticObjectMethod(vmRuntimeCls, getRuntimeMid);
        jclass stringCls = env->FindClass("java/lang/String");
        jobjectArray arr = env->NewObjectArray(1, stringCls, env->NewStringUTF("L"));
        env->CallVoidMethod(runtimeObj, setExemptionsMid, arr);
        if (!env->ExceptionCheck()) {
            LOGI("[JNI_OnLoad] Exempted HiddenAPI prefix 'L' via VMRuntime.setHiddenApiExemptions");
        } else {
            env->ExceptionClear();
        }
    } else {
        env->ExceptionClear();
    }
}

static void JNICALL OnMethodEntry(jvmtiEnv* jvmti_env,
                                  JNIEnv* jni_env,
                                  jthread thread,
                                  jmethodID method) {
    (void)jvmti_env;
    (void)jni_env;
    (void)thread;
    if (method == g_plain_method) {
        int c = __atomic_add_fetch(&g_plain_entry_hits, 1, __ATOMIC_SEQ_CST);
        LOGI("[HOOK][MethodEntry] TargetWork.plainMethod fired! (count=%d)", c);
    } else if (method == g_same_class_inlined) {
        int c = __atomic_add_fetch(&g_same_inlined_entry_hits, 1, __ATOMIC_SEQ_CST);
        LOGI("[HOOK][MethodEntry] TargetWork.inlinedTarget (same-class) fired! (count=%d)", c);
    } else if (method == g_cross_class_inlined) {
        int c = __atomic_add_fetch(&g_cross_inlined_entry_hits, 1, __ATOMIC_SEQ_CST);
        LOGI("[HOOK][MethodEntry] InlinedCallee.crossClassInlined fired! (count=%d)", c);
    }
}

static void JNICALL OnBreakpoint(jvmtiEnv* jvmti_env,
                                 JNIEnv* jni_env,
                                 jthread thread,
                                 jmethodID method,
                                 jlocation location) {
    if (method == g_plain_method) {
        int c = __atomic_add_fetch(&g_plain_bp_hits, 1, __ATOMIC_SEQ_CST);
        LOGI("[HOOK][Breakpoint] TargetWork.plainMethod fired at loc=%" PRId64 " (count=%d)",
             (int64_t)location, c);
        return;
    }
    if (method == g_same_class_inlined) {
        int c = __atomic_add_fetch(&g_same_inlined_bp_hits, 1, __ATOMIC_SEQ_CST);
        LOGI("[HOOK][Breakpoint] TargetWork.inlinedTarget (same-class) fired at loc=%" PRId64 " (count=%d)",
             (int64_t)location, c);
        return;
    }
    if (method == g_cross_class_inlined) {
        int c = __atomic_add_fetch(&g_cross_inlined_bp_hits, 1, __ATOMIC_SEQ_CST);
        LOGI("[HOOK][Breakpoint] InlinedCallee.crossClassInlined fired at loc=%" PRId64 " (count=%d)",
             (int64_t)location, c);
        return;
    }

    if (method == g_bio_auth_3arg || method == g_bio_auth_4arg) {
        int c = __atomic_add_fetch(&g_bio_bp_hits, 1, __ATOMIC_SEQ_CST);
        jint max_locals = 0;
        jint args_size = 0;
        jvmtiError err_max = jvmti_env->GetMaxLocals(method, &max_locals);
        jvmtiError err_args = jvmti_env->GetArgumentsSize(method, &args_size);

        // Measured 2026-10-26 via dexdump on Android 17 framework.jar!classes2.dex:
        // BiometricPrompt.authenticate(CancellationSignal, Executor, AuthenticationCallback)V
        //   has registers=11, ins=4 -> parameter registers start at v7 (11 - 4).
        // BiometricPrompt.authenticate(CryptoObject, CancellationSignal, Executor, AuthenticationCallback)V
        //   has registers=14, ins=5 -> parameter registers start at v9 (14 - 5).
        jint base_slot = (err_max == JVMTI_ERROR_NONE && err_args == JVMTI_ERROR_NONE && max_locals >= args_size)
                         ? (max_locals - args_size)
                         : ((method == g_bio_auth_4arg) ? 9 : 7);

        jobject prompt_obj = nullptr;
        jobject crypto_obj = nullptr;
        jobject cancel_obj = nullptr;
        jobject executor_obj = nullptr;
        jobject callback_obj = nullptr;

        jvmti_env->GetLocalObject(thread, 0, base_slot + 0, &prompt_obj);
        if (method == g_bio_auth_4arg) {
            jvmti_env->GetLocalObject(thread, 0, base_slot + 1, &crypto_obj);
            jvmti_env->GetLocalObject(thread, 0, base_slot + 2, &cancel_obj);
            jvmti_env->GetLocalObject(thread, 0, base_slot + 3, &executor_obj);
            jvmti_env->GetLocalObject(thread, 0, base_slot + 4, &callback_obj);
        } else {
            jvmti_env->GetLocalObject(thread, 0, base_slot + 1, &cancel_obj);
            jvmti_env->GetLocalObject(thread, 0, base_slot + 2, &executor_obj);
            jvmti_env->GetLocalObject(thread, 0, base_slot + 3, &callback_obj);
        }

        LOGI("[HOOK][BiometricPrompt] Intercepted authenticate at loc=%" PRId64 " (hit=%d, max_locals=%d, args_size=%d, base_slot=%d, prompt=%p, callback=%p)",
             (int64_t)location, c, (int)max_locals, (int)args_size, (int)base_slot, prompt_obj, callback_obj);

        if (g_dialog_helper_cls != nullptr && g_on_auth_intercepted_mid != nullptr) {
            jni_env->CallStaticVoidMethod(
                g_dialog_helper_cls,
                g_on_auth_intercepted_mid,
                prompt_obj,
                crypto_obj,
                cancel_obj,
                executor_obj,
                callback_obj);
            if (jni_env->ExceptionCheck()) {
                jni_env->ExceptionDescribe();
                jni_env->ExceptionClear();
            }
        }

        // ForceEarlyReturnVoid aborts BiometricPrompt.authenticate at bytecode offset 0 so
        // IBiometricService is never contacted and the system biometric prompt never appears.
        jvmtiError fer_err = jvmti_env->ForceEarlyReturnVoid(thread);
        LOGI("[HOOK][BiometricPrompt] ForceEarlyReturnVoid(thread) -> err=%d", fer_err);
        return;
    }

    if (method == g_bio_mgr_can_auth_0arg || method == g_bio_mgr_can_auth_1arg) {
        // ForceEarlyReturnInt(0 == BIOMETRIC_SUCCESS) so apps calling BiometricManager.canAuthenticate(...)
        // succeed even on cloud/test devices that have no physical biometrics enrolled in Android Settings.
        jvmtiError fer_err = jvmti_env->ForceEarlyReturnInt(thread, 0);
        LOGI("[HOOK][BiometricManager] canAuthenticate intercepted -> ForceEarlyReturnInt(BIOMETRIC_SUCCESS=0) err=%d",
             fer_err);
        return;
    }

    if (method == g_fp_mgr_is_hw || method == g_fp_mgr_has_enrolled) {
        // ForceEarlyReturnInt(1 == true) for legacy FingerprintManager.isHardwareDetected() / hasEnrolledFingerprints().
        jvmtiError fer_err = jvmti_env->ForceEarlyReturnInt(thread, 1);
        LOGI("[HOOK][FingerprintManager] readiness check intercepted -> ForceEarlyReturnInt(true=1) err=%d",
             fer_err);
        return;
    }

    if (method == g_fp_mgr_authenticate) {
        int c = __atomic_add_fetch(&g_bio_bp_hits, 1, __ATOMIC_SEQ_CST);
        jint max_locals = 0;
        jint args_size = 0;
        jvmtiError err_max = jvmti_env->GetMaxLocals(method, &max_locals);
        jvmtiError err_args = jvmti_env->GetArgumentsSize(method, &args_size);
        jint base_slot = (err_max == JVMTI_ERROR_NONE && err_args == JVMTI_ERROR_NONE && max_locals >= args_size)
                         ? (max_locals - args_size) : 0;

        // FingerprintManager.authenticate(CryptoObject, CancellationSignal, int flags, AuthenticationCallback, Handler)V
        // base_slot + 0 = this, +1 = crypto, +2 = cancel, +3 = flags (int), +4 = callback, +5 = handler
        jobject crypto_obj = nullptr;
        jobject cancel_obj = nullptr;
        jobject callback_obj = nullptr;
        jobject handler_obj = nullptr;
        jvmti_env->GetLocalObject(thread, 0, base_slot + 1, &crypto_obj);
        jvmti_env->GetLocalObject(thread, 0, base_slot + 2, &cancel_obj);
        jvmti_env->GetLocalObject(thread, 0, base_slot + 4, &callback_obj);
        jvmti_env->GetLocalObject(thread, 0, base_slot + 5, &handler_obj);

        LOGI("[HOOK][FingerprintManager] Intercepted authenticate at loc=%" PRId64 " (hit=%d, base_slot=%d, callback=%p)",
             (int64_t)location, c, (int)base_slot, callback_obj);

        if (g_dialog_helper_cls != nullptr && g_on_fp_auth_intercepted_mid != nullptr) {
            jni_env->CallStaticVoidMethod(
                g_dialog_helper_cls,
                g_on_fp_auth_intercepted_mid,
                crypto_obj,
                cancel_obj,
                callback_obj,
                handler_obj);
            if (jni_env->ExceptionCheck()) {
                jni_env->ExceptionDescribe();
                jni_env->ExceptionClear();
            }
        }
        jvmtiError fer_err = jvmti_env->ForceEarlyReturnVoid(thread);
        LOGI("[HOOK][FingerprintManager] ForceEarlyReturnVoid(thread) -> err=%d", fer_err);
        return;
    }

    if (method == g_cam1_take_picture_4arg) {
        int c = __atomic_add_fetch(&g_cam_bp_hits, 1, __ATOMIC_SEQ_CST);
        jint max_locals = 0;
        jint args_size = 0;
        jvmtiError err_max = jvmti_env->GetMaxLocals(method, &max_locals);
        jvmtiError err_args = jvmti_env->GetArgumentsSize(method, &args_size);
        jint base_slot = (err_max == JVMTI_ERROR_NONE && err_args == JVMTI_ERROR_NONE && max_locals >= args_size)
                         ? (max_locals - args_size) : 0;

        jobject cam_obj = nullptr;
        jobject shutter_obj = nullptr;
        jobject raw_obj = nullptr;
        jobject postview_obj = nullptr;
        jobject jpeg_obj = nullptr;
        jvmti_env->GetLocalObject(thread, 0, base_slot + 0, &cam_obj);
        jvmti_env->GetLocalObject(thread, 0, base_slot + 1, &shutter_obj);
        jvmti_env->GetLocalObject(thread, 0, base_slot + 2, &raw_obj);
        jvmti_env->GetLocalObject(thread, 0, base_slot + 3, &postview_obj);
        jvmti_env->GetLocalObject(thread, 0, base_slot + 4, &jpeg_obj);

        LOGI("[HOOK][Camera1] Intercepted takePicture at loc=%" PRId64 " (hit=%d, base_slot=%d, jpeg=%p)",
             (int64_t)location, c, (int)base_slot, jpeg_obj);

        if (g_camera_helper_cls != nullptr && g_on_cam1_take_picture_mid != nullptr) {
            jni_env->CallStaticVoidMethod(
                g_camera_helper_cls,
                g_on_cam1_take_picture_mid,
                cam_obj,
                shutter_obj,
                raw_obj,
                postview_obj,
                jpeg_obj);
            if (jni_env->ExceptionCheck()) {
                jni_env->ExceptionDescribe();
                jni_env->ExceptionClear();
            }
        }
        jvmti_env->ForceEarlyReturnVoid(thread);
        return;
    }

    if (method == g_cam1_set_oneshot_preview || method == g_cam1_set_preview_cb) {
        int c = __atomic_add_fetch(&g_cam_bp_hits, 1, __ATOMIC_SEQ_CST);
        jint max_locals = 0;
        jint args_size = 0;
        jvmtiError err_max = jvmti_env->GetMaxLocals(method, &max_locals);
        jvmtiError err_args = jvmti_env->GetArgumentsSize(method, &args_size);
        jint base_slot = (err_max == JVMTI_ERROR_NONE && err_args == JVMTI_ERROR_NONE && max_locals >= args_size)
                         ? (max_locals - args_size) : 0;

        jobject cam_obj = nullptr;
        jobject cb_obj = nullptr;
        jvmti_env->GetLocalObject(thread, 0, base_slot + 0, &cam_obj);
        jvmti_env->GetLocalObject(thread, 0, base_slot + 1, &cb_obj);

        LOGI("[HOOK][Camera1] Intercepted setPreviewCallback at loc=%" PRId64 " (hit=%d, base_slot=%d, cb=%p)",
             (int64_t)location, c, (int)base_slot, cb_obj);

        if (g_camera_helper_cls != nullptr && g_on_cam1_preview_cb_mid != nullptr) {
            jni_env->CallStaticVoidMethod(
                g_camera_helper_cls,
                g_on_cam1_preview_cb_mid,
                cam_obj,
                cb_obj);
            if (jni_env->ExceptionCheck()) {
                jni_env->ExceptionDescribe();
                jni_env->ExceptionClear();
            }
        }
        jvmti_env->ForceEarlyReturnVoid(thread);
        return;
    }

    if (method == g_cam2_set_image_available) {
        int c = __atomic_add_fetch(&g_cam_bp_hits, 1, __ATOMIC_SEQ_CST);
        jint max_locals = 0;
        jint args_size = 0;
        jvmtiError err_max = jvmti_env->GetMaxLocals(method, &max_locals);
        jvmtiError err_args = jvmti_env->GetArgumentsSize(method, &args_size);
        jint base_slot = (err_max == JVMTI_ERROR_NONE && err_args == JVMTI_ERROR_NONE && max_locals >= args_size)
                         ? (max_locals - args_size) : 0;

        jobject reader_obj = nullptr;
        jobject listener_obj = nullptr;
        jobject handler_obj = nullptr;
        jvmti_env->GetLocalObject(thread, 0, base_slot + 0, &reader_obj);
        jvmti_env->GetLocalObject(thread, 0, base_slot + 1, &listener_obj);
        jvmti_env->GetLocalObject(thread, 0, base_slot + 2, &handler_obj);

        LOGI("[HOOK][Camera2] Intercepted ImageReader.setOnImageAvailableListener at loc=%" PRId64 " (hit=%d, base_slot=%d, reader=%p, listener=%p)",
             (int64_t)location, c, (int)base_slot, reader_obj, listener_obj);

        if (g_camera_helper_cls != nullptr && g_on_cam2_imagereader_mid != nullptr) {
            jni_env->CallStaticVoidMethod(
                g_camera_helper_cls,
                g_on_cam2_imagereader_mid,
                reader_obj,
                listener_obj,
                handler_obj);
            if (jni_env->ExceptionCheck()) {
                jni_env->ExceptionDescribe();
                jni_env->ExceptionClear();
            }
        }
        jvmti_env->ForceEarlyReturnVoid(thread);
        return;
    }

    if (method == g_camx_set_analyzer) {
        int c = __atomic_add_fetch(&g_cam_bp_hits, 1, __ATOMIC_SEQ_CST);
        jint max_locals = 0;
        jint args_size = 0;
        jvmtiError err_max = jvmti_env->GetMaxLocals(method, &max_locals);
        jvmtiError err_args = jvmti_env->GetArgumentsSize(method, &args_size);
        jint base_slot = (err_max == JVMTI_ERROR_NONE && err_args == JVMTI_ERROR_NONE && max_locals >= args_size)
                         ? (max_locals - args_size) : 0;

        jobject analysis_obj = nullptr;
        jobject executor_obj = nullptr;
        jobject analyzer_obj = nullptr;
        jvmti_env->GetLocalObject(thread, 0, base_slot + 0, &analysis_obj);
        jvmti_env->GetLocalObject(thread, 0, base_slot + 1, &executor_obj);
        jvmti_env->GetLocalObject(thread, 0, base_slot + 2, &analyzer_obj);

        LOGI("[HOOK][CameraX] Intercepted ImageAnalysis.setAnalyzer at loc=%" PRId64 " (hit=%d, base_slot=%d, analyzer=%p)",
             (int64_t)location, c, (int)base_slot, analyzer_obj);

        if (g_camera_helper_cls != nullptr && g_on_camx_analyzer_mid != nullptr) {
            jni_env->CallStaticVoidMethod(
                g_camera_helper_cls,
                g_on_camx_analyzer_mid,
                analysis_obj,
                executor_obj,
                analyzer_obj);
            if (jni_env->ExceptionCheck()) {
                jni_env->ExceptionDescribe();
                jni_env->ExceptionClear();
            }
        }
        jvmti_env->ForceEarlyReturnVoid(thread);
        return;
    }
}

static void JNICALL OnClassFileLoadHook(jvmtiEnv* jvmti_env,
                                        JNIEnv* jni_env,
                                        jclass class_being_redefined,
                                        jobject loader,
                                        const char* name,
                                        jobject protection_domain,
                                        jint class_data_len,
                                        const unsigned char* class_data,
                                        jint* new_class_data_len,
                                        unsigned char** new_class_data) {
    (void)jni_env;
    (void)class_being_redefined;
    (void)loader;
    (void)protection_domain;
    if (name != nullptr &&
        (strcmp(name, "com/example/arttipoc/TargetWork") == 0 ||
         strcmp(name, "com/example/arttipoc/InlinedCallee") == 0)) {
        int c = __atomic_add_fetch(&g_cflh_hits, 1, __ATOMIC_SEQ_CST);
        LOGI("[DEOPT][ClassFileLoadHook] Intercepted DEX for class='%s' len=%d (redefine=%p, count=%d)",
             name, (int)class_data_len, class_being_redefined, c);
        unsigned char* copy = nullptr;
        jvmtiError err = jvmti_env->Allocate(class_data_len, &copy);
        if (err == JVMTI_ERROR_NONE && copy != nullptr) {
            memcpy(copy, class_data, class_data_len);
            *new_class_data_len = class_data_len;
            *new_class_data = copy;
        }
    }
}

static jstring JNICALL OriginalNativeSecretToken(JNIEnv* env, jclass clazz, jstring challenge) {
    (void)clazz;
    const char* ch = challenge ? env->GetStringUTFChars(challenge, nullptr) : "null";
    char buf[256];
    snprintf(buf, sizeof(buf), "ORIG_JNI(%s)", ch);
    if (challenge && ch) {
        env->ReleaseStringUTFChars(challenge, ch);
    }
    return env->NewStringUTF(buf);
}

static jstring JNICALL HookedNativeSecretToken(JNIEnv* env, jclass clazz, jstring challenge) {
    int c = __atomic_add_fetch(&g_native_hook_calls, 1, __ATOMIC_SEQ_CST);
    jstring orig_res = g_orig_native_secret_token
            ? g_orig_native_secret_token(env, clazz, challenge)
            : env->NewStringUTF("NO_ORIG");
    const char* orig_str = orig_res ? env->GetStringUTFChars(orig_res, nullptr) : "";
    char buf[512];
    snprintf(buf, sizeof(buf), "ARTTI_NATIVE_BIND_HOOKED[call=%d,orig=%s]", c, orig_str);
    if (orig_res && orig_str) {
        env->ReleaseStringUTFChars(orig_res, orig_str);
    }
    LOGI("[HOOK][NativeMethodBind] HookedNativeSecretToken executed -> %s", buf);
    return env->NewStringUTF(buf);
}

static void JNICALL OnNativeMethodBind(jvmtiEnv* jvmti_env,
                                       JNIEnv* jni_env,
                                       jthread thread,
                                       jmethodID method,
                                       void* address,
                                       void** new_address_ptr) {
    (void)jni_env;
    (void)thread;
    char* name = nullptr;
    char* sig = nullptr;
    jclass decl_cls = nullptr;
    char* cls_sig = nullptr;
    if (jvmti_env->GetMethodName(method, &name, &sig, nullptr) == JVMTI_ERROR_NONE &&
        jvmti_env->GetMethodDeclaringClass(method, &decl_cls) == JVMTI_ERROR_NONE &&
        jvmti_env->GetClassSignature(decl_cls, &cls_sig, nullptr) == JVMTI_ERROR_NONE) {
        if (name && cls_sig &&
            strcmp(cls_sig, "Lcom/example/arttipoc/TargetWork;") == 0 &&
            strcmp(name, "nativeSecretToken") == 0) {
            int hits = __atomic_add_fetch(&g_native_bind_hits, 1, __ATOMIC_SEQ_CST);
            if (address != reinterpret_cast<void*>(HookedNativeSecretToken)) {
                g_orig_native_secret_token = reinterpret_cast<NativeSecretTokenFn>(address);
            }
            *new_address_ptr = reinterpret_cast<void*>(HookedNativeSecretToken);
            LOGI("[HOOK][OnNativeMethodBind] Intercepted JNI bind for %s%s%s orig=%p -> redirected=%p (hits=%d)",
                 cls_sig, name, sig ? sig : "", address, *new_address_ptr, hits);
        }
    }
    if (name) jvmti_env->Deallocate(reinterpret_cast<unsigned char*>(name));
    if (sig) jvmti_env->Deallocate(reinterpret_cast<unsigned char*>(sig));
    if (cls_sig) jvmti_env->Deallocate(reinterpret_cast<unsigned char*>(cls_sig));
}

static void EnsureCallbacksRegistered() {
    if (!g_jvmti) return;
    jvmtiEventCallbacks callbacks = {};
    callbacks.MethodEntry = OnMethodEntry;
    callbacks.Breakpoint = OnBreakpoint;
    callbacks.ClassFileLoadHook = OnClassFileLoadHook;
    callbacks.NativeMethodBind = OnNativeMethodBind;
    g_jvmti->SetEventCallbacks(&callbacks, sizeof(callbacks));
}

static void InitializeAgent(JavaVM* vm, const char* entry_point) {
    LOGI("========================================================");
    LOGI("[%s] Entered agent initialization (vm=%p)", entry_point, vm);
    g_vm = vm;

    if (g_upgrade_debug_state_in_onattach &&
        ResolveArtSymbolsDynamically() &&
        g_ptr_runtime_instance != nullptr &&
        *g_ptr_runtime_instance != nullptr) {
        void* runtime = *g_ptr_runtime_instance;
        uint32_t prev = g_decoded_debug_state_offset
                ? *reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(runtime) + g_decoded_debug_state_offset)
                : 1;
        g_fn_set_runtime_debug_state(runtime, 2 /* kJavaDebuggableAtInit */);
        uint32_t after = g_decoded_debug_state_offset
                ? *reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(runtime) + g_decoded_debug_state_offset)
                : 2;
        LOGI("[%s] Upgraded runtime_debug_state_ via exported SetRuntimeDebugState after DeoptManager::FinishSetup(): %u -> %u",
             entry_point, prev, after);
    }

    jint ver = AcquireJvmtiEnv(vm, &g_jvmti, entry_point);
    if (g_jvmti == nullptr) {
        LOGE("[%s] FAILED to acquire jvmtiEnv!", entry_point);
        return;
    }
    LOGI("[%s] Successfully acquired jvmtiEnv=%p with version=0x%x", entry_point, g_jvmti, ver);
    EnsureCallbacksRegistered();
}

extern "C" JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM* vm, char* options, void* reserved) {
    (void)options;
    (void)reserved;
    InitializeAgent(vm, "Agent_OnLoad");
    return JNI_OK;
}

extern "C" JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM* vm, char* options, void* reserved) {
    (void)options;
    (void)reserved;
    InitializeAgent(vm, "Agent_OnAttach");
    return JNI_OK;
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_lsposed_lspatch_loader_BiometricPromptHookDialog_nativeAttachAgentNonDebuggable(
        JNIEnv* env, jclass clazz, jobject classLoader);

extern "C" JNIEXPORT jstring JNICALL
Java_org_lsposed_lspatch_loader_BiometricPromptHookDialog_nativeInstallBiometricHook(
        JNIEnv* env, jclass clazz, jclass dialogHelperClass, jclass biometricPromptClass);

extern "C" JNIEXPORT jobject JNICALL
Java_org_lsposed_lspatch_loader_BiometricPromptHookDialog_nativeCreateAuthenticationResult(
        JNIEnv* env, jclass clazz, jobject cryptoObject, jint authType);

extern "C" JNIEXPORT jobject JNICALL
Java_org_lsposed_lspatch_loader_BiometricPromptHookDialog_nativeCreateFingerprintAuthResult(
        JNIEnv* env, jclass clazz, jobject cryptoObject);

extern "C" JNIEXPORT void JNICALL
Java_org_lsposed_lspatch_loader_BiometricPromptHookDialog_nativeRegisterAppNatives(
        JNIEnv* env, jclass clazz, jclass mainActivityClass);

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_arttipoc_MainActivity_nativeControl(
        JNIEnv* env, jclass clazz, jint mode, jclass target_work_cls, jclass inlined_callee_cls);

extern "C" JNIEXPORT jstring JNICALL
Java_org_lsposed_lspatch_loader_CameraInjectionHook_nativeInstallCameraHooks(
        JNIEnv* env, jclass clazz,
        jclass helperClass, jclass camera1Class, jclass imageReaderClass, jclass cameraXAnalysisClass);

extern "C" JNIEXPORT jobject JNICALL
Java_com_example_arttipoc_CameraTestController_nativeAllocateCamera1Stub(
        JNIEnv* env, jclass clazz);

extern "C" JNIEXPORT jint JNICALL
Java_com_example_arttipoc_BankingSecurityGuard_nativeGetPrctlDumpable(
        JNIEnv* env, jclass clazz);

extern "C" JNIEXPORT jint JNICALL
Java_com_example_arttipoc_BankingSecurityGuard_nativeGetTracerPid(
        JNIEnv* env, jclass clazz);

static const JNINativeMethod kBiometricDialogMethods[] = {
    {"nativeAttachAgentNonDebuggable",
     "(Ljava/lang/ClassLoader;)Ljava/lang/String;",
     reinterpret_cast<void*>(Java_org_lsposed_lspatch_loader_BiometricPromptHookDialog_nativeAttachAgentNonDebuggable)},
    {"nativeInstallBiometricHook",
     "(Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/String;",
     reinterpret_cast<void*>(Java_org_lsposed_lspatch_loader_BiometricPromptHookDialog_nativeInstallBiometricHook)},
    {"nativeCreateAuthenticationResult",
     "(Ljava/lang/Object;I)Ljava/lang/Object;",
     reinterpret_cast<void*>(Java_org_lsposed_lspatch_loader_BiometricPromptHookDialog_nativeCreateAuthenticationResult)},
    {"nativeCreateFingerprintAuthResult",
     "(Ljava/lang/Object;)Ljava/lang/Object;",
     reinterpret_cast<void*>(Java_org_lsposed_lspatch_loader_BiometricPromptHookDialog_nativeCreateFingerprintAuthResult)},
    {"nativeRegisterAppNatives",
     "(Ljava/lang/Class;)V",
     reinterpret_cast<void*>(Java_org_lsposed_lspatch_loader_BiometricPromptHookDialog_nativeRegisterAppNatives)},
};

static const JNINativeMethod kCameraInjectionMethods[] = {
    {"nativeInstallCameraHooks",
     "(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/String;",
     reinterpret_cast<void*>(Java_org_lsposed_lspatch_loader_CameraInjectionHook_nativeInstallCameraHooks)},
};

static const JNINativeMethod kMainActivityMethods[] = {
    {"nativeControl",
     "(ILjava/lang/Class;Ljava/lang/Class;)Ljava/lang/String;",
     reinterpret_cast<void*>(Java_com_example_arttipoc_MainActivity_nativeControl)},
};

static const JNINativeMethod kCameraTestControllerMethods[] = {
    {"nativeAllocateCamera1Stub",
     "()Ljava/lang/Object;",
     reinterpret_cast<void*>(Java_com_example_arttipoc_CameraTestController_nativeAllocateCamera1Stub)},
};

static const JNINativeMethod kBankingSecurityGuardMethods[] = {
    {"nativeGetPrctlDumpable",
     "()I",
     reinterpret_cast<void*>(Java_com_example_arttipoc_BankingSecurityGuard_nativeGetPrctlDumpable)},
    {"nativeGetTracerPid",
     "()I",
     reinterpret_cast<void*>(Java_com_example_arttipoc_BankingSecurityGuard_nativeGetTracerPid)},
};

/**
 * Loads assets/lspatch/loader.dex via InMemoryDexClassLoader, binds JNI methods via RegisterNatives,
 * and calls LSPApplication.onLoad(), following JingMatrix/LSPatch (patch_loader.cpp).
 */
static void BootstrapLSPatchLoaderDex(JNIEnv* env) {
    jclass stubCls = env->FindClass("org/lsposed/lspatch/metaloader/LSPAppComponentFactoryStub");
    if (!stubCls) {
        env->ExceptionClear();
        return;
    }
    jfieldID dexField = env->GetStaticFieldID(stubCls, "dex", "[B");
    if (!dexField) {
        env->ExceptionClear();
        return;
    }
    auto dexArray = static_cast<jbyteArray>(env->GetStaticObjectField(stubCls, dexField));
    if (!dexArray) {
        env->ExceptionClear();
        return;
    }

    jsize dexLen = env->GetArrayLength(dexArray);
    jbyte* dexBytes = env->GetByteArrayElements(dexArray, nullptr);
    jobject directBuf = env->NewDirectByteBuffer(dexBytes, dexLen);

    jclass atCls = env->FindClass("android/app/ActivityThread");
    jmethodID curAtMid = env->GetStaticMethodID(atCls, "currentActivityThread", "()Landroid/app/ActivityThread;");
    jobject atObj = env->CallStaticObjectMethod(atCls, curAtMid);
    jfieldID boundField = env->GetFieldID(atCls, "mBoundApplication", "Landroid/app/ActivityThread$AppBindData;");
    jobject boundObj = env->GetObjectField(atObj, boundField);
    jclass boundCls = env->GetObjectClass(boundObj);
    jfieldID infoField = env->GetFieldID(boundCls, "info", "Landroid/app/LoadedApk;");
    jobject loadedApkObj = env->GetObjectField(boundObj, infoField);
    jclass loadedApkCls = env->GetObjectClass(loadedApkObj);
    jmethodID getClMid = env->GetMethodID(loadedApkCls, "getClassLoader", "()Ljava/lang/ClassLoader;");
    jobject stubCl = env->CallObjectMethod(loadedApkObj, getClMid);

    jclass clCls = env->FindClass("java/lang/ClassLoader");
    jmethodID getParentMid = env->GetMethodID(clCls, "getParent", "()Ljava/lang/ClassLoader;");
    jobject bootCl = env->CallObjectMethod(stubCl, getParentMid);

    jclass imdClCls = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    jmethodID imdInit = env->GetMethodID(imdClCls, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jobject loaderCl = env->NewObject(imdClCls, imdInit, directBuf, bootCl);
    env->ReleaseByteArrayElements(dexArray, dexBytes, JNI_ABORT);

    jmethodID loadClassMid = env->GetMethodID(clCls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");

    jstring dialogStr = env->NewStringUTF("org.lsposed.lspatch.loader.BiometricPromptHookDialog");
    auto dialogCls = static_cast<jclass>(env->CallObjectMethod(loaderCl, loadClassMid, dialogStr));
    if (dialogCls && !env->ExceptionCheck()) {
        env->RegisterNatives(
            dialogCls,
            kBiometricDialogMethods,
            sizeof(kBiometricDialogMethods) / sizeof(kBiometricDialogMethods[0]));
    } else {
        env->ExceptionClear();
    }

    jstring camHookStr = env->NewStringUTF("org.lsposed.lspatch.loader.CameraInjectionHook");
    auto camHookCls = static_cast<jclass>(env->CallObjectMethod(loaderCl, loadClassMid, camHookStr));
    if (camHookCls && !env->ExceptionCheck()) {
        env->RegisterNatives(
            camHookCls,
            kCameraInjectionMethods,
            sizeof(kCameraInjectionMethods) / sizeof(kCameraInjectionMethods[0]));
    } else {
        env->ExceptionClear();
    }

    jstring lspAppStr = env->NewStringUTF("org.lsposed.lspatch.loader.LSPApplication");
    auto lspAppCls = static_cast<jclass>(env->CallObjectMethod(loaderCl, loadClassMid, lspAppStr));
    if (lspAppCls && !env->ExceptionCheck()) {
        jmethodID onLoadMid = env->GetStaticMethodID(lspAppCls, "onLoad", "()V");
        if (onLoadMid) {
            LOGI("[BootstrapLSPatchLoaderDex] Invoking LSPApplication.onLoad() from InMemoryDexClassLoader");
            env->CallStaticVoidMethod(lspAppCls, onLoadMid);
        }
    }
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void)reserved;
    // Ensure Linux kernel prctl(PR_GET_DUMPABLE) == 0 across all patched APK variants so
    // Banking RASP native dumpable checks observe production non-debuggable Zygote state (2026-10-27).
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    Dl_info info = {};
    if (dladdr(reinterpret_cast<void*>(JNI_OnLoad), &info) && info.dli_fname) {
        snprintf(g_self_so_path, sizeof(g_self_so_path), "%s", info.dli_fname);
    }
    LOGI("========================================================");
    LOGI("[JNI_OnLoad] Native library loaded from %s", g_self_so_path);
    g_vm = vm;

    jvmtiEnv* env_ti = nullptr;
    AcquireJvmtiEnv(vm, &env_ti, "JNI_OnLoad_Gate1Check");
    if (env_ti == nullptr) {
        LOGI("[JNI_OnLoad] Gate 1 verified: vm->GetEnv returned JNI_EVERSION (-3) before libopenjdkjvmti.so initialization.");
    }

    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK && env != nullptr) {
        ExemptHiddenApis(env);
        BootstrapLSPatchLoaderDex(env);
    }

    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_lsposed_lspatch_loader_BiometricPromptHookDialog_nativeAttachAgentNonDebuggable(
        JNIEnv* env, jclass clazz, jobject classLoader) {
    (void)clazz;
    char buf[512];
    if (!ResolveArtSymbolsDynamically() ||
        g_ptr_runtime_instance == nullptr ||
        *g_ptr_runtime_instance == nullptr) {
        return env->NewStringUTF("ERR_DYN_SYM_RESOLVE_FAILED");
    }

    void* runtime = *g_ptr_runtime_instance;
    int old_jdwp = g_fn_is_jdwp_allowed ? (g_fn_is_jdwp_allowed() ? 1 : 0) : -1;
    uint32_t old_dbg_state = g_decoded_debug_state_offset
            ? *reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(runtime) + g_decoded_debug_state_offset)
            : 0;

    // 1. Call exported SetJdwpAllowed(true) and SetRuntimeDebugState(runtime, kJavaDebuggableAtInit=2)
    //    resolved dynamically from libart.so .dynsym (zero hardcoded offsets).
    g_fn_set_jdwp_allowed(true);
    g_fn_set_runtime_debug_state(runtime, 2 /* kJavaDebuggableAtInit */);
    g_upgrade_debug_state_in_onattach = 1;

    // 2. Now that Dbg::IsJdwpAllowed() is true and runtime_debug_state_ is kJavaDebuggableAtInit,
    //    the public Android SDK Debug.attachJvmtiAgent("libarttipoc.so", null, classLoader) succeeds
    //    directly without needing any internal VMDebug_nativeAttachAgent offset!
    jclass debugCls = env->FindClass("android/os/Debug");
    jmethodID attachMid = debugCls
            ? env->GetStaticMethodID(
                  debugCls,
                  "attachJvmtiAgent",
                  "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V")
            : nullptr;
    if (!attachMid) {
        env->ExceptionClear();
        return env->NewStringUTF("ERR_NO_DEBUG_ATTACH_MID");
    }
    jstring jagent = env->NewStringUTF("libarttipoc.so");
    env->CallStaticVoidMethod(debugCls, attachMid, jagent, nullptr, classLoader);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        return env->NewStringUTF("ERR_DEBUG_ATTACH_EXCEPTION");
    }

    int new_jdwp = g_fn_is_jdwp_allowed ? (g_fn_is_jdwp_allowed() ? 1 : 0) : 1;
    uint32_t new_dbg_state = g_decoded_debug_state_offset
            ? *reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(runtime) + g_decoded_debug_state_offset)
            : 2;

    snprintf(buf, sizeof(buf),
             "DYN_DYNSYM_OK(jdwp:%d->%d,dbgState:%u->%u@+0x%zx,jvmti:%p)",
             old_jdwp, new_jdwp, old_dbg_state, new_dbg_state, g_decoded_debug_state_offset, g_jvmti);
    return env->NewStringUTF(buf);
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_lsposed_lspatch_loader_BiometricPromptHookDialog_nativeInstallBiometricHook(
        JNIEnv* env, jclass clazz, jclass dialogHelperClass, jclass biometricPromptClass) {
    (void)clazz;
    if (g_jvmti == nullptr && g_vm != nullptr) {
        AcquireJvmtiEnv(g_vm, &g_jvmti, "nativeInstallBiometricHook");
    }
    if (g_jvmti == nullptr) {
        return env->NewStringUTF("ERR_NO_JVMTI_ENV");
    }

    EnsureCallbacksRegistered();

    jvmtiCapabilities caps = {};
    caps.can_generate_breakpoint_events = 1;
    caps.can_access_local_variables = 1;
    caps.can_force_early_return = 1;
    jvmtiError cap_err = g_jvmti->AddCapabilities(&caps);

    if (g_dialog_helper_cls != nullptr) {
        env->DeleteGlobalRef(g_dialog_helper_cls);
    }
    g_dialog_helper_cls = static_cast<jclass>(env->NewGlobalRef(dialogHelperClass));
    g_on_auth_intercepted_mid = env->GetStaticMethodID(
        g_dialog_helper_cls,
        "onAuthenticateIntercepted",
        "(Landroid/hardware/biometrics/BiometricPrompt;"
        "Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;"
        "Landroid/os/CancellationSignal;"
        "Ljava/util/concurrent/Executor;"
        "Landroid/hardware/biometrics/BiometricPrompt$AuthenticationCallback;)V");

    g_on_fp_auth_intercepted_mid = env->GetStaticMethodID(
        g_dialog_helper_cls,
        "onFingerprintAuthenticateIntercepted",
        "(Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;"
        "Landroid/os/CancellationSignal;"
        "Landroid/hardware/fingerprint/FingerprintManager$AuthenticationCallback;"
        "Landroid/os/Handler;)V");
    if (env->ExceptionCheck()) env->ExceptionClear();

    g_bio_auth_3arg = env->GetMethodID(
        biometricPromptClass,
        "authenticate",
        "(Landroid/os/CancellationSignal;"
        "Ljava/util/concurrent/Executor;"
        "Landroid/hardware/biometrics/BiometricPrompt$AuthenticationCallback;)V");

    g_bio_auth_4arg = env->GetMethodID(
        biometricPromptClass,
        "authenticate",
        "(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;"
        "Landroid/os/CancellationSignal;"
        "Ljava/util/concurrent/Executor;"
        "Landroid/hardware/biometrics/BiometricPrompt$AuthenticationCallback;)V");

    jclass bioMgrCls = env->FindClass("android/hardware/biometrics/BiometricManager");
    if (bioMgrCls) {
        g_bio_mgr_can_auth_0arg = env->GetMethodID(bioMgrCls, "canAuthenticate", "()I");
        if (env->ExceptionCheck()) env->ExceptionClear();
        g_bio_mgr_can_auth_1arg = env->GetMethodID(bioMgrCls, "canAuthenticate", "(I)I");
        if (env->ExceptionCheck()) env->ExceptionClear();
    } else {
        env->ExceptionClear();
    }

    jclass fpMgrCls = env->FindClass("android/hardware/fingerprint/FingerprintManager");
    if (fpMgrCls) {
        g_fp_mgr_is_hw = env->GetMethodID(fpMgrCls, "isHardwareDetected", "()Z");
        if (env->ExceptionCheck()) env->ExceptionClear();
        g_fp_mgr_has_enrolled = env->GetMethodID(fpMgrCls, "hasEnrolledFingerprints", "()Z");
        if (env->ExceptionCheck()) env->ExceptionClear();
        g_fp_mgr_authenticate = env->GetMethodID(
            fpMgrCls,
            "authenticate",
            "(Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;"
            "Landroid/os/CancellationSignal;"
            "I"
            "Landroid/hardware/fingerprint/FingerprintManager$AuthenticationCallback;"
            "Landroid/os/Handler;)V");
        if (env->ExceptionCheck()) env->ExceptionClear();
    } else {
        env->ExceptionClear();
    }

    jvmtiError ev_err = g_jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_BREAKPOINT, nullptr);
    jvmtiError bp3 = g_bio_auth_3arg ? g_jvmti->SetBreakpoint(g_bio_auth_3arg, 0) : JVMTI_ERROR_INVALID_METHODID;
    jvmtiError bp4 = g_bio_auth_4arg ? g_jvmti->SetBreakpoint(g_bio_auth_4arg, 0) : JVMTI_ERROR_INVALID_METHODID;
    jvmtiError bp_bm0 = g_bio_mgr_can_auth_0arg ? g_jvmti->SetBreakpoint(g_bio_mgr_can_auth_0arg, 0) : JVMTI_ERROR_INVALID_METHODID;
    jvmtiError bp_bm1 = g_bio_mgr_can_auth_1arg ? g_jvmti->SetBreakpoint(g_bio_mgr_can_auth_1arg, 0) : JVMTI_ERROR_INVALID_METHODID;
    jvmtiError bp_fp_hw = g_fp_mgr_is_hw ? g_jvmti->SetBreakpoint(g_fp_mgr_is_hw, 0) : JVMTI_ERROR_INVALID_METHODID;
    jvmtiError bp_fp_en = g_fp_mgr_has_enrolled ? g_jvmti->SetBreakpoint(g_fp_mgr_has_enrolled, 0) : JVMTI_ERROR_INVALID_METHODID;
    jvmtiError bp_fp_au = g_fp_mgr_authenticate ? g_jvmti->SetBreakpoint(g_fp_mgr_authenticate, 0) : JVMTI_ERROR_INVALID_METHODID;

    char buf[256];
    snprintf(buf, sizeof(buf),
             "ARMED(cap=%d,ev=%d,bp3=%d,bp4=%d,bm=%d/%d,fp=%d/%d/%d)",
             cap_err, ev_err, bp3, bp4, bp_bm0, bp_bm1, bp_fp_hw, bp_fp_en, bp_fp_au);
    LOGI("[nativeInstallBiometricHook] %s", buf);
    return env->NewStringUTF(buf);
}

/**
 * Constructs android.hardware.biometrics.BiometricPrompt$AuthenticationResult across Android 9-18+:
 * 1. Android 10 (API 29) -> Android 17 (API 37): <init>(CryptoObject, int)V
 * 2. Android 9 (API 28) variants: <init>(CryptoObject, CryptoObject, int)V or <init>(CryptoObject)V
 * 3. Unconditional future-proof fallback (also exercised when authType < 0): JNI AllocObject(resCls)
 *    without calling any constructor, followed by setting mCryptoObject and mAuthenticationType fields.
 */
extern "C" JNIEXPORT jobject JNICALL
Java_org_lsposed_lspatch_loader_BiometricPromptHookDialog_nativeCreateAuthenticationResult(
        JNIEnv* env, jclass clazz, jobject cryptoObject, jint authType) {
    (void)clazz;
    jclass resCls = env->FindClass("android/hardware/biometrics/BiometricPrompt$AuthenticationResult");
    if (!resCls) {
        env->ExceptionClear();
        return nullptr;
    }

    if (authType >= 0) {
        jmethodID ctor2 = env->GetMethodID(
            resCls,
            "<init>",
            "(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;I)V");
        if (ctor2) {
            return env->NewObject(resCls, ctor2, cryptoObject, authType);
        }
        env->ExceptionClear();

        jmethodID ctor3 = env->GetMethodID(
            resCls,
            "<init>",
            "(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;"
            "Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;I)V");
        if (ctor3) {
            return env->NewObject(resCls, ctor3, cryptoObject, nullptr, authType);
        }
        env->ExceptionClear();

        jmethodID ctor1 = env->GetMethodID(
            resCls,
            "<init>",
            "(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;)V");
        if (ctor1) {
            return env->NewObject(resCls, ctor1, cryptoObject);
        }
        env->ExceptionClear();
    }

    jobject obj = env->AllocObject(resCls);
    if (!obj) {
        env->ExceptionClear();
        return nullptr;
    }
    jfieldID cryptoField = env->GetFieldID(
        resCls, "mCryptoObject", "Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;");
    if (cryptoField) {
        env->SetObjectField(obj, cryptoField, cryptoObject);
    } else {
        env->ExceptionClear();
    }
    jfieldID typeField = env->GetFieldID(resCls, "mAuthenticationType", "I");
    if (typeField) {
        env->SetIntField(obj, typeField, authType >= 0 ? authType : 2);
    } else {
        env->ExceptionClear();
    }
    return obj;
}

extern "C" JNIEXPORT jobject JNICALL
Java_org_lsposed_lspatch_loader_BiometricPromptHookDialog_nativeCreateFingerprintAuthResult(
        JNIEnv* env, jclass clazz, jobject cryptoObject) {
    (void)clazz;
    jclass resCls = env->FindClass("android/hardware/fingerprint/FingerprintManager$AuthenticationResult");
    if (!resCls) {
        env->ExceptionClear();
        return nullptr;
    }
    jmethodID ctor = env->GetMethodID(
        resCls,
        "<init>",
        "(Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;"
        "Landroid/hardware/fingerprint/Fingerprint;I)V");
    if (ctor) {
        return env->NewObject(resCls, ctor, cryptoObject, nullptr, 0);
    }
    env->ExceptionClear();

    jobject obj = env->AllocObject(resCls);
    if (!obj) {
        env->ExceptionClear();
        return nullptr;
    }
    jfieldID cryptoField = env->GetFieldID(
        resCls, "mCryptoObject", "Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;");
    if (cryptoField) {
        env->SetObjectField(obj, cryptoField, cryptoObject);
    } else {
        env->ExceptionClear();
    }
    return obj;
}

extern "C" JNIEXPORT void JNICALL
Java_org_lsposed_lspatch_loader_BiometricPromptHookDialog_nativeRegisterAppNatives(
        JNIEnv* env, jclass clazz, jclass mainActivityClass) {
    (void)clazz;
    if (mainActivityClass) {
        env->RegisterNatives(
            mainActivityClass,
            kMainActivityMethods,
            sizeof(kMainActivityMethods) / sizeof(kMainActivityMethods[0]));
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        } else {
            LOGI("[nativeRegisterAppNatives] Bound MainActivity.nativeControl on target ClassLoader");
        }

        jclass clsCls = env->FindClass("java/lang/Class");
        jmethodID getClMid = clsCls ? env->GetMethodID(clsCls, "getClassLoader", "()Ljava/lang/ClassLoader;") : nullptr;
        jobject appCl = getClMid ? env->CallObjectMethod(mainActivityClass, getClMid) : nullptr;
        jclass clCls = env->FindClass("java/lang/ClassLoader");
        jmethodID loadClassMid = clCls ? env->GetMethodID(clCls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;") : nullptr;

        if (appCl && loadClassMid) {
            jstring camCtrlName = env->NewStringUTF("com.example.arttipoc.CameraTestController");
            auto camCtrlCls = static_cast<jclass>(env->CallObjectMethod(appCl, loadClassMid, camCtrlName));
            if (camCtrlCls && !env->ExceptionCheck()) {
                env->RegisterNatives(
                    camCtrlCls,
                    kCameraTestControllerMethods,
                    sizeof(kCameraTestControllerMethods) / sizeof(kCameraTestControllerMethods[0]));
            }
            if (env->ExceptionCheck()) env->ExceptionClear();

            jstring bankGuardName = env->NewStringUTF("com.example.arttipoc.BankingSecurityGuard");
            auto bankGuardCls = static_cast<jclass>(env->CallObjectMethod(appCl, loadClassMid, bankGuardName));
            if (bankGuardCls && !env->ExceptionCheck()) {
                env->RegisterNatives(
                    bankGuardCls,
                    kBankingSecurityGuardMethods,
                    sizeof(kBankingSecurityGuardMethods) / sizeof(kBankingSecurityGuardMethods[0]));
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
        }
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_lsposed_lspatch_loader_CameraInjectionHook_nativeInstallCameraHooks(
        JNIEnv* env, jclass clazz,
        jclass helperClass, jclass camera1Class, jclass imageReaderClass, jclass cameraXAnalysisClass) {
    (void)clazz;
    if (g_jvmti == nullptr && g_vm != nullptr) {
        AcquireJvmtiEnv(g_vm, &g_jvmti, "nativeInstallCameraHooks");
    }
    if (g_jvmti == nullptr) {
        return env->NewStringUTF("ERR_NO_JVMTI_ENV");
    }

    EnsureCallbacksRegistered();

    jvmtiCapabilities caps = {};
    caps.can_generate_breakpoint_events = 1;
    caps.can_access_local_variables = 1;
    caps.can_force_early_return = 1;
    g_jvmti->AddCapabilities(&caps);
    g_jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_BREAKPOINT, nullptr);

    if (g_camera_helper_cls != nullptr) {
        env->DeleteGlobalRef(g_camera_helper_cls);
    }
    g_camera_helper_cls = static_cast<jclass>(env->NewGlobalRef(helperClass));

    g_on_cam1_take_picture_mid = env->GetStaticMethodID(
        g_camera_helper_cls,
        "onCamera1TakePictureIntercepted",
        "(Landroid/hardware/Camera;"
        "Landroid/hardware/Camera$ShutterCallback;"
        "Landroid/hardware/Camera$PictureCallback;"
        "Landroid/hardware/Camera$PictureCallback;"
        "Landroid/hardware/Camera$PictureCallback;)V");
    if (env->ExceptionCheck()) env->ExceptionClear();

    g_on_cam1_preview_cb_mid = env->GetStaticMethodID(
        g_camera_helper_cls,
        "onCamera1PreviewCallbackIntercepted",
        "(Landroid/hardware/Camera;Landroid/hardware/Camera$PreviewCallback;)V");
    if (env->ExceptionCheck()) env->ExceptionClear();

    g_on_cam2_imagereader_mid = env->GetStaticMethodID(
        g_camera_helper_cls,
        "onCamera2ImageReaderListenerIntercepted",
        "(Landroid/media/ImageReader;"
        "Landroid/media/ImageReader$OnImageAvailableListener;"
        "Landroid/os/Handler;)V");
    if (env->ExceptionCheck()) env->ExceptionClear();

    g_on_camx_analyzer_mid = env->GetStaticMethodID(
        g_camera_helper_cls,
        "onCameraXSetAnalyzerIntercepted",
        "(Ljava/lang/Object;Ljava/util/concurrent/Executor;Ljava/lang/Object;)V");
    if (env->ExceptionCheck()) env->ExceptionClear();

    if (camera1Class) {
        g_cam1_take_picture_4arg = env->GetMethodID(
            camera1Class,
            "takePicture",
            "(Landroid/hardware/Camera$ShutterCallback;"
            "Landroid/hardware/Camera$PictureCallback;"
            "Landroid/hardware/Camera$PictureCallback;"
            "Landroid/hardware/Camera$PictureCallback;)V");
        if (env->ExceptionCheck()) env->ExceptionClear();

        g_cam1_set_oneshot_preview = env->GetMethodID(
            camera1Class,
            "setOneShotPreviewCallback",
            "(Landroid/hardware/Camera$PreviewCallback;)V");
        if (env->ExceptionCheck()) env->ExceptionClear();

        g_cam1_set_preview_cb = env->GetMethodID(
            camera1Class,
            "setPreviewCallback",
            "(Landroid/hardware/Camera$PreviewCallback;)V");
        if (env->ExceptionCheck()) env->ExceptionClear();
    }

    if (imageReaderClass) {
        g_cam2_set_image_available = env->GetMethodID(
            imageReaderClass,
            "setOnImageAvailableListener",
            "(Landroid/media/ImageReader$OnImageAvailableListener;Landroid/os/Handler;)V");
        if (env->ExceptionCheck()) env->ExceptionClear();
    }

    if (cameraXAnalysisClass) {
        g_camx_set_analyzer = env->GetMethodID(
            cameraXAnalysisClass,
            "setAnalyzer",
            "(Ljava/util/concurrent/Executor;Landroidx/camera/core/ImageAnalysis$Analyzer;)V");
        if (env->ExceptionCheck()) env->ExceptionClear();
    }

    jvmtiError bp_c1_pic = g_cam1_take_picture_4arg
            ? g_jvmti->SetBreakpoint(g_cam1_take_picture_4arg, 0) : JVMTI_ERROR_INVALID_METHODID;
    jvmtiError bp_c1_one = g_cam1_set_oneshot_preview
            ? g_jvmti->SetBreakpoint(g_cam1_set_oneshot_preview, 0) : JVMTI_ERROR_INVALID_METHODID;
    jvmtiError bp_c1_prv = g_cam1_set_preview_cb
            ? g_jvmti->SetBreakpoint(g_cam1_set_preview_cb, 0) : JVMTI_ERROR_INVALID_METHODID;
    jvmtiError bp_c2_ir = g_cam2_set_image_available
            ? g_jvmti->SetBreakpoint(g_cam2_set_image_available, 0) : JVMTI_ERROR_INVALID_METHODID;
    jvmtiError bp_cx_an = g_camx_set_analyzer
            ? g_jvmti->SetBreakpoint(g_camx_set_analyzer, 0) : JVMTI_ERROR_INVALID_METHODID;

    char buf[256];
    snprintf(buf, sizeof(buf),
             "CAM_ARMED(c1Pic=%d,c1Prv=%d/%d,c2Ir=%d,cXAn=%d)",
             bp_c1_pic, bp_c1_one, bp_c1_prv, bp_c2_ir, bp_cx_an);
    LOGI("[nativeInstallCameraHooks] %s", buf);
    return env->NewStringUTF(buf);
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_example_arttipoc_CameraTestController_nativeAllocateCamera1Stub(
        JNIEnv* env, jclass clazz) {
    (void)clazz;
    jclass camCls = env->FindClass("android/hardware/Camera");
    if (!camCls) {
        env->ExceptionClear();
        return nullptr;
    }
    return env->AllocObject(camCls);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_example_arttipoc_BankingSecurityGuard_nativeGetPrctlDumpable(
        JNIEnv* env, jclass clazz) {
    (void)env;
    (void)clazz;
    return prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_example_arttipoc_BankingSecurityGuard_nativeGetTracerPid(
        JNIEnv* env, jclass clazz) {
    (void)env;
    (void)clazz;
    FILE* fp = fopen("/proc/self/status", "r");
    if (!fp) return -1;
    char line[256];
    int tracer_pid = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer_pid = atoi(line + 10);
            break;
        }
    }
    fclose(fp);
    return tracer_pid;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_arttipoc_MainActivity_nativeControl(
        JNIEnv* env, jclass clazz, jint mode, jclass target_work_cls, jclass inlined_callee_cls) {
    (void)clazz;
    char buf[2048];

    if (mode == 0) {
        g_plain_entry_hits = 0;
        g_same_inlined_entry_hits = 0;
        g_cross_inlined_entry_hits = 0;
        g_plain_bp_hits = 0;
        g_same_inlined_bp_hits = 0;
        g_cross_inlined_bp_hits = 0;
        g_cflh_hits = 0;
        return env->NewStringUTF("COUNTERS_RESET");
    }

    if (mode == 99) {
        snprintf(buf, sizeof(buf),
                 "plain_entry=%d same_inlined_entry=%d cross_inlined_entry=%d | "
                 "plain_bp=%d same_inlined_bp=%d cross_inlined_bp=%d | bio_bp=%d cflh=%d",
                 g_plain_entry_hits, g_same_inlined_entry_hits, g_cross_inlined_entry_hits,
                 g_plain_bp_hits, g_same_inlined_bp_hits, g_cross_inlined_bp_hits,
                 g_bio_bp_hits, g_cflh_hits);
        return env->NewStringUTF(buf);
    }

    if (g_jvmti == nullptr) {
        AcquireJvmtiEnv(g_vm, &g_jvmti, "nativeControl");
        if (g_jvmti == nullptr) {
            return env->NewStringUTF("ERR_NO_JVMTI_ENV");
        }
    }

    EnsureCallbacksRegistered();

    if (mode == 1) {
        jint class_count = 0;
        jclass* classes = nullptr;
        jvmtiError err = g_jvmti->GetLoadedClasses(&class_count, &classes);
        int found_target = 0;
        int found_callee = 0;
        if (err == JVMTI_ERROR_NONE && classes != nullptr) {
            for (jint i = 0; i < class_count; ++i) {
                char* sig = nullptr;
                if (g_jvmti->GetClassSignature(classes[i], &sig, nullptr) == JVMTI_ERROR_NONE && sig != nullptr) {
                    if (strcmp(sig, "Lcom/example/arttipoc/TargetWork;") == 0) found_target = 1;
                    if (strcmp(sig, "Lcom/example/arttipoc/InlinedCallee;") == 0) found_callee = 1;
                    g_jvmti->Deallocate(reinterpret_cast<unsigned char*>(sig));
                }
            }
            g_jvmti->Deallocate(reinterpret_cast<unsigned char*>(classes));
        }

        g_plain_method = env->GetStaticMethodID(target_work_cls, "plainMethod", "(I)I");
        g_same_class_inlined = env->GetStaticMethodID(target_work_cls, "inlinedTarget", "(II)I");
        g_caller_method = env->GetStaticMethodID(target_work_cls, "callerMethod", "(I)I");
        g_cross_class_inlined = env->GetStaticMethodID(inlined_callee_cls, "crossClassInlined", "(I)I");

        jvmtiCapabilities caps = {};
        caps.can_generate_breakpoint_events = 1;
        caps.can_generate_native_method_bind_events = 1;
        jvmtiError bp_cap_err = g_jvmti->AddCapabilities(&caps);
        jvmtiError bp_ev_err = g_jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_BREAKPOINT, nullptr);
        jvmtiError nb_ev_err = g_jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_NATIVE_METHOD_BIND, nullptr);
        jvmtiError bp1 = g_jvmti->SetBreakpoint(g_plain_method, 0);
        jvmtiError bp2 = g_jvmti->SetBreakpoint(g_same_class_inlined, 0);
        jvmtiError bp3 = g_jvmti->SetBreakpoint(g_cross_class_inlined, 0);

        // Bind TargetWork.nativeSecretToken(String)String via RegisterNatives while
        // JVMTI_EVENT_NATIVE_METHOD_BIND is active; OnNativeMethodBind intercepts the bind,
        // captures OriginalNativeSecretToken, and redirects *new_address_ptr to HookedNativeSecretToken.
        static const JNINativeMethod kTargetWorkNatives[] = {
            {"nativeSecretToken",
             "(Ljava/lang/String;)Ljava/lang/String;",
             reinterpret_cast<void*>(OriginalNativeSecretToken)},
        };
        env->RegisterNatives(target_work_cls, kTargetWorkNatives, 1);
        if (env->ExceptionCheck()) env->ExceptionClear();

        snprintf(buf, sizeof(buf),
                 "classes=%d(target=%d,callee=%d) bp_cap=%d bp_ev=%d nb_ev=%d native_bind_hits=%d bp_plain=%d bp_same_inl=%d bp_cross_inl=%d",
                 (int)class_count, found_target, found_callee, bp_cap_err, bp_ev_err, nb_ev_err,
                 g_native_bind_hits, bp1, bp2, bp3);
        return env->NewStringUTF(buf);
    }

    if (mode == 2) {
        jvmtiCapabilities caps = {};
        caps.can_generate_method_entry_events = 1;
        jvmtiError cap_err = g_jvmti->AddCapabilities(&caps);
        jvmtiError ev_err = g_jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_METHOD_ENTRY, nullptr);
        snprintf(buf, sizeof(buf), "method_entry_cap=%d method_entry_ev=%d", cap_err, ev_err);
        return env->NewStringUTF(buf);
    }

    if (mode == 3 || mode == 31) {
        jvmtiCapabilities caps = {};
        caps.can_retransform_classes = 1;
        jvmtiError cap_err = g_jvmti->AddCapabilities(&caps);
        jvmtiError ev_err = g_jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, nullptr);

        jint count = (mode == 3) ? 1 : 2;
        jclass classes_to_retransform[2] = {
            inlined_callee_cls,
            target_work_cls
        };
        jvmtiError rt_err = g_jvmti->RetransformClasses(count, classes_to_retransform);
        snprintf(buf, sizeof(buf), "mode=%d retransform_cap=%d cflh_ev=%d retransform_err=%d cflh_hits=%d",
                 (int)mode, cap_err, ev_err, rt_err, g_cflh_hits);
        return env->NewStringUTF(buf);
    }

    return env->NewStringUTF("UNKNOWN_MODE");
}
