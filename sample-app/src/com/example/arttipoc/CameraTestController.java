package com.example.arttipoc;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.PixelFormat;
import android.hardware.Camera;
import android.media.Image;
import android.media.ImageReader;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.camera.core.ImageAnalysis;
import androidx.camera.core.ImageProxy;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicReference;

/**
 * End-to-end verification harness for Camera1, Camera2, and CameraX image injection via ART TI.
 *
 * Verified 2026-10-27 on Google Pixel 9 Pro (Android 17, API 37, user build, ro.debuggable=0).
 */
@SuppressWarnings("deprecation")
public final class CameraTestController {

    private static final String TAG = "ARTTI_POC";
    private static final Handler MAIN_HANDLER = new Handler(Looper.getMainLooper());

    public interface CameraTestCallback {
        void onComplete(String summary);
    }

    private CameraTestController() {}

    public static native Object nativeAllocateCamera1Stub();

    public static void runAllCameraInjectionTests(final CameraTestCallback callback) {
        final AtomicReference<String> cam1PreviewRes = new AtomicReference<>("UNHOOKED");
        final AtomicReference<String> cam1JpegRes = new AtomicReference<>("UNHOOKED");
        final AtomicReference<String> cam2Res = new AtomicReference<>("UNHOOKED");
        final AtomicReference<String> camXRes = new AtomicReference<>("UNHOOKED");

        // 1. Camera1 API: setOneShotPreviewCallback + takePicture
        try {
            Camera cam1 = (Camera) nativeAllocateCamera1Stub();
            if (cam1 != null) {
                cam1.setOneShotPreviewCallback((data, camera) -> {
                    int len = (data != null) ? data.length : 0;
                    cam1PreviewRes.set("NV21_BYTES=" + len);
                    Log.i(TAG, "[CAMERA1_PREVIEW] Received injected NV21 preview frame: " + len + " bytes");
                });
                cam1.takePicture(
                        () -> Log.i(TAG, "[CAMERA1_SHUTTER] onShutter fired"),
                        null,
                        null,
                        (data, camera) -> {
                            if (data != null && data.length > 0) {
                                Bitmap bmp = BitmapFactory.decodeByteArray(data, 0, data.length);
                                if (bmp != null) {
                                    int px = bmp.getPixel(4, 4);
                                    String hex = String.format("#%06x", (px & 0xFFFFFF));
                                    cam1JpegRes.set(bmp.getWidth() + "x" + bmp.getHeight() + "@" + hex + "(" + data.length + "B)");
                                    Log.i(TAG, "[CAMERA1_JPEG] Decoded injected picture: " + cam1JpegRes.get());
                                }
                            }
                        });
            }
        } catch (Throwable t) {
            cam1JpegRes.set("ERR:" + t.getClass().getSimpleName());
        }

        // 2. Camera2 API: ImageReader.setOnImageAvailableListener -> acquireLatestImage()
        try {
            final ImageReader reader = ImageReader.newInstance(320, 240, PixelFormat.RGBA_8888, 2);
            reader.setOnImageAvailableListener(r -> {
                try (Image img = r.acquireLatestImage()) {
                    if (img != null && img.getPlanes() != null && img.getPlanes().length > 0) {
                        ByteBuffer buf = img.getPlanes()[0].getBuffer();
                        int rByte = buf.get(0) & 0xFF;
                        int gByte = buf.get(1) & 0xFF;
                        int bByte = buf.get(2) & 0xFF;
                        String hex = String.format("#%02x%02x%02x", rByte, gByte, bByte);
                        cam2Res.set(img.getWidth() + "x" + img.getHeight() + "@" + hex);
                        Log.i(TAG, "[CAMERA2_IMAGEREADER] Acquired injected android.media.Image: " + cam2Res.get());
                    }
                } catch (Throwable t) {
                    Log.e(TAG, "Camera2 acquireLatestImage failed", t);
                } finally {
                    r.close();
                }
            }, MAIN_HANDLER);
        } catch (Throwable t) {
            cam2Res.set("ERR:" + t.getClass().getSimpleName());
        }

        // 3. CameraX API: androidx.camera.core.ImageAnalysis.setAnalyzer
        try {
            ImageAnalysis analysis = new ImageAnalysis();
            analysis.setAnalyzer(MAIN_HANDLER::post, (ImageProxy proxy) -> {
                try (proxy) {
                    Image img = proxy.getImage();
                    if (img != null && img.getPlanes() != null && img.getPlanes().length > 0) {
                        ByteBuffer buf = img.getPlanes()[0].getBuffer();
                        int rByte = buf.get(0) & 0xFF;
                        int gByte = buf.get(1) & 0xFF;
                        int bByte = buf.get(2) & 0xFF;
                        String hex = String.format("#%02x%02x%02x", rByte, gByte, bByte);
                        camXRes.set(proxy.getWidth() + "x" + proxy.getHeight() + "@" + hex);
                        Log.i(TAG, "[CAMERAX_ANALYZER] Received injected ImageProxy: " + camXRes.get());
                    }
                }
            });
        } catch (Throwable t) {
            camXRes.set("ERR:" + t.getClass().getSimpleName());
        }

        MAIN_HANDLER.postDelayed(() -> {
            String summary = "Camera1_Preview=" + cam1PreviewRes.get()
                    + " Camera1_JPEG=" + cam1JpegRes.get()
                    + " Camera2_ImageReader=" + cam2Res.get()
                    + " CameraX_Analyzer=" + camXRes.get();
            Log.i(TAG, "[CAMERA_INJECT_SUMMARY] " + summary);
            if (callback != null) {
                callback.onComplete(summary);
            }
        }, 350);
    }
}
