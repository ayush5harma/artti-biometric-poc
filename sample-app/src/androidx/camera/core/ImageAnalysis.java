package androidx.camera.core;

import android.util.Log;

import java.util.concurrent.Executor;

/**
 * Jetpack CameraX ImageAnalysis use-case matching androidx.camera.core.ImageAnalysis.
 *
 * When unhooked, setAnalyzer logs that no physical CameraX session is bound.
 * When ART TI is active, JVMTI OnBreakpoint at bytecode offset 0 intercepts setAnalyzer,
 * calls ForceEarlyReturnVoid, and feeds an ImageProxy constructed from the injected image file.
 */
public final class ImageAnalysis {
    private static final String TAG = "ARTTI_POC";

    public interface Analyzer {
        void analyze(ImageProxy image);
    }

    public void setAnalyzer(Executor executor, Analyzer analyzer) {
        Log.i(TAG, "[Unpatched CameraX] ImageAnalysis.setAnalyzer called without ART TI hook");
    }
}
