package androidx.camera.core;

import android.media.Image;

/**
 * Jetpack CameraX ImageProxy interface matching androidx.camera.core.ImageProxy.
 */
public interface ImageProxy extends AutoCloseable {
    int getWidth();
    int getHeight();
    int getFormat();
    Image getImage();
    @Override
    void close();
}
