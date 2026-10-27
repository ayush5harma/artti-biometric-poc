package androidx.camera.core;

import android.media.Image;
import android.media.ImageReader;

/**
 * Jetpack CameraX ImageProxy wrapper around an android.media.Image.
 */
public final class AndroidImageProxy implements ImageProxy {
    private final Image mImage;
    private final ImageReader mReader;

    public AndroidImageProxy(Image image, ImageReader reader) {
        mImage = image;
        mReader = reader;
    }

    @Override
    public int getWidth() {
        return mImage != null ? mImage.getWidth() : 0;
    }

    @Override
    public int getHeight() {
        return mImage != null ? mImage.getHeight() : 0;
    }

    @Override
    public int getFormat() {
        return mImage != null ? mImage.getFormat() : 0;
    }

    @Override
    public Image getImage() {
        return mImage;
    }

    @Override
    public void close() {
        if (mImage != null) {
            mImage.close();
        }
        if (mReader != null) {
            mReader.close();
        }
    }
}
