package net.wrlu.ase;

import android.app.Application;
import android.os.Build;
import android.util.Log;

import org.lsposed.hiddenapibypass.HiddenApiBypass;

/**
 * Base Application class for AttackSurfaceExplorer.
 *
 * <p>Initializes process-level environment such as HiddenApiBypass exemptions
 * for every process spawned by this package (main process, :runner, etc.).
 */
public class AseApplication extends Application {
    private static final String TAG = "AseApplication";

    @Override
    public void onCreate() {
        super.onCreate();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                HiddenApiBypass.addHiddenApiExemptions("");
                Log.i(TAG, "HiddenApiBypass exemptions applied to process: " + getProcessName());
            } catch (Throwable t) {
                Log.w(TAG, "Failed to apply HiddenApiBypass exemptions: " + t.getMessage());
            }
        }
    }
}
