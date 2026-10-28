package net.wrlu.ase;

import android.app.Application;
import android.os.Build;
import android.util.Log;

import org.lsposed.hiddenapibypass.HiddenApiBypass;

/**
 * Base Application class for AttackSurfaceExplorer.
 *
 * <p>Initializes process-level environment such as HiddenApiBypass exemptions
 * for the isolated {@code :runner} process, where dynamic scripts execute.
 */
public class AseApplication extends Application {
    private static final String TAG = "AseApplication";
    private static final String RUNNER_PROCESS_SUFFIX = ":runner";

    @Override
    public void onCreate() {
        super.onCreate();
        // Scripts run in the dedicated :runner process; keep the exemption scoped there
        // instead of weakening every process of the app.
        String processName = getProcessName();
        boolean isRunner = processName != null && processName.endsWith(RUNNER_PROCESS_SUFFIX);
        if (isRunner && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                HiddenApiBypass.addHiddenApiExemptions("");
                Log.i(TAG, "HiddenApiBypass exemptions applied to process: " + processName);
            } catch (Throwable t) {
                Log.w(TAG, "Failed to apply HiddenApiBypass exemptions: " + t.getMessage());
            }
        }
    }
}
