package net.wrlu.ase.script;

import android.content.Context;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;

/**
 * Shared storage for script execution results across processes and with the host.
 */
public class ScriptResultStore {
    private static final String TAG = "ASE_RUNNER";
    public static final String RESULT_FILE_NAME = "script_result.json";

    public static File getInternalResultFile(Context context) {
        return new File(context.getCacheDir(), RESULT_FILE_NAME);
    }

    public static File getExternalResultFile(Context context) {
        File ext = context.getExternalCacheDir();
        return ext != null ? new File(ext, RESULT_FILE_NAME) : null;
    }

    public static synchronized void saveResult(Context context, JSONObject json) {
        String content = json.toString();
        // 1. Internal cache file (shared between all processes under same UID)
        try {
            File internalFile = getInternalResultFile(context);
            try (FileWriter fw = new FileWriter(internalFile)) {
                fw.write(content);
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to write internal result file: " + e.getMessage());
        }

        // 2. External cache file (directly readable by adb shell without root)
        try {
            File externalFile = getExternalResultFile(context);
            if (externalFile != null) {
                try (FileWriter fw = new FileWriter(externalFile)) {
                    fw.write(content);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to write external result file: " + e.getMessage());
        }
    }

    public static synchronized JSONObject loadResult(Context context) {
        File internalFile = getInternalResultFile(context);
        if (internalFile.exists()) {
            try (BufferedReader br = new BufferedReader(new FileReader(internalFile))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line).append('\n');
                }
                return new JSONObject(sb.toString());
            } catch (Exception e) {
                Log.w(TAG, "Failed to read result: " + e.getMessage());
            }
        }
        return null;
    }
}
