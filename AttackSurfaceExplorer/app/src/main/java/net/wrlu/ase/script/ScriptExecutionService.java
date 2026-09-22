package net.wrlu.ase.script;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import dalvik.system.PathClassLoader;

/**
 * Foreground Service running in a dedicated process (:runner) to execute dynamic scripts.
 *
 * <p>Triggered via {@code am start-foreground-service}:
 * <pre>
 *   adb shell am start-foreground-service \
 *       -n net.wrlu.ase/.script.ScriptExecutionService \
 *       --es dex_path /data/local/tmp/ase_script.dex \
 *       --es entry_class com.example.MyScript \
 *       [--es args "my_arguments"] \
 *       [--es result_file /data/local/tmp/ase_result.json]
 * </pre>
 */
public class ScriptExecutionService extends Service {
    private static final String TAG = "ASE_RUNNER";
    private static final String CHANNEL_ID = "ase_script_runner_channel";
    private static final int NOTIFICATION_ID = 2001;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "ASE Script Runner",
                    NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Running dynamic attack surface test script");
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) {
                nm.createNotificationChannel(channel);
            }
        }
    }

    private void promoteToForeground() {
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("ASE Script Runner")
                .setContentText("Executing dynamic verification script...")
                .setSmallIcon(android.R.drawable.ic_menu_manage)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) { // API 34
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        promoteToForeground();

        if (intent == null) {
            Log.w(TAG, "Null intent received, stopping service");
            stopForegroundCompat();
            stopSelf(startId);
            return START_NOT_STICKY;
        }

        String dexPath = intent.getStringExtra("dex_path");
        String entryClass = intent.getStringExtra("entry_class");
        String args = intent.getStringExtra("args");
        String resultFile = intent.getStringExtra("result_file");

        executor.execute(() -> {
            try {
                executeScript(dexPath, entryClass, args, resultFile);
            } finally {
                stopForegroundCompat();
                stopSelf(startId);
            }
        });

        return START_NOT_STICKY;
    }

    private void stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE);
        } else {
            stopForeground(true);
        }
    }

    private void executeScript(String dexPath, String entryClass, String args, String resultFile) {
        long startTime = System.currentTimeMillis();
        JSONObject report = new JSONObject();
        PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;
        ByteArrayOutputStream capturedOutput = new ByteArrayOutputStream();

        try {
            // Mark state as running
            report.put("status", "running");
            report.put("timestamp", startTime);
            ScriptResultStore.saveResult(this, report);

            if (dexPath == null || dexPath.trim().isEmpty()) {
                throw new IllegalArgumentException("dex_path extra is missing");
            }
            if (entryClass == null || entryClass.trim().isEmpty()) {
                throw new IllegalArgumentException("entry_class extra is missing");
            }

            File srcFile = resolveDexFile(dexPath);
            if (srcFile == null || !srcFile.exists()) {
                throw new IllegalArgumentException("DEX file not found or inaccessible: " + dexPath);
            }

            // Copy to app's codeCacheDir to avoid W^X and SELinux execution blocks
            File codeCache = getCodeCacheDir();
            File activeDex = new File(codeCache, "active_payload_" + System.currentTimeMillis() + ".dex");
            copyFile(srcFile, activeDex);

            ClassLoader classLoader = new PathClassLoader(activeDex.getAbsolutePath(), getClassLoader());
            Class<?> clazz = Class.forName(entryClass, true, classLoader);

            // Redirect stdout and stderr during script execution
            PrintStream redirectStream = new PrintStream(capturedOutput, true, "UTF-8");
            System.setOut(redirectStream);
            System.setErr(redirectStream);

            Object invocationResult = invokeEntry(clazz, args != null ? args : "");
            redirectStream.flush();

            long elapsed = System.currentTimeMillis() - startTime;
            report.put("status", "success");
            report.put("result", invocationResult != null ? invocationResult.toString() : "");
            report.put("stdout", capturedOutput.toString("UTF-8"));
            report.put("error", "");
            report.put("elapsed_ms", elapsed);
            report.put("timestamp", System.currentTimeMillis());
            Log.i(TAG, "Script executed successfully in " + elapsed + "ms");
        } catch (Throwable t) {
            long elapsed = System.currentTimeMillis() - startTime;
            StringWriter sw = new StringWriter();
            t.printStackTrace(new PrintWriter(sw));
            String errorMsg = sw.toString();

            try {
                report.put("status", "error");
                report.put("result", "");
                report.put("stdout", capturedOutput.toString("UTF-8"));
                report.put("error", errorMsg);
                report.put("elapsed_ms", elapsed);
                report.put("timestamp", System.currentTimeMillis());
            } catch (Exception ignored) {
            }
            Log.e(TAG, "Script execution failed: " + t.getMessage(), t);
        } finally {
            System.setOut(originalOut);
            System.setErr(originalErr);
        }

        // 1. Save to ScriptResultStore
        ScriptResultStore.saveResult(this, report);
        Log.i(TAG, "[RESULT] " + report.toString());

        // 2. Try writing to result_file if specified
        if (resultFile != null && !resultFile.trim().isEmpty()) {
            try {
                File rf = new File(resultFile.trim());
                File parent = rf.getParentFile();
                if (parent != null && !parent.exists()) {
                    parent.mkdirs();
                }
                try (FileWriter fw = new FileWriter(rf)) {
                    fw.write(report.toString());
                }
            } catch (Throwable t) {
                Log.w(TAG, "Could not write to requested result_file (" + resultFile + "): " + t.getMessage());
            }
        }
    }

    private String invokeEntry(Class<?> clazz, String args) throws Throwable {
        if (!AseScript.class.isAssignableFrom(clazz)) {
            throw new IllegalArgumentException("Entry class " + clazz.getName()
                    + " must implement " + AseScript.class.getName());
        }
        Constructor<?> ctor = clazz.getDeclaredConstructor();
        ctor.setAccessible(true);
        AseScript script = (AseScript) ctor.newInstance();
        return script.run(this, args);
    }

    private File resolveDexFile(String path) {
        File file = new File(path);
        if (file.exists() && file.canRead()) {
            return file;
        }
        // Fallback: check app's external cache dir
        File extCache = getExternalCacheDir();
        if (extCache != null) {
            File fallback = new File(extCache, file.getName());
            if (fallback.exists() && fallback.canRead()) {
                return fallback;
            }
        }
        return file;
    }

    private static void copyFile(File src, File dst) throws Exception {
        try (InputStream in = new FileInputStream(src);
             OutputStream out = new FileOutputStream(dst)) {
            byte[] buf = new byte[8192];
            int len;
            while ((len = in.read(buf)) > 0) {
                out.write(buf, 0, len);
            }
            out.flush();
        }
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}
