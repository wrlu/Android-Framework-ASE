package net.wrlu.ase.probe;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Process;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import net.wrlu.ase.probe.BinderProber.ProbeResult;

import java.util.ArrayList;
import java.util.List;

/**
 * Exported ContentProvider that lets a host (e.g. {@code adb shell content query}) check
 * whether binder services can be obtained through this app's identity.
 *
 * <p>The service name is taken from the query arguments (first {@code selectionArg}, else
 * {@code selection}). When absent, every registered service is enumerated and probed.
 *
 * <pre>
 *   content://net.wrlu.ase.probe                      # probe all services
 *   content://net.wrlu.ase.probe  where=activity      # probe "activity"
 * </pre>
 *
 * <p>Returns two columns: {@code service} and {@code accessible} (1 = obtainable, 0 = not).
 * Only the {@link android.os.IBinder} handle is resolved; no AIDL method is invoked.
 *
 * <p>Access is restricted to this app itself, system (uid 1000), adb shell (uid 2000)
 * and root (uid 0); other apps are rejected.
 */
public class BinderProbeProvider extends ContentProvider {

    public static final String AUTHORITY = "net.wrlu.ase.probe";

    private static final String[] COLUMNS = {
            "service", "accessible"
    };

    @Override
    public boolean onCreate() {
        return true;
    }

    @Nullable
    @Override
    public Cursor query(@NonNull Uri uri, @Nullable String[] projection, @Nullable String selection,
                        @Nullable String[] selectionArgs, @Nullable String sortOrder) {
        enforceShellCaller();

        String serviceName = resolveServiceName(selection, selectionArgs);

        List<ProbeResult> results = new ArrayList<>();
        if (serviceName != null && !serviceName.isEmpty()) {
            results.add(BinderProber.probe(serviceName));
        } else {
            results.addAll(BinderProber.listServices());
        }

        MatrixCursor cursor = new MatrixCursor(COLUMNS);
        for (ProbeResult r : results) {
            cursor.addRow(new Object[]{
                    r.service,
                    r.accessible ? 1 : 0
            });
        }
        return cursor;
    }

    /**
     * Allow queries only from this app itself, system (uid 1000), adb shell (uid 2000)
     * or root (uid 0); reject other apps.
     */
    private static void enforceShellCaller() {
        int uid = Binder.getCallingUid();
        if (uid != Process.myUid()
                && uid != Process.SYSTEM_UID
                && uid != Process.SHELL_UID
                && uid != Process.ROOT_UID) {
            throw new SecurityException(
                    "BinderProbeProvider is accessible from system/shell/root only");
        }
    }

    /**
     * Extract the target service name from the query arguments. The first non-empty
     * {@code selectionArgs} entry wins; otherwise the {@code selection} string is used,
     * tolerating {@code service=NAME} and quoted forms.
     */
    private static String resolveServiceName(@Nullable String selection,
                                             @Nullable String[] selectionArgs) {
        if (selectionArgs != null) {
            for (String arg : selectionArgs) {
                if (arg != null && !arg.trim().isEmpty()) {
                    return stripQuotes(arg.trim());
                }
            }
        }
        if (selection == null || selection.trim().isEmpty()) {
            return null;
        }
        String s = selection.trim();
        int eq = s.indexOf('=');
        if (eq >= 0) {
            s = s.substring(eq + 1).trim();
        }
        s = stripQuotes(s);
        return s.isEmpty() ? null : s;
    }

    private static String stripQuotes(String s) {
        if (s.length() >= 2) {
            char first = s.charAt(0);
            char last = s.charAt(s.length() - 1);
            if ((first == '\'' && last == '\'') || (first == '"' && last == '"')) {
                return s.substring(1, s.length() - 1);
            }
        }
        return s;
    }

    @Nullable
    @Override
    public String getType(@NonNull Uri uri) {
        return null;
    }

    @Nullable
    @Override
    public Uri insert(@NonNull Uri uri, @Nullable ContentValues values) {
        throw new UnsupportedOperationException("read-only provider");
    }

    @Override
    public int delete(@NonNull Uri uri, @Nullable String selection, @Nullable String[] selectionArgs) {
        throw new UnsupportedOperationException("read-only provider");
    }

    @Override
    public int update(@NonNull Uri uri, @Nullable ContentValues values, @Nullable String selection,
                      @Nullable String[] selectionArgs) {
        throw new UnsupportedOperationException("read-only provider");
    }
}
