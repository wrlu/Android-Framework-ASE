package net.wrlu.ase.data;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Process;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import net.wrlu.ase.data.handlers.BinderServiceHandler;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Generic, read-only, exported data provider for on-device collection.
 *
 * <p>Endpoints are selected by the first path segment of the query URI and dispatched
 * to a registered {@link DataHandler}. Query arguments are passed the same way as
 * before: the first non-empty {@code selectionArgs} entry wins, otherwise the
 * {@code selection} string is used ({@code name=value} and quoted forms tolerated).
 *
 * <pre>
 *   content://net.wrlu.ase.probe/binder_service                     # all binder services
 *   content://net.wrlu.ase.probe/binder_service  where=activity     # one service
 * </pre>
 *
 * <p>To expose more data, implement {@link DataHandler} and register it in
 * {@link #registerHandlers()}.
 *
 * <p>Access is restricted to this app itself, system (uid 1000), adb shell (uid 2000)
 * and root (uid 0); other apps are rejected.
 */
public class DataProvider extends ContentProvider {

    public static final String AUTHORITY = "net.wrlu.ase.probe";

    private final Map<String, DataHandler> handlers = new LinkedHashMap<>();

    @Override
    public boolean onCreate() {
        registerHandlers();
        return true;
    }

    /** Extension point: register every data endpoint exposed by this provider. */
    private void registerHandlers() {
        handlers.clear();
        register(new BinderServiceHandler());
        // Register additional DataHandler implementations here.
    }

    private void register(DataHandler handler) {
        handlers.put(handler.path(), handler);
    }

    @Nullable
    @Override
    public Cursor query(@NonNull Uri uri, @Nullable String[] projection, @Nullable String selection,
                        @Nullable String[] selectionArgs, @Nullable String sortOrder) {
        enforceAllowedCaller();

        String path = firstPathSegment(uri);
        DataHandler handler = path == null ? null : handlers.get(path);
        if (handler == null) {
            throw new IllegalArgumentException("unknown data path: " + path
                    + " (available: " + handlers.keySet() + ")");
        }
        return handler.query(resolveQueryArg(selection, selectionArgs));
    }

    private static String firstPathSegment(Uri uri) {
        List<String> segments = uri.getPathSegments();
        return segments.isEmpty() ? null : segments.get(0);
    }

    /**
     * Extract the caller argument from the query. The first non-empty
     * {@code selectionArgs} entry wins; otherwise the {@code selection} string is
     * used, tolerating {@code name=value} and quoted forms.
     */
    private static String resolveQueryArg(@Nullable String selection,
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

    /**
     * Allow queries only from this app itself, system (uid 1000), adb shell (uid 2000)
     * or root (uid 0); reject other apps.
     */
    private static void enforceAllowedCaller() {
        int uid = Binder.getCallingUid();
        if (uid != Process.myUid()
                && uid != Process.SYSTEM_UID
                && uid != Process.SHELL_UID
                && uid != Process.ROOT_UID) {
            throw new SecurityException(
                    "DataProvider is accessible from system/shell/root only");
        }
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
