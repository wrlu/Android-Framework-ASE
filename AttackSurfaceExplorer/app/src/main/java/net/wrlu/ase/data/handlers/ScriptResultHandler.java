package net.wrlu.ase.data.handlers;

import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;

import net.wrlu.ase.data.DataHandler;
import net.wrlu.ase.script.ScriptResultStore;

import org.json.JSONObject;

/**
 * {@code script_result} endpoint: returns the execution state and output of the latest dynamic script.
 *
 * <p>Returns columns: {@code status}, {@code result}, {@code stdout}, {@code error}, {@code elapsed_ms}, {@code json}.
 */
public class ScriptResultHandler implements DataHandler {

    public static final String PATH = "script_result";

    private static final String[] COLUMNS = {
            "status", "result", "stdout", "error", "elapsed_ms", "json"
    };

    private final Context context;

    public ScriptResultHandler(Context context) {
        this.context = context;
    }

    @Override
    public String path() {
        return PATH;
    }

    @Override
    public Cursor query(String arg) {
        MatrixCursor cursor = new MatrixCursor(COLUMNS);
        JSONObject result = ScriptResultStore.loadResult(context);
        if (result != null) {
            cursor.addRow(new Object[]{
                    result.optString("status", "unknown"),
                    result.optString("result", ""),
                    result.optString("stdout", ""),
                    result.optString("error", ""),
                    result.optLong("elapsed_ms", 0),
                    result.toString()
            });
        } else {
            cursor.addRow(new Object[]{
                    "idle",
                    "",
                    "",
                    "",
                    0,
                    "{\"status\":\"idle\"}"
            });
        }
        return cursor;
    }
}
