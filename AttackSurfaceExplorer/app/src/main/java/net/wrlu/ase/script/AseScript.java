package net.wrlu.ase.script;

import android.content.Context;

/**
 * Standard interface for dynamic scripts executed by {@link ScriptExecutionService}.
 */
public interface AseScript {
    /**
     * Entry method executed in a worker thread within the :runner process.
     *
     * @param context the Service context
     * @param args optional arguments passed from host (JSON string or arbitrary text)
     * @return result string (e.g. JSON or summary) to return to host
     * @throws Throwable any unhandled error, which will be captured in the result report
     */
    String run(Context context, String args) throws Throwable;
}
