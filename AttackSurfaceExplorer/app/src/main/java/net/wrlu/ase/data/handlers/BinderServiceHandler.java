package net.wrlu.ase.data.handlers;

import android.database.Cursor;
import android.database.MatrixCursor;

import net.wrlu.ase.data.DataHandler;
import net.wrlu.ase.probe.BinderProber;
import net.wrlu.ase.probe.BinderProber.ProbeResult;

import java.util.ArrayList;
import java.util.List;

/**
 * {@code binder_service} endpoint: checks whether binder services can be obtained
 * through this app's identity.
 *
 * <p>Returns two columns: {@code service} and {@code accessible} (1 = obtainable,
 * 0 = not). Only the {@link android.os.IBinder} handle is resolved; no AIDL method
 * is invoked.
 */
public class BinderServiceHandler implements DataHandler {

    public static final String PATH = "binder_service";

    private static final String[] COLUMNS = {
            "service", "accessible"
    };

    @Override
    public String path() {
        return PATH;
    }

    @Override
    public Cursor query(String serviceName) {
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
}
