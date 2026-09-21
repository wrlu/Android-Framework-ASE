package net.wrlu.ase.probe;

import android.os.IBinder;

import net.wrlu.ase.binder.ServiceManager;

import java.util.ArrayList;
import java.util.List;

/**
 * Probes whether a binder service can be <b>obtained</b> from this app's identity.
 *
 * <p>Only the {@link IBinder} handle is resolved; no AIDL method is invoked.
 */
public final class BinderProber {

    private BinderProber() {
    }

    public static final class ProbeResult {
        public String service;
        public boolean accessible;
    }

    /**
     * Probe a single service by name.
     *
     * @param serviceName service name
     */
    public static ProbeResult probe(String serviceName) {
        ProbeResult r = new ProbeResult();
        r.service = serviceName;
        if (serviceName != null && !serviceName.isEmpty()) {
            IBinder binder = ServiceManager.getService(serviceName);
            r.accessible = binder != null && binder.isBinderAlive();
        }
        return r;
    }

    /**
     * Enumerate every registered binder service and probe it.
     */
    public static List<ProbeResult> listServices() {
        List<ProbeResult> out = new ArrayList<>();
        for (String name : ServiceManager.listServices()) {
            ProbeResult r = new ProbeResult();
            r.service = name;
            IBinder binder = ServiceManager.getService(name);
            r.accessible = binder != null && binder.isBinderAlive();
            out.add(r);
        }
        return out;
    }
}
