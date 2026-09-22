package net.wrlu.ase.payload;

import android.content.Context;
import android.os.IBinder;

import net.wrlu.ase.binder.ServiceManager;
import net.wrlu.ase.script.AseScript;

/**
 * Sample verification script demonstrating dynamic execution in ASE's :runner process.
 */
public class TestServiceProbe implements AseScript {

    @Override
    public String run(Context context, String args) throws Throwable {
        String serviceName = (args != null && !args.trim().isEmpty()) ? args.trim() : "activity";
        System.out.println("[TestServiceProbe] Probing service: " + serviceName);

        IBinder binder = ServiceManager.getService(serviceName);
        if (binder == null) {
            System.out.println("[TestServiceProbe] Service not found or denied: " + serviceName);
            return "NULL_BINDER";
        }

        boolean alive = binder.isBinderAlive();
        String descriptor = binder.getInterfaceDescriptor();
        System.out.println("[TestServiceProbe] Service obtained: alive=" + alive + ", descriptor=" + descriptor);
        return "SUCCESS: service=" + serviceName + ", descriptor=" + descriptor + ", alive=" + alive;
    }
}
