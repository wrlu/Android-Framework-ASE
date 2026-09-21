package net.wrlu.ase.binder;

import android.annotation.SuppressLint;
import android.os.IBinder;

import org.lsposed.hiddenapibypass.HiddenApiBypass;

public class ServiceManager {
    private static final String SERVICE_MANAGER = "android.os.ServiceManager";

    @SuppressLint({"PrivateApi"})
    public static IBinder getService(String serviceName) {
        try {
            return (IBinder) HiddenApiBypass.invoke(Class.forName(SERVICE_MANAGER),
                    null, "getService", serviceName);
        } catch (ReflectiveOperationException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * List all binder service names registered in servicemanager.
     *
     * @return never null; empty array on failure
     */
    @SuppressLint({"PrivateApi", "DiscouragedPrivateApi"})
    public static String[] listServices() {
        try {
            String[] services = (String[]) HiddenApiBypass.invoke(Class.forName(SERVICE_MANAGER),
                    null, "listServices");
            return services != null ? services : new String[0];
        } catch (ReflectiveOperationException e) {
            e.printStackTrace();
        }
        return new String[0];
    }
}
