package net.wrlu.ase.binder;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;

import org.lsposed.hiddenapibypass.HiddenApiBypass;

public class BinderInterface {
    public static IInterface asInterface(IBinder service) {
        try {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            service.transact(IBinder.INTERFACE_TRANSACTION, data, reply, 0);
            String interfaceToken = reply.readString();
            if (interfaceToken != null && !interfaceToken.isEmpty()) {
                return (IInterface) HiddenApiBypass
                        .invoke(Class.forName(interfaceToken + "$Stub"), null,
                                "asInterface", service);
            }
        } catch (ReflectiveOperationException | RemoteException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Get the binder extension of this binder interface.
     * This allows one to customize an interface without having to modify the original interface.
     *
     * @return null if don't have binder extension
     */
    public static IBinder getExtension(IBinder service) {
        try {
            return (IBinder) HiddenApiBypass.invoke(IBinder.class, service,
                    "getExtension");
        } catch (ReflectiveOperationException e) {
            e.printStackTrace();
        }
        return null;
    }
}
