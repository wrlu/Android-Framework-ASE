package net.wrlu.android.ase.components;

import com.google.gson.annotations.SerializedName;
import java.util.List;

public class PackageInfo {
    @SerializedName("package")
    public String packageName;
    public String filename;
    public List<Component> components;
    @SerializedName("defined_permissions")
    public List<DefinedPermission> definedPermissions;
    @SerializedName("uses_permissions")
    public List<String> usesPermissions;
    @SerializedName("protected_broadcasts")
    public List<String> protectedBroadcasts;
}
