package net.wrlu.android.ase.components;

import com.google.gson.annotations.SerializedName;
import java.util.List;

public class Component {
    public String name;
    public String type;
    public String permission;
    public String readPermission;
    public String writePermission;
    @SerializedName("path_permission")
    public List<PathPermission> pathPermission;
    public List<String> actions;
    public List<IntentFilter> intentFilters;
}
