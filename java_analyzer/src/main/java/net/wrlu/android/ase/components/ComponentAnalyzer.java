package net.wrlu.android.ase.components;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import net.wrlu.android.ase.jadx.JadxInstance;
import net.wrlu.android.ase.workspace.Workspace;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ComponentAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(ComponentAnalyzer.class);
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final String[] TYPES = {"activity", "service", "provider", "receiver"};

    public void run(Workspace ws) throws IOException {
        File packagesDir = ws.getPackagesDir();
        if (!packagesDir.isDirectory()) {
            logger.error("packages directory not found: {}", packagesDir);
            return;
        }

        File allCompFile = ws.getOutputFile("all_comp.json");
        List<PackageInfo> baseData;
        if (allCompFile.exists()) {
            logger.info("Reuse cached {}", allCompFile.getName());
            try (FileReader fr = new FileReader(allCompFile)) {
                Type type = new TypeToken<List<PackageInfo>>() {}.getType();
                baseData = GSON.fromJson(fr, type);
            }
            if (baseData == null) {
                logger.warn("Cached file invalid, re-scan: {}", allCompFile);
                baseData = scanDir(packagesDir);
            }
        } else {
            baseData = scanDir(packagesDir);
        }

        // Store APK paths relative to the workspace root
        for (PackageInfo info : baseData) {
            info.filename = toRelativePath(ws.getRoot(), info.filename);
        }
        try (FileWriter fw = new FileWriter(allCompFile)) {
            GSON.toJson(baseData, fw);
        }

        Map<String, Object> result = analyze(baseData);

        File accessibleFile = ws.getOutputFile("accessible_comp.json");
        try (FileWriter fw = new FileWriter(accessibleFile)) {
            GSON.toJson(result, fw);
        }
        logger.info("Component analysis done: {}", accessibleFile.getAbsolutePath());
    }

    /**
     * Convert an absolute APK path to one relative to the workspace root; leave
     * non-absolute paths unchanged.
     */
    private static String toRelativePath(File root, String path) {
        if (path == null || path.isEmpty()) {
            return path;
        }
        File file = new File(path);
        if (!file.isAbsolute()) {
            return path;
        }
        try {
            return root.toPath().toAbsolutePath().normalize()
                    .relativize(file.toPath().toAbsolutePath().normalize()).toString();
        } catch (IllegalArgumentException e) {
            return path;
        }
    }

    private List<PackageInfo> scanDir(File packagesDir) {
        List<PackageInfo> baseData = new ArrayList<>();
        File[] entries = packagesDir.listFiles();
        if (entries == null) return baseData;

        for (File packageEntry : entries) {
            if (packageEntry.getName().contains("auto_generated_rro_product")) {
                logger.info("Skip auto_generated_rro_product: {}", packageEntry.getName());
                continue;
            }
            if (packageEntry.isDirectory()) {
                File[] files = packageEntry.listFiles();
                if (files == null) continue;
                for (File file : files) {
                    if (file.getName().contains("auto_generated_rro_product")) continue;
                    if (file.getName().endsWith(".apk") && file.isFile()) {
                        PackageInfo info = processApk(file);
                        if (info != null) baseData.add(info);
                    }
                }
            } else if (packageEntry.isFile() && packageEntry.getName().endsWith(".apk")) {
                PackageInfo info = processApk(packageEntry);
                if (info != null) baseData.add(info);
            }
        }
        return baseData;
    }

    private PackageInfo processApk(File apkFile) {
        logger.info("Start analysis apk file: {}", apkFile.getAbsolutePath());
        JadxInstance instance = new JadxInstance(apkFile.getAbsolutePath());
        instance.load();
        String manifest;
        try {
            manifest = instance.getManifest();
        } finally {
            instance.close();
        }
        if (manifest == null) {
            logger.warn("Failed to get manifest for {}", apkFile);
            return null;
        }
        PackageInfo info = ManifestParser.parse(manifest);
        if (info == null) return null;
        info.filename = apkFile.getAbsolutePath();
        return info;
    }

    public Map<String, Object> analyze(List<PackageInfo> baseData) {
        List<Component> allComponents = new ArrayList<>();
        List<DefinedPermission> allDefined = new ArrayList<>();
        List<String> allUses = new ArrayList<>();
        List<String> allProtected = new ArrayList<>();
        for (PackageInfo info : baseData) {
            if (info.components != null) allComponents.addAll(info.components);
            if (info.definedPermissions != null) allDefined.addAll(info.definedPermissions);
            if (info.usesPermissions != null) allUses.addAll(info.usesPermissions);
            if (info.protectedBroadcasts != null) allProtected.addAll(info.protectedBroadcasts);
        }

        Map<String, List<Map<String, Object>>> issues = initBuckets();

        for (Component component : allComponents) {
            Map<String, String> status = new LinkedHashMap<>();
            status.put("permission", "blank");
            status.put("readPermission", "blank");
            status.put("writePermission", "blank");

            if ("provider".equals(component.type)) {
                String[] keywords = {"writePermission", "readPermission", "permission"};
                for (String key : keywords) {
                    String val = getField(component, key);
                    if (val != null && !val.isEmpty()) {
                        status.put(key, "undefined");
                        for (DefinedPermission dp : allDefined) {
                            if (dp.name != null && dp.name.equals(val)) {
                                if (isPermissionPrivileged(dp)) {
                                    status.put(key, "privileged");
                                } else {
                                    status.put(key, "unprivileged");
                                }
                                break;
                            }
                        }
                    } else {
                        status.put(key, "unprivileged");
                    }
                }

                boolean appended = false;
                if ("unprivileged".equals(status.get("permission"))) {
                    if ("undefined".equals(status.get("writePermission")) || "undefined".equals(status.get("readPermission"))) {
                        issues.get("provider").add(providerIssueMap(component, "undefined"));
                        appended = true;
                    } else if ("unprivileged".equals(status.get("writePermission")) || "unprivileged".equals(status.get("readPermission"))) {
                        issues.get("provider").add(providerIssueMap(component, "unprivileged"));
                        appended = true;
                    }
                } else if ("undefined".equals(status.get("permission"))) {
                    if ("unprivileged".equals(status.get("writePermission")) || "unprivileged".equals(status.get("readPermission"))) {
                        issues.get("provider").add(providerIssueMap(component, "undefined"));
                        appended = true;
                    } else if ("undefined".equals(status.get("writePermission")) || "undefined".equals(status.get("readPermission"))) {
                        issues.get("provider").add(providerIssueMap(component, "undefined"));
                        appended = true;
                    }
                }
                if (appended) continue;

                if (component.pathPermission != null) {
                    boolean found = false;
                    for (PathPermission pp : component.pathPermission) {
                        String[] permKeys = {"permission", "readPermission", "writePermission"};
                        for (String key : permKeys) {
                            String val = getPathPermField(pp, key);
                            if (val != null && !val.isEmpty()) {
                                boolean defined = false;
                                boolean privileged = false;
                                for (DefinedPermission dp : allDefined) {
                                    if (dp.name != null && dp.name.equals(val)) {
                                        defined = true;
                                        if (isPermissionPrivileged(dp)) {
                                            privileged = true;
                                        } else {
                                            issues.get("provider").add(providerIssueMap(component, "unprivileged"));
                                            privileged = false;
                                        }
                                        break;
                                    }
                                }
                                if (!defined) {
                                    issues.get("provider").add(providerIssueMap(component, "undefined"));
                                }
                                if (!defined || !privileged) {
                                    found = true;
                                    break;
                                }
                            }
                        }
                        if (found) break;
                    }
                }
            } else {
                String perm = component.permission;
                if (perm != null && !perm.isEmpty()) {
                    status.put("permission", "undefined");
                    for (DefinedPermission dp : allDefined) {
                        if (dp.name != null && dp.name.equals(perm)) {
                            if (isPermissionPrivileged(dp)) {
                                status.put("permission", "privileged");
                            } else {
                                status.put("permission", "unprivileged");
                            }
                            break;
                        }
                    }
                } else {
                    status.put("permission", "unprivileged");
                }

                if ("receiver".equals(component.type)) {
                    boolean hasUnprotectedAction = false;
                    if (component.actions != null) {
                        for (String action : component.actions) {
                            if (!allProtected.contains(action)) {
                                hasUnprotectedAction = true;
                                break;
                            }
                        }
                    }
                    if (!hasUnprotectedAction) continue;
                }

                if ("undefined".equals(status.get("permission"))) {
                    issues.get(component.type).add(simpleIssueMap(component, "undefined"));
                } else if ("unprivileged".equals(status.get("permission"))) {
                    issues.get(component.type).add(simpleIssueMap(component, "unprivileged"));
                }
            }
        }

        return new LinkedHashMap<>(issues);
    }

    private static boolean isPermissionPrivileged(DefinedPermission dp) {
        if (dp.protectionLevel == null || dp.protectionLevel.isEmpty()) return false;
        int level = parseProtectionLevel(dp.protectionLevel);
        // signature | system | privileged | internal | preinstalled
        return (level & (0x2 | 0x10 | 0x20 | 0x40 | 0x4000)) != 0;
    }

    private static int parseProtectionLevel(String level) {
        try {
            return Integer.parseInt(level, 10);
        } catch (NumberFormatException e1) {
            try {
                return Integer.parseInt(level, 16);
            } catch (NumberFormatException e2) {
                return mapProtectionLevelName(level);
            }
        }
    }

    private static int mapProtectionLevelName(String name) {
        if (name == null) return 0;
        int result = 0;
        for (String part : name.toLowerCase().split("\\|")) {
            switch (part.trim()) {
                case "normal":            result |= 0;      break;
                case "dangerous":         result |= 0x1;    break;
                case "signature":         result |= 0x2;    break;
                case "signatureorsystem": result |= 0x3;    break;
                case "system":            result |= 0x10;   break;
                case "privileged":
                case "priv":              result |= 0x20;   break;
                case "internal":          result |= 0x40;   break;
                case "preinstalled":      result |= 0x4000; break;
                case "development":       result |= 0x100;  break;
                case "appop":             result |= 0x40;   break;
                default:                  break;
            }
        }
        return result;
    }

    private static String getField(Component c, String key) {
        switch (key) {
            case "permission": return c.permission;
            case "readPermission": return c.readPermission;
            case "writePermission": return c.writePermission;
            default: return null;
        }
    }

    private static String getPathPermField(PathPermission pp, String key) {
        switch (key) {
            case "permission": return pp.permission;
            case "readPermission": return pp.readPermission;
            case "writePermission": return pp.writePermission;
            default: return null;
        }
    }

    private static Map<String, List<Map<String, Object>>> initBuckets() {
        Map<String, List<Map<String, Object>>> buckets = new LinkedHashMap<>();
        for (String type : TYPES) buckets.put(type, new ArrayList<>());
        return buckets;
    }

    private static Map<String, Object> providerIssueMap(Component c, String issueType) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", issueType);
        m.put("name", c.name);
        m.put("writePermission", c.writePermission);
        m.put("readPermission", c.readPermission);
        m.put("permission", c.permission);
        m.put("path_permission", c.pathPermission);
        return m;
    }

    private static Map<String, Object> simpleIssueMap(Component c, String issueType) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", issueType);
        m.put("name", c.name);
        m.put("permission", c.permission);
        if (c.intentFilters != null) {
            m.put("intentFilters", c.intentFilters);
        }
        return m;
    }
}
