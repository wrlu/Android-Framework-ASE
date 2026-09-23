package net.wrlu.android.ase.aidl;

import net.wrlu.android.ase.jadx.JadxInstance;
import net.wrlu.android.ase.workspace.Workspace;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AidlSearcher {
    private static final Logger logger = LoggerFactory.getLogger(AidlSearcher.class);

    private static final Pattern PROBE_FIELD = Pattern.compile("(\\w+)=([^,]*)");

    public void search(Workspace ws, boolean ignoreRegistered) throws IOException {
        List<File> targetFiles = new ArrayList<>();

        // 1. Framework files in packages/android
        File frameworkDir = new File(ws.getPackagesDir(), "android");
        if (frameworkDir.isDirectory()) {
            File[] files = frameworkDir.listFiles();
            if (files != null) {
                for (File f : files) {
                    if (JadxInstance.isAndroidFile(f.getName()) && !Files.isSymbolicLink(f.toPath())) {
                        targetFiles.add(f);
                    }
                }
            }
        } else {
            logger.warn("packages/android not found.");
        }

        // 2. APEX javalib JARs (skip symlinks / Finder aliases / 替身 to prevent duplicate scanning)
        File apexDir = ws.getApexDir();
        if (apexDir.isDirectory()) {
            File[] apexEntries = apexDir.listFiles();
            if (apexEntries != null) {
                Arrays.sort(apexEntries, Comparator.comparing(File::getName));
                for (File entry : apexEntries) {
                    if (Files.isSymbolicLink(entry.toPath()) || !entry.isDirectory()) {
                        continue;
                    }
                    File javalibDir = new File(entry, "javalib");
                    if (javalibDir.isDirectory()) {
                        File[] jars = javalibDir.listFiles();
                        if (jars != null) {
                            for (File jar : jars) {
                                if (JadxInstance.isAndroidFile(jar.getName()) && !Files.isSymbolicLink(jar.toPath())) {
                                    targetFiles.add(jar);
                                }
                            }
                        }
                    }
                }
            }
        }

        if (targetFiles.isEmpty()) {
            logger.warn("No Android framework or APEX files found, skip AIDL search.");
            return;
        }

        logger.info("Total framework & APEX target files to scan: {}", targetFiles.size());

        File outputFile = ws.getOutputFile("service_aidl.txt");
        JadxInstance instance = new JadxInstance(targetFiles);
        instance.load();
        try {
            List<String> aidlClasses = instance.searchAidlClasses();
            if (aidlClasses == null || aidlClasses.isEmpty()) {
                logger.warn("No AIDL classes found.");
                return;
            }
            logger.info("AIDL classes count: {}", aidlClasses.size());

            // Registered filter: load service_list.txt unless ignored.
            // Accessibility results (accessible_services.txt) drive a separate output.
            ServiceList serviceList = loadServiceList(ws);
            Set<String> registered = serviceList.descriptors;
            Map<String, Boolean> accessible = null;
            if (!ignoreRegistered) {
                logger.info("Registered services: {}", registered.size());
                accessible = loadAccessibleServices(ws, serviceList.nameToDesc);
            } else if (!serviceList.nameToDesc.isEmpty()) {
                accessible = loadAccessibleServices(ws, serviceList.nameToDesc);
            }

            // Collect the registered AIDL classes to output
            List<String> outputClasses = new ArrayList<>();
            for (String aidlClass : aidlClasses) {
                if (ignoreRegistered || registered.contains(aidlClass)) {
                    outputClasses.add(aidlClass);
                }
            }

            // Main output: keeps [accessible=...] markers
            try (FileWriter fw = new FileWriter(outputFile)) {
                for (String aidlClass : outputClasses) {
                    String sTag = serviceTag(serviceList.descToNames, aidlClass);
                    writeAidl(fw, instance, aidlClass, sTag, accessibleTag(accessible, aidlClass));
                }
            }
            logger.info("Total: {} AIDL interfaces", outputClasses.size());

            // Accessible subset -> separate output (clean format); original file keeps markers.
            if (accessible != null) {
                File accessibleFile = ws.getOutputFile("accessible_service_aidl.txt");
                int accessibleCount = 0;
                int notAccessible = 0;
                int unknown = 0;
                try (FileWriter fw = new FileWriter(accessibleFile)) {
                    for (String aidlClass : outputClasses) {
                        Boolean value = accessible.get(aidlClass);
                        if (value == null) {
                            unknown++;
                            continue;
                        }
                        if (!value) {
                            notAccessible++;
                            continue;
                        }
                        accessibleCount++;
                        String sTag = serviceTag(serviceList.descToNames, aidlClass);
                        writeAidl(fw, instance, aidlClass, sTag, "");
                    }
                }
                logger.info("Accessible output: {}", accessibleFile.getAbsolutePath());
                logger.info("Accessibility verification: accessible={} not_accessible={} unknown={}",
                        accessibleCount, notAccessible, unknown);
            }
        } finally {
            instance.close();
        }
        logger.info("AIDL search done: {}", outputFile.getAbsolutePath());
    }

    private static String serviceTag(Map<String, List<String>> descToNames, String aidlClass) {
        if (descToNames == null) {
            return "";
        }
        List<String> names = descToNames.get(aidlClass);
        if (names == null || names.isEmpty()) {
            return "";
        }
        List<String> sortedNames = new ArrayList<>(new HashSet<>(names));
        Collections.sort(sortedNames);
        return " [service=" + String.join(", ", sortedNames) + "]";
    }

    private static String accessibleTag(Map<String, Boolean> accessible, String aidlClass) {
        if (accessible == null) {
            return "";
        }
        Boolean value = accessible.get(aidlClass);
        if (value == null) {
            return " [accessible=unknown]";
        }
        return " [accessible=" + (value ? 1 : 0) + "]";
    }

    private void writeAidl(FileWriter fw, JadxInstance instance, String aidlClass,
                           String serviceTag, String accessibleTag)
            throws IOException {
        String aidlImplClass = instance.getAidlImplClass(aidlClass);
        fw.write(aidlClass + " [" + aidlImplClass + "]" + serviceTag + accessibleTag + "\n");
        List<String> aidlMethods = instance.getAidlMethods(aidlClass);
        logger.info("AIDL classes {} methods count: {}",
                aidlClass, aidlMethods != null ? aidlMethods.size() : 0);
        if (aidlMethods != null) {
            for (String aidlMethod : aidlMethods) {
                fw.write(aidlMethod + "\n");
            }
        }
        fw.write("\n");
    }

    private static final class ServiceList {
        final Set<String> descriptors = new HashSet<>();
        final Map<String, String> nameToDesc = new HashMap<>();
        final Map<String, List<String>> descToNames = new HashMap<>();
    }

    private static ServiceList loadServiceList(Workspace ws) throws IOException {
        ServiceList serviceList = new ServiceList();
        File serviceFile = new File(ws.getRoot(), "service_list.txt");
        if (!serviceFile.exists()) {
            logger.warn("service_list.txt not found");
            return serviceList;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(serviceFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("Found") || !line.contains(":")) {
                    continue;
                }
                int colon = line.indexOf(':');
                String name = line.substring(0, colon).replaceFirst("^\\d+\\s+", "").trim();
                String descPart = line.substring(colon + 1).trim();
                if (descPart.startsWith("[") && descPart.endsWith("]")) {
                    String desc = descPart.substring(1, descPart.length() - 1).trim();
                    if (!desc.isEmpty()) {
                        serviceList.descriptors.add(desc);
                        serviceList.nameToDesc.put(name, desc);
                        serviceList.descToNames.computeIfAbsent(desc, k -> new ArrayList<>()).add(name);
                    } else if (!name.isEmpty()) {
                        serviceList.nameToDesc.putIfAbsent(name, "");
                    }
                }
            }
        }
        return serviceList;
    }

    /**
     * Parse ASE on-device accessibility results from accessible_services.txt (raw output of
     * {@code adb shell content query --uri content://net.wrlu.ase.probe/binder_service}).
     *
     * <p>Rows look like {@code Row: 2 service=activity, accessible=1}; the service name is
     * mapped to its descriptor via service_list.txt.
     *
     * @return descriptor -> accessible, or null when accessible_services.txt is absent
     */
    private static Map<String, Boolean> loadAccessibleServices(Workspace ws, Map<String, String> nameToDesc)
            throws IOException {
        File accessibleFile = new File(ws.getRoot(), "accessible_services.txt");
        if (!accessibleFile.exists()) {
            return null;
        }

        Map<String, Boolean> byDesc = new HashMap<>();
        try (BufferedReader br = new BufferedReader(new FileReader(accessibleFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (!line.contains("service=")) {
                    continue;
                }
                Map<String, String> fields = new HashMap<>();
                Matcher m = PROBE_FIELD.matcher(line);
                while (m.find()) {
                    fields.put(m.group(1), m.group(2).trim());
                }
                String name = fields.getOrDefault("service", "");
                String accessibleVal = fields.getOrDefault("accessible", "");
                String desc = nameToDesc.getOrDefault(name, "");
                if (!desc.isEmpty() && ("0".equals(accessibleVal) || "1".equals(accessibleVal))) {
                    byDesc.put(desc, "1".equals(accessibleVal));
                }
            }
        }
        logger.info("Accessible services: {}", byDesc.size());
        return byDesc;
    }
}
