package net.wrlu.android.ase.jadx;

import net.wrlu.android.ase.aidl.AidlClass;
import net.wrlu.android.ase.aidl.ClassSearch;
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.ResourceFile;
import jadx.core.utils.android.AndroidManifestParser;
import jadx.core.xmlgen.ResContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.*;

public class JadxInstance {
    private static final Logger logger = LoggerFactory.getLogger(JadxInstance.class);
    private JadxDecompiler decompiler;
    private final String filePath;
    private final Map<String, AidlClass> aidlCacheMap = new HashMap<>();

    private List<JavaClass> allClasses;
    private ClassSearch classSearcher;

    public JadxInstance(String path) {
        this.filePath = path;
    }

    public void load() {
        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            logger.error("Invalid file path: {}", file.getAbsolutePath());
            return;
        }
        realLoad(Collections.singletonList(file));
    }

    public void loadDir() {
        File dir = new File(filePath);
        if (!dir.exists() || !dir.isDirectory()) {
            logger.error("Invalid directory path: {}", dir.getAbsolutePath());
            return;
        }

        File[] dirFiles = dir.listFiles();
        if (dirFiles == null) {
            logger.error("Permission denied or I/O error: {}", dir.getAbsolutePath());
            return;
        }

        List<File> dexFiles = new ArrayList<>();
        for (File f : dirFiles) {
            if (isAndroidFile(f.getPath())) {
                dexFiles.add(f);
            }
        }

        if (dexFiles.isEmpty()) {
            logger.warn("No valid Android files found in: {}", dir.getAbsolutePath());
            return;
        }
        realLoad(dexFiles);
    }

    private void realLoad(List<File> files) {
        if (files == null || files.isEmpty()) {
            return;
        }

        if (isLoaded()) {
            close();
        }

        JadxArgs jadxArgs = new JadxArgs();
        if (files.size() > 1) {
            jadxArgs.setInputFiles(files);
        } else {
            jadxArgs.setInputFile(files.getFirst());
        }

        // Disable dex checksum verify.
        Map<String, String> pluginOptions = new HashMap<>();
        pluginOptions.put("dex-input.verify-checksum", "false");
        jadxArgs.setPluginOptions(pluginOptions);

        decompiler = new JadxDecompiler(jadxArgs);
        try {
            decompiler.load();
            logger.info("Successfully loaded {} file(s).", files.size());
        } catch (Exception e) {
            logger.error("Failed to load files via JADX", e);
            decompiler = null;
        }
    }

    public String getManifest() {
        if (!isLoaded()) return null;

        List<ResourceFile> resources = decompiler.getResources();
        ResourceFile manifest = AndroidManifestParser.getAndroidManifest(resources);

        if (manifest == null) {
            logger.error("AndroidManifest.xml not found.");
            return null;
        }

        ResContainer container = manifest.loadContent();
        return container.getText().getCodeStr();
    }

    private List<JavaClass> getAllClasses() {
        if (allClasses == null && isLoaded()) {
            allClasses = decompiler.getClassesWithInners();
        }
        return allClasses;
    }

    private ClassSearch getClassSearcher() {
        if (classSearcher == null) {
            List<JavaClass> classes = getAllClasses();
            if (classes != null) {
                classSearcher = new ClassSearch(classes);
                logger.info("ClassSearch index built: {} classes", classes.size());
            }
        }
        return classSearcher;
    }

    public List<String> searchAidlClasses() {
        if (!isLoaded()) return Collections.emptyList();

        List<JavaClass> classes = getAllClasses();
        if (classes == null) return Collections.emptyList();

        int count = 0;
        for (JavaClass cls : classes) {
            if (cls.isInner()) continue;
            AidlClass aidlClass = AidlClass.fromInterface(cls);
            if (aidlClass != null) {
                aidlCacheMap.put(aidlClass.interfaceClassName, aidlClass);
                count++;
            }
        }
        logger.info("AIDL interfaces found: {}", count);
        return new ArrayList<>(aidlCacheMap.keySet());
    }

    private AidlClass findAidlClass(String aidlClassName) {
        AidlClass cachedAidl = aidlCacheMap.get(aidlClassName);
        if (cachedAidl != null) {
            return cachedAidl;
        }

        AidlClass foundAidlClass = Optional.ofNullable(findJavaClass(aidlClassName))
                .flatMap(javaClass -> Optional.ofNullable(AidlClass.fromInterface(javaClass)))
                .orElse(null);

        if (foundAidlClass != null) {
            aidlCacheMap.put(aidlClassName, foundAidlClass);
        }

        return foundAidlClass;
    }

    public List<String> getAidlMethods(String aidlClassName) {
        if (!isLoaded()) return null;

        AidlClass aidlClass = findAidlClass(aidlClassName);

        return aidlClass != null ? aidlClass.getAidlMethods() : null;
    }

    public String getAidlImplClass(String aidlClassName) {
        if (!isLoaded()) return null;

        ClassSearch searcher = getClassSearcher();
        if (searcher == null) return null;

        AidlClass aidlClass = findAidlClass(aidlClassName);

        return Optional.ofNullable(aidlClass)
                .flatMap(ac -> Optional.ofNullable(ac.findImpl(searcher, false)))
                .map(JavaClass::getFullName)
                .orElse(null);
    }

    private JavaClass findJavaClass(String className) {
        List<JavaClass> classes = getAllClasses();
        if (classes == null) return null;
        for (JavaClass cls : classes) {
            if (cls.getFullName().equals(className)) {
                return cls;
            }
        }
        return null;
    }

    public boolean isLoaded() {
        return decompiler != null;
    }

    public void close() {
        if (decompiler != null) {
            decompiler.close();
            decompiler = null;
        }
        allClasses = null;
        classSearcher = null;
    }

    private static boolean isAndroidFile(String path) {
        return path.endsWith(".apk") ||
                path.endsWith(".dex") ||
                path.endsWith(".jar");
    }
}
