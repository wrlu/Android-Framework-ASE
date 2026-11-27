package net.wrlu.android.ase.dexexport;

import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Field;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.MultiDexContainer;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.dexlib2.iface.reference.Reference;
import com.android.tools.smali.dexlib2.iface.reference.StringReference;
import net.wrlu.android.ase.classdiff.DexFingerprint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

/**
 * Exports all DEX containers in an ASE workspace into a self-contained SQLite
 * feature database ({@code <workspace>/dex_index.db}).
 *
 * <p>Containers are streamed one at a time so JVM heap usage stays bounded even
 * on full Android firmware dumps.</p>
 */
public final class DexExportMain {
    private static final Logger logger = LoggerFactory.getLogger(DexExportMain.class);
    private static final int SCHEMA_VERSION = 1;
    private static final int BATCH_LIMIT = 4000;
    private static final int MIN_INDEXED_STRING_LEN = 6;

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: DexExportMain <workspace_dir> [-o <output_db>]");
            System.exit(2);
        }
        Path workspace = Paths.get(args[0]).toAbsolutePath().normalize();
        Path output = workspace.resolve("dex_index.db");
        for (int i = 1; i < args.length; i++) {
            if (("-o".equals(args[i]) || "--output".equals(args[i])) && i + 1 < args.length) {
                output = Paths.get(args[++i]).toAbsolutePath().normalize();
            }
        }
        export(workspace, output);
    }

    public static void export(Path workspace, Path outputDb) throws Exception {
        if (!Files.isDirectory(workspace)) {
            throw new IllegalArgumentException("Workspace directory not found: " + workspace);
        }
        long startMs = System.currentTimeMillis();
        List<ContainerSpec> containers = discoverContainers(workspace);
        logger.info("DexExport: discovered {} DEX containers under {}", containers.size(), workspace);

        if (outputDb.getParent() != null) {
            Files.createDirectories(outputDb.getParent());
        }
        Path tmpDb = outputDb.resolveSibling(outputDb.getFileName().toString() + ".tmp");
        Files.deleteIfExists(tmpDb);

        long nextContainerId = 1;
        long nextClassId = 1;
        long nextMethodId = 1;
        long nextSymbolId = 1;
        long totalStrings = 0;
        long totalEdges = 0;
        long errorContainers = 0;
        Map<String, Long> symbolIds = new HashMap<>(65536);

        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + tmpDb.toAbsolutePath())) {
            try (Statement st = conn.createStatement()) {
                st.execute("PRAGMA synchronous = OFF");
                st.execute("PRAGMA journal_mode = OFF");
                st.execute("PRAGMA temp_store = MEMORY");
                st.execute("PRAGMA cache_size = -65536");
            }
            conn.setAutoCommit(false);
            createSchema(conn);
            conn.commit();

            String insertContainerSql =
                    "INSERT INTO containers(id, rel_path, package, kind, sha256, size, dex_count, class_count) "
                            + "VALUES(?,?,?,?,?,?,?,?)";
            String insertSymbolSql =
                    "INSERT INTO symbols(id, desc) VALUES(?,?)";
            String insertClassSql =
                    "INSERT INTO classes(id, container_id, dex_entry, desc, super_desc, interfaces, "
                            + "access_flags, is_obfuscated, method_count, field_count, exact_hash, fuzzy_hash, string_hash) "
                            + "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)";
            String insertMethodSql =
                    "INSERT INTO methods(id, class_id, name, proto, access_flags, insn_count, "
                            + "exact_body_hash) VALUES(?,?,?,?,?,?,?)";
            String insertStringSql =
                    "INSERT INTO class_strings(class_id, str_hash, str_len) VALUES(?,?,?)";
            String insertEdgeSql =
                    "INSERT INTO call_edges(caller_class_id, callee_sym_id) VALUES(?,?)";

            try (PreparedStatement psContainer = conn.prepareStatement(insertContainerSql);
                 PreparedStatement psSymbol = conn.prepareStatement(insertSymbolSql);
                 PreparedStatement psClass = conn.prepareStatement(insertClassSql);
                 PreparedStatement psMethod = conn.prepareStatement(insertMethodSql);
                 PreparedStatement psString = conn.prepareStatement(insertStringSql);
                 PreparedStatement psEdge = conn.prepareStatement(insertEdgeSql)) {

                int symbolBatch = 0;
                int classBatch = 0;
                int methodBatch = 0;
                int stringBatch = 0;
                int edgeBatch = 0;

                for (int idx = 0; idx < containers.size(); idx++) {
                    ContainerSpec spec = containers.get(idx);
                    long containerId = nextContainerId++;
                    long fileSize;
                    String fileSha256;
                    try {
                        fileSize = Files.size(spec.path);
                        fileSha256 = sha256File(spec.path);
                    } catch (IOException e) {
                        errorContainers++;
                        logger.warn("DexExport: failed to read {}: {}", spec.relPath, e.getMessage());
                        continue;
                    }

                    int dexCount = 0;
                    int containerClassCount = 0;
                    try {
                        MultiDexContainer<? extends DexBackedDexFile> container =
                                DexFileFactory.loadDexContainer(spec.path.toFile(), Opcodes.getDefault());
                        List<String> entryNames = new ArrayList<>(container.getDexEntryNames());
                        Collections.sort(entryNames);
                        for (String entryName : entryNames) {
                            MultiDexContainer.DexEntry<? extends DexBackedDexFile> entry =
                                    container.getEntry(entryName);
                            if (entry == null) {
                                continue;
                            }
                            dexCount++;
                            for (ClassDef classDef : entry.getDexFile().getClasses()) {
                                long classId = nextClassId++;
                                containerClassCount++;

                                String desc = classDef.getType();
                                String superDesc = classDef.getSuperclass();
                                List<String> ifaces = new ArrayList<>(classDef.getInterfaces());
                                Collections.sort(ifaces);
                                String ifaceStr = ifaces.isEmpty() ? "" : String.join(",", ifaces);

                                int fieldCount = 0;
                                for (Field ignored : classDef.getFields()) {
                                    fieldCount++;
                                }

                                Map<String, String> exactHashes = new HashMap<>();
                                Map<String, String> fuzzyHashes = new HashMap<>();
                                TreeSet<String> allStrings = new TreeSet<>();
                                Set<String> callees = new HashSet<>();
                                List<MethodRow> methodRows = new ArrayList<>();

                                for (Method method : classDef.getMethods()) {
                                    MethodImplementation impl = method.getImplementation();
                                    int insnCount = 0;
                                    if (impl != null) {
                                        for (Instruction insn : impl.getInstructions()) {
                                            insnCount++;
                                            if (insn instanceof ReferenceInstruction) {
                                                Reference ref = ((ReferenceInstruction) insn).getReference();
                                                if (ref instanceof StringReference) {
                                                    String s = ((StringReference) ref).getString();
                                                    if (s != null && !s.isEmpty()) {
                                                        allStrings.add(s);
                                                    }
                                                } else if (ref instanceof MethodReference) {
                                                    String callee = ((MethodReference) ref).getDefiningClass();
                                                    if (callee != null && !callee.equals(desc)
                                                            && !DexFingerprint.isStdLibClass(callee)) {
                                                        callees.add(callee);
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    if (DexFingerprint.isSynthetic(method.getName())) {
                                        continue;
                                    }
                                    String mKey = DexFingerprint.methodKey(method);
                                    byte[] exactBodySha1 = DexFingerprint.methodBodySha1(method, false);
                                    byte[] fuzzyBodySha1 = DexFingerprint.methodBodySha1(method, true);
                                    exactHashes.put(mKey, DexFingerprint.toHex(exactBodySha1));
                                    fuzzyHashes.put(mKey, DexFingerprint.toHex(fuzzyBodySha1));
                                    methodRows.add(new MethodRow(
                                            method.getName(),
                                            DexFingerprint.methodProto(method),
                                            method.getAccessFlags(),
                                            insnCount,
                                            exactBodySha1));
                                }

                                byte[] exactClassHash = DexFingerprint.classBodySha1(desc, exactHashes, false);
                                byte[] fuzzyClassHash = DexFingerprint.classBodySha1(desc, fuzzyHashes, true);
                                byte[] stringHash = allStrings.isEmpty()
                                        ? null
                                        : DexFingerprint.sha1Bytes(String.join("\0", allStrings));

                                psClass.setLong(1, classId);
                                psClass.setLong(2, containerId);
                                psClass.setString(3, entryName);
                                psClass.setString(4, desc);
                                psClass.setString(5, superDesc);
                                psClass.setString(6, ifaceStr);
                                psClass.setInt(7, classDef.getAccessFlags());
                                psClass.setInt(8, DexFingerprint.isObfuscatedType(desc) ? 1 : 0);
                                psClass.setInt(9, methodRows.size());
                                psClass.setInt(10, fieldCount);
                                psClass.setBytes(11, exactClassHash);
                                psClass.setBytes(12, fuzzyClassHash);
                                psClass.setBytes(13, stringHash);
                                psClass.addBatch();
                                if (++classBatch >= BATCH_LIMIT) {
                                    psClass.executeBatch();
                                    classBatch = 0;
                                }

                                for (MethodRow row : methodRows) {
                                    psMethod.setLong(1, nextMethodId++);
                                    psMethod.setLong(2, classId);
                                    psMethod.setString(3, row.name);
                                    psMethod.setString(4, row.proto);
                                    psMethod.setInt(5, row.accessFlags);
                                    psMethod.setInt(6, row.insnCount);
                                    psMethod.setBytes(7, row.exactBodyHash);
                                    psMethod.addBatch();
                                    if (++methodBatch >= BATCH_LIMIT) {
                                        psMethod.executeBatch();
                                        methodBatch = 0;
                                    }
                                }

                                for (String s : allStrings) {
                                    if (isDistinctiveString(s)) {
                                        psString.setLong(1, classId);
                                        psString.setBytes(2, DexFingerprint.sha1Bytes(s));
                                        psString.setInt(3, s.length());
                                        psString.addBatch();
                                        totalStrings++;
                                        if (++stringBatch >= BATCH_LIMIT) {
                                            psString.executeBatch();
                                            stringBatch = 0;
                                        }
                                    }
                                }

                                for (String callee : callees) {
                                    Long symId = symbolIds.get(callee);
                                    if (symId == null) {
                                        symId = nextSymbolId++;
                                        symbolIds.put(callee, symId);
                                        psSymbol.setLong(1, symId);
                                        psSymbol.setString(2, callee);
                                        psSymbol.addBatch();
                                        if (++symbolBatch >= BATCH_LIMIT) {
                                            psSymbol.executeBatch();
                                            symbolBatch = 0;
                                        }
                                    }
                                    psEdge.setLong(1, classId);
                                    psEdge.setLong(2, symId);
                                    psEdge.addBatch();
                                    totalEdges++;
                                    if (++edgeBatch >= BATCH_LIMIT) {
                                        psEdge.executeBatch();
                                        edgeBatch = 0;
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        errorContainers++;
                        logger.warn("DexExport: failed to parse {}: {}", spec.relPath, e.getMessage());
                    }

                    psContainer.setLong(1, containerId);
                    psContainer.setString(2, spec.relPath);
                    psContainer.setString(3, spec.packageName);
                    psContainer.setString(4, spec.kind);
                    psContainer.setString(5, fileSha256);
                    psContainer.setLong(6, fileSize);
                    psContainer.setInt(7, dexCount);
                    psContainer.setInt(8, containerClassCount);
                    psContainer.executeUpdate();

                    if (symbolBatch > 0) {
                        psSymbol.executeBatch();
                        symbolBatch = 0;
                    }
                    if (classBatch > 0) {
                        psClass.executeBatch();
                        classBatch = 0;
                    }
                    if (methodBatch > 0) {
                        psMethod.executeBatch();
                        methodBatch = 0;
                    }
                    if (stringBatch > 0) {
                        psString.executeBatch();
                        stringBatch = 0;
                    }
                    if (edgeBatch > 0) {
                        psEdge.executeBatch();
                        edgeBatch = 0;
                    }
                    conn.commit();

                    if ((idx + 1) % 50 == 0 || idx + 1 == containers.size()) {
                        logger.info("DexExport: [{}/{}] containers, {} classes, {} methods",
                                idx + 1, containers.size(), nextClassId - 1, nextMethodId - 1);
                    }
                }
            }

            long totalContainers = nextContainerId - 1;
            long totalClasses = nextClassId - 1;
            long totalMethods = nextMethodId - 1;

            writeMeta(conn, workspace, totalContainers, totalClasses, totalMethods,
                    totalStrings, totalEdges, symbolIds.size(), errorContainers);
            conn.commit();

            logger.info("DexExport: creating indexes...");
            createIndexes(conn);
            conn.commit();
        } catch (Exception e) {
            Files.deleteIfExists(tmpDb);
            throw e;
        }

        Files.move(tmpDb, outputDb, StandardCopyOption.REPLACE_EXISTING);
        long elapsedMs = System.currentTimeMillis() - startMs;
        long dbBytes = Files.size(outputDb);
        logger.info("DexExport done: {} ({} MB) in {} ms — containers={}, classes={}, methods={}, strings={}, edges={}, symbols={}, errors={}",
                outputDb, String.format("%.1f", dbBytes / (1024.0 * 1024.0)), elapsedMs,
                nextContainerId - 1, nextClassId - 1, nextMethodId - 1,
                totalStrings, totalEdges, symbolIds.size(), errorContainers);
    }

    private static void createSchema(Connection conn) throws Exception {
        try (Statement st = conn.createStatement()) {
            st.execute("CREATE TABLE meta ("
                    + "key TEXT PRIMARY KEY, "
                    + "value TEXT NOT NULL)");
            st.execute("CREATE TABLE containers ("
                    + "id INTEGER PRIMARY KEY, "
                    + "rel_path TEXT UNIQUE NOT NULL, "
                    + "package TEXT, "
                    + "kind TEXT NOT NULL, "
                    + "sha256 TEXT NOT NULL, "
                    + "size INTEGER NOT NULL, "
                    + "dex_count INTEGER NOT NULL, "
                    + "class_count INTEGER NOT NULL)");
            st.execute("CREATE TABLE symbols ("
                    + "id INTEGER PRIMARY KEY, "
                    + "desc TEXT UNIQUE NOT NULL)");
            st.execute("CREATE TABLE classes ("
                    + "id INTEGER PRIMARY KEY, "
                    + "container_id INTEGER NOT NULL, "
                    + "dex_entry TEXT NOT NULL, "
                    + "desc TEXT NOT NULL, "
                    + "super_desc TEXT, "
                    + "interfaces TEXT, "
                    + "access_flags INTEGER NOT NULL, "
                    + "is_obfuscated INTEGER NOT NULL, "
                    + "method_count INTEGER NOT NULL, "
                    + "field_count INTEGER NOT NULL, "
                    + "exact_hash BLOB NOT NULL, "
                    + "fuzzy_hash BLOB NOT NULL, "
                    + "string_hash BLOB)");
            st.execute("CREATE TABLE methods ("
                    + "id INTEGER PRIMARY KEY, "
                    + "class_id INTEGER NOT NULL, "
                    + "name TEXT NOT NULL, "
                    + "proto TEXT NOT NULL, "
                    + "access_flags INTEGER NOT NULL, "
                    + "insn_count INTEGER NOT NULL, "
                    + "exact_body_hash BLOB NOT NULL)");
            st.execute("CREATE TABLE class_strings ("
                    + "class_id INTEGER NOT NULL, "
                    + "str_hash BLOB NOT NULL, "
                    + "str_len INTEGER NOT NULL)");
            st.execute("CREATE TABLE call_edges ("
                    + "caller_class_id INTEGER NOT NULL, "
                    + "callee_sym_id INTEGER NOT NULL)");
        }
    }

    private static void createIndexes(Connection conn) throws Exception {
        try (Statement st = conn.createStatement()) {
            st.execute("CREATE INDEX idx_classes_desc ON classes(desc)");
            st.execute("CREATE INDEX idx_classes_exact ON classes(exact_hash)");
            st.execute("CREATE INDEX idx_classes_fuzzy ON classes(fuzzy_hash)");
            st.execute("CREATE INDEX idx_classes_container ON classes(container_id)");
            st.execute("CREATE INDEX idx_methods_class ON methods(class_id)");
            st.execute("CREATE INDEX idx_strings_hash ON class_strings(str_hash)");
            st.execute("CREATE INDEX idx_edges_caller ON call_edges(caller_class_id)");
            st.execute("CREATE INDEX idx_edges_callee ON call_edges(callee_sym_id)");
        }
    }

    private static void writeMeta(Connection conn, Path workspace, long containers,
                                  long classes, long methods, long strings,
                                  long edges, long symbols, long errors) throws Exception {
        Map<String, String> meta = new HashMap<>();
        meta.put("schema_version", String.valueOf(SCHEMA_VERSION));
        meta.put("hash_algorithm", "sha1_blob");
        meta.put("generated_at", OffsetDateTime.now().truncatedTo(ChronoUnit.SECONDS).toString());
        meta.put("workspace", workspace.toString());
        meta.put("container_count", String.valueOf(containers));
        meta.put("class_count", String.valueOf(classes));
        meta.put("method_count", String.valueOf(methods));
        meta.put("string_count", String.valueOf(strings));
        meta.put("edge_count", String.valueOf(edges));
        meta.put("symbol_count", String.valueOf(symbols));
        meta.put("error_containers", String.valueOf(errors));

        try (PreparedStatement ps = conn.prepareStatement("INSERT INTO meta(key, value) VALUES(?,?)")) {
            for (Map.Entry<String, String> e : meta.entrySet()) {
                ps.setString(1, e.getKey());
                ps.setString(2, e.getValue());
                ps.addBatch();
            }
            ps.executeBatch();
        }
    }

    private static List<ContainerSpec> discoverContainers(Path workspace) throws IOException {
        List<ContainerSpec> result = new ArrayList<>();
        Set<Path> seenRealPaths = new HashSet<>();

        Path packagesDir = workspace.resolve("packages");
        if (Files.isDirectory(packagesDir)) {
            try (Stream<Path> pkgStream = Files.list(packagesDir)) {
                List<Path> pkgDirs = pkgStream.sorted(Comparator.comparing(Path::toString)).toList();
                for (Path pkgDir : pkgDirs) {
                    if (Files.isSymbolicLink(pkgDir) || !Files.isDirectory(pkgDir)) {
                        continue;
                    }
                    String pkgName = pkgDir.getFileName().toString();
                    if (pkgName.startsWith(".") || pkgName.contains("auto_generated_rro_product")) {
                        continue;
                    }
                    try (Stream<Path> fileStream = Files.walk(pkgDir, 3)) {
                        fileStream.filter(p -> !Files.isSymbolicLink(p) && Files.isRegularFile(p))
                                .forEach(p -> {
                                    String fname = p.getFileName().toString();
                                    if (fname.startsWith(".") || fname.contains("auto_generated_rro_product")) {
                                        return;
                                    }
                                    String kind = null;
                                    if (fname.endsWith(".apk")) {
                                        kind = "apk";
                                    } else if (fname.endsWith(".jar")) {
                                        kind = "framework_jar";
                                    }
                                    if (kind == null) {
                                        return;
                                    }
                                    Path normalized = p.toAbsolutePath().normalize();
                                    if (seenRealPaths.add(normalized)) {
                                        result.add(new ContainerSpec(
                                                normalized,
                                                workspace.relativize(normalized).toString(),
                                                pkgName,
                                                kind));
                                    }
                                });
                    }
                }
            }
        }

        Path apexDir = workspace.resolve("apex");
        if (Files.isDirectory(apexDir) && !Files.isSymbolicLink(apexDir)) {
            try (Stream<Path> apexStream = Files.list(apexDir)) {
                List<Path> apexEntries = apexStream.sorted(Comparator.comparing(Path::toString)).toList();
                for (Path apexEntry : apexEntries) {
                    if (Files.isSymbolicLink(apexEntry) || !Files.isDirectory(apexEntry)) {
                        continue;
                    }
                    String apexName = apexEntry.getFileName().toString();
                    if (apexName.startsWith(".")) {
                        continue;
                    }
                    Path directJavalib = apexEntry.resolve("javalib");
                    Path scanRoot = Files.isDirectory(directJavalib) ? directJavalib : apexEntry;
                    try (Stream<Path> jarStream = Files.walk(scanRoot, 4)) {
                        jarStream.filter(p -> !Files.isSymbolicLink(p) && Files.isRegularFile(p))
                                .filter(p -> p.getFileName().toString().endsWith(".jar"))
                                .filter(p -> p.getParent() != null
                                        && "javalib".equals(p.getParent().getFileName().toString()))
                                .forEach(p -> {
                                    Path normalized = p.toAbsolutePath().normalize();
                                    if (seenRealPaths.add(normalized)) {
                                        result.add(new ContainerSpec(
                                                normalized,
                                                workspace.relativize(normalized).toString(),
                                                apexName,
                                                "apex_jar"));
                                    }
                                });
                    }
                }
            }
        }

        result.sort(Comparator.comparing(c -> c.relPath));
        return result;
    }

    private static boolean isDistinctiveString(String s) {
        if (s == null || s.length() < MIN_INDEXED_STRING_LEN) {
            return false;
        }
        boolean hasNonDigit = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!Character.isDigit(c) && !Character.isWhitespace(c)) {
                hasNonDigit = true;
                break;
            }
        }
        return hasNonDigit;
    }

    private static String sha256File(Path path) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[65536];
            try (InputStream in = Files.newInputStream(path)) {
                int read;
                while ((read = in.read(buf)) != -1) {
                    digest.update(buf, 0, read);
                }
            }
            byte[] hash = digest.digest();
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static final class ContainerSpec {
        final Path path;
        final String relPath;
        final String packageName;
        final String kind;

        ContainerSpec(Path path, String relPath, String packageName, String kind) {
            this.path = path;
            this.relPath = relPath;
            this.packageName = packageName;
            this.kind = kind;
        }
    }

    private static final class MethodRow {
        final String name;
        final String proto;
        final int accessFlags;
        final int insnCount;
        final byte[] exactBodyHash;

        MethodRow(String name, String proto, int accessFlags, int insnCount,
                  byte[] exactBodyHash) {
            this.name = name;
            this.proto = proto;
            this.accessFlags = accessFlags;
            this.insnCount = insnCount;
            this.exactBodyHash = exactBodyHash;
        }
    }
}
