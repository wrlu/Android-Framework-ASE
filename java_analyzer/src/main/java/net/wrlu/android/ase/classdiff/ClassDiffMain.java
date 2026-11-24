package net.wrlu.android.ase.classdiff;

import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.ExceptionHandler;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.MultiDexContainer;
import com.android.tools.smali.dexlib2.iface.TryBlock;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.NarrowLiteralInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.SwitchElement;
import com.android.tools.smali.dexlib2.iface.instruction.SwitchPayload;
import com.android.tools.smali.dexlib2.iface.instruction.WideLiteralInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.formats.ArrayPayload;
import com.android.tools.smali.dexlib2.iface.reference.FieldReference;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.dexlib2.iface.reference.Reference;
import com.android.tools.smali.dexlib2.iface.reference.StringReference;
import com.android.tools.smali.dexlib2.iface.reference.TypeReference;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Class-level change detector for ASE dumps.
 *
 * <p>Reads a JSON request (baseline/candidate roots plus target classes) and writes a
 * JSON response. Containers are scanned one at a time; only requested classes are
 * fingerprinted, so memory stays bounded for large dumps.</p>
 *
 * Usage: java -cp analyzer.jar net.wrlu.android.ase.classdiff.ClassDiffMain request.json response.json
 */
public final class ClassDiffMain {
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: ClassDiffMain <request.json> <response.json>");
            System.exit(2);
        }
        Request request;
        try (Reader reader = Files.newBufferedReader(Paths.get(args[0]), StandardCharsets.UTF_8)) {
            request = GSON.fromJson(reader, Request.class);
        }

        Response response = new Response();
        try {
            Set<String> wanted = new HashSet<>();
            if (request.components != null) {
                for (ComponentTarget target : request.components) {
                    if (target.className != null && !target.className.isEmpty()) {
                        wanted.add(classKeyFromClassName(target.className));
                    }
                }
            }
            if (request.binderImpl != null) {
                for (BinderTarget target : request.binderImpl) {
                    wanted.add(classKeyFromClassName(target.className));
                }
            }

            SideIndex baseline = new SideIndex(Paths.get(request.baselineRoot), wanted, request.body);
            SideIndex candidate = new SideIndex(Paths.get(request.candidateRoot), wanted, request.body);

            response.components = new Section();
            response.binderImpl = new Section();

            if (request.components != null) {
                for (ComponentTarget target : request.components) {
                    compareComponent(target, baseline, candidate, response);
                }
            }
            if (request.binderImpl != null) {
                for (BinderTarget target : request.binderImpl) {
                    compareBinder(target, baseline, candidate, response);
                }
            }
            response.errors.addAll(baseline.errors);
            response.errors.addAll(candidate.errors);
        } catch (Exception e) {
            response.available = false;
            response.error = e.getClass().getSimpleName() + ": " + e.getMessage();
            e.printStackTrace(System.err);
        }

        try (Writer writer = Files.newBufferedWriter(Paths.get(args[1]), StandardCharsets.UTF_8)) {
            GSON.toJson(response, writer);
        }
    }

    private static void compareComponent(ComponentTarget target, SideIndex baseline,
                                         SideIndex candidate, Response response) {
        response.components.total++;
        if (target.className == null || target.className.isEmpty()) {
            addUnresolved(response.components, target, "empty class name");
            return;
        }
        boolean inBaseline = target.inBaseline;
        boolean inCandidate = target.inCandidate;
        // Added/removed components classify by their declaration: a class that
        // already existed on the other side still belongs to added/removed.
        Fingerprint a = inBaseline ? baseline.resolveComponent(target) : null;
        Fingerprint b = inCandidate ? candidate.resolveComponent(target) : null;

        if (inBaseline && inCandidate) {
            if (a == null || b == null) {
                addUnresolved(response.components, target,
                        a == null ? "not found in baseline" : "not found in candidate");
                return;
            }
            response.components.resolved++;
            ChangedEntry entry = compare(target.className, target.packageName, target.type, a, b);
            if (entry != null) {
                response.components.changed.add(entry);
            }
        } else if (inCandidate) {
            if (b == null) {
                addUnresolved(response.components, target, "not found in candidate");
                return;
            }
            response.components.resolved++;
            response.components.added.add(classEntry(
                    target.className, target.packageName, target.type, b.container));
        } else if (inBaseline) {
            if (a == null) {
                addUnresolved(response.components, target, "not found in baseline");
                return;
            }
            response.components.resolved++;
            response.components.removed.add(classEntry(
                    target.className, target.packageName, target.type, a.container));
        } else {
            addUnresolved(response.components, target, "not present on either side");
        }
        response.components.changedCount = response.components.changed.size();
        response.components.addedCount = response.components.added.size();
        response.components.removedCount = response.components.removed.size();
    }

    private static void compareBinder(BinderTarget target, SideIndex baseline,
                                      SideIndex candidate, Response response) {
        response.binderImpl.total++;
        String className = target.className;
        Fingerprint a = baseline.resolveBinder(className);
        Fingerprint b = candidate.resolveBinder(className);
        if (a != null && b != null) {
            response.binderImpl.resolved++;
            ChangedEntry entry = compare(className, null, null, a, b);
            if (entry != null) {
                response.binderImpl.changed.add(entry);
            }
        } else if (b != null) {
            response.binderImpl.resolved++;
            response.binderImpl.added.add(classEntry(className, null, null, b.container));
        } else if (a != null) {
            response.binderImpl.resolved++;
            response.binderImpl.removed.add(classEntry(className, null, null, a.container));
        } else {
            UnresolvedEntry item = new UnresolvedEntry();
            item.className = className;
            item.reason = "not found in baseline or candidate";
            response.binderImpl.unresolved.add(item);
        }
        response.binderImpl.changedCount = response.binderImpl.changed.size();
        response.binderImpl.addedCount = response.binderImpl.added.size();
        response.binderImpl.removedCount = response.binderImpl.removed.size();
    }

    private static ClassEntry classEntry(String className, String packageName, String type,
                                         String container) {
        ClassEntry entry = new ClassEntry();
        entry.className = className;
        entry.packageName = packageName;
        entry.type = type;
        entry.container = container;
        return entry;
    }

    private static void addUnresolved(Section section, ComponentTarget target, String reason) {
        UnresolvedEntry item = new UnresolvedEntry();
        item.className = target.className;
        item.packageName = target.packageName;
        item.type = target.type;
        item.reason = reason;
        section.unresolved.add(item);
    }

    private static ChangedEntry compare(String className, String packageName, String type,
                                        Fingerprint a, Fingerprint b) {
        boolean bodyChanged = a.bodyHash != null && b.bodyHash != null
                && !a.bodyHash.equals(b.bodyHash);
        if (!bodyChanged) {
            return null;
        }
        ChangedEntry entry = new ChangedEntry();
        entry.className = className;
        entry.packageName = packageName;
        entry.type = type;
        entry.bodyChanged = true;
        entry.baseline = a.container;
        entry.candidate = b.container;
        return entry;
    }

    // ------------------------------------------------------------------ //
    // Fingerprints
    // ------------------------------------------------------------------ //

    private static String bodyHash(ClassDef classDef) {
        StringBuilder sb = new StringBuilder(8192);
        List<Method> methods = new ArrayList<>();
        classDef.getMethods().forEach(methods::add);
        methods.sort(Comparator.comparing(ClassDiffMain::methodKey));
        for (Method method : methods) {
            if (isSynthetic(method.getName())) {
                continue;
            }
            MethodImplementation implementation = method.getImplementation();
            if (implementation == null) {
                sb.append("abstract ").append(methodKey(method)).append('\n');
                continue;
            }
            sb.append("method ").append(methodKey(method)).append('\n');
            List<Instruction> instructions = new ArrayList<>();
            implementation.getInstructions().forEach(instructions::add);
            Map<Integer, Integer> addressToIndex = new HashMap<>();
            int address = 0;
            for (int index = 0; index < instructions.size(); index++) {
                addressToIndex.put(address, index);
                address += instructions.get(index).getCodeUnits();
            }
            address = 0;
            for (Instruction instruction : instructions) {
                sb.append(canonicalInstruction(instruction, address, addressToIndex)).append(';');
                address += instruction.getCodeUnits();
            }
            sb.append('\n');
            for (TryBlock<? extends ExceptionHandler> tryBlock : implementation.getTryBlocks()) {
                int start = addressToIndex.getOrDefault(tryBlock.getStartCodeAddress(), -1);
                int end = addressToIndex.getOrDefault(
                        tryBlock.getStartCodeAddress() + tryBlock.getCodeUnitCount(), -1);
                for (ExceptionHandler handler : tryBlock.getExceptionHandlers()) {
                    int target = addressToIndex.getOrDefault(handler.getHandlerCodeAddress(), -1);
                    sb.append("try ").append(start).append('-').append(end)
                            .append(" -> ").append(nullSafe(handler.getExceptionType()))
                            .append('@').append(target).append(';');
                }
            }
            sb.append('\n');
        }
        return sha256(sb.toString());
    }

    private static String canonicalInstruction(Instruction instruction, int address,
                                               Map<Integer, Integer> addressToIndex) {
        StringBuilder sb = new StringBuilder(instruction.getOpcode().name);
        if (instruction instanceof ReferenceInstruction) {
            sb.append(' ').append(canonicalReference(
                    ((ReferenceInstruction) instruction).getReference()));
        }
        if (instruction instanceof NarrowLiteralInstruction) {
            sb.append(" #").append(((NarrowLiteralInstruction) instruction).getNarrowLiteral());
        } else if (instruction instanceof WideLiteralInstruction) {
            sb.append(" #").append(((WideLiteralInstruction) instruction).getWideLiteral());
        }
        if (instruction instanceof OffsetInstruction) {
            int target = address + ((OffsetInstruction) instruction).getCodeOffset();
            sb.append(" @").append(addressToIndex.getOrDefault(target, -1));
        }
        if (instruction instanceof SwitchPayload) {
            TreeSet<Integer> keys = new TreeSet<>();
            for (SwitchElement element : ((SwitchPayload) instruction).getSwitchElements()) {
                keys.add(element.getKey());
            }
            sb.append(" keys=").append(keys);
        }
        if (instruction instanceof ArrayPayload) {
            sb.append(" values=").append(((ArrayPayload) instruction).getArrayElements());
        }
        return sb.toString();
    }

    private static String canonicalReference(Reference reference) {
        if (reference instanceof TypeReference) {
            return "T:" + ((TypeReference) reference).getType();
        }
        if (reference instanceof FieldReference) {
            FieldReference field = (FieldReference) reference;
            return "F:" + field.getDefiningClass() + "->" + field.getName() + ":" + field.getType();
        }
        if (reference instanceof MethodReference) {
            MethodReference method = (MethodReference) reference;
            return "M:" + method.getDefiningClass() + "->" + method.getName()
                    + "(" + String.join(",", method.getParameterTypes()) + ")"
                    + method.getReturnType();
        }
        if (reference instanceof StringReference) {
            return "S:" + ((StringReference) reference).getString();
        }
        return reference.getClass().getSimpleName() + ":" + reference;
    }

    private static String methodKey(Method method) {
        return method.getName() + "(" + String.join(",", method.getParameterTypes()) + ")"
                + method.getReturnType();
    }

    private static boolean isSynthetic(String name) {
        return name.startsWith("lambda$")
                || name.contains("$$ExternalSynthetic")
                || name.startsWith("access$")
                || name.startsWith("$r8$");
    }

    private static String sha256(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String nullSafe(String value) {
        return value == null ? "" : value;
    }

    /**
     * all_comp.json renders inner classes with '.', while DEX uses '$' and '/'
     * separators. Both sides normalize to a dotted class name so
     * Settings.Foo and Settings$Foo resolve to the same key.
     */
    private static String classKeyFromClassName(String className) {
        return className.replace('$', '.');
    }

    private static String classKeyFromDescriptor(String descriptor) {
        String value = descriptor;
        if (value.startsWith("L") && value.endsWith(";")) {
            value = value.substring(1, value.length() - 1);
        }
        return value.replace('/', '.').replace('$', '.');
    }

    // ------------------------------------------------------------------ //
    // Class resolution
    // ------------------------------------------------------------------ //

    private static final class Fingerprint {
        final String bodyHash;
        final String container;

        Fingerprint(String bodyHash, String container) {
            this.bodyHash = bodyHash;
            this.container = container;
        }
    }

    private static final class SideIndex {
        final Path root;
        final Set<String> wanted;
        final boolean body;
        final Map<String, Fingerprint> fingerprints = new HashMap<>();
        final Set<Path> loaded = new HashSet<>();
        final List<String> errors = new ArrayList<>();
        boolean jarsIndexed;

        SideIndex(Path root, Set<String> wanted, boolean body) {
            this.root = root;
            this.wanted = wanted;
            this.body = body;
        }

        Fingerprint resolveComponent(ComponentTarget target) {
            String key = classKeyFromClassName(target.className);
            if (target.apkHint != null && !target.apkHint.isEmpty()) {
                indexContainer(root.resolve(target.apkHint));
                Fingerprint fingerprint = fingerprints.get(key);
                if (fingerprint != null) return fingerprint;
            }
            if (target.packageName != null && !target.packageName.isEmpty()) {
                Path packageDir = root.resolve("packages").resolve(target.packageName);
                for (Path apk : listFiles(packageDir, ".apk")) {
                    indexContainer(apk);
                    Fingerprint fingerprint = fingerprints.get(key);
                    if (fingerprint != null) return fingerprint;
                }
            }
            indexJars();
            Fingerprint fingerprint = fingerprints.get(key);
            if (fingerprint != null) return fingerprint;
            return resolveByClassPackage(target.className, key);
        }

        Fingerprint resolveBinder(String className) {
            String key = classKeyFromClassName(className);
            indexJars();
            Fingerprint fingerprint = fingerprints.get(key);
            if (fingerprint != null) return fingerprint;

            return resolveByClassPackage(className, key);
        }

        private Fingerprint resolveByClassPackage(String className, String key) {
            String[] parts = className.split("\\.");
            for (int count = parts.length - 1; count >= 2; count--) {
                String packageName = String.join(".", Arrays.copyOf(parts, count));
                Path packageDir = root.resolve("packages").resolve(packageName);
                for (Path apk : listFiles(packageDir, ".apk")) {
                    indexContainer(apk);
                    Fingerprint fingerprint = fingerprints.get(key);
                    if (fingerprint != null) return fingerprint;
                }
            }
            return null;
        }

        void indexJars() {
            if (jarsIndexed) return;
            jarsIndexed = true;
            List<Path> jars = new ArrayList<>();
            Path packages = root.resolve("packages");
            if (Files.isDirectory(packages)) {
                try (Stream<Path> stream = Files.walk(packages, 2)) {
                    stream.filter(path -> path.toString().endsWith(".jar")).forEach(jars::add);
                } catch (IOException e) {
                    errors.add("walk packages: " + e.getMessage());
                }
            }
            Path apex = root.resolve("apex");
            if (Files.isDirectory(apex)) {
                try (Stream<Path> stream = Files.walk(apex, 6)) {
                    stream.filter(path -> path.toString().endsWith(".jar"))
                            .filter(path -> path.getParent() != null
                                    && "javalib".equals(path.getParent().getFileName().toString()))
                            .forEach(jars::add);
                } catch (IOException e) {
                    errors.add("walk apex: " + e.getMessage());
                }
            }
            jars.sort(Comparator.comparing(Path::toString));
            for (Path jar : jars) {
                indexContainer(jar);
            }
        }

        void indexContainer(Path file) {
            if (file == null || !Files.isRegularFile(file)) return;
            Path absolute = file.toAbsolutePath().normalize();
            if (!loaded.add(absolute)) return;
            try {
                MultiDexContainer<? extends DexBackedDexFile> container =
                        DexFileFactory.loadDexContainer(absolute.toFile(), Opcodes.getDefault());
                String relative = relative(absolute);
                for (String entryName : container.getDexEntryNames()) {
                    MultiDexContainer.DexEntry<? extends DexBackedDexFile> entry =
                            container.getEntry(entryName);
                    if (entry == null) continue;
                    for (ClassDef classDef : entry.getDexFile().getClasses()) {
                        String type = classKeyFromDescriptor(classDef.getType());
                        if (!wanted.contains(type) || fingerprints.containsKey(type)) {
                            continue;
                        }
                        String bodyHash = body ? bodyHash(classDef) : "";
                        fingerprints.put(type, new Fingerprint(bodyHash,
                                relative + "!" + entryName));
                    }
                }
            } catch (Exception e) {
                errors.add(relative(absolute) + ": " + e.getClass().getSimpleName()
                        + ": " + e.getMessage());
            }
        }

        private String relative(Path path) {
            try {
                return root.relativize(path).toString();
            } catch (IllegalArgumentException e) {
                return path.toString();
            }
        }
    }

    private static List<Path> listFiles(Path dir, String suffix) {
        if (dir == null || !Files.isDirectory(dir)) return List.of();
        try (Stream<Path> stream = Files.list(dir)) {
            return stream.filter(path -> path.toString().endsWith(suffix))
                    .sorted(Comparator.comparing(Path::toString))
                    .collect(Collectors.toList());
        } catch (IOException e) {
            return List.of();
        }
    }

    // ------------------------------------------------------------------ //
    // JSON model
    // ------------------------------------------------------------------ //

    static final class Request {
        String baselineRoot;
        String candidateRoot;
        boolean body = true;
        List<ComponentTarget> components = new ArrayList<>();
        List<BinderTarget> binderImpl = new ArrayList<>();
    }

    static final class BinderTarget {
        String className;
        boolean inBaseline = true;
        boolean inCandidate = true;
    }

    static final class ComponentTarget {
        @SerializedName("package")
        String packageName;
        String type;
        String className;
        String apkHint;
        boolean inBaseline = true;
        boolean inCandidate = true;
    }

    static final class Response {
        boolean available = true;
        String error;
        List<String> errors = new ArrayList<>();
        Section components;
        @SerializedName("binder_impl")
        Section binderImpl;
    }

    static final class Section {
        int total;
        int resolved;
        @SerializedName("changed_count")
        int changedCount;
        @SerializedName("added_count")
        int addedCount;
        @SerializedName("removed_count")
        int removedCount;
        List<ChangedEntry> changed = new ArrayList<>();
        List<ClassEntry> added = new ArrayList<>();
        List<ClassEntry> removed = new ArrayList<>();
        List<UnresolvedEntry> unresolved = new ArrayList<>();
    }

    static final class ClassEntry {
        @SerializedName("class")
        String className;
        @SerializedName("package")
        String packageName;
        String type;
        String container;
    }

    static final class ChangedEntry {
        @SerializedName("class")
        String className;
        @SerializedName("package")
        String packageName;
        String type;
        @SerializedName("body_changed")
        boolean bodyChanged;
        String baseline;
        String candidate;
    }

    static final class UnresolvedEntry {
        @SerializedName("class")
        String className;
        @SerializedName("package")
        String packageName;
        String type;
        String reason;
    }
}
