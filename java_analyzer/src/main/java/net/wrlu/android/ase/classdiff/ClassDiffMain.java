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
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;
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
                    for (String enclosing : enclosingClasses(target.className)) {
                        wanted.add(classKeyFromClassName(enclosing));
                    }
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
            List<Fingerprint[]> enclosingPairs = new ArrayList<>();
            if (entry == null) {
                List<String> enclosingCandidates = !b.referencedEnclosing.isEmpty()
                        ? b.referencedEnclosing : a.referencedEnclosing;
                for (String enclosing : enclosingCandidates) {
                    Fingerprint ea = baseline.resolveEnclosing(enclosing, target, a.container);
                    Fingerprint eb = candidate.resolveEnclosing(enclosing, target, b.container);
                    if (ea != null && eb != null) {
                        enclosingPairs.add(new Fingerprint[]{ea, eb});
                        ChangedEntry enclosingEntry = compare(
                                target.className, target.packageName, target.type, ea, eb);
                        if (enclosingEntry != null) {
                            enclosingEntry.enclosing = enclosing;
                            entry = enclosingEntry;
                            break;
                        }
                    }
                }
            }
            if (entry != null) {
                entry.entrypointChanged = hasChangedComponentEntrypoint(
                        target.type, a, b, enclosingPairs);
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
            List<Fingerprint[]> enclosingPairs = new ArrayList<>();
            for (String enclosing : enclosingClasses(className)) {
                Fingerprint ea = baseline.resolveBinder(enclosing);
                Fingerprint eb = candidate.resolveBinder(enclosing);
                if (ea != null && eb != null) {
                    enclosingPairs.add(new Fingerprint[]{ea, eb});
                    if (entry == null) {
                        ChangedEntry enclosingEntry = compare(className, null, null, ea, eb);
                        if (enclosingEntry != null) {
                            enclosingEntry.enclosing = enclosing;
                            entry = enclosingEntry;
                        }
                    }
                }
            }
            List<Fingerprint[]> superPairs = new ArrayList<>();
            String curSuperA = a.superClass;
            String curSuperB = b.superClass;
            String curContainerA = a.container;
            String curContainerB = b.container;
            for (int depth = 0; depth < 2 && isTrackableBinderSuper(curSuperB); depth++) {
                String superNameB = rawClassNameFromDescriptor(curSuperB);
                String superNameA = isTrackableBinderSuper(curSuperA)
                        ? rawClassNameFromDescriptor(curSuperA) : superNameB;
                Fingerprint sa = baseline.resolveBinderSuper(superNameA, curContainerA);
                Fingerprint sb = candidate.resolveBinderSuper(superNameB, curContainerB);
                if (sa == null || sb == null) {
                    break;
                }
                superPairs.add(new Fingerprint[]{sa, sb});
                if (entry == null) {
                    ChangedEntry superEntry = compare(className, null, null, sa, sb);
                    if (superEntry != null) {
                        superEntry.superClass = superNameB;
                        entry = superEntry;
                    }
                }
                curSuperA = sa.superClass;
                curSuperB = sb.superClass;
                curContainerA = sa.container;
                curContainerB = sb.container;
            }
            if (entry != null) {
                List<String> affected = affectedBinderMethods(a, b, enclosingPairs, superPairs);
                if (!affected.isEmpty()) {
                    entry.changedMethods = affected;
                }
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
    // Fingerprints (delegated to DexFingerprint)
    // ------------------------------------------------------------------ //

    private static boolean isStdLibClass(String desc) {
        return DexFingerprint.isStdLibClass(desc);
    }

    private static String normalizedMethodKey(String definingDesc, String rawMethodKey) {
        return DexFingerprint.normalizedMethodKey(definingDesc, rawMethodKey, false);
    }

    private static Map<String, String> computeMethodHashes(ClassDef classDef) {
        return DexFingerprint.computeMethodHashes(classDef, false);
    }

    private static String classBodyHash(String definingDesc, Map<String, String> methodHashes) {
        return DexFingerprint.classBodyHash(definingDesc, methodHashes, false);
    }

    private static boolean isTrackableBinderSuper(String desc) {
        if (desc == null || !desc.startsWith("L") || !desc.endsWith(";")) {
            return false;
        }
        if (desc.equals("Ljava/lang/Object;") || desc.equals("Landroid/os/Binder;")
                || desc.endsWith("$Stub;") || isStdLibClass(desc)) {
            return false;
        }
        return true;
    }

    private static String rawClassNameFromDescriptor(String desc) {
        String value = desc;
        if (value.startsWith("L") && value.endsWith(";")) {
            value = value.substring(1, value.length() - 1);
        }
        return value.replace('/', '.');
    }

    private static Map<String, Set<String>> computeCallEdges(ClassDef classDef) {
        String selfDesc = classDef.getType();
        if (selfDesc == null) {
            return Map.of();
        }
        Set<String> trackedDescriptors = new HashSet<>();
        trackedDescriptors.add(selfDesc);
        if (isTrackableBinderSuper(classDef.getSuperclass())) {
            trackedDescriptors.add(classDef.getSuperclass());
        }
        if (selfDesc.startsWith("L") && selfDesc.endsWith(";") && selfDesc.indexOf('$') > 0) {
            String internal = selfDesc.substring(1, selfDesc.length() - 1);
            int idx = internal.lastIndexOf('$');
            while (idx > 0) {
                String prefix = internal.substring(0, idx);
                trackedDescriptors.add("L" + prefix + ";");
                idx = prefix.lastIndexOf('$');
            }
        }
        Map<String, Set<String>> edges = new HashMap<>();
        for (Method method : classDef.getMethods()) {
            MethodImplementation implementation = method.getImplementation();
            if (implementation == null) {
                continue;
            }
            String callerNode = selfDesc + "->" + methodKey(method);
            Set<String> callees = null;
            for (Instruction instruction : implementation.getInstructions()) {
                if (!(instruction instanceof ReferenceInstruction)) {
                    continue;
                }
                Reference ref = ((ReferenceInstruction) instruction).getReference();
                if (!(ref instanceof MethodReference)) {
                    continue;
                }
                MethodReference target = (MethodReference) ref;
                String defining = target.getDefiningClass();
                if (!trackedDescriptors.contains(defining)) {
                    continue;
                }
                if (callees == null) {
                    callees = new HashSet<>();
                }
                callees.add(defining + "->" + methodRefKey(target));
            }
            if (callees != null) {
                edges.put(callerNode, callees);
            }
        }
        return edges;
    }

    private static List<String> affectedBinderMethods(Fingerprint implA, Fingerprint implB,
                                                      List<Fingerprint[]> enclosingPairs,
                                                      List<Fingerprint[]> superPairs) {
        Set<String> changedNodes = new HashSet<>();
        collectChangedNodes(implA, implB, changedNodes);
        for (Fingerprint[] pair : enclosingPairs) {
            collectChangedNodes(pair[0], pair[1], changedNodes);
        }
        for (Fingerprint[] pair : superPairs) {
            collectChangedNodes(pair[0], pair[1], changedNodes);
        }
        if (changedNodes.isEmpty()) {
            return List.of();
        }
        Map<String, Set<String>> graph = new HashMap<>(implB.callEdges);
        for (Fingerprint[] pair : enclosingPairs) {
            graph.putAll(pair[1].callEdges);
        }
        for (Fingerprint[] pair : superPairs) {
            graph.putAll(pair[1].callEdges);
        }
        Set<String> affected = new HashSet<>();
        Set<String> definedInChild = new HashSet<>();
        for (String mKey : implB.methodHashes.keySet()) {
            definedInChild.add(mKey);
            if (mKey.startsWith("<init>(") || mKey.startsWith("<clinit>(")) {
                continue;
            }
            String start = implB.descriptor + "->" + mKey;
            if (reachesChanged(start, changedNodes, graph)) {
                affected.add(mKey);
            }
        }
        for (Fingerprint[] pair : superPairs) {
            Fingerprint sb = pair[1];
            for (String mKey : sb.methodHashes.keySet()) {
                if (definedInChild.contains(mKey)
                        || mKey.startsWith("<init>(") || mKey.startsWith("<clinit>(")) {
                    continue;
                }
                definedInChild.add(mKey);
                String start = sb.descriptor + "->" + mKey;
                if (reachesChanged(start, changedNodes, graph)) {
                    affected.add(mKey);
                }
            }
        }
        List<String> sorted = new ArrayList<>(affected);
        Collections.sort(sorted);
        return sorted;
    }

    private static void collectChangedNodes(Fingerprint a, Fingerprint b, Set<String> out) {
        if (a.descriptor == null || b.descriptor == null) {
            return;
        }
        Map<String, Integer> baselineBag = new HashMap<>();
        for (Map.Entry<String, String> e : a.methodHashes.entrySet()) {
            String sig = normalizedMethodKey(a.descriptor, e.getKey()) + '=' + e.getValue();
            baselineBag.merge(sig, 1, Integer::sum);
        }
        for (Map.Entry<String, String> e : b.methodHashes.entrySet()) {
            String key = e.getKey();
            String ha = a.methodHashes.get(key);
            if (ha != null && ha.equals(e.getValue())) {
                continue;
            }
            String sig = normalizedMethodKey(b.descriptor, key) + '=' + e.getValue();
            Integer remaining = baselineBag.get(sig);
            if (remaining != null && remaining > 0) {
                baselineBag.put(sig, remaining - 1);
                continue;
            }
            out.add(b.descriptor + "->" + key);
        }
        for (String key : a.methodHashes.keySet()) {
            if (!b.methodHashes.containsKey(key)) {
                String sig = normalizedMethodKey(a.descriptor, key) + '=' + a.methodHashes.get(key);
                Integer remaining = baselineBag.get(sig);
                if (remaining != null && remaining > 0) {
                    out.add(b.descriptor + "->" + key);
                }
            }
        }
    }

    private static boolean reachesChanged(String start, Set<String> changedNodes,
                                          Map<String, Set<String>> graph) {
        if (changedNodes.contains(start)) {
            return true;
        }
        Set<String> visited = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>();
        visited.add(start);
        queue.add(start);
        while (!queue.isEmpty()) {
            String current = queue.poll();
            Set<String> next = graph.get(current);
            if (next == null) {
                continue;
            }
            for (String callee : next) {
                if (changedNodes.contains(callee)) {
                    return true;
                }
                if (visited.add(callee)) {
                    queue.add(callee);
                }
            }
        }
        return false;
    }

    private static final Set<String> ACTIVITY_ENTRYPOINTS = Set.of(
            "onCreate", "onNewIntent", "onActivityResult", "onStart", "onResume");
    private static final Set<String> SERVICE_ENTRYPOINTS = Set.of(
            "onCreate", "onStartCommand", "onStart", "onBind", "onRebind",
            "onHandleIntent", "onHandleWork", "onStartJob", "onStopJob");
    private static final Set<String> RECEIVER_ENTRYPOINTS = Set.of("onReceive");
    private static final Set<String> PROVIDER_ENTRYPOINTS = Set.of(
            "onCreate", "query", "insert", "bulkInsert", "update", "delete", "call",
            "openFile", "openAssetFile", "openTypedAssetFile", "getType", "applyBatch");

    private static boolean isComponentEntrypoint(String componentType, String methodName) {
        if (componentType == null || methodName == null) {
            return false;
        }
        switch (componentType) {
            case "activity":
                return ACTIVITY_ENTRYPOINTS.contains(methodName);
            case "service":
                return SERVICE_ENTRYPOINTS.contains(methodName);
            case "receiver":
                return RECEIVER_ENTRYPOINTS.contains(methodName);
            case "provider":
                return PROVIDER_ENTRYPOINTS.contains(methodName);
            default:
                return false;
        }
    }

    private static boolean hasChangedComponentEntrypoint(String componentType,
                                                         Fingerprint compA, Fingerprint compB,
                                                         List<Fingerprint[]> enclosingPairs) {
        Set<String> changedNodes = new HashSet<>();
        collectChangedNodes(compA, compB, changedNodes);
        for (Fingerprint[] pair : enclosingPairs) {
            collectChangedNodes(pair[0], pair[1], changedNodes);
        }
        if (changedNodes.isEmpty()) {
            return false;
        }
        Map<String, Set<String>> graph = new HashMap<>(compB.callEdges);
        for (Fingerprint[] pair : enclosingPairs) {
            graph.putAll(pair[1].callEdges);
        }
        for (String mKey : compB.methodHashes.keySet()) {
            int paren = mKey.indexOf('(');
            if (paren <= 0) {
                continue;
            }
            String methodName = mKey.substring(0, paren);
            if (!isComponentEntrypoint(componentType, methodName)) {
                continue;
            }
            if (reachesChanged(compB.descriptor + "->" + mKey, changedNodes, graph)) {
                return true;
            }
        }
        return false;
    }

    private static String methodRefKey(MethodReference method) {
        return DexFingerprint.methodRefKey(method);
    }

    private static String methodKey(Method method) {
        return DexFingerprint.methodKey(method);
    }

    private static boolean isSynthetic(String name) {
        return DexFingerprint.isSynthetic(name);
    }

    private static List<String> referencedEnclosingClasses(ClassDef classDef) {
        String descriptor = classDef.getType();
        if (descriptor == null || !descriptor.startsWith("L") || !descriptor.endsWith(";")
                || descriptor.indexOf('$') < 0) {
            return List.of();
        }
        String internal = descriptor.substring(1, descriptor.length() - 1);
        List<String> candidateDescriptors = new ArrayList<>();
        int idx = internal.lastIndexOf('$');
        while (idx > 0) {
            String prefix = internal.substring(0, idx);
            candidateDescriptors.add("L" + prefix + ";");
            idx = prefix.lastIndexOf('$');
        }
        if (candidateDescriptors.isEmpty()) {
            return List.of();
        }
        Set<String> candidateSet = new HashSet<>(candidateDescriptors);
        Set<String> referenced = new HashSet<>();
        for (Method method : classDef.getMethods()) {
            if (isSynthetic(method.getName())) {
                continue;
            }
            MethodImplementation implementation = method.getImplementation();
            if (implementation == null) {
                continue;
            }
            for (Instruction instruction : implementation.getInstructions()) {
                if (!(instruction instanceof ReferenceInstruction)) {
                    continue;
                }
                Reference ref = ((ReferenceInstruction) instruction).getReference();
                String defining = null;
                if (ref instanceof MethodReference) {
                    defining = ((MethodReference) ref).getDefiningClass();
                } else if (ref instanceof FieldReference) {
                    defining = ((FieldReference) ref).getDefiningClass();
                }
                if (defining != null && candidateSet.contains(defining)) {
                    referenced.add(defining);
                }
            }
        }
        if (referenced.isEmpty()) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (String desc : candidateDescriptors) {
            if (referenced.contains(desc)) {
                String raw = desc.substring(1, desc.length() - 1).replace('/', '.');
                result.add(raw);
            }
        }
        return result;
    }

    private static List<String> enclosingClasses(String className) {
        List<String> result = new ArrayList<>();
        if (className == null) {
            return result;
        }
        int idx = className.lastIndexOf('$');
        while (idx > 0) {
            String prefix = className.substring(0, idx);
            result.add(prefix);
            idx = prefix.lastIndexOf('$');
        }
        return result;
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
        final String descriptor;
        final String superClass;
        final List<String> referencedEnclosing;
        final Map<String, String> methodHashes;
        final Map<String, Set<String>> callEdges;

        Fingerprint(String bodyHash, String container, String descriptor, String superClass,
                    List<String> referencedEnclosing,
                    Map<String, String> methodHashes,
                    Map<String, Set<String>> callEdges) {
            this.bodyHash = bodyHash;
            this.container = container;
            this.descriptor = descriptor;
            this.superClass = superClass;
            this.referencedEnclosing = referencedEnclosing;
            this.methodHashes = methodHashes;
            this.callEdges = callEdges;
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

        Fingerprint resolveEnclosing(String enclosingClassName, ComponentTarget target,
                                     String innerContainer) {
            String key = classKeyFromClassName(enclosingClassName);
            Fingerprint existing = fingerprints.get(key);
            if (existing != null) {
                return existing;
            }
            wanted.add(key);
            if (innerContainer != null) {
                int bang = innerContainer.indexOf('!');
                String containerRel = bang >= 0 ? innerContainer.substring(0, bang) : innerContainer;
                if (!containerRel.isEmpty()) {
                    indexContainerForKey(root.resolve(containerRel), key);
                    existing = fingerprints.get(key);
                    if (existing != null) return existing;
                }
            }
            if (target.packageName != null && !target.packageName.isEmpty()) {
                Path packageDir = root.resolve("packages").resolve(target.packageName);
                for (Path apk : listFiles(packageDir, ".apk")) {
                    indexContainerForKey(apk, key);
                    existing = fingerprints.get(key);
                    if (existing != null) return existing;
                }
            }
            return null;
        }

        Fingerprint resolveBinder(String className) {
            String key = classKeyFromClassName(className);
            indexJars();
            Fingerprint fingerprint = fingerprints.get(key);
            if (fingerprint != null) return fingerprint;

            return resolveByClassPackage(className, key);
        }

        Fingerprint resolveBinderSuper(String className, String childContainer) {
            String key = classKeyFromClassName(className);
            Fingerprint existing = fingerprints.get(key);
            if (existing != null) return existing;
            wanted.add(key);
            if (childContainer != null) {
                int bang = childContainer.indexOf('!');
                String containerRel = bang >= 0 ? childContainer.substring(0, bang) : childContainer;
                if (!containerRel.isEmpty()) {
                    indexContainerForKey(root.resolve(containerRel), key);
                    existing = fingerprints.get(key);
                    if (existing != null) return existing;
                }
            }
            for (Path loadedFile : new ArrayList<>(loaded)) {
                indexContainerForKey(loadedFile, key);
                existing = fingerprints.get(key);
                if (existing != null) return existing;
            }
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
                        Map<String, String> methodHashes = body ? computeMethodHashes(classDef) : Map.of();
                        String bodyHash = body ? classBodyHash(classDef.getType(), methodHashes) : "";
                        List<String> refEnclosing = referencedEnclosingClasses(classDef);
                        Map<String, Set<String>> callEdges = body ? computeCallEdges(classDef) : Map.of();
                        fingerprints.put(type, new Fingerprint(bodyHash,
                                relative + "!" + entryName, classDef.getType(),
                                classDef.getSuperclass(),
                                refEnclosing, methodHashes, callEdges));
                    }
                }
            } catch (Exception e) {
                errors.add(relative(absolute) + ": " + e.getClass().getSimpleName()
                        + ": " + e.getMessage());
            }
        }

        void indexContainerForKey(Path file, String targetKey) {
            if (file == null || !Files.isRegularFile(file) || fingerprints.containsKey(targetKey)) {
                return;
            }
            Path absolute = file.toAbsolutePath().normalize();
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
                        if (!targetKey.equals(type)) {
                            continue;
                        }
                        Map<String, String> methodHashes = body ? computeMethodHashes(classDef) : Map.of();
                        String bodyHash = body ? classBodyHash(classDef.getType(), methodHashes) : "";
                        List<String> refEnclosing = referencedEnclosingClasses(classDef);
                        Map<String, Set<String>> callEdges = body ? computeCallEdges(classDef) : Map.of();
                        fingerprints.put(type, new Fingerprint(bodyHash,
                                relative + "!" + entryName, classDef.getType(),
                                classDef.getSuperclass(),
                                refEnclosing, methodHashes, callEdges));
                        return;
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
        @SerializedName("entrypoint_changed")
        Boolean entrypointChanged;
        String enclosing;
        @SerializedName("super")
        String superClass;
        @SerializedName("changed_methods")
        List<String> changedMethods;
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
