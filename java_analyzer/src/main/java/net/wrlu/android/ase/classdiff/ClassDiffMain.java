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
            if (entry != null) {
                List<String> affected = affectedBinderMethods(a, b, enclosingPairs);
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
    // Fingerprints
    // ------------------------------------------------------------------ //

    private static final Pattern EXT_SYNTH_TYPE =
            Pattern.compile("L[^;]+\\$\\$ExternalSynthetic[^;]*;");
    private static final Pattern LAMBDA_METHOD = Pattern.compile("lambda\\$[^$]*\\$\\d+");
    private static final Pattern ACCESS_METHOD = Pattern.compile("access\\$\\d+");
    private static final Pattern R8_SYM = Pattern.compile("\\$r8\\$[A-Za-z0-9_$]+");
    private static final Pattern NEST_METHOD = Pattern.compile("-?\\$\\$Nest\\$[A-Za-z0-9_$]+");
    private static final Pattern OBF_ROOT_TYPE =
            Pattern.compile("^([a-z]{1,4}[0-9]*|[a-zA-Z]{1,2}[0-9]*)$");
    private static final Pattern OBF_PKG_SEG = Pattern.compile("^[a-z]{1,2}[0-9]*$");
    private static final Pattern OBF_SIMPLE_LOWER = Pattern.compile("^[a-z]{1,3}[0-9]*$");
    private static final Pattern OBF_SIMPLE_MIXED = Pattern.compile("^[a-zA-Z]{1,2}[0-9]*$");
    private static final Pattern OBF_MEMBER_IN_OBF =
            Pattern.compile("^([a-z]{1,3}[0-9]*|[a-zA-Z]{1,2}[0-9]*)$");
    private static final Pattern OBF_MEMBER_IN_KEEP =
            Pattern.compile("^([a-z]|[a-z][A-Z]|[a-z]{2,3}[0-9]+)$");

    private static boolean isStdLibClass(String desc) {
        if (desc == null || !desc.startsWith("L") || !desc.endsWith(";")) {
            return false;
        }
        String inner = desc.substring(1, desc.length() - 1);
        return inner.startsWith("java/") || inner.startsWith("javax/")
                || inner.startsWith("kotlin/") || inner.startsWith("kotlinx/")
                || inner.startsWith("dalvik/") || inner.startsWith("org/json/")
                || inner.startsWith("org/w3c/") || inner.startsWith("org/xml/");
    }

    private static boolean isObfuscatedType(String desc) {
        if (desc == null || !desc.startsWith("L") || !desc.endsWith(";")
                || isStdLibClass(desc)) {
            return false;
        }
        String inner = desc.substring(1, desc.length() - 1);
        int dollar = inner.indexOf('$');
        String outer = dollar > 0 ? inner.substring(0, dollar) : inner;
        int slash = outer.lastIndexOf('/');
        if (slash < 0) {
            return OBF_ROOT_TYPE.matcher(outer).matches();
        }
        String simple = outer.substring(slash + 1);
        if (OBF_SIMPLE_LOWER.matcher(simple).matches()) {
            return true;
        }
        if (OBF_SIMPLE_MIXED.matcher(simple).matches()) {
            String[] pkgParts = outer.substring(0, slash).split("/");
            for (String seg : pkgParts) {
                if (OBF_PKG_SEG.matcher(seg).matches()) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String normalizeTypeDesc(String desc) {
        if (desc == null || desc.isEmpty()) {
            return "";
        }
        int dims = 0;
        while (dims < desc.length() && desc.charAt(dims) == '[') {
            dims++;
        }
        String base = dims > 0 ? desc.substring(dims) : desc;
        if (isObfuscatedType(base)) {
            return dims > 0 ? desc.substring(0, dims) + "L#OBF;" : "L#OBF;";
        }
        return desc;
    }

    private static String normalizeMemberName(String definingDesc, String name) {
        if (name == null || name.equals("<init>") || name.equals("<clinit>")
                || isStdLibClass(definingDesc)) {
            return name;
        }
        if (isObfuscatedType(definingDesc)) {
            if (OBF_MEMBER_IN_OBF.matcher(name).matches()) {
                return "#obf";
            }
        } else if (OBF_MEMBER_IN_KEEP.matcher(name).matches()) {
            return "#obf";
        }
        return name;
    }

    private static String normalizedMethodKey(String definingDesc, String rawMethodKey) {
        int lp = rawMethodKey.indexOf('(');
        int rp = rawMethodKey.lastIndexOf(')');
        if (lp <= 0 || rp < lp) {
            return rawMethodKey;
        }
        String name = normalizeMemberName(definingDesc, rawMethodKey.substring(0, lp));
        String paramsRaw = rawMethodKey.substring(lp + 1, rp);
        String ret = normalizeTypeDesc(rawMethodKey.substring(rp + 1));
        if (paramsRaw.isEmpty()) {
            return name + "()" + ret;
        }
        String[] parts = paramsRaw.split(",");
        StringBuilder sb = new StringBuilder(name).append('(');
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(normalizeTypeDesc(parts[i]));
        }
        return sb.append(')').append(ret).toString();
    }

    private static Map<String, String> computeMethodHashes(ClassDef classDef) {
        Map<String, String> hashes = new HashMap<>();
        for (Method method : classDef.getMethods()) {
            if (isSynthetic(method.getName())) {
                continue;
            }
            hashes.put(methodKey(method), methodBodyHash(method));
        }
        return hashes;
    }

    private static String classBodyHash(String definingDesc, Map<String, String> methodHashes) {
        List<String> entries = new ArrayList<>(methodHashes.size());
        for (Map.Entry<String, String> entry : methodHashes.entrySet()) {
            entries.add(normalizedMethodKey(definingDesc, entry.getKey())
                    + '=' + entry.getValue());
        }
        Collections.sort(entries);
        StringBuilder sb = new StringBuilder(Math.max(256, entries.size() * 96));
        for (String line : entries) {
            sb.append(line).append('\n');
        }
        return sha256(sb.toString());
    }

    private static String methodBodyHash(Method method) {
        MethodImplementation implementation = method.getImplementation();
        if (implementation == null) {
            return "abstract";
        }
        StringBuilder sb = new StringBuilder(512);
        List<Instruction> kept = new ArrayList<>();
        List<Integer> keptAddresses = new ArrayList<>();
        TreeMap<Integer, Integer> addressToIndex = new TreeMap<>();
        int address = 0;
        for (Instruction instruction : implementation.getInstructions()) {
            if (!isNoiseInstruction(instruction)) {
                addressToIndex.put(address, kept.size());
                kept.add(instruction);
                keptAddresses.add(address);
            }
            address += instruction.getCodeUnits();
        }
        int endAddress = address;
        for (int i = 0; i < kept.size(); i++) {
            sb.append(canonicalInstruction(kept.get(i), keptAddresses.get(i), addressToIndex))
                    .append(';');
        }
        sb.append('\n');
        for (TryBlock<? extends ExceptionHandler> tryBlock : implementation.getTryBlocks()) {
            int start = resolveIndex(addressToIndex, tryBlock.getStartCodeAddress(),
                    endAddress, kept.size());
            int end = resolveIndex(addressToIndex,
                    tryBlock.getStartCodeAddress() + tryBlock.getCodeUnitCount(),
                    endAddress, kept.size());
            for (ExceptionHandler handler : tryBlock.getExceptionHandlers()) {
                int target = resolveIndex(addressToIndex, handler.getHandlerCodeAddress(),
                        endAddress, kept.size());
                sb.append("try ").append(start).append('-').append(end)
                        .append(" -> ").append(nullSafe(handler.getExceptionType()))
                        .append('@').append(target).append(';');
            }
        }
        return sha256(sb.toString());
    }

    private static Map<String, Set<String>> computeCallEdges(ClassDef classDef) {
        String selfDesc = classDef.getType();
        if (selfDesc == null) {
            return Map.of();
        }
        Set<String> trackedDescriptors = new HashSet<>();
        trackedDescriptors.add(selfDesc);
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
                                                      List<Fingerprint[]> enclosingPairs) {
        Set<String> changedNodes = new HashSet<>();
        collectChangedNodes(implA, implB, changedNodes);
        for (Fingerprint[] pair : enclosingPairs) {
            collectChangedNodes(pair[0], pair[1], changedNodes);
        }
        if (changedNodes.isEmpty()) {
            return List.of();
        }
        Map<String, Set<String>> graph = new HashMap<>(implB.callEdges);
        for (Fingerprint[] pair : enclosingPairs) {
            graph.putAll(pair[1].callEdges);
        }
        List<String> affected = new ArrayList<>();
        for (String mKey : implB.methodHashes.keySet()) {
            if (mKey.startsWith("<init>(") || mKey.startsWith("<clinit>(")) {
                continue;
            }
            String start = implB.descriptor + "->" + mKey;
            if (reachesChanged(start, changedNodes, graph)) {
                affected.add(mKey);
            }
        }
        Collections.sort(affected);
        return affected;
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
        return method.getName() + "(" + String.join(",", method.getParameterTypes()) + ")"
                + method.getReturnType();
    }

    private static boolean isNoiseInstruction(Instruction instruction) {
        String op = instruction.getOpcode().name;
        return op.equals("nop")
                || op.equals("move") || op.equals("move/from16") || op.equals("move/16")
                || op.equals("move-wide") || op.equals("move-wide/from16") || op.equals("move-wide/16")
                || op.equals("move-object") || op.equals("move-object/from16") || op.equals("move-object/16");
    }

    private static int resolveIndex(TreeMap<Integer, Integer> addressToIndex, int target,
                                    int endAddress, int keptSize) {
        Map.Entry<Integer, Integer> entry = addressToIndex.ceilingEntry(target);
        if (entry != null) {
            return entry.getValue();
        }
        return target >= endAddress ? keptSize : -1;
    }

    private static String normalizeOpcode(String op) {
        if (op.endsWith("/range")) {
            return op.substring(0, op.length() - 6);
        }
        if (op.endsWith("/2addr")) {
            return op.substring(0, op.length() - 6);
        }
        if (op.endsWith("/lit8") || op.endsWith("/lit16")) {
            return op.substring(0, op.lastIndexOf('/'));
        }
        if (op.equals("const-string/jumbo")) {
            return "const-string";
        }
        if (op.startsWith("goto/")) {
            return "goto";
        }
        if (op.equals("const/4") || op.equals("const/16") || op.equals("const/high16")) {
            return "const";
        }
        if (op.startsWith("const-wide/")) {
            return "const-wide";
        }
        return op;
    }

    private static boolean isResourceId(int value) {
        int pkg = (value >>> 24) & 0xFF;
        int type = (value >>> 16) & 0xFF;
        return (pkg == 0x01 || pkg == 0x7f) && type >= 0x01 && type <= 0x2f;
    }

    private static String canonicalInstruction(Instruction instruction, int address,
                                               TreeMap<Integer, Integer> addressToIndex) {
        StringBuilder sb = new StringBuilder(normalizeOpcode(instruction.getOpcode().name));
        if (instruction instanceof ReferenceInstruction) {
            sb.append(' ').append(canonicalReference(
                    ((ReferenceInstruction) instruction).getReference()));
        }
        if (instruction instanceof NarrowLiteralInstruction) {
            int literal = ((NarrowLiteralInstruction) instruction).getNarrowLiteral();
            if (isResourceId(literal)) {
                sb.append(" #RES");
            } else {
                sb.append(" #").append(literal);
            }
        } else if (instruction instanceof WideLiteralInstruction) {
            sb.append(" #").append(((WideLiteralInstruction) instruction).getWideLiteral());
        }
        if (instruction instanceof OffsetInstruction) {
            int target = address + ((OffsetInstruction) instruction).getCodeOffset();
            Map.Entry<Integer, Integer> entry = addressToIndex.ceilingEntry(target);
            sb.append(" @").append(entry != null ? entry.getValue() : -1);
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
        if (reference instanceof StringReference) {
            return "S:" + ((StringReference) reference).getString();
        }
        String raw;
        if (reference instanceof TypeReference) {
            raw = "T:" + normalizeTypeDesc(((TypeReference) reference).getType());
        } else if (reference instanceof FieldReference) {
            FieldReference field = (FieldReference) reference;
            String defining = field.getDefiningClass();
            raw = "F:" + normalizeTypeDesc(defining) + "->"
                    + normalizeMemberName(defining, field.getName()) + ":"
                    + normalizeTypeDesc(field.getType());
        } else if (reference instanceof MethodReference) {
            MethodReference method = (MethodReference) reference;
            String defining = method.getDefiningClass();
            List<String> params = new ArrayList<>();
            for (CharSequence param : method.getParameterTypes()) {
                params.add(normalizeTypeDesc(param.toString()));
            }
            raw = "M:" + normalizeTypeDesc(defining) + "->"
                    + normalizeMemberName(defining, method.getName())
                    + "(" + String.join(",", params) + ")"
                    + normalizeTypeDesc(method.getReturnType());
        } else {
            raw = reference.getClass().getSimpleName() + ":" + reference;
        }
        String normalized = EXT_SYNTH_TYPE.matcher(raw).replaceAll("L\\$\\$ExternalSynthetic;");
        normalized = LAMBDA_METHOD.matcher(normalized).replaceAll("lambda\\$");
        normalized = ACCESS_METHOD.matcher(normalized).replaceAll("access\\$");
        normalized = R8_SYM.matcher(normalized).replaceAll("\\$r8\\$");
        normalized = NEST_METHOD.matcher(normalized).replaceAll("\\$\\$Nest\\$");
        return normalized;
    }

    private static String methodKey(Method method) {
        return method.getName() + "(" + String.join(",", method.getParameterTypes()) + ")"
                + method.getReturnType();
    }

    private static boolean isSynthetic(String name) {
        return name.startsWith("lambda$")
                || name.contains("$$ExternalSynthetic")
                || name.startsWith("access$")
                || name.startsWith("$r8$")
                || name.startsWith("-$$Nest$")
                || name.startsWith("$$Nest$");
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
        final List<String> referencedEnclosing;
        final Map<String, String> methodHashes;
        final Map<String, Set<String>> callEdges;

        Fingerprint(String bodyHash, String container, String descriptor,
                    List<String> referencedEnclosing,
                    Map<String, String> methodHashes,
                    Map<String, Set<String>> callEdges) {
            this.bodyHash = bodyHash;
            this.container = container;
            this.descriptor = descriptor;
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
