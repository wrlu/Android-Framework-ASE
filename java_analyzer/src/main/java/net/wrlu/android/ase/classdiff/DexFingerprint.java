package net.wrlu.android.ase.classdiff;

import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.ExceptionHandler;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Shared DEX bytecode normalization and fingerprinting utilities used by both
 * {@link ClassDiffMain} and {@code DexExportMain}.
 */
public final class DexFingerprint {
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

    private DexFingerprint() {}

    public static boolean isStdLibClass(String desc) {
        if (desc == null || !desc.startsWith("L") || !desc.endsWith(";")) {
            return false;
        }
        String inner = desc.substring(1, desc.length() - 1);
        return inner.startsWith("java/") || inner.startsWith("javax/")
                || inner.startsWith("kotlin/") || inner.startsWith("kotlinx/")
                || inner.startsWith("dalvik/") || inner.startsWith("org/json/")
                || inner.startsWith("org/w3c/") || inner.startsWith("org/xml/");
    }

    public static boolean isSdkOrStdLibClass(String desc) {
        if (isStdLibClass(desc)) {
            return true;
        }
        if (desc == null || !desc.startsWith("L") || !desc.endsWith(";")) {
            return false;
        }
        String inner = desc.substring(1, desc.length() - 1);
        return inner.startsWith("android/") || inner.startsWith("androidx/");
    }

    public static boolean isObfuscatedType(String desc) {
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

    public static String normalizeTypeDesc(String desc) {
        return normalizeTypeDesc(desc, false);
    }

    public static String normalizeTypeDesc(String desc, boolean fuzzy) {
        if (desc == null || desc.isEmpty()) {
            return "";
        }
        int dims = 0;
        while (dims < desc.length() && desc.charAt(dims) == '[') {
            dims++;
        }
        String base = dims > 0 ? desc.substring(dims) : desc;
        boolean mask = fuzzy
                ? (base.startsWith("L") && base.endsWith(";") && !isSdkOrStdLibClass(base))
                : isObfuscatedType(base);
        if (mask) {
            return dims > 0 ? desc.substring(0, dims) + "L#OBF;" : "L#OBF;";
        }
        return desc;
    }

    public static String normalizeMemberName(String definingDesc, String name) {
        return normalizeMemberName(definingDesc, name, false);
    }

    public static String normalizeMemberName(String definingDesc, String name, boolean fuzzy) {
        if (name == null || name.equals("<init>") || name.equals("<clinit>")) {
            return name;
        }
        if (fuzzy) {
            return isSdkOrStdLibClass(definingDesc) ? name : "#obf";
        }
        if (isStdLibClass(definingDesc)) {
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

    public static String normalizedMethodKey(String definingDesc, String rawMethodKey) {
        return normalizedMethodKey(definingDesc, rawMethodKey, false);
    }

    public static String normalizedMethodKey(String definingDesc, String rawMethodKey,
                                             boolean fuzzy) {
        int lp = rawMethodKey.indexOf('(');
        int rp = rawMethodKey.lastIndexOf(')');
        if (lp <= 0 || rp < lp) {
            return rawMethodKey;
        }
        String name = normalizeMemberName(definingDesc, rawMethodKey.substring(0, lp), fuzzy);
        String paramsRaw = rawMethodKey.substring(lp + 1, rp);
        String ret = normalizeTypeDesc(rawMethodKey.substring(rp + 1), fuzzy);
        if (paramsRaw.isEmpty()) {
            return name + "()" + ret;
        }
        String[] parts = paramsRaw.split(",");
        StringBuilder sb = new StringBuilder(name).append('(');
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(normalizeTypeDesc(parts[i], fuzzy));
        }
        return sb.append(')').append(ret).toString();
    }

    public static Map<String, String> computeMethodHashes(ClassDef classDef) {
        return computeMethodHashes(classDef, false);
    }

    public static Map<String, String> computeMethodHashes(ClassDef classDef, boolean fuzzy) {
        Map<String, String> hashes = new HashMap<>();
        for (Method method : classDef.getMethods()) {
            if (isSynthetic(method.getName())) {
                continue;
            }
            hashes.put(methodKey(method), methodBodyHash(method, fuzzy));
        }
        return hashes;
    }

    public static String classBodyHash(String definingDesc, Map<String, String> methodHashes) {
        return classBodyHash(definingDesc, methodHashes, false);
    }

    public static String classBodyHash(String definingDesc, Map<String, String> methodHashes,
                                       boolean fuzzy) {
        return sha256(classBodyCanonical(definingDesc, methodHashes, fuzzy));
    }

    public static byte[] classBodySha1(String definingDesc, Map<String, String> methodHashes,
                                       boolean fuzzy) {
        return sha1Bytes(classBodyCanonical(definingDesc, methodHashes, fuzzy));
    }

    private static String classBodyCanonical(String definingDesc, Map<String, String> methodHashes,
                                             boolean fuzzy) {
        List<String> entries = new ArrayList<>(methodHashes.size());
        for (Map.Entry<String, String> entry : methodHashes.entrySet()) {
            entries.add(normalizedMethodKey(definingDesc, entry.getKey(), fuzzy)
                    + '=' + entry.getValue());
        }
        Collections.sort(entries);
        StringBuilder sb = new StringBuilder(Math.max(256, entries.size() * 64));
        for (String line : entries) {
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    public static String methodBodyHash(Method method) {
        return methodBodyHash(method, false);
    }

    public static String methodBodyHash(Method method, boolean fuzzy) {
        String canonical = methodBodyCanonical(method, fuzzy);
        return canonical == null ? "abstract" : sha256(canonical);
    }

    public static byte[] methodBodySha1(Method method, boolean fuzzy) {
        String canonical = methodBodyCanonical(method, fuzzy);
        return sha1Bytes(canonical == null ? "abstract" : canonical);
    }

    private static String methodBodyCanonical(Method method, boolean fuzzy) {
        MethodImplementation implementation = method.getImplementation();
        if (implementation == null) {
            return null;
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
            sb.append(canonicalInstruction(kept.get(i), keptAddresses.get(i),
                    addressToIndex, fuzzy)).append(';');
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
                String excType = handler.getExceptionType();
                if (fuzzy && excType != null && !excType.isEmpty()) {
                    excType = normalizeTypeDesc(excType, true);
                }
                sb.append("try ").append(start).append('-').append(end)
                        .append(" -> ").append(nullSafe(excType))
                        .append('@').append(target).append(';');
            }
        }
        return sb.toString();
    }

    public static boolean isNoiseInstruction(Instruction instruction) {
        String op = instruction.getOpcode().name;
        return op.equals("nop")
                || op.equals("move") || op.equals("move/from16") || op.equals("move/16")
                || op.equals("move-wide") || op.equals("move-wide/from16") || op.equals("move-wide/16")
                || op.equals("move-object") || op.equals("move-object/from16") || op.equals("move-object/16");
    }

    public static int resolveIndex(TreeMap<Integer, Integer> addressToIndex, int target,
                                   int endAddress, int keptSize) {
        Map.Entry<Integer, Integer> entry = addressToIndex.ceilingEntry(target);
        if (entry != null) {
            return entry.getValue();
        }
        return target >= endAddress ? keptSize : -1;
    }

    public static String normalizeOpcode(String op) {
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

    public static boolean isResourceId(int value) {
        int pkg = (value >>> 24) & 0xFF;
        int type = (value >>> 16) & 0xFF;
        return (pkg == 0x01 || pkg == 0x7f) && type >= 0x01 && type <= 0x2f;
    }

    public static String canonicalInstruction(Instruction instruction, int address,
                                              TreeMap<Integer, Integer> addressToIndex,
                                              boolean fuzzy) {
        StringBuilder sb = new StringBuilder(normalizeOpcode(instruction.getOpcode().name));
        if (instruction instanceof ReferenceInstruction) {
            sb.append(' ').append(canonicalReference(
                    ((ReferenceInstruction) instruction).getReference(), fuzzy));
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

    public static String canonicalReference(Reference reference, boolean fuzzy) {
        if (reference instanceof StringReference) {
            return "S:" + ((StringReference) reference).getString();
        }
        String raw;
        if (reference instanceof TypeReference) {
            raw = "T:" + normalizeTypeDesc(((TypeReference) reference).getType(), fuzzy);
        } else if (reference instanceof FieldReference) {
            FieldReference field = (FieldReference) reference;
            String defining = field.getDefiningClass();
            raw = "F:" + normalizeTypeDesc(defining, fuzzy) + "->"
                    + normalizeMemberName(defining, field.getName(), fuzzy) + ":"
                    + normalizeTypeDesc(field.getType(), fuzzy);
        } else if (reference instanceof MethodReference) {
            MethodReference method = (MethodReference) reference;
            String defining = method.getDefiningClass();
            List<String> params = new ArrayList<>();
            for (CharSequence param : method.getParameterTypes()) {
                params.add(normalizeTypeDesc(param.toString(), fuzzy));
            }
            raw = "M:" + normalizeTypeDesc(defining, fuzzy) + "->"
                    + normalizeMemberName(defining, method.getName(), fuzzy)
                    + "(" + String.join(",", params) + ")"
                    + normalizeTypeDesc(method.getReturnType(), fuzzy);
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

    public static String methodKey(Method method) {
        return method.getName() + "(" + String.join(",", method.getParameterTypes()) + ")"
                + method.getReturnType();
    }

    public static String methodProto(Method method) {
        return "(" + String.join(",", method.getParameterTypes()) + ")" + method.getReturnType();
    }

    public static String methodRefKey(MethodReference method) {
        return method.getName() + "(" + String.join(",", method.getParameterTypes()) + ")"
                + method.getReturnType();
    }

    public static boolean isSynthetic(String name) {
        return name.startsWith("lambda$")
                || name.contains("$$ExternalSynthetic")
                || name.startsWith("access$")
                || name.startsWith("$r8$")
                || name.startsWith("-$$Nest$")
                || name.startsWith("$$Nest$");
    }

    public static String sha256(String text) {
        return toHex(digest("SHA-256", text));
    }

    public static byte[] sha1Bytes(String text) {
        return digest("SHA-1", text);
    }

    public static String toHex(byte[] hash) {
        StringBuilder sb = new StringBuilder(hash.length * 2);
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] digest(String algorithm, String text) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            return md.digest(text.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String nullSafe(String value) {
        return value == null ? "" : value;
    }
}
