package net.wrlu.android.ase.aidl;

import jadx.api.JavaClass;
import jadx.core.dex.nodes.ClassNode;
import jadx.core.dex.nodes.MethodNode;

import java.util.*;

public class AidlClass {
    public String interfaceClassName;

    private transient final JavaClass interfaceClass;
    private transient JavaClass implClass;

    public static final String AIDL_DEFAULT = "Default";
    public static final String AIDL_STUB = "Stub";
    public static final String AIDL_STUB_PROXY = "Proxy";

    private AidlClass(JavaClass interfaceClass) {
        this.interfaceClass = interfaceClass;
        this.interfaceClassName = interfaceClass.getFullName();
    }

    /**
     * 通过接口类尝试实例化AidlClass
     * Default/Stub/StubProxy类必须都存在才是一个AIDL
     *
     * @param interfaceClass 接口类的实例。
     * @return 如果是AIDL，返回一个AidlClass，否则返回null。
     */
    public static AidlClass fromInterface(JavaClass interfaceClass) {
        ClassNode classNode = interfaceClass.getClassNode();
        List<ClassNode> innerNodes = classNode.getInnerClasses();
        if (innerNodes == null || innerNodes.isEmpty()) return null;

        boolean hasDefault = false;
        ClassNode stubNode = null;

        for (ClassNode inner : innerNodes) {
            String name = inner.getClassInfo().getShortName();
            if (AIDL_DEFAULT.equals(name)) {
                hasDefault = true;
            } else if (AIDL_STUB.equals(name)) {
                stubNode = inner;
            }
            if (hasDefault && stubNode != null) break;
        }
        if (!hasDefault || stubNode == null) return null;

        List<ClassNode> stubInners = stubNode.getInnerClasses();
        if (stubInners == null) return null;
        for (ClassNode inner : stubInners) {
            if (AIDL_STUB_PROXY.equals(inner.getClassInfo().getShortName())) {
                return new AidlClass(interfaceClass);
            }
        }
        return null;
    }

    public List<String> getAidlMethods() {
        List<MethodNode> methods = interfaceClass.getClassNode().getMethods();
        if (methods == null || methods.isEmpty()) return Collections.emptyList();

        List<String> result = new ArrayList<>(methods.size());
        for (MethodNode m : methods) {
            String name = m.getName();
            if ("<clinit>".equals(name) || "<init>".equals(name)) continue;
            result.add(m.toString());
        }
        return result;
    }

    public JavaClass findImpl(IClassSearch classSearcher, boolean force) {
        if (implClass != null && !force) {
            return implClass;
        }
        implClass = null;

        String stubRawName = interfaceClass.getClassNode().getClassInfo().getFullName()
                + "$" + AIDL_STUB;

        // BFS: find first class that inherits (directly or indirectly) from Stub
        Set<String> visited = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>();
        queue.add(stubRawName);

        while (!queue.isEmpty()) {
            String current = queue.poll();
            if (!visited.add(current)) continue;

            List<JavaClass> children = classSearcher.findBySuperClass(current);
            if (children != null) {
                for (JavaClass child : children) {
                    implClass = child;
                    return child;
                }
                for (JavaClass child : children) {
                    queue.add(child.getClassNode().getClassInfo().getFullName());
                }
            }
        }
        return null;
    }
}
