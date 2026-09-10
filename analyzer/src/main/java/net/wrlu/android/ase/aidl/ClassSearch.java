package net.wrlu.android.ase.aidl;

import jadx.api.JavaClass;
import jadx.core.dex.instructions.args.ArgType;

import java.util.*;

public class ClassSearch implements IClassSearch {

    private final Map<String, JavaClass> byRawName = new HashMap<>();
    private final Map<String, List<JavaClass>> childrenBySuper = new HashMap<>();

    public ClassSearch(List<JavaClass> classes) {
        Objects.requireNonNull(classes, "Class list cannot be null.");
        for (JavaClass cls : classes) {
            String rawName = cls.getClassNode().getClassInfo().getFullName();
            byRawName.putIfAbsent(rawName, cls);

            ArgType superType = cls.getClassNode().getSuperClass();
            if (superType != null) {
                childrenBySuper.computeIfAbsent(superType.getObject(), k -> new ArrayList<>()).add(cls);
            }
        }
    }

    @Override
    public JavaClass findByRawName(String rawFullName) {
        return byRawName.get(rawFullName);
    }

    @Override
    public List<JavaClass> findBySuperClass(String superRawName) {
        return childrenBySuper.get(superRawName);
    }
}
