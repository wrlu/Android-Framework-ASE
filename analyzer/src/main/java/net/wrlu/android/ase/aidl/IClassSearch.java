package net.wrlu.android.ase.aidl;

import jadx.api.JavaClass;

import java.util.List;

public interface IClassSearch {
    JavaClass findByRawName(String rawFullName);
    List<JavaClass> findBySuperClass(String superRawName);
}
