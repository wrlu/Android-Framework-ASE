package net.wrlu.android.ase.workspace;

import java.io.File;

public class Workspace {
    private final File rootDir;

    public Workspace(String rootPath) {
        this.rootDir = new File(rootPath);
        if (!rootDir.isDirectory()) {
            throw new IllegalArgumentException("Invalid workspace directory: " + rootPath);
        }
    }

    public File getRoot() {
        return rootDir;
    }

    public File getPackagesDir() {
        return new File(rootDir, "packages");
    }

    public File getApexDir() {
        return new File(rootDir, "apex");
    }

    public File getOutputFile(String name) {
        return new File(rootDir, name);
    }

    public File ensureSubDir(String name) {
        File dir = new File(rootDir, name);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }
}
