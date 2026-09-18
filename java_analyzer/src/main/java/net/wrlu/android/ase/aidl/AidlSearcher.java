package net.wrlu.android.ase.aidl;

import net.wrlu.android.ase.jadx.JadxInstance;
import net.wrlu.android.ase.workspace.Workspace;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

public class AidlSearcher {
    private static final Logger logger = LoggerFactory.getLogger(AidlSearcher.class);

    public void search(Workspace ws) throws IOException {
        File frameworkDir = new File(ws.getPackagesDir(), "android");
        if (!frameworkDir.isDirectory()) {
            logger.warn("packages/android not found, skip AIDL search.");
            return;
        }

        File outputFile = ws.getOutputFile("service_aidl.txt");
        JadxInstance instance = new JadxInstance(frameworkDir.getAbsolutePath());
        instance.loadDir();
        try {
            List<String> aidlClasses = instance.searchAidlClasses();
            if (aidlClasses == null || aidlClasses.isEmpty()) {
                logger.warn("No AIDL classes found.");
                return;
            }
            logger.info("AIDL classes count: {}", aidlClasses.size());

            try (FileWriter fw = new FileWriter(outputFile)) {
                for (String aidlClass : aidlClasses) {
                    String aidlImplClass = instance.getAidlImplClass(aidlClass);
                    fw.write(aidlClass + " [" + aidlImplClass + "]\n");
                    List<String> aidlMethods = instance.getAidlMethods(aidlClass);
                    logger.info("AIDL classes {} methods count: {}",
                            aidlClass, aidlMethods != null ? aidlMethods.size() : 0);
                    if (aidlMethods != null) {
                        for (String aidlMethod : aidlMethods) {
                            fw.write(aidlMethod + "\n");
                        }
                    }
                    fw.write("\n");
                }
            }
        } finally {
            instance.close();
        }
        logger.info("AIDL search done: {}", outputFile.getAbsolutePath());
    }
}
