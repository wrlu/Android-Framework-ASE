package net.wrlu.android.ase;

import net.wrlu.android.ase.aidl.AidlSearcher;
import net.wrlu.android.ase.components.ComponentAnalyzer;
import net.wrlu.android.ase.workspace.Workspace;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AnalyzerMain {
    private static final Logger logger = LoggerFactory.getLogger(AnalyzerMain.class);

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java -jar analyzer-all.jar <workspace_dir> [--components] [--aidl]");
            System.err.println("  <workspace_dir>  firmware dump directory (contains packages/ etc.)");
            System.err.println("  --components     run component accessibility analysis only");
            System.err.println("  --aidl           run AIDL interface search only");
            System.err.println("  (default: run both)");
            System.exit(1);
        }

        String workspacePath = args[0];
        boolean runComponents = true;
        boolean runAidl = true;
        for (int i = 1; i < args.length; i++) {
            if ("--components".equals(args[i])) {
                runAidl = false;
            } else if ("--aidl".equals(args[i])) {
                runComponents = false;
            }
        }

        Workspace ws;
        try {
            ws = new Workspace(workspacePath);
        } catch (IllegalArgumentException e) {
            logger.error(e.getMessage());
            System.exit(1);
            return;
        }

        try {
            if (runComponents) {
                logger.info("=== Component Accessibility Analysis ===");
                new ComponentAnalyzer().run(ws);
            }
            if (runAidl) {
                logger.info("=== AIDL Interface Search ===");
                new AidlSearcher().search(ws);
            }
        } catch (Exception e) {
            logger.error("Analysis failed", e);
            System.exit(2);
        }
        logger.info("All analysis tasks done.");
    }
}
