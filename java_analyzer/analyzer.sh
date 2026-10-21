#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR_PATH="$SCRIPT_DIR/build/libs/analyzer-1.0.0-all.jar"

# Allow standalone build command: ./analyzer.sh --build
if [ "${1:-}" = "--build" ] || [ "${1:-}" = "build" ]; then
    echo "[*] Building java_analyzer jar..."
    (cd "$SCRIPT_DIR" && ./gradlew shadowJar)
    exit 0
fi

if [ $# -lt 1 ]; then
    echo "Usage: $0 <workspace_dir> [--components] [--aidl] [--ignore-registered]"
    echo "  <workspace_dir>       firmware dump directory (contains packages/ etc.)"
    echo "  --components          run component accessibility analysis only"
    echo "  --aidl                run AIDL interface search only"
    echo "  --ignore-registered   output all AIDL interfaces (default: only registered services)"
    echo "  (default: run both)"
    echo ""
    echo "Helper:"
    echo "  $0 --build            build/rebuild analyzer jar only"
    exit 1
fi

# Auto-recompile if jar is missing, source files changed, or REBUILD=1
need_build=false
if [ ! -f "$JAR_PATH" ]; then
    echo "[*] Analyzer jar not found, building..."
    need_build=true
elif [ "${REBUILD:-0}" = "1" ]; then
    echo "[*] Force rebuild requested via REBUILD=1..."
    need_build=true
elif [ -n "$(find "$SCRIPT_DIR/src" "$SCRIPT_DIR/build.gradle.kts" "$SCRIPT_DIR/settings.gradle.kts" -type f ! -name ".*" -newer "$JAR_PATH" 2>/dev/null | head -n 1)" ]; then
    echo "[*] Source code changed since last build, re-building jar..."
    need_build=true
fi

if [ "$need_build" = true ]; then
    (cd "$SCRIPT_DIR" && ./gradlew shadowJar)
    if [ ! -f "$JAR_PATH" ]; then
        echo "Error: Build finished but $JAR_PATH was not found." >&2
        exit 1
    fi
    touch "$JAR_PATH"
fi

JAVA_OPTS="${JAVA_OPTS:--XX:MaxRAMPercentage=50.0}"
exec java $JAVA_OPTS -jar "$JAR_PATH" "$@"
