#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR_PATH="$SCRIPT_DIR/build/libs/analyzer-1.0.0-all.jar"

if [ ! -f "$JAR_PATH" ]; then
    echo "Error: analyzer jar not found at $JAR_PATH" >&2
    echo "Please build first: cd $SCRIPT_DIR && ./gradlew shadowJar" >&2
    exit 1
fi

if [ $# -lt 1 ]; then
    echo "Usage: $0 <workspace_dir> [--components] [--aidl] [--ignore-registered]"
    echo "  <workspace_dir>       firmware dump directory (contains packages/ etc.)"
    echo "  --components          run component accessibility analysis only"
    echo "  --aidl                run AIDL interface search only"
    echo "  --ignore-registered   output all AIDL interfaces (default: only registered services)"
    echo "  (default: run both)"
    exit 1
fi

JAVA_OPTS="${JAVA_OPTS:--XX:MaxRAMPercentage=50.0}"
exec java $JAVA_OPTS -jar "$JAR_PATH" "$@"
