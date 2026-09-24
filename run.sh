#!/usr/bin/env bash
#
# Android Framework Attack Surface Explorer (ASE)
# One-click collection and full analysis pipeline.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] <workspace_dir>

Run the end-to-end Android Framework Attack Surface Explorer pipeline:
  [Collector] -> [Java Analyzer] -> [Native Analyzer] -> [Post Analyzer]

Arguments:
  <workspace_dir>         Directory for dumped firmware and analysis results.

Workflow Modes:
  (default)               Full pipeline: collect from device and analyze.
  --analyze-only, --skip-collect
                          Skip collection phase, run all analyzers on existing dump.
  --collect-only          Run firmware collection only, skip analysis phases.
  --probe-only            Only refresh accessible_services.txt on device, then run analyzers.

Collector Options:
  -d, --device <serial>   Target adb device serial ID.
  -s, --system            Only dump system packages.
  -3, --third-party       Only dump third-party packages.
  --ase-apk <path>        Path to custom AttackSurfaceExplorer APK.

Analyzer Options:
  --components-only       Run component accessibility analysis only (skip AIDL, Native, Post).
  --aidl-only             Run AIDL analysis only (skip Components).
  --ignore-registered     Do not filter by service_list.txt; output all discovered AIDL services.
  --skip-components       Skip component accessibility analysis.
  --skip-java             Skip Java analysis (components and Java AIDL).
  --skip-native           Skip Native AIDL analysis.
  --skip-post             Skip Post reconciliation analysis.

General Options:
  -h, --help              Show this help message.

Examples:
  # One-click: collect from connected adb device and analyze
  ./$(basename "$0") /path/to/firmware_dump

  # Analyze an existing firmware dump (no adb required)
  ./$(basename "$0") /path/to/firmware_dump --analyze-only

  # Re-probe accessibility on device and re-run all analyzers
  ./$(basename "$0") /path/to/firmware_dump --probe-only
EOF
}

WORKSPACE=""
DEVICE_SERIAL=""
PKG_FILTER=""
ASE_APK=""
COLLECT_MODE="full"       # full, probe_only, skip
ANALYSIS_MODE="full"      # full, collect_only
IGNORE_REGISTERED=false
COMPONENTS_ONLY=false
AIDL_ONLY=false
SKIP_COMPONENTS=false
SKIP_JAVA=false
SKIP_NATIVE=false
SKIP_POST=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        --analyze-only|--skip-collect)
            COLLECT_MODE="skip"
            shift
            ;;
        --collect-only)
            ANALYSIS_MODE="collect_only"
            shift
            ;;
        --probe-only)
            COLLECT_MODE="probe_only"
            shift
            ;;
        -d|--device)
            DEVICE_SERIAL="$2"
            shift 2
            ;;
        -s|--system)
            PKG_FILTER="-s"
            shift
            ;;
        -3|--third-party)
            PKG_FILTER="-3"
            shift
            ;;
        --ase-apk)
            ASE_APK="$2"
            shift 2
            ;;
        --ignore-registered)
            IGNORE_REGISTERED=true
            shift
            ;;
        --components-only)
            COMPONENTS_ONLY=true
            SKIP_NATIVE=true
            SKIP_POST=true
            shift
            ;;
        --aidl-only)
            AIDL_ONLY=true
            shift
            ;;
        --skip-components)
            SKIP_COMPONENTS=true
            shift
            ;;
        --skip-java)
            SKIP_JAVA=true
            shift
            ;;
        --skip-native)
            SKIP_NATIVE=true
            shift
            ;;
        --skip-post)
            SKIP_POST=true
            shift
            ;;
        -o|--output)
            WORKSPACE="$2"
            shift 2
            ;;
        *)
            if [ -z "$WORKSPACE" ]; then
                WORKSPACE="$1"
                shift
            else
                echo -e "${RED}Error: Unexpected argument: $1${NC}" >&2
                show_help
                exit 1
            fi
            ;;
    esac
done

if [ -z "$WORKSPACE" ]; then
    echo -e "${RED}Error: <workspace_dir> is required.${NC}" >&2
    show_help
    exit 1
fi

mkdir -p "$WORKSPACE"
WORKSPACE="$(cd "$WORKSPACE" && pwd)"

check_adb_device() {
    if ! command -v adb >/dev/null 2>&1; then
        return 1
    fi
    local count
    if [ -n "$DEVICE_SERIAL" ]; then
        count=$(adb devices 2>/dev/null | grep -cw "$DEVICE_SERIAL" || true)
    else
        count=$(adb devices 2>/dev/null | awk 'NR>1 && $2=="device" {c++} END {print c+0}')
    fi
    [ "${count:-0}" -gt 0 ]
}

# ==============================================================================
# Phase 1: Collector
# ==============================================================================
if [ "$COLLECT_MODE" != "skip" ]; then
    echo -e "${GREEN}${BOLD}============================================================${NC}"
    echo -e "${GREEN}${BOLD}[ASE] Phase 1/4: Firmware Collection (collector)${NC}"
    echo -e "${GREEN}${BOLD}============================================================${NC}"

    HAS_DEVICE=false
    if check_adb_device; then
        HAS_DEVICE=true
    fi

    if [ "$HAS_DEVICE" = true ]; then
        COLLECT_ARGS=(-o "$WORKSPACE")
        [ -n "$DEVICE_SERIAL" ] && COLLECT_ARGS+=(-d "$DEVICE_SERIAL")
        [ -n "$PKG_FILTER" ] && COLLECT_ARGS+=("$PKG_FILTER")
        [ -n "$ASE_APK" ] && COLLECT_ARGS+=(--ase-apk "$ASE_APK")
        [ "$COLLECT_MODE" = "probe_only" ] && COLLECT_ARGS+=(--probe-only)

        echo -e "${BLUE}[*] Running collector on device...${NC}"
        "$PYTHON" "$SCRIPT_DIR/collector/collect.py" "${COLLECT_ARGS[@]}"
    else
        if [ "$COLLECT_MODE" = "probe_only" ]; then
            echo -e "${RED}Error: --probe-only specified, but no adb device detected.${NC}" >&2
            exit 1
        fi

        # Check if workspace already contains dumped firmware
        if [ -d "$WORKSPACE/packages" ] || [ -f "$WORKSPACE/service_list.txt" ]; then
            echo -e "${YELLOW}[!] Warning: No adb device detected, but existing firmware dump found in '$WORKSPACE'.${NC}"
            echo -e "${YELLOW}[!] Skipping collection and proceeding directly to analysis...${NC}"
        else
            echo -e "${RED}Error: No adb device detected and '$WORKSPACE' is not an existing firmware dump.${NC}" >&2
            echo -e "${RED}Please connect a device via adb or provide an existing dump directory.${NC}" >&2
            exit 1
        fi
    fi
fi

if [ "$ANALYSIS_MODE" = "collect_only" ]; then
    echo
    echo -e "${GREEN}${BOLD}============================================================${NC}"
    echo -e "${GREEN}${BOLD}[ASE] Collection Completed Successfully!${NC}"
    echo -e "${GREEN}${BOLD}============================================================${NC}"
    echo -e "${BOLD}Dump directory:${NC} $WORKSPACE"
    exit 0
fi

# ==============================================================================
# Phase 2: Java Analyzer
# ==============================================================================
if [ "$SKIP_JAVA" = false ]; then
    echo
    echo -e "${GREEN}${BOLD}============================================================${NC}"
    echo -e "${GREEN}${BOLD}[ASE] Phase 2/4: Java Components & AIDL Analysis (java_analyzer)${NC}"
    echo -e "${GREEN}${BOLD}============================================================${NC}"

    JAR_PATH="$SCRIPT_DIR/java_analyzer/build/libs/analyzer-1.0.0-all.jar"
    if [ ! -f "$JAR_PATH" ]; then
        echo -e "${BLUE}[*] Building java_analyzer jar (analyzer-1.0.0-all.jar)...${NC}"
        (cd "$SCRIPT_DIR/java_analyzer" && ./gradlew shadowJar)
    fi

    JAVA_ARGS=("$WORKSPACE")
    if [ "$COMPONENTS_ONLY" = true ]; then
        JAVA_ARGS+=(--components)
    elif [ "$AIDL_ONLY" = true ] || [ "$SKIP_COMPONENTS" = true ]; then
        JAVA_ARGS+=(--aidl)
    fi

    if [ "$IGNORE_REGISTERED" = true ]; then
        JAVA_ARGS+=(--ignore-registered)
    fi

    "$SCRIPT_DIR/java_analyzer/analyzer.sh" "${JAVA_ARGS[@]}"
fi

# ==============================================================================
# Phase 3: Native Analyzer
# ==============================================================================
if [ "$SKIP_NATIVE" = false ] && [ "$COMPONENTS_ONLY" = false ]; then
    echo
    echo -e "${GREEN}${BOLD}============================================================${NC}"
    echo -e "${GREEN}${BOLD}[ASE] Phase 3/4: Native AIDL Analysis (native_analyzer)${NC}"
    echo -e "${GREEN}${BOLD}============================================================${NC}"

    NATIVE_ARGS=("$WORKSPACE")
    if [ "$IGNORE_REGISTERED" = true ]; then
        NATIVE_ARGS+=(--ignore-registered)
    fi

    "$PYTHON" "$SCRIPT_DIR/native_analyzer/native_analyzer.py" "${NATIVE_ARGS[@]}"
fi

# ==============================================================================
# Phase 4: Post Analyzer
# ==============================================================================
if [ "$SKIP_POST" = false ] && [ "$COMPONENTS_ONLY" = false ]; then
    echo
    echo -e "${GREEN}${BOLD}============================================================${NC}"
    echo -e "${GREEN}${BOLD}[ASE] Phase 4/4: Reconciliation & Gap Analysis (post_analyzer)${NC}"
    echo -e "${GREEN}${BOLD}============================================================${NC}"

    "$PYTHON" "$SCRIPT_DIR/post_analyzer/post_analyzer.py" "$WORKSPACE"
fi

# ==============================================================================
# Summary
# ==============================================================================
echo
echo -e "${GREEN}${BOLD}============================================================${NC}"
echo -e "${GREEN}${BOLD}[ASE] Pipeline Execution Completed!${NC}"
echo -e "${GREEN}${BOLD}============================================================${NC}"
echo -e "${BOLD}Workspace directory:${NC} $WORKSPACE"
echo -e "${BOLD}Output artifacts:${NC}"
[ -f "$WORKSPACE/all_comp.json" ] && echo -e "  - Full Components:       $WORKSPACE/all_comp.json"
[ -f "$WORKSPACE/accessible_comp.json" ] && echo -e "  - Accessible Components: $WORKSPACE/accessible_comp.json"
[ -f "$WORKSPACE/service_aidl.txt" ] && echo -e "  - Registered Java AIDL:  $WORKSPACE/service_aidl.txt"
[ -f "$WORKSPACE/accessible_service_aidl.txt" ] && echo -e "  - Accessible Java AIDL:  $WORKSPACE/accessible_service_aidl.txt"
[ -f "$WORKSPACE/native_aidl.txt" ] && echo -e "  - Native AIDL:           $WORKSPACE/native_aidl.txt"
[ -f "$WORKSPACE/accessible_native_aidl.txt" ] && echo -e "  - Accessible Native AIDL:$WORKSPACE/accessible_native_aidl.txt"
[ -f "$WORKSPACE/unresolved_accessible_services.txt" ] && echo -e "  - Unresolved Blindspots: $WORKSPACE/unresolved_accessible_services.txt"
echo
