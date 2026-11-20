#!/bin/bash
# CyberSecurity Suite - Quick Scan Script
# Fast assessment of targets

set -euo pipefail

# Source utilities
source "$(dirname "$0")/utils.sh"

PROJECT_DIR="$(dirname "$(dirname "$0")")"
cd "$PROJECT_DIR"

# Default values
TARGET_FILE="data/targets/targets.txt"
OUTPUT_DIR="reports"
SCAN_TYPE="quick"

# ---- argument parsing (unchanged) ----------------------------------------
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--targets)  TARGET_FILE="$2"; shift 2 ;;
        -o|--output)   OUTPUT_DIR="$2";  shift 2 ;;
        -f|--full)     SCAN_TYPE="full"; shift   ;;
        -h|--help)
            echo "Usage: $0 [-t targets_file] [-o output_dir] [-f]"
            exit 0
            ;;
        *) print_error "Unknown option: $1"; exit 1 ;;
    esac
done

show_banner
echo "Quick Scan Started"
echo "Target file: $TARGET_FILE"
echo "Scan type: $SCAN_TYPE"
echo ""

# ---- validate target file ------------------------------------------------
if [ ! -f "$TARGET_FILE" ]; then
    print_error "Target file not found: $TARGET_FILE"
    echo "Create data/targets/targets.txt with one target per line"
    exit 1
fi

TARGET_COUNT=$(grep -vc '^#\|^$' "$TARGET_FILE" || true)
print_info "Found $TARGET_COUNT targets"
echo ""

if [ "$TARGET_COUNT" -eq 0 ]; then
    print_error "Target file contains no targets"
    exit 1
fi

# ---- activate venv -------------------------------------------------------
if [ -d ".venv" ]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate
fi

# ---- run the scanner -----------------------------------------------------
# FIX 1: --output-dir takes a DIRECTORY, not a filename.  The scanner names
# the files itself as scan_<target>_<ts>.json etc. inside that directory.
print_info "Running port scanner (mode: $SCAN_TYPE)..."
mkdir -p data/intermediate

if ! python3 -m tools.port_scanner.scanner "$TARGET_FILE" \
        --scan-type "$SCAN_TYPE" \
        --output-dir data/intermediate; then
    print_error "Port scanner exited with an error"
    echo "---- contents of data/intermediate ----"
    ls -la data/intermediate || true
    echo "---- newest nmap log, if any ----"
    NEWEST_LOG=$(ls -1t data/intermediate/nmap_*.log 2>/dev/null | head -1 || true)
    if [ -n "${NEWEST_LOG:-}" ]; then
        echo ">>> $NEWEST_LOG"
        tail -n 40 "$NEWEST_LOG" || true
    fi
    exit 1
fi

print_success "Port scan complete"
beep 1 || true

# ---- find the newest scan JSON -------------------------------------------
# FIX 2: use mapfile so an empty result doesn't silently succeed under set -e
mapfile -t CANDIDATES < <(ls -1t data/intermediate/scan_*.json 2>/dev/null || true)

if [ "${#CANDIDATES[@]}" -eq 0 ]; then
    print_error "Scan results not found — scanner produced no JSON"
    echo "---- contents of data/intermediate ----"
    ls -la data/intermediate || true
    echo "---- newest nmap log ----"
    NEWEST_LOG=$(ls -1t data/intermediate/nmap_*.log 2>/dev/null | head -1 || true)
    if [ -n "${NEWEST_LOG:-}" ]; then
        echo ">>> $NEWEST_LOG"
        tail -n 60 "$NEWEST_LOG" || true
    fi
    exit 1
fi

SCAN_FILE="${CANDIDATES[0]}"
print_info "Using scan file: $SCAN_FILE"

# ---- generate reports ----------------------------------------------------
print_info "Generating reports..."
python3 - "$SCAN_FILE" "$OUTPUT_DIR" <<'PY'
import sys
sys.path.insert(0, '.')
from tools.report_builder import ReportGenerator

scan_file, out_dir = sys.argv[1], sys.argv[2]
gen = ReportGenerator()
gen.generate_from_file(scan_file, report_type='technical', formats=['html', 'txt'])
print(f"Reports generated in {out_dir}")
PY

print_success "Reports generated"
beep 2 || true

echo ""
print_success "Quick scan complete!"
echo "Reports available in: $OUTPUT_DIR"