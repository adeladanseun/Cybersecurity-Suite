#!/bin/bash
# CyberSecurity Suite - Full Audit Script
# Complete security audit workflow

set -e

# Source utilities
source "$(dirname "$0")/utils.sh"

PROJECT_DIR="$(dirname "$(dirname "$0")")"
cd "$PROJECT_DIR"

# Default values
TARGET_FILE="data/targets/targets.txt"
OUTPUT_DIR="reports"
AUDIT_NAME="audit_$(get_timestamp)"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--targets)
            TARGET_FILE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -n|--name)
            AUDIT_NAME="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [-t targets_file] [-o output_dir] [-n audit_name]"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

show_banner
echo "Full Security Audit Started"
echo "Target file: $TARGET_FILE"
echo "Audit name: $AUDIT_NAME"
echo ""

# Validate target file
if [ ! -f "$TARGET_FILE" ]; then
    print_error "Target file not found: $TARGET_FILE"
    exit 1
fi

# Activate virtual environment
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# Step 1: Network Discovery
print_info "Step 1: Network Discovery..."

DISCOVERY_OUT="data/intermediate/${AUDIT_NAME:-scan}_discovery.json"

if python3 -m tools.network_discovery.cli "$TARGET_FILE" --output "$DISCOVERY_OUT"; then
    print_success "Network discovery complete"
else
    rc=$?
    case $rc in
        3) print_warn  "Discovery ran clean, but no hosts responded" ;;
        *) print_error "Network discovery failed (rc=$rc)" ;;
    esac
fi

echo ""

# Step 2: Port Scanning
print_info "Step 2: Port Scanning..."

SCAN_OUT="data/intermediate/${AUDIT_NAME:-scan}_scan.json"

# SCAN_MODE is set earlier in the script: quick | full  (default quick)
: "${SCAN_MODE:=full}"

if python3 -m tools.port_scanner.cli "$TARGET_FILE" \
        --mode "$SCAN_MODE" \
        --audit-name "${AUDIT_NAME:-scan}" \
        --combined-output "$SCAN_OUT" \
        --output-dir data/intermediate; then
    print_success "Port scanning complete"
else
    rc=$?
    case $rc in
        3) print_warn  "Port scan ran clean, but 0 open ports across all targets" ;;
        *) print_error "Port scan failed (rc=$rc)";;
    esac
fi

echo ""

# Step 3: Vulnerability Checking
print_info "Step 3: Vulnerability Checking..."

SCAN_IN="data/intermediate/${AUDIT_NAME:-scan}_scan.json"
VULN_OUT="data/intermediate/${AUDIT_NAME:-scan}_vulns.json"

if [ ! -f "$SCAN_IN" ]; then
    print_error "Scan results missing: $SCAN_IN (did step 2 succeed?)"
    exit 1
fi

if python3 -m tools.vuln_checker.cli "$SCAN_IN" --output "$VULN_OUT"; then
    print_success "Vulnerability check complete"
else
    rc=$?
    case $rc in
        3) print_warn  "Vulnerability check ran, but no findings" ;;
        *) print_error "Vulnerability check failed (rc=$rc)";;
    esac
fi

echo ""

# Step 4: Report Generation
print_info "Step 4: Generating Reports..."

VULN_IN="data/intermediate/${AUDIT_NAME:-scan}_vulns.json"
SCAN_IN="data/intermediate/${AUDIT_NAME:-scan}_scan.json"
DISC_IN="data/intermediate/${AUDIT_NAME:-scan}_discovery.json"
REPORT_DIR="reports"

if [ ! -f "$VULN_IN" ]; then
    print_error "Vuln results missing: $VULN_IN (did step 3 succeed?)"
    exit 1
fi

# --include is optional; missing files are skipped with a warning
# rather than aborting the whole step.
INCLUDE_ARGS=()
[ -f "$SCAN_IN" ] && INCLUDE_ARGS+=("--include" "$SCAN_IN")
[ -f "$DISC_IN" ] && INCLUDE_ARGS+=("--include" "$DISC_IN")

if python3 -m tools.report_builder.cli "$VULN_IN" \
        "${INCLUDE_ARGS[@]}" \
        --output-dir "$REPORT_DIR" \
        --report-type full \
        --formats html,csv,txt,json \
        --name "${AUDIT_NAME:-scan}"; then
    print_success "Reports generated"
else
    rc=$?
    case $rc in
        3) print_warn  "Reports generated with some formats missing" ;;
        *) print_error "Report generation failed (rc=$rc)";;
    esac
fi

echo ""

# Step 5: Summary
print_info "Audit Complete!"
echo "Results:"
echo "  - Discovery: data/intermediate/${AUDIT_NAME}_discovery.json"
echo "  - Scan data: data/intermediate/${AUDIT_NAME}_scan.json"
echo "  - Vulnerability data: data/intermediate/${AUDIT_NAME}_vulns.json"
echo "  - Reports: $OUTPUT_DIR"
echo ""

print_success "Full audit finished successfully!"
beep 2