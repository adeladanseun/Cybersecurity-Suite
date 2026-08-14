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
beep 1

DISCOVERY_FILE="data/intermediate/${AUDIT_NAME}_discovery.json"

if python3 -m tools.network_discovery.discover "$TARGET_FILE" --output "$DISCOVERY_FILE" 2>/dev/null; then
    print_success "Network discovery complete"
else
    print_warning "Network discovery module not available, skipping"
fi

echo ""

# Step 2: Port Scanning
print_info "Step 2: Port Scanning..."
beep 1

SCAN_FILE="data/intermediate/${AUDIT_NAME}_scan.json"

if [ -f "$DISCOVERY_FILE" ]; then
    python3 -m tools.port_scanner.scanner "$DISCOVERY_FILE" --scan-type full --output "$SCAN_FILE"
else
    python3 -m tools.port_scanner.scanner "$TARGET_FILE" --scan-type full --output "$SCAN_FILE"
fi

print_success "Port scanning complete"
beep 2

echo ""

# Step 3: Vulnerability Checking
print_info "Step 3: Vulnerability Checking..."

VULN_FILE="data/intermediate/${AUDIT_NAME}_vulns.json"

if python3 -m tools.vuln_checker.service_vulns "$SCAN_FILE" --output "$VULN_FILE" 2>/dev/null; then
    print_success "Vulnerability check complete"
    beep 1
else
    print_warning "Vulnerability checker not available, skipping"
    VULN_FILE="$SCAN_FILE"
fi

echo ""

# Step 4: Report Generation
print_info "Step 4: Generating Reports..."

REPORT_INPUT="${VULN_FILE:-$SCAN_FILE}"

python3 -m tools.report_builder.generator "$REPORT_INPUT" \
    --output "$OUTPUT_DIR" \
    --report-type full \
    --formats html,csv,txt,json \
    --name "$AUDIT_NAME"

print_success "Reports generated"
beep 3

echo ""

# Step 5: Summary
print_info "Audit Complete!"
echo "Results:"
echo "  - Scan data: $SCAN_FILE"
echo "  - Vulnerability data: ${VULN_FILE:-N/A}"
echo "  - Reports: $OUTPUT_DIR"
echo ""

print_success "Full audit finished successfully!"
beep 2