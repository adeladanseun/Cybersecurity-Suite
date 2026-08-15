#!/bin/bash
# CyberSecurity Suite - Quick Scan Script
# Fast assessment of targets

set -e

# Source utilities
source "$(dirname "$0")/utils.sh"

PROJECT_DIR="$(dirname "$(dirname "$0")")"
cd "$PROJECT_DIR"

# Default values
TARGET_FILE="data/targets/targets.txt"
OUTPUT_DIR="reports"
SCAN_TYPE="quick"

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
        -f|--full)
            SCAN_TYPE="full"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [-t targets_file] [-o output_dir] [-f]"
            echo "  -t: Target file (default: data/targets/targets.txt)"
            echo "  -o: Output directory (default: reports)"
            echo "  -f: Full scan instead of quick"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

show_banner
echo "Quick Scan Started"
echo "Target file: $TARGET_FILE"
echo "Scan type: $SCAN_TYPE"
echo ""

# Validate target file
if [ ! -f "$TARGET_FILE" ]; then
    print_error "Target file not found: $TARGET_FILE"
    echo "Create data/targets/targets.txt with one target per line"
    exit 1
fi

# Count targets
TARGET_COUNT=$(grep -v '^#' "$TARGET_FILE" | grep -v '^$' | wc -l)
print_info "Found $TARGET_COUNT targets"
echo ""

# Activate virtual environment if exists
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# Run port scanner
print_info "Running port scanner..."
TIMESTAMP=$(get_timestamp)

if [ "$SCAN_TYPE" = "full" ]; then
    python3 -m tools.port_scanner.scanner "$TARGET_FILE" --scan-type full --output "data/intermediate/scan_${TIMESTAMP}.json"
else
    python3 -m tools.port_scanner.scanner "$TARGET_FILE" --scan-type quick --output "data/intermediate/scan_${TIMESTAMP}.json"
fi

print_success "Port scan complete"
beep 1

# Generate report
print_info "Generating reports..."

SCAN_FILE="data/intermediate/scan_${TIMESTAMP}.json"

if [ -f "$SCAN_FILE" ]; then
    python3 -m tools.report_builder.generator "$SCAN_FILE" --output "$OUTPUT_DIR" --report-type technical
    
    print_success "Reports generated"
    beep 2
else
    print_error "Scan results not found"
    exit 1
fi

echo ""
print_success "Quick scan complete!"
echo "Reports available in: $OUTPUT_DIR"