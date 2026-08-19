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

python3 -c "
import sys
sys.path.insert(0, '.')
from tools.network_discovery import NetworkDiscovery
import json

discovery = NetworkDiscovery()
with open('$TARGET_FILE') as f:
    targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]

print(f'Discovering {len(targets)} targets...')
results = {'targets': targets, 'hosts': [], 'timestamp': __import__('datetime').datetime.now().isoformat()}

for target in targets:
    try:
        result = discovery.discover_network(target)
        results['hosts'].extend(result.get('hosts', []))
    except Exception as e:
        print(f'  Warning: Discovery failed for {target}: {e}')

with open('data/intermediate/${AUDIT_NAME}_discovery.json', 'w') as f:
    json.dump(results, f, indent=2, default=str)

print(f'Discovery complete: {len(results[\"hosts\"])} hosts found')
"

print_success "Network discovery complete"
beep 1

echo ""

# Step 2: Port Scanning
print_info "Step 2: Port Scanning..."
beep 1

python3 -c "
import sys
sys.path.insert(0, '.')
from tools.port_scanner import PortScanner
import json

scanner = PortScanner()
with open('$TARGET_FILE') as f:
    targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]

print(f'Scanning {len(targets)} targets...')
all_results = []

for target in targets:
    try:
        result = scanner.full_scan(target)
        all_results.append(result)
        print(f'  Scanned: {target} - {result[\"summary\"][\"total_open_ports\"]} open ports')
    except Exception as e:
        print(f'  Warning: Scan failed for {target}: {e}')

# Combine results
combined = {
    'scan_metadata': {
        'audit_name': '$AUDIT_NAME',
        'targets': targets,
        'timestamp': __import__('datetime').datetime.now().isoformat(),
    },
    'ports': [],
    'hosts': [],
    'summary': {'total_open_ports': 0}
}

for result in all_results:
    combined['ports'].extend(result.get('ports', []))
    combined['hosts'].extend(result.get('hosts', []))
    combined['summary']['total_open_ports'] += result.get('summary', {}).get('total_open_ports', 0)

with open('data/intermediate/${AUDIT_NAME}_scan.json', 'w') as f:
    json.dump(combined, f, indent=2, default=str)

print(f'Port scanning complete: {combined[\"summary\"][\"total_open_ports\"]} open ports total')
"

print_success "Port scanning complete"
beep 2

echo ""

# Step 3: Vulnerability Checking
print_info "Step 3: Vulnerability Checking..."

python3 -c "
import sys
sys.path.insert(0, '.')
from tools.vuln_checker import ServiceVulnChecker
import json

checker = ServiceVulnChecker()

with open('data/intermediate/${AUDIT_NAME}_scan.json') as f:
    scan_data = json.load(f)

print('Checking vulnerabilities...')
vuln_results = checker.check_scan_results(scan_data)

with open('data/intermediate/${AUDIT_NAME}_vulns.json', 'w') as f:
    json.dump(vuln_results, f, indent=2, default=str)

print(f'Vulnerability check complete: {vuln_results[\"summary\"][\"total_vulnerabilities\"]} found')
"

print_success "Vulnerability check complete"
beep 1

echo ""

# Step 4: Report Generation
print_info "Step 4: Generating Reports..."

python3 -c "
import sys
sys.path.insert(0, '.')
from tools.report_builder import ReportGenerator
import json

generator = ReportGenerator()

with open('data/intermediate/${AUDIT_NAME}_vulns.json') as f:
    vuln_data = json.load(f)

generator.generate_report(
    vuln_data,
    report_type='full',
    formats=['html', 'csv', 'txt', 'json'],
    report_name='$AUDIT_NAME'
)

print('Reports generated')
"

print_success "Reports generated"
beep 3

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