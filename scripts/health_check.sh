#!/bin/bash
# CyberSecurity Suite - Health Check Script
# Verifies all components are working

set -e

# Source utilities
source "$(dirname "$0")/utils.sh"

PROJECT_DIR="$(dirname "$(dirname "$0")")"
cd "$PROJECT_DIR"

show_banner
echo "Health Check Report"
echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""
echo "========================================"
echo ""

# System checks
echo "SYSTEM CHECKS"
echo "----------------------------------------"

# OS
if is_kali; then
    print_success "OS: Kali Linux"
else
    print_warning "OS: Not Kali Linux (may still work)"
fi

# Python
if check_python_version; then
    print_success "Python: $(python3 --version 2>&1)"
else
    print_error "Python: Version too old or not found"
fi

# Disk
if check_disk_space; then
    print_success "Disk: Space OK"
else
    print_error "Disk: Low space"
fi

echo ""

# Tool checks
echo "TOOL CHECKS"
echo "----------------------------------------"

TOOLS=("nmap" "masscan" "gobuster" "hydra" "searchsploit" "whois" "dig")

for tool in "${TOOLS[@]}"; do
    if command_exists "$tool"; then
        VERSION=$($tool --version 2>&1 | head -n 1)
        print_success "$tool: Found ($VERSION)"
    else
        print_warning "$tool: Not found"
    fi
done

echo ""

# Project checks
echo "PROJECT CHECKS"
echo "----------------------------------------"

# Directories
for dir in data reports logs; do
    if [ -d "$dir" ]; then
        print_success "Directory $dir: Exists"
    else
        print_error "Directory $dir: Missing"
    fi
done

# Config
if [ -f "config.json" ]; then
    print_success "Config: Found"
else
    print_warning "Config: Missing"
fi

# Database
if [ -f "data/databases/cybersec_suite.sqlite" ]; then
    DB_SIZE=$(du -h data/databases/cybersec_suite.sqlite | cut -f1)
    print_success "Database: Found ($DB_SIZE)"
else
    print_warning "Database: Not initialized"
fi

echo ""

# Python module checks
echo "PYTHON MODULE CHECKS"
echo "----------------------------------------"

if [ -d ".venv" ]; then
    source .venv/bin/activate
    print_success "Virtual environment: Active"
else
    print_warning "Virtual environment: Not found"
fi

MODULES=("core.file_manager" "core.validator" "core.config" "core.database")

for module in "${MODULES[@]}"; do
    if python3 -c "import $module" 2>/dev/null; then
        print_success "Module $module: OK"
    else
        print_error "Module $module: Failed"
    fi
done

echo ""

# Run quick tests
echo "TEST RUN"
echo "----------------------------------------"

if [ -f "tests/test_validator.py" ]; then
    if python3 tests/test_validator.py >/dev/null 2>&1; then
        print_success "Validator tests: Passed"
    else
        print_error "Validator tests: Failed"
    fi
fi

echo ""

# Summary
echo "========================================"
echo "HEALTH CHECK COMPLETE"
echo "========================================"

# Count issues
ISSUES=0
if ! check_python_version; then ISSUES=$((ISSUES+1)); fi
if [ ! -f "config.json" ]; then ISSUES=$((ISSUES+1)); fi
if [ ! -f "data/databases/cybersec_suite.sqlite" ]; then ISSUES=$((ISSUES+1)); fi

if [ $ISSUES -eq 0 ]; then
    print_success "All systems healthy!"
    exit 0
else
    print_warning "$ISSUES issue(s) found. Run setup.sh to fix."
    exit 1
fi