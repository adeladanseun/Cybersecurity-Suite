#!/bin/bash
# CyberSecurity Suite - Health Check Script
# Verifies all components are working

# Locate project root and source libraries
PROJECT_DIR="$(d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; while [ ! -f "$d/.cybersec-root" ] && [ "$d" != "/" ]; do d="$(dirname "$d")"; done; echo "$d")"
source "$(dirname "$0")/utils.sh"
source "$PROJECT_DIR/scripts/lib/init.sh"

cd "$PROJECT_DIR" || exit 1

ISSUES=0
WARNINGS=0

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
    WARNINGS=$((WARNINGS+1))
fi

# Python
if check_python_version; then
    print_success "Python: $(python3 --version 2>&1)"
else
    print_error "Python: Version too old or not found"
    ISSUES=$((ISSUES+1))
fi

# Disk
if check_disk_space; then
    print_success "Disk: Space OK"
else
    print_error "Disk: Low space"
    ISSUES=$((ISSUES+1))
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
        WARNINGS=$((WARNINGS+1))
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
        ISSUES=$((ISSUES+1))
    fi
done

# Config
if [ -f "config.json" ]; then
    print_success "Config: Found"
else
    print_error "Config: Missing"
    ISSUES=$((ISSUES+1))
fi

# Database
if [ -f "data/databases/cybersec_suite.sqlite" ]; then
    DB_SIZE=$(du -h data/databases/cybersec_suite.sqlite | cut -f1)
    print_success "Database: Found ($DB_SIZE)"
else
    print_error "Database: Not initialized"
    ISSUES=$((ISSUES+1))
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
    WARNINGS=$((WARNINGS+1))
fi

# Note: dnspython imports as 'dns' and djangorestframework imports as 'rest_framework'
MODULES=("core.file_manager" "core.validator" "core.config" "core.database" "scapy" "django" "dns" "rest_framework")

for module in "${MODULES[@]}"; do
    if python3 -c "import $module" 2>/dev/null; then
        print_success "Module $module: OK"
    else
        print_error "Module $module: Failed"
        ISSUES=$((ISSUES+1))
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
        ISSUES=$((ISSUES+1))
    fi
fi

echo ""

# Summary
echo "========================================"
echo "HEALTH CHECK COMPLETE"
echo "========================================"

if [ $ISSUES -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    print_success "All systems healthy!"
    exit 0
elif [ $ISSUES -eq 0 ]; then
    print_warning "Healthy, with $WARNINGS warning(s)."
    exit 0
else
    print_error "$ISSUES error(s) and $WARNINGS warning(s) found. Run setup.sh to fix."
    exit 1
fi
