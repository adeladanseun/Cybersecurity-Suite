#!/bin/bash
# Run all Phase 1 tests
# Usage: ./run_tests.sh [module_name]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "  CyberSecurity Suite - Test Runner"
echo "  Phase 1: Core Framework"
echo "=========================================="
echo ""

# Function to run a test
run_test() {
    local test_name=$1
    local test_file="tests/${test_name}"
    
    echo -e "${YELLOW}[RUNNING]${NC} $test_name"
    
    if python3 "$test_file"; then
        echo -e "${GREEN}[PASSED]${NC}  $test_name"
        echo ""
        return 0
    else
        echo -e "${RED}[FAILED]${NC}  $test_name"
        echo ""
        return 1
    fi
}

# Track failures
FAILURES=0

# If specific test provided, run only that
if [ -n "$1" ]; then
    case "$1" in
        validator)
            run_test "test_validator.py" || ((FAILURES++))
            ;;
        file_manager)
            run_test "test_file_manager.py" || ((FAILURES++))
            ;;
        config)
            run_test "test_config.py" || ((FAILURES++))
            ;;
        logger)
            run_test "test_logger.py" || ((FAILURES++))
            ;;
        notifier)
            run_test "test_notifier.py" || ((FAILURES++))
            ;;
        database)
            run_test "test_database.py" || ((FAILURES++))
            ;;
        integration)
            run_test "test_integration.py" || ((FAILURES++))
            ;;
        all)
            ;&  # Fall through to run all
            *)
            echo "Unknown test: $1"
            echo "Available: validator, file_manager, config, logger, notifier, database, integration, all"
            exit 1
            ;;
    esac
fi

# Run all tests if no argument or "all"
if [ -z "$1" ] || [ "$1" = "all" ]; then
    echo "Running all tests..."
    echo ""
    
    run_test "test_validator.py" || ((FAILURES++))
    run_test "test_file_manager.py" || ((FAILURES++))
    run_test "test_config.py" || ((FAILURES++))
    run_test "test_logger.py" || ((FAILURES++))
    run_test "test_notifier.py" || ((FAILURES++))
    run_test "test_database.py" || ((FAILURES++))
    #added code
    run_test "test_dns_enum.py" || ((FAILURES++))
    run_test "test_web_enum.py" || ((FAILURES++))
    run_test "test_port_scanner.py" || ((FAILURES++))
    run_test "test_vuln_checker.py" || ((FAILURES++))
    run_test "test_network_discovery.py" || ((FAILURES++))
    run_test "test_report_builder.py" || ((FAILURES++))
    #end of addition

    run_test "test_integration.py" || ((FAILURES++))
fi

# Summary
echo "=========================================="
if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
else
    echo -e "${RED}❌ $FAILURES test(s) failed!${NC}"
fi
echo "=========================================="

exit $FAILURES