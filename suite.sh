#!/bin/bash
# CyberSecurity Suite - Main Entry Point
# Unified interface for all tools

# Source utilities
source "$(dirname "$0")/scripts/utils.sh"

PROJECT_DIR="$(dirname "$0")"
cd "$PROJECT_DIR"

# Show help
show_help() {
    show_banner
    echo "Usage: ./suite.sh [command] [options]"
    echo ""
    echo "Commands:"
    echo "  scan       Run port scanning"
    echo "  report     Generate reports"
    echo "  update     Update databases and tools"
    echo "  setup      Initial setup"
    echo "  health     Run health check"
    echo "  clean      Clean temporary files"
    echo "  help       Show this help"
    echo ""
    echo "Options:"
    echo "  --quick    Quick scan (top 1000 ports)"
    echo "  --full     Full scan (all ports)"
    echo "  -t FILE    Target file"
    echo "  -o DIR     Output directory"
    echo ""
    echo "Examples:"
    echo "  ./suite.sh scan --quick -t data/targets/targets.txt"
    echo "  ./suite.sh report -i data/intermediate/scan.json"
    echo "  ./suite.sh health"
    echo ""
}

# Main command handling
case "$1" in
    scan)
        shift
        # Check if quick or full scan requested
        if [[ "$*" == *"--quick"* ]]; then
            # Remove --quick from arguments
            args="${*//--quick/}"
            bash scripts/quick_scan.sh $args
        elif [[ "$*" == *"--full"* ]]; then
            # Remove --full from arguments
            args="${*//--full/}"
            bash scripts/full_audit.sh $args
        else
            bash scripts/quick_scan.sh "$@"
        fi
        ;;
        
    report)
        shift
        # Activate venv if exists
        [ -d ".venv" ] && source .venv/bin/activate
        
        # Parse report arguments
        INPUT_FILE=""
        REPORT_TYPE="full"
        FORMATS="html"
        OUTPUT_DIR="reports"
        REPORT_NAME=""
        
        while [[ $# -gt 0 ]]; do
            case $1 in
                -i|--input)
                    INPUT_FILE="$2"
                    shift 2
                    ;;
                -t|--type)
                    REPORT_TYPE="$2"
                    shift 2
                    ;;
                -f|--format)
                    FORMATS="$2"
                    shift 2
                    ;;
                -o|--output)
                    OUTPUT_DIR="$2"
                    shift 2
                    ;;
                -n|--name)
                    REPORT_NAME="$2"
                    shift 2
                    ;;
                *)
                    print_error "Unknown option: $1"
                    exit 1
                    ;;
            esac
        done
        
        if [ -z "$INPUT_FILE" ]; then
            print_error "Input file required: -i FILE"
            exit 1
        fi
        
        IFS=',' read -ra FORMAT_ARRAY <<< "$FORMATS"
        
        python3 -m tools.report_builder.generator \
            "$INPUT_FILE" \
            --report-type "$REPORT_TYPE" \
            --formats "${FORMAT_ARRAY[@]}" \
            --output "$OUTPUT_DIR" \
            ${REPORT_NAME:+--name "$REPORT_NAME"}
        ;;
        
    update)
        shift
        if [[ "$*" == *"--databases"* ]]; then
            bash scripts/update_databases.sh
        else
            bash scripts/update.sh
        fi
        ;;
        
    setup)
        bash scripts/setup.sh
        ;;
        
    health)
        bash scripts/health_check.sh
        ;;
        
    clean)
        print_info "Cleaning temporary files..."
        cleanup_temp "data/temp" 0
        print_success "Cleanup complete"
        ;;
        
    help|--help|-h)
        show_help
        ;;
        
    *)
        show_help
        exit 1
        ;;
esac

# Return to original directory
cd - >/dev/null 2>&1