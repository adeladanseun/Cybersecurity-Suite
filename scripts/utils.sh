#!/bin/bash
# Shared utility functions for all scripts

# Color codes
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export MAGENTA='\033[0;35m'
export CYAN='\033[0;36m'
export NC='\033[0m' # No Color

# Get script directory
get_script_dir() {
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
    echo "$SCRIPT_DIR"
}

# Get project root directory
get_project_dir() {
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    echo "$PROJECT_DIR"
}

# Print colored message
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_success() {
    print_message "$GREEN" "✅ $1"
}

print_error() {
    print_message "$RED" "❌ $1"
}

print_warning() {
    print_message "$YELLOW" "⚠️  $1"
}

print_info() {
    print_message "$BLUE" "ℹ️  $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if running as root
is_root() {
    if [ "$(id -u)" -eq 0 ]; then
        return 0
    else
        return 1
    fi
}

# Check if running on Kali Linux
is_kali() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" == "kali" ]]; then
            return 0
        fi
    fi
    return 1
}

# Create directory if not exists
ensure_dir() {
    local dir=$1
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
    fi
}

# Check Python version
check_python_version() {
    if command_exists python3; then
        local version=$(python3 --version 2>&1 | awk '{print $2}')
        local major=$(echo "$version" | cut -d. -f1)
        local minor=$(echo "$version" | cut -d. -f2)
        
        if [ "$major" -ge 3 ] && [ "$minor" -ge 8 ]; then
            return 0
        fi
    fi
    return 1
}

# Function to check disk space (requires at least 1GB)
check_disk_space() {
    local available=$(df / --output=avail -BG 2>/dev/null | tail -1 | tr -dc '0-9')
    if [ -z "$available" ]; then
        available=$(df / 2>/dev/null | awk 'NR==2 {print $4}' | awk '{printf "%.0f", $1/1024/1024}')
    fi
    
    if [ "$available" -lt 1 ]; then
        return 1
    fi
    return 0
}

# Log message to file
log_message() {
    local message=$1
    local log_file=${2:-"./logs/general.log"}
    
    ensure_dir "$(dirname "$log_file")"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" >> "$log_file"
}

# Backup file before modification
backup_file() {
    local file=$1
    if [ -f "$file" ]; then
        local backup="${file}.backup_$(date +%Y%m%d_%H%M%S)"
        cp "$file" "$backup"
        echo "$backup"
    fi
}

# Check internet connectivity
check_internet() {
    ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1
    return $?
}

# Get user confirmation
confirm() {
    local prompt=$1
    local response
    
    read -p "$prompt [y/N]: " response
    case "$response" in
        [yY]|[yY][eE][sS])
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Beep function (cross-platform)
beep() {
    local times=${1:-1}
    
    if command_exists beep; then
        for i in $(seq 1 $times); do
            beep -f 1000 -l 100 2>/dev/null
            sleep 0.1
        done
    elif command_exists play; then
        for i in $(seq 1 $times); do
            play -nq -t alsa synth 0.1 sine 1000 2>/dev/null
        done
    else
        echo -e "\a"
    fi
}

# Display banner
show_banner() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║          CYBERSECURITY SUITE                              ║"
    echo "║          Network Security Assessment Toolkit              ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
}

# Check tool and suggest installation
check_tool() {
    local tool=$1
    local package=${2:-$tool}
    
    if command_exists "$tool"; then
        return 0
    else
        print_warning "$tool not found"
        if confirm "Install $package?"; then
            sudo apt-get install -y "$package"
            return $?
        fi
        return 1
    fi
}

# Get timestamp
get_timestamp() {
    date +%Y%m%d_%H%M%S
}

# Clean up temp files
cleanup_temp() {
    local temp_dir="${1:-./data/temp}"
    local max_age_hours=${2:-24}
    
    if [ -d "$temp_dir" ]; then
        find "$temp_dir" -type f -mtime +${max_age_hours} -delete 2>/dev/null
    fi
}

# Rotate logs
rotate_logs() {
    local log_dir="${1:-./logs}"
    local max_logs=${2:-30}
    
    if [ -d "$log_dir" ]; then
        find "$log_dir" -name "*.log" -type f | sort | head -n -$max_logs | while read log; do
            rm "$log"
        done
    fi
}

# Export functions for use in other scripts
export -f get_script_dir
export -f get_project_dir
export -f print_message
export -f print_success
export -f print_error
export -f print_warning
export -f print_info
export -f command_exists
export -f is_root
export -f is_kali
export -f ensure_dir
export -f check_python_version
export -f check_disk_space
export -f log_message
export -f backup_file
export -f check_internet
export -f confirm
export -f beep
export -f show_banner
export -f check_tool
export -f get_timestamp
export -f cleanup_temp
export -f rotate_logs