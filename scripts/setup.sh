#!/bin/bash
# CyberSecurity Suite - Setup Script
# Initializes entire project environment

set -e

# Source utilities
source "$(dirname "$0")/utils.sh"

# Get project directory
PROJECT_DIR="$(dirname "$(dirname "$0")")"
cd "$PROJECT_DIR"

# Show banner
show_banner
echo "Starting CyberSecurity Suite Setup..."
echo ""

# Step 1: System Check
print_info "Step 1: Checking system requirements..."

if ! is_kali; then
    print_warning "This system doesn't appear to be Kali Linux"
    print_warning "The suite is optimized for Kali Linux but may work on other Debian-based systems"
    
    if ! confirm "Continue anyway?"; then
        print_error "Setup aborted"
        exit 1
    fi
else
    print_success "Kali Linux detected"
fi

if ! check_python_version; then
    print_error "Python 3.8+ is required"
    print_error "Current version: $(python3 --version 2>&1)"
    exit 1
fi
print_success "Python version OK: $(python3 --version 2>&1)"

if ! check_disk_space; then
    print_error "Insufficient disk space (minimum 1GB required)"
    exit 1
fi
print_success "Disk space OK"

echo ""

# Step 2: Create Directory Structure
print_info "Step 2: Creating directory structure..."

DIRS=(
    "data/targets"
    "data/intermediate"
    "data/databases"
    "data/wordlists"
    "data/screenshots"
    "data/sessions"
    "data/temp"
    "reports/html"
    "reports/pdf"
    "reports/csv"
    "reports/txt"
    "reports/json"
    "logs"
)

for dir in "${DIRS[@]}"; do
    ensure_dir "$dir"
    # Create .gitkeep for empty directories
    if [ ! -f "$dir/.gitkeep" ]; then
        touch "$dir/.gitkeep"
    fi
done

print_success "Directories created"
echo ""

# Step 3: System Tools Check
print_info "Step 3: Checking required tools..."

TOOLS=(
    "nmap"
    "masscan"
    "gobuster"
    "hydra"
    "searchsploit"
    "whois"
    "dig:dnsutils"
    "beep"
    "sox"
)

for tool_entry in "${TOOLS[@]}"; do
    IFS=':' read -r tool package <<< "$tool_entry"
    package=${package:-$tool}
    
    if command_exists "$tool"; then
        print_success "$tool found: $(command -v $tool)"
    else
        print_warning "$tool not found"
        if confirm "Install $package?"; then
            sudo apt-get install -y "$package"
            print_success "$tool installed"
        fi
    fi
done

echo ""

# Step 4: Python Environment
print_info "Step 4: Setting up Python environment..."

# Create virtual environment
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    print_success "Virtual environment created"
else
    print_info "Virtual environment already exists"
fi

# Activate and install packages
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

print_success "Python packages installed"
echo ""

# Step 5: Offline Databases
print_info "Step 5: Setting up offline databases..."

# Update nmap scripts
if command_exists nmap; then
    print_info "Updating nmap scripts..."
    sudo nmap --script-updatedb
    print_success "Nmap scripts updated"
fi

# Update searchsploit
if command_exists searchsploit; then
    print_info "Updating searchsploit database..."
    searchsploit -u
    print_success "Searchsploit updated"
fi

# Clone SecLists if not present
if [ ! -d "data/wordlists/SecLists" ]; then
    if check_internet; then
        print_info "Downloading SecLists..."
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git data/wordlists/SecLists
        print_success "SecLists downloaded"
    else
        print_warning "No internet connection, skipping SecLists"
    fi
else
    print_info "SecLists already present"
fi

echo ""

# Step 6: Initialize Database
print_info "Step 6: Initializing database..."

if python3 -c "from core.database import Database; db = Database(); db.init_database()" 2>/dev/null; then
    print_success "Database initialized"
else
    print_warning "Database initialization skipped (core module not found)"
fi

echo ""

# Step 7: Configuration
print_info "Step 7: Creating configuration..."

if [ ! -f "config.json" ]; then
    python3 -c "from core.config import Config; Config(); print('Config created')" 2>/dev/null || {
        cat > config.json << EOF
{
    "version": "1.0.0",
    "project_name": "CyberSecurity Suite",
    "paths": {
        "data_dir": "./data",
        "reports_dir": "./reports",
        "logs_dir": "./logs"
    }
}
EOF
        print_success "Default config created"
    }
else
    print_info "Config already exists"
fi

echo ""

# Step 8: Bash Integration
print_info "Step 8: Setting up bash integration..."

# Make scripts executable
chmod +x scripts/*.sh suite.sh 2>/dev/null

# Add alias if requested
if confirm "Add 'cyberscan' alias to .bashrc?"; then
    echo "alias cyberscan='$PROJECT_DIR/suite.sh'" >> ~/.bashrc
    print_success "Alias added to .bashrc"
fi

# Setup tab completion
if confirm "Install bash completion?"; then
    sudo cp scripts/completion.sh /etc/bash_completion.d/cybersec-suite
    print_success "Tab completion installed"
fi

echo ""

# Step 9: Validation
print_info "Step 9: Running validation tests..."

if [ -d "tests" ]; then
    if python3 tests/test_validator.py >/dev/null 2>&1; then
        print_success "Validator tests passed"
    else
        print_warning "Validator tests failed"
    fi
    
    if python3 tests/test_file_manager.py >/dev/null 2>&1; then
        print_success "File manager tests passed"
    else
        print_warning "File manager tests failed"
    fi
else
    print_warning "Tests directory not found, skipping validation"
fi

echo ""

# Step 10: Complete
print_success "Setup complete!"
beep 3
echo ""
echo "Next steps:"
echo "  1. Add targets to data/targets/"
echo "  2. Run quick scan: ./suite.sh scan --quick"
echo "  3. View reports in reports/html/"
echo ""