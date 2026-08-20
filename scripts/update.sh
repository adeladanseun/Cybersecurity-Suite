#!/bin/bash
# CyberSecurity Suite - Update Script
# Updates everything: system tools, databases, Python packages

set -e

# Source utilities
source "$(dirname "$0")/utils.sh"

# Get project directory
PROJECT_DIR="$(dirname "$(dirname "$0")")"
cd "$PROJECT_DIR"

show_banner
echo "Updating CyberSecurity Suite..."
echo ""

# Step 1: System Updates
print_info "Step 1: Updating system packages..."
if confirm "Run apt-get update and upgrade?"; then
    sudo apt-get update
    sudo apt-get upgrade -y
    print_success "System packages updated"
else
    print_info "System update skipped"
fi

echo ""

# Step 2: Update Nmap Scripts
print_info "Step 2: Updating nmap scripts..."
if command_exists nmap; then
    sudo nmap --script-updatedb
    print_success "Nmap scripts updated"
fi

echo ""

# Step 3: Update Searchsploit
print_info "Step 3: Updating searchsploit..."
if command_exists searchsploit; then
    searchsploit -u
    print_success "Searchsploit updated"
fi

echo ""

# Step 4: Update SecLists
print_info "Step 4: Updating SecLists..."
if [ -d "data/wordlists/SecLists" ]; then
    cd data/wordlists/SecLists
    git pull
    cd "$PROJECT_DIR"
    print_success "SecLists updated"
else
    print_warning "SecLists not found, skipping"
fi

echo ""

# Step 5: Update Python Packages
print_info "Step 5: Updating Python packages..."
if [ -d ".venv" ]; then
    source .venv/bin/activate
    pip install --upgrade -r requirements.txt
    print_success "Python packages updated"
else
    print_warning "Virtual environment not found"
fi

echo ""

# Step 6: Cleanup
print_info "Step 6: Cleaning up..."

cleanup_temp "data/temp" 7
rotate_logs "logs" 30

# Vacuum database
if [ -f "data/databases/cybersec_suite.sqlite" ]; then
    python3 -c "from core.database import Database; db = Database(); db.vacuum()" 2>/dev/null
    print_success "Database optimized"
fi

print_success "Cleanup complete"
echo ""

# Step 7: Health Check
print_info "Step 7: Running health check..."
if [ -f "scripts/health_check.sh" ]; then
    bash scripts/health_check.sh
else
    print_warning "Health check script not found"
fi

echo ""

print_success "Update complete!"
beep 2