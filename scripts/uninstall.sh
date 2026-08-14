#!/bin/bash
# CyberSecurity Suite - Uninstall Script
# Removes the project cleanly

set -e

# Source utilities
source "$(dirname "$0")/utils.sh"

PROJECT_DIR="$(dirname "$(dirname "$0")")"
cd "$PROJECT_DIR"

show_banner
echo "Uninstalling CyberSecurity Suite..."
echo ""

# Warning
print_warning "This will remove the CyberSecurity Suite from your system"
print_warning "Your reports and data may be lost!"

if ! confirm "Are you sure you want to continue?"; then
    print_info "Uninstall cancelled"
    exit 0
fi

echo ""

# Backup option
if confirm "Do you want to backup reports and data?"; then
    BACKUP_DIR="${HOME}/cybersec_backup_$(get_timestamp)"
    ensure_dir "$BACKUP_DIR"
    
    print_info "Backing up to $BACKUP_DIR..."
    cp -r reports "$BACKUP_DIR/" 2>/dev/null
    cp -r data "$BACKUP_DIR/" 2>/dev/null
    cp config.json "$BACKUP_DIR/" 2>/dev/null
    
    print_success "Backup created at $BACKUP_DIR"
fi

echo ""

# Remove virtual environment
if [ -d ".venv" ]; then
    print_info "Removing virtual environment..."
    rm -rf .venv
fi

# Remove database
if [ -f "data/databases/cybersec_suite.sqlite" ]; then
    print_info "Removing database..."
    rm -f data/databases/cybersec_suite.sqlite
fi

# Remove logs
if [ -d "logs" ]; then
    print_info "Cleaning logs..."
    rm -rf logs/*
fi

# Remove aliases
if grep -q "cyberscan" ~/.bashrc; then
    print_info "Removing alias from .bashrc..."
    sed -i '/cyberscan/d' ~/.bashrc
fi

# Remove completion
if [ -f "/etc/bash_completion.d/cybersec-suite" ]; then
    print_info "Removing tab completion..."
    sudo rm /etc/bash_completion.d/cybersec-suite
fi

echo ""

if confirm "Remove entire project directory?"; then
    print_info "Removing project directory..."
    cd ..
    rm -rf "$PROJECT_DIR"
    print_success "Project removed"
else
    print_info "Project files kept, but environment cleaned"
fi

echo ""
print_success "Uninstall complete!"