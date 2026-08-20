#!/bin/bash
# CyberSecurity Suite - Database Update Script
# Updates only offline databases

set -e

# Source utilities
source "$(dirname "$0")/utils.sh"

PROJECT_DIR="$(dirname "$(dirname "$0")")"
cd "$PROJECT_DIR"

show_banner
echo "Updating Offline Databases..."
echo ""

# Nmap Scripts
print_info "Updating nmap scripts..."
if command_exists nmap; then
    sudo nmap --script-updatedb
    print_success "Nmap scripts updated"
fi

echo ""

# Searchsploit
print_info "Updating searchsploit database..."
if command_exists searchsploit; then
    searchsploit -u
    print_success "Searchsploit updated"
fi

echo ""

# SecLists
print_info "Updating SecLists..."
if [ -d "data/wordlists/SecLists" ]; then
    cd data/wordlists/SecLists
    git pull
    cd "$PROJECT_DIR"
    print_success "SecLists updated"
elif check_internet; then
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git data/wordlists/SecLists
    print_success "SecLists downloaded"
else
    print_warning "SecLists not found and no internet"
fi

echo ""

# Wappalyzer
print_info "Updating Wappalyzer signatures..."
if [ -d "data/databases/wappalyzer" ]; then
    cd data/databases/wappalyzer
    git pull
    cd "$PROJECT_DIR"
    print_success "Wappalyzer updated"
elif check_internet; then
    git clone --depth 1 https://github.com/enthec/webappanalyzer.git data/databases/wappalyzer
    print_success "Wappalyzer downloaded"
fi

echo ""

print_success "Database updates complete!"
beep 1