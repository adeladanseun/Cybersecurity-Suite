# Installation Guide

This guide covers the complete installation of CyberSecurity Suite on Kali Linux or Ubuntu/Debian systems.

---

## 📋 Prerequisites

### System Requirements
- **OS:** Kali Linux (preferred) or Ubuntu/Debian (tested on Ubuntu 22.04)
- **Python:** 3.8 or higher
- **RAM:** 2GB minimum (4GB recommended)
- **Disk Space:** 1GB+ for project + 2GB for optional databases
- **Internet:** Required for initial setup

### Required Tools

| Tool | Purpose | Required? |
|------|---------|-----------|
| nmap | Port scanning | Yes |
| masscan | Fast port scanning | Optional |
| gobuster | Directory brute forcing | Optional |
| hydra | Credential testing | Optional |
| searchsploit | CVE database (44,000+ entries) | Recommended |
| whois | Domain information | Optional |
| dnsutils (dig) | DNS tools | Optional |
| beep | Audio notifications | Optional |
| sox | Audio synthesis | Optional |

---

## 🚀 Main Project Installation

### Step 1: Install System Tools

```bash
sudo apt update
sudo apt install -y nmap masscan gobuster hydra whois dnsutils beep sox

#For non-kali users with no searchsploit
# Clone the exploitdb repository
sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb

# Create symlink so system can find it
sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# Verify installation
searchsploit --version


# Clone or download the project
git clone [your-repository-url] cybersec-suite
cd cybersec-suite

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install packages
pip install -r requirements.txt

#Run setup
bash scripts/setup.sh

this will:
- Create directory structure (data/, reports/, logs/)
- Initialize SQLite database
- Create config.json
- Set up bash aliases (optional)
- Install tab completion (optional)

#The web app runs scans in background threads. Without this, scans will hang waiting for sudo password:
sudo visudo
#Add this line at the bottom (replace YOUR_USERNAME with your actual username):
YOUR_USERNAME ALL=(ALL) NOPASSWD: /usr/bin/nmap

#Create if not created
mkdir -p reports/html reports/pdf reports/csv reports/txt reports/json

#Verify installation
bash scripts/health_check.sh
```

### Step 2: Web App Installation
```bash
cd web_viewer

#Setup virtual environment
python3 -m venv venv
source venv/bin/activate

#Install requirements
pip install -r requirements.txt

#Initialize the database
python manage.py makemigrations
python manage.py migrate

mkdir -p staticfiles

#Create a superuser for website
python manage.py createsuperuser
#Follow the prompts for username, email, and password.

#Run Server
python manage.py runserver 127.0.0.1:8000
#Access at http://127.0.0.1:8000
#use 127.0.0.1 and not localhost to avoid iframe issues


##OPTIONAL DATABASE DOWNLOAD
#nmap
sudo nmap --script-updatedb
#Searchsploit
searchsploit -u
#SecLists
mkdir -p data/wordlists
git clone --depth 1 https://github.com/danielmiessler/SecLists.git data/wordlists/SecLists
#Wappalyzer
mkdir -p data/databases
git clone --depth 1 https://github.com/enthec/webappanalyzer.git data/databases/wappalyzer
```

### Step 3: Configuration web_viewer/config/settings.py
```json
#config.json created during setup
{
    "version": "1.0.0",
    "project_name": "CyberSecurity Suite",
    "paths": {
        "data_dir": "./data",
        "reports_dir": "./reports",
        "logs_dir": "./logs"
    },
    "scan_defaults": {
        "timing": "T4",
        "timeout": 300,
        "max_threads": 5
    },
    "notifications": {
        "beep_on_complete": true,
        "beep_on_finding": true
    }
}
```
```python
DATABASES = { #switch database to postgresql
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'cybersec',
        'USER': 'your_user',
        'PASSWORD': 'your_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}

DEBUG = FALSE
ALLOWED_HOST = ['*'] #or internal or local ip
SECRET_KEY = 'change_secret_key_to_a_string_long_and_random'
```

## 🐛 Known Issues & Fixes
### Issue 1: Scans stuck at 25% progress
Cause: sudo password prompt hanging in background thread
Fix: Configure NOPASSWD for nmap (see Step 6 above)

### Issue 2: Wappalyzer clone fails
- Cause: Repository moved
- Fix: Use https://github.com/enthec/webappanalyzer.git instead

### Issue 3: Searchsploit loading 0 entries
- Cause: CSV filename is files_exploits.csv not exploits.csv
- Fix: Ensure file exists at /opt/exploitdb/files_exploits.csv

### Issue 4: "No directory at staticfiles"
- Cause: Directory doesn't exist
- Fix: mkdir -p staticfiles

### Issue 5: PDF preview shows HTML content
- Cause: weasyprint not installed
- Fix: pip install weasyprint

### Issue 6: iframe preview blocked
- Cause: X-Frame-Options set to DENY
- Fix: Set X_FRAME_OPTIONS = 'SAMEORIGIN' in settings.py

### Issue 7: Reports empty after scan
- Cause: Missing settings import in scans/services.py
- Fix: Add from django.conf import settings at top of file

### Issue 8: "Module not found: config"
- Cause: Running Django tests from wrong directory
- Fix: Run tests from web_viewer/ directory: python manage.py test

### ✅ Post-Installation Checklist
- □ System tools installed (nmap, masscan, gobuster, hydra)
- □ Searchsploit installed from source
- □ Python virtual environment created
- □ Setup script completed
- □ Health check shows "All systems healthy"
- □ Sudo configured for nmap (NOPASSWD)
- □ Web app migrations run
- □ Superuser created
- □ Static directory created
- □ Web server starts at 127.0.0.1:8000
- □ Report directories exist
- □ Offline databases downloaded (optional)

## Verify Installation
## Test Main Project
```bash
cd /path/to/cybersec-suite
source .venv/bin/activate

# Test core modules
python3 tests/test_validator.py
python3 tests/test_database.py

# Test scanner
python3 -c "
from tools.port_scanner import PortScanner
scanner = PortScanner()
results = scanner.quick_scan('127.0.0.1')
print(f'Found {results[\"summary\"][\"total_open_ports\"]} open ports')
"
```

## Test Web App
```bash
cd web_viewer
source venv/bin/activate
python manage.py test

# Should show: Ran 43 tests, OK
```

## Test Full workflow
```bash
# Create target file
echo "127.0.0.1" > data/targets/test.txt

# Run quick scan
bash scripts/quick_scan.sh -t data/targets/test.txt

# Check reports
ls reports/html/
```

## 📞 Support
If you encounter issues not covered here:
- Check docs/TROUBLESHOOTING/COMMON_ISSUES.md
- Run bash scripts/health_check.sh
- Check logs in logs/ directory
- Review test failures with python manage.py test -v 2