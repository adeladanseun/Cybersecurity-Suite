# CyberSecurity Suite

A comprehensive cybersecurity toolkit for network reconnaissance, vulnerability assessment, and penetration testing. Built with Python and Bash, featuring both CLI tools and a full-featured Django web application.

---

## 🛡️ Overview

CyberSecurity Suite is a modular security assessment platform that automates the workflow from target discovery through vulnerability identification and report generation. It combines 8 standalone command-line tools with a web-based management interface, REST API, and offline CVE database.

### Key Features

- **8 Standalone CLI Tools** — Port scanning, DNS enumeration, network discovery, web enumeration, vulnerability checking, exploitation testing, report building
- **Full Django Web Application** — Target management, scan orchestration, results viewing, report generation, vulnerability tracking
- **15 Scan Types** — TCP, UDP, full port, service detection, DNS, subdomain, reverse DNS, zone transfer, directory brute force, tech fingerprinting, web vuln scans, parameter discovery, vulnerability scanning, SSL/TLS audit
- **Offline CVE Database** — 44,000+ entries from ExploitDB/Searchsploit
- **Multi-format Reports** — HTML, PDF, CSV, TXT, JSON with risk scoring
- **REST API** — Full API access to all web app features
- **Notification System** — In-app and email notifications
- **Scheduled Scans** — Automate recurring assessments
- **Scan Comparison** — Track security posture changes over time
- **CVE Search** — Search 44,000+ vulnerabilities from web interface
- **Default Credential Check** — Test devices for known default passwords
- **CVSS-based Risk Scoring** — Vulnerability prioritization

---

## 📁 Project Structure

```
cybersec-suite/
├── core/                    # Core framework (file I/O, validation, logging, config)
├── tools/                   # Standalone CLI tools
│   ├── port_scanner/        # Nmap-based port scanning
│   ├── dns_enum/            # DNS enumeration & subdomain discovery
│   ├── network_discovery/   # ARP/ICMP host discovery
│   ├── web_enum/            # Directory busting & tech fingerprinting
│   ├── vuln_checker/        # Vulnerability & CVE checking
│   ├── exploitation/        # Credential testing
│   └── report_builder/      # Multi-format report generation
├── scripts/                 # Bash scripts for automation
├── data/                    # Runtime data (targets, results, databases)
├── reports/                 # Generated reports
├── web_viewer/              # Django web application
│   ├── accounts/            # User authentication
│   ├── targets/             # Target management
│   ├── scans/               # Scan orchestration
│   ├── results/             # Results viewing
│   ├── reports/             # Report generation
│   ├── vulnerabilities/     # Vulnerability management
│   ├── notifications/       # User notifications
│   ├── dashboard/           # Dashboard views
│   └── api/                 # REST API
├── docs/                    # Complete documentation
│   ├── USER_GUIDE/          # CLI tools, web interface, workflows
│   ├── DEVELOPER_GUIDE/     # Architecture, core modules, development
│   ├── API_REFERENCE/       # Core, tools, REST API
│   ├── TESTING/             # Test guide, test plan
│   └── TROUBLESHOOTING/     # Common issues, FAQ
├── tests/                   # Test suite
├── INSTALLATION.md          # Installation guide
├── QUICK_START.md           # Quick start guide
└── suite.sh                 # Main entry point
```

---

## 🔧 Requirements

### System Requirements

- **OS:** Kali Linux (preferred) or Ubuntu/Debian
- **Python:** 3.8+
- **RAM:** 2GB minimum (4GB recommended)
- **Disk:** 1GB+ for project + databases

### Required Tools

| Tool | Purpose | Install |
|------|---------|---------|
| nmap | Port scanning | `sudo apt install nmap` |
| masscan | Fast port scanning | `sudo apt install masscan` |
| gobuster | Directory brute forcing | `sudo apt install gobuster` |
| hydra | Credential testing | `sudo apt install hydra` |
| searchsploit | CVE database | Install from source |
| whois | Domain information | `sudo apt install whois` |
| dnsutils | DNS tools | `sudo apt install dnsutils` |

---

## 🚀 Installation

```bash
# Clone the repository
git clone [repository-url] cybersec-suite
cd cybersec-suite

# Install system tools
sudo apt update
sudo apt install -y nmap masscan gobuster hydra whois dnsutils

# Install searchsploit from source
sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# Run setup script
bash scripts/setup.sh

# Configure sudo for nmap (IMPORTANT for web app)
sudo visudo
# Add: YOUR_USERNAME ALL=(ALL) NOPASSWD: /usr/bin/nmap
```

### Web App Installation

```bash
cd web_viewer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python manage.py makemigrations
python manage.py migrate
mkdir -p staticfiles
python manage.py createsuperuser
python manage.py runserver 127.0.0.1:8000
```

**Full instructions:** See [INSTALLATION.md](INSTALLATION.md)

---

## 📖 Quick Start

### CLI Scan

```bash
# Create target file
echo "192.168.1.1" > data/targets/targets.txt

# Quick scan
bash scripts/quick_scan.sh -t data/targets/targets.txt

# Full audit
bash scripts/full_audit.sh -t data/targets/targets.txt
```

### Python API

```python
from tools.port_scanner import PortScanner

scanner = PortScanner()
results = scanner.quick_scan("192.168.1.1")
print(f"Found {results['summary']['total_open_ports']} open ports")
```

### Web Interface

1. Start server: `cd web_viewer && python manage.py runserver`
2. Open: `http://127.0.0.1:8000`
3. Register or login
4. Add target → Run scan → View results → Generate report

**More examples:** See [QUICK_START.md](QUICK_START.md)

---

## 🧪 Testing

### Main Project (96 test groups)

```bash
source .venv/bin/activate

# Core tests
python3 tests/test_validator.py
python3 tests/test_file_manager.py
python3 tests/test_config.py
python3 tests/test_logger.py
python3 tests/test_notifier.py
python3 tests/test_database.py
python3 tests/test_integration.py

# Tool tests
python3 tests/test_port_scanner.py
python3 tests/test_report_builder.py
python3 tests/test_dns_enum.py
python3 tests/test_network_discovery.py
python3 tests/test_web_enum.py
python3 tests/test_vuln_checker.py
python3 tests/test_exploitation.py
```

### Web App (43 tests)

```bash
cd web_viewer
source venv/bin/activate
python manage.py test
```

**Total: 139 tests passing across all modules.**

---

## 📊 Tools Overview

### CLI Tools

| Tool | Function |
|------|----------|
| Port Scanner | TCP/UDP scanning, service detection, scan comparison |
| DNS Enumeration | Record enumeration, zone transfer, subdomain discovery |
| Network Discovery | ARP/ICMP host discovery, network mapping |
| Web Enumeration | Directory brute forcing, tech fingerprinting, parameter fuzzing |
| Vulnerability Checker | CVE matching, SSL/TLS audit, web vulnerability checks |
| Exploitation | Credential testing, default credential checking |
| Report Builder | HTML/PDF/CSV/TXT/JSON reports with risk scoring |

### Web App Features

| Module | Features |
|--------|----------|
| Dashboard | Statistics, recent activity, notifications |
| Targets | CRUD, import/export, groups, projects |
| Scans | 15 scan types, progress tracking, scheduled scans, comparison |
| Results | Port results, vulnerability results, export |
| Reports | Generation, templates, preview, download |
| Vulnerabilities | Tracking, remediation tasks, notes, CVE search, cred check |
| API | REST endpoints for all features |
| Notifications | In-app alerts, email preferences |

---

## 📚 Documentation

### User Guides
- [CLI Tools Guide](docs/USER_GUIDE/CLI_TOOLS.md)
- [Web Interface Guide](docs/USER_GUIDE/WEB_INTERFACE.md)
- [Workflows Guide](docs/USER_GUIDE/WORKFLOWS.md)

### Developer Guides
- [Architecture](docs/DEVELOPER_GUIDE/ARCHITECTURE.md)
- [Core Modules](docs/DEVELOPER_GUIDE/CORE_MODULES.md)
- [Tool Development](docs/DEVELOPER_GUIDE/TOOL_DEVELOPMENT.md)
- [Web App Development](docs/DEVELOPER_GUIDE/WEB_APP_DEVELOPMENT.md)

### API Reference
- [Core API](docs/API_REFERENCE/CORE_API.md)
- [Tools API](docs/API_REFERENCE/TOOLS_API.md)
- [REST API](docs/API_REFERENCE/REST_API.md)

### Testing & Support
- [Testing Guide](docs/TESTING/TEST_GUIDE.md)
- [Test Plan](docs/TESTING/TEST_PLAN.md)
- [Common Issues](docs/TROUBLESHOOTING/COMMON_ISSUES.md)
- [FAQ](docs/TROUBLESHOOTING/FAQ.md)

---

## ✅ Validated Against Metasploitable

The suite has been tested end-to-end against Metasploitable VM:

- 23 open ports discovered
- 35 vulnerabilities identified
- Critical backdoor found (CVE-2011-2523)
- Reports generated in all formats
- Full workflow validated

---

## 🔒 Security

- **For Authorized Testing Only**
- Always obtain written permission before testing
- Results contain sensitive data — keep secure
- Use strong passwords for web app accounts
- Run web app on trusted networks only

---

## 📄 License

MIT License

---

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this software. Always comply with applicable laws and regulations.

---

## 📊 Project Status

- ✅ Core Framework (40 test groups)
- ✅ 8 CLI Tools (all tests passing)
- ✅ Bash Scripts (working)
- ✅ Django Web App (43 tests passing)
- ✅ CVE Database (44,220 entries)
- ✅ 15 Scan Types
- ✅ Metasploitable assessment validated
- ✅ Complete documentation
- ✅ 139 total tests passing

---

**Version:** 1.0.0  
**Last Updated:** August 2026
