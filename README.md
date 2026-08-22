# CyberSecurity Suite

A comprehensive cybersecurity toolkit for network reconnaissance, vulnerability assessment, and penetration testing. Built with Python and Bash, featuring both CLI tools and a full-featured Django web application.

---

## 🛡️ Overview

CyberSecurity Suite is a modular security assessment platform that combines command-line tools with a web-based management interface. It automates the workflow from target discovery through vulnerability identification and report generation.

### Key Features

- **8 Standalone CLI Tools** — Port scanning, DNS enumeration, network discovery, web enumeration, vulnerability checking, exploitation testing, report building
- **Full Django Web Application** — Target management, scan orchestration, results viewing, report generation, vulnerability tracking
- **Offline CVE Database** — 44,000+ entries from ExploitDB/Searchsploit
- **Multi-format Reports** — HTML, PDF, CSV, TXT, JSON
- **REST API** — Full API access to all web app features
- **Notification System** — In-app and email notifications
- **Scheduled Scans** — Automate recurring assessments
- **Built-in Risk Scoring** — CVSS-based vulnerability prioritization

---

## 📁 Project Structure
cybersec-suite/

├── core/ # Core framework (file I/O, validation, logging, config)

├── tools/ # Standalone CLI tools

│ ├── port_scanner/ # Nmap-based port scanning

│ ├── dns_enum/ # DNS enumeration & subdomain discovery

│ ├── network_discovery/ # ARP/ICMP host discovery

│ ├── web_enum/ # Directory busting & tech fingerprinting

│ ├── vuln_checker/ # Vulnerability & CVE checking

│ ├── exploitation/ # Credential testing

│ └── report_builder/ # Multi-format report generation

├── scripts/ # Bash scripts for automation

├── data/ # Runtime data (targets, results, databases)

├── reports/ # Generated reports

├── web_viewer/ # Django web application

│ ├── accounts/ # User authentication

│ ├── targets/ # Target management

│ ├── scans/ # Scan orchestration

│ ├── results/ # Results viewing

│ ├── reports/ # Report generation

│ ├── vulnerabilities/ # Vulnerability management

│ ├── notifications/ # User notifications

│ ├── dashboard/ # Dashboard views

│ └── api/ # REST API

├── tests/ # Test suite

└── suite.sh # Main entry point


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

### Python Packages

```bash
pip install -r requirements.txt
```

### Django Packages
```bash
cd web_viewer
pip install -r requirements.txt
```

### Installation
```bash
## Main Project
# Clone or download the project
git clone [your-repository-url] cybersec-suite
cd cybersec-suite

# Run setup script
bash scripts/setup.sh

## Web App
cd web_viewer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Initialize database
python manage.py migrate

# Create admin user
python manage.py createsuperuser

# Run server
python manage.py runserver
```

### Quick Start

## CLI Tools
# Quick port scan
```bash
./suite.sh scan --quick -t data/targets/targets.txt
```

# Full audit
```bash
bash scripts/full_audit.sh -t data/targets/targets.txt
```

# Run health check
```bash
bash scripts/health_check.sh
```

## Python API
```bash
from tools.port_scanner import PortScanner

scanner = PortScanner()
results = scanner.quick_scan("192.168.X.X")
print(f"Found {results['summary']['total_open_ports']} open ports")
```
### Web Interface
- Start server: cd web_viewer && python manage.py runserver

- Open: http://127.0.0.1:8000

- Login or register

- Add target → Run scan → View results → Generate report


### Testing
```bash
## Main Project Test
# Run all tests
python3 tests/test_validator.py
python3 tests/test_file_manager.py
python3 tests/test_config.py
python3 tests/test_logger.py
python3 tests/test_notifier.py
python3 tests/test_database.py
python3 tests/test_integration.py
python3 tests/test_port_scanner.py
python3 tests/test_report_builder.py
python3 tests/test_dns_enum.py
python3 tests/test_network_discovery.py
python3 tests/test_web_enum.py
python3 tests/test_vuln_checker.py
python3 tests/test_exploitation.py


## Web App Test
cd web_viewer
source venv/bin/activate
python manage.py test
```




### 📊 Features in Detail
## CLI Tools
| Tool |	Function |
|------|---------|
| Port Scanner |	TCP/UDP scanning, service detection, OS fingerprinting |
| DNS Enumeration |	Record enumeration, zone transfer, subdomain discovery |
| Network Discovery |	ARP/ICMP host discovery, network mapping |
| Web Enumeration |	Directory brute forcing, tech fingerprinting |
| Vulnerability | Checker	CVE matching, SSL/TLS audit, web vulnerability checks |
| Exploitation |	Credential testing, default credential checking |
| Report Builder |	HTML/PDF/CSV/TXT/JSON reports with risk scoring |

## Web App
| Module |	Function |
|------|---------|
| Dashboard |	Statistics, recent activity, notifications |
| Targets |	CRUD operations, import/export, groups, projects |
| Scans |	Execute scans, track progress, schedule recurring scans |
| Results |	View port scans, vulnerabilities, export data |
| Reports |	Generate reports, templates, download/preview |
| Vulnerabilities |	Track findings, remediation tasks, notes, status workflow |
| API |	REST endpoints for all features|
| Notifications |	In-app alerts, email preferences|


## 🔒 Security
- For Authorized Testing Only
- Always obtain written permission before testing
- Results contain sensitive data — keep secure
- Use strong passwords for web app accounts
- Run web app on trusted networks only

## 📄 License
MIT License

## ⚠️ Disclaimer
This tool is for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this software. Always comply with applicable laws and regulations.

## 🤝 Contributing
- Contributions are welcome! Please:
- Fork the repository
- Create a feature branch
- Make your changes
- Run tests
- Submit a pull request

## 📚 Documentation
- Installation Guide
- Quick Start
- CLI Tools Guide
- Web Interface Guide
- Workflows
- Architecture
- API Reference
- Testing Guide
- Troubleshooting


## Version: 1.0.0
Last Updated: 2026-08-20