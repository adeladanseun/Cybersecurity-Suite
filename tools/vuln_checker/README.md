# Vulnerability Checker Tool

Automated vulnerability assessment and CVE matching.

## Features
- Service vulnerability checking
- Web application vulnerability scanning
- SSL/TLS configuration audit
- Offline CVE database lookup
- Searchsploit integration
- Risk assessment and reporting

## Usage

### Service Vulnerability Check
```python
from tools.vuln_checker import ServiceVulnChecker

checker = ServiceVulnChecker()
vulns = checker.check_service("apache", "Apache", "2.4.49", 80, "example.com")