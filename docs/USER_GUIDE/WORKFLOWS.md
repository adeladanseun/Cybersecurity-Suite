# Workflows Guide

This guide covers common workflows for using CyberSecurity Suite effectively in real-world scenarios.

---

## Overview

CyberSecurity Suite supports multiple workflows depending on your needs. Each workflow combines CLI tools, bash scripts, and web application features to accomplish specific security assessment tasks.

---

## Workflow 1: Quick Assessment

**Goal:** Get a rapid overview of a target's security posture.

**Time:** 5-10 minutes

### Steps

1. **Create target file** (CLI method)
```bash
echo "192.168.1.10" > data/targets/quick.txt
```

2. **Run quick scan**
```bash
bash scripts/quick_scan.sh -t data/targets/quick.txt
```

3. **Review results**
- Check `reports/html/` for HTML report
- Check `reports/txt/` for text summary
- Review open ports and services

4. **Alternative: Web app method**
- Add target in web app
- Run "Port Scan" with `{"ports": "top-1000"}`
- View results in Results section

### When to Use
- Initial reconnaissance
- Quick check after changes
- Routine monitoring

---

## Workflow 2: Full Security Audit

**Goal:** Comprehensive security assessment with vulnerability identification.

**Time:** 30 minutes to several hours

### Steps

1. **Create target list**
```bash
cat > data/targets/audit.txt << EOF
192.168.1.10
192.168.1.20
example.com
EOF
```

2. **Run full audit script**
```bash
bash scripts/full_audit.sh -t data/targets/audit.txt
```

This executes:
- Network discovery
- Full port scanning (all 65535 ports)
- Service version detection
- Vulnerability checking against CVE database
- Multi-format report generation

3. **Review results**
- `data/intermediate/audit_*_scan.json` — Port scan data
- `data/intermediate/audit_*_vulns.json` — Vulnerability data
- `reports/html/` — HTML reports
- `reports/csv/` — CSV exports

4. **Generate executive report**
```python
from tools.report_builder import ReportGenerator
import json

with open('data/intermediate/audit_*_vulns.json') as f:
    data = json.load(f)

generator = ReportGenerator()
generator.generate_report(
    data,
    report_type='executive',
    formats=['html', 'pdf']
)
```

### When to Use
- Initial assessments
- Compliance audits
- Penetration testing engagements

---

## Workflow 3: Web Application Testing

**Goal:** Test web applications for vulnerabilities and misconfigurations.

**Time:** 15-30 minutes per application

### Steps

1. **Technology fingerprinting**
```python
from tools.web_enum import TechFingerprint

fingerprint = TechFingerprint()
results = fingerprint.fingerprint("https://target.com")
```

2. **Directory brute forcing**
```python
from tools.web_enum import DirBuster

buster = DirBuster()
results = buster.brute_force(
    "https://target.com",
    wordlist=['admin', 'login', 'api', 'uploads']
)
```

3. **Parameter discovery**
```python
from tools.web_enum import ParamFuzzer

fuzzer = ParamFuzzer()
results = fuzzer.discover_params("https://target.com/page")
```

4. **Vulnerability checking**
```python
from tools.vuln_checker import WebVulnChecker

checker = WebVulnChecker()
results = checker.check_url(
    "https://target.com/page?id=1",
    checks=['sqli', 'xss', 'headers']
)
```

5. **Web app method**
- Use scan types: `tech_fingerprint`, `dir_buster`, `param_fuzzer`, `web_vuln_scan`
- Results appear in Results section

### When to Use
- Web application assessments
- API testing
- New deployment reviews

---

## Workflow 4: DNS Assessment

**Goal:** Enumerate DNS records and discover subdomains.

**Time:** 10-20 minutes

### Steps

1. **DNS enumeration**
```python
from tools.dns_enum import DNSEnumerator

enumerator = DNSEnumerator()
results = enumerator.enumerate(
    "example.com",
    record_types=['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
)
```

2. **Zone transfer test**
```python
from tools.dns_enum import ZoneTransfer

zt = ZoneTransfer()
results = zt.attempt_transfer("example.com")

if results['vulnerable']:
    print(f"Zone transfer possible! {len(results['records'])} records found")
```

3. **Subdomain discovery**
```python
from tools.dns_enum import SubdomainFinder

finder = SubdomainFinder()
results = finder.find_subdomains("example.com")
```

4. **Reverse DNS lookup**
```python
results = enumerator.reverse_lookup("8.8.8.8")
```

### When to Use
- Domain reconnaissance
- Attack surface discovery
- DNS misconfiguration testing

---

## Workflow 5: Network Discovery

**Goal:** Map internal networks and identify live hosts.

**Time:** 5-15 minutes

### Steps

1. **Discover local networks**
```python
from tools.network_discovery import NetworkDiscovery

discovery = NetworkDiscovery()
networks = discovery.get_local_networks()

for network in networks:
    print(f"{network['interface']}: {network['network']}")
```

2. **Scan network for hosts**
```python
results = discovery.discover_network("192.168.1.0/24", method='arp')
```

3. **Create network map**
```python
from tools.network_discovery import NetworkMapper

mapper = NetworkMapper()
network_map = mapper.create_network_map(results)
mapper.export_network_map(network_map, format='html')
```

4. **Enrich with vendor info**
```python
from tools.network_discovery import ARPScanner

scanner = ARPScanner()
hosts = scanner.scan_network("192.168.1.0/24")
hosts = scanner.enrich_with_vendor(hosts)
```

### When to Use
- Internal network mapping
- Device inventory
- Rogue device detection

---

## Workflow 6: Vulnerability Management

**Goal:** Track and remediate vulnerabilities over time.

**Time:** Ongoing

### Steps

1. **Run vulnerability scan**
```bash
# CLI method
python3 -c "
from tools.vuln_checker import ServiceVulnChecker, CVELookup
from tools.port_scanner import PortScanner

scanner = PortScanner()
port_results = scanner.scan('target.com', service_detection=True)

checker = ServiceVulnChecker()
vulns = checker.check_scan_results(port_results)
"
```

2. **Review findings in web app**
- Navigate to Vulnerabilities
- Filter by severity
- Review each finding

3. **Assign priorities**
- P1: Critical, immediate action
- P2: High, urgent
- P3: Medium, scheduled
- P4: Low, routine

4. **Create remediation tasks**
- Click vulnerability
- Add task with title, description
- Assign to team member
- Set due date

5. **Track progress**
- Update status as work progresses
- Add notes documenting findings
- Mark as resolved when complete

6. **Generate status report**
- Navigate to Reports
- Generate Findings Report
- Export as PDF for stakeholders

### When to Use
- Ongoing security programs
- Compliance requirements
- Risk management

---

## Workflow 7: Scheduled Monitoring

**Goal:** Automate regular security checks.

**Time:** Setup once, runs automatically

### Steps

1. **Create scheduled scan in web app**
- Navigate to Scans → Scheduled
- Click "Schedule Scan"
- Select target and scan type
- Choose frequency (daily, weekly, monthly)
- Set time

2. **Configure notifications**
- Navigate to Notifications → Settings
- Enable email alerts
- Enable in-app notifications

3. **Review results regularly**
- Check dashboard for new scan results
- Review scan comparison
- Investigate changes

### CLI Alternative

```bash
# Add to crontab
crontab -e

# Daily scan at 3 AM
0 3 * * * cd /path/to/cybersec-suite && bash scripts/quick_scan.sh -t data/targets/production.txt

# Weekly full audit
0 2 * * 0 cd /path/to/cybersec-suite && bash scripts/full_audit.sh -t data/targets/production.txt
```

### When to Use
- Production monitoring
- Change detection
- Compliance requirements

---

## Workflow 8: Metasploitable Testing

**Goal:** Practice and validate tools against a known vulnerable system.

**Time:** 1-2 hours

### Setup

1. **Start Metasploitable VM**
- Ensure VM is running
- Get IP address (typically 192.168.x.x)

2. **Create target**
```bash
echo "192.168.43.58" > data/targets/metasploitable.txt
```

### Testing Steps

1. **Port scan**
```bash
bash scripts/quick_scan.sh -t data/targets/metasploitable.txt
```

Expected: 20+ open ports including FTP, SSH, Telnet, MySQL, PostgreSQL, VNC, IRC

2. **Service detection**
```python
from tools.port_scanner import PortScanner

scanner = PortScanner()
results = scanner.scan(
    "192.168.43.58",
    service_detection=True
)
```

Expected: Identifies vsftpd 2.3.4, UnrealIRCd, Samba, Apache 2.2.8

3. **Vulnerability scan**
```python
from tools.vuln_checker import ServiceVulnChecker, CVELookup

checker = ServiceVulnChecker()
vulns = checker.check_scan_results(results)
```

Expected: Finds CVE-2011-2523 (vsftpd backdoor), CVE-2010-2075 (UnrealIRCd)

4. **Generate report**
```bash
bash scripts/full_audit.sh -t data/targets/metasploitable.txt
```

### Known Findings

| Service | Version | CVE | Severity |
|---------|---------|-----|----------|
| vsftpd | 2.3.4 | CVE-2011-2523 | Critical |
| UnrealIRCd | 3.2.8.1 | CVE-2010-2075 | Critical |
| Apache | 2.2.8 | Multiple | High |
| MySQL | 5.0.51a | Multiple | High |
| PostgreSQL | 8.3 | Multiple | High |
| Samba | 3.x | Multiple | High |

---

## Workflow 9: Credential Testing

**Goal:** Test for weak or default credentials.

**Time:** 10-30 minutes

### Steps

1. **Create credentials file**
```bash
cat > credentials.txt << EOF
admin:admin
root:root
msfadmin:msfadmin
user:user
EOF
```

2. **Test from scan results**
```python
from tools.exploitation import CredTester
from tools.port_scanner import PortScanner

# First scan
scanner = PortScanner()
results = scanner.quick_scan("192.168.43.58")

# Test credentials
tester = CredTester()
results = tester.test_from_scan(
    results,
    credentials_file='credentials.txt'
)
```

3. **Check default credentials**
```python
from tools.exploitation import DefaultCredChecker

checker = DefaultCredChecker()
results = checker.check_device("192.168.43.58", "router")
```

4. **Web app method**
- Navigate to Vulnerabilities → Cred Check
- Enter target IP
- Select device type
- Click Check

### When to Use
- Password policy audits
- Device hardening verification
- Penetration testing

---

## Workflow 10: Report Generation Pipeline

**Goal:** Generate professional reports for stakeholders.

**Time:** 5-15 minutes

### Steps

1. **Collect scan data**
```python
import json

# Load from file
with open('data/intermediate/scan_results.json') as f:
    data = json.load(f)
```

2. **Generate multiple formats**
```python
from tools.report_builder import ReportGenerator

generator = ReportGenerator()

files = generator.generate_report(
    data,
    report_type='full',
    formats=['html', 'pdf', 'csv', 'txt', 'json'],
    report_name='security_assessment_2024'
)
```

3. **Generate executive summary**
```python
files = generator.generate_report(
    data,
    report_type='executive',
    formats=['html', 'pdf'],
    report_name='executive_summary'
)
```

4. **Generate findings report**
```python
files = generator.generate_report(
    data,
    report_type='findings',
    formats=['csv', 'txt'],
    report_name='vulnerability_findings'
)
```

5. **Calculate risk score**
```python
from tools.report_builder import RiskCalculator

calculator = RiskCalculator()
risk = calculator.calculate_risk_score(data)

print(f"Risk Score: {risk['score']}")
print(f"Level: {risk['level']}")
print(f"Summary: {risk['summary']}")
```

### When to Use
- Client deliverables
- Compliance reporting
- Executive briefings

---

## Best Practices for All Workflows

1. **Document everything** — Keep notes and scan results
2. **Use descriptive names** — Makes reports readable
3. **Test on authorized targets only** — Legal compliance
4. **Keep databases updated** — Latest CVE information
5. **Review false positives** — Automated tools aren't perfect
6. **Track changes over time** — Use scan comparison
7. **Prioritize findings** — Focus on critical first
8. **Communicate clearly** — Use executive summaries for non-technical stakeholders