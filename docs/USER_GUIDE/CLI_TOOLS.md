# CLI Tools Guide

This guide covers all command-line tools available in CyberSecurity Suite, including usage examples and output formats.

---

## Overview

The suite provides 8 standalone CLI tools that can be used independently or as part of automated workflows. Each tool follows a consistent pattern for initialization, execution, and result handling. All tools are located in the `tools/` directory and can be imported from Python scripts or used through the bash scripts provided in `scripts/`.

---

## Port Scanner

**Location:** `tools/port_scanner/`

The port scanner wraps nmap to provide TCP, UDP, and service detection scanning with progress tracking and structured results.

### Basic Usage

```python
from tools.port_scanner import PortScanner

scanner = PortScanner()

# Quick scan (top 1000 ports)
results = scanner.quick_scan("192.168.1.1")

# Full scan (all ports with service detection)
results = scanner.full_scan("192.168.1.1")

# UDP scan
results = scanner.udp_scan("192.168.1.1")

# Custom scan
results = scanner.scan(
    "192.168.1.1",
    scan_type='tcp',
    ports='80,443,8080',
    timing='T4',
    service_detection=True,
    script_scan=False,
    ping_first=True,
    sudo=True
)

# Scan multiple targets
targets = ['192.168.1.1', '192.168.1.2', 'example.com']
results = scanner.scan_multiple(targets)
```

### Scan Types
| Method	| Ports	| Service Detection	| NSE Scripts	| Use Case |
|----|----|----|----|----|
| quick_scan()	| top-1000	| No	| No	| Fast reconnaissance |
| full_scan()	| 1-65535	| Yes	| Yes	| Comprehensive audit |
| udp_scan()	| top-100	| Yes	| No	| UDP service discovery |
| scan()	| Custom	| Optional	| Optional	| Flexible scanning |

### Parameters
| Parameter	 | Values	 | Default	 | Description |
|---|---|---|---|
| scan_type	 | 'tcp', 'udp', 'both'	 | 'tcp'	 | Protocol to scan |
| ports	 | '80,443', '1-1000', 'top-100'	 | 'top-1000' |	Port specification | 
| timing	 | 'T0' to 'T5'	 | 'T4'	 | Scan speed |
| service_detection	 | True/False	 | False	 | Version  detection |
| script_scan	 | True/False	 | False	 | Run NSE scripts |
| ping_first	 | True/False	 | True	 | Ping before scan |
| sudo	 | True/False	 | True	| Use sudo for SYN scan |

## Result Structure
```python
{
    'scan_metadata': {
        'target': '192.168.1.1',
        'duration': 45.5,
        'command': 'sudo nmap -T4 ...'
    },
    'hosts': [
        {
            'ip': '192.168.1.1',
            'status': 'up',
            'ports': [...]
        }
    ],
    'ports': [
        {
            'port': 80,
            'protocol': 'tcp',
            'state': 'open',
            'service': 'http',
            'product': 'Apache',
            'version': '2.4.41'
        }
    ],
    'summary': {
        'total_open_ports': 10,
        'hosts_up': 1,
        'service_counts': {'http': 2, 'ssh': 1}
    }
}
```

## Scan Differ
### Compare two scan to detect changes
```python
from tools.port_scanner import ScanDiffer

differ = ScanDiffer()
diff = differ.compare_scans(current_scan, previous_scan)

print(f"New ports: {diff['summary']['total_new']}")
print(f"Closed ports: {diff['summary']['total_closed']}")
print(f"Changed ports: {diff['summary']['total_changed']}")
print(f"Risk level: {diff['summary']['risk_level']}")

# Generate diff report
report = differ.generate_diff_report(diff, 'diff_report.txt')
```

## DNS Enumeration
### Location: tools/dns_enum/
- Performs comprehensive DNS record enumeration, subdomain discovery, and zone transfer testing.
Basic Usage
```python
from tools.dns_enum import DNSEnumerator

enumerator = DNSEnumerator()

# Enumerate all record types
results = enumerator.enumerate("example.com")

# Enumerate specific records
results = enumerator.enumerate(
    "example.com",
    record_types=['A', 'MX', 'NS', 'TXT']
)

# Use custom DNS servers
results = enumerator.enumerate(
    "example.com",
    dns_servers=['8.8.8.8', '1.1.1.1']
)

# Reverse lookup
result = enumerator.reverse_lookup("8.8.8.8")

# Get mail servers
mail_servers = enumerator.get_mail_servers("example.com")

# Get name servers
name_servers = enumerator.get_name_servers("example.com")

# Check DNSSEC
dnssec = enumerator.check_dnssec("example.com")

# Get TXT records
txt_records = enumerator.get_txt_records("example.com")

# Enumerate multiple domains
domains = ['example.com', 'test.com']
results = enumerator.enumerate_multiple(domains)
```

Record Types
Type	Description
A	IPv4 address
AAAA	IPv6 address
MX	Mail servers
NS	Name servers
TXT	Text records
SOA	Start of authority
CNAME	Canonical name
PTR	Reverse lookup
SRV	Service records


## Zone Transfer
```python
from tools.dns_enum import ZoneTransfer

zt = ZoneTransfer()

# Test single domain
results = zt.attempt_transfer("example.com")

if results['vulnerable']:
    print(f"Zone transfer possible!")
    print(f"Records found: {len(results['records'])}")
    print(f"Vulnerable NS: {results['vulnerable_nameserver']}")

# Test multiple domains
domains = ['example.com', 'test.com', 'vulnerable.org']
results = zt.test_multiple(domains)
```

## Subdomain Discovery
```python
from tools.dns_enum import SubdomainFinder

finder = SubdomainFinder()

# Use built-in wordlist
results = finder.find_subdomains("example.com")

# Use custom wordlist file
results = finder.find_from_file("example.com", "wordlist.txt")

# Use custom wordlist with more threads
results = finder.find_subdomains(
    "example.com",
    wordlist=['www', 'mail', 'ftp', 'admin'],
    max_threads=20
)

# Passive discovery using certificate transparency
subdomains = finder.passive_discovery("example.com")
```


## Network Discovery
### Location: tools/network_discovery/
- Identifies live hosts on internal networks using ARP, ICMP, or nmap.
```python
from tools.network_discovery import NetworkDiscovery

discovery = NetworkDiscovery()

# Discover hosts on network (auto method)
results = discovery.discover_network("192.168.1.0/24")

# Use specific method
results = discovery.discover_network("192.168.1.0/24", method='arp')
results = discovery.discover_network("192.168.1.0/24", method='ping')
results = discovery.discover_network("192.168.1.0/24", method='nmap')

# Get local network interfaces
interfaces = discovery.get_network_interfaces()

# Get local networks
networks = discovery.get_local_networks()
```


Discovery Methods
Method	Use Case	Requirements
arp	Local networks	Root, scapy
ping	Any network	ICMP allowed
nmap	Any network	nmap installed
auto	Automatic selection	Detects best method


## ARP Scanner
```python
from tools.network_discovery import ARPScanner

scanner = ARPScanner()

# Scan network
hosts = scanner.scan_network("192.168.1.0/24")

# Enrich with vendor info
hosts = scanner.enrich_with_vendor(hosts)

# Check single host
is_alive = scanner.scan_single("192.168.1.1")
```

## Network Mapper
```python
from tools.network_discovery import NetworkMapper

mapper = NetworkMapper()

# Create network map
network_map = mapper.create_network_map(discovery_results)

# Export in different formats
mapper.export_network_map(network_map, format='json')
mapper.export_network_map(network_map, format='txt')
mapper.export_network_map(network_map, format='csv')
mapper.export_network_map(network_map, format='html')
```


### Web Enumeration
## Location: tools/web_enum/
- Performs directory brute forcing, technology fingerprinting, and parameter discovery on web applications.

# Directory Buster
```python
from tools.web_enum import DirBuster

buster = DirBuster()

# Use default wordlist
results = buster.brute_force("https://example.com")

# Use custom wordlist
results = buster.brute_force(
    "https://example.com",
    wordlist=['admin', 'login', 'api', 'uploads'],
    extensions=['', '.php', '.html'],
    threads=10
)

# Use wordlist from file
results = buster.brute_force_with_file(
    "https://example.com",
    "wordlist.txt"
)
```

# Technology Fingerprint
```python
from tools.web_enum import TechFingerprint

fingerprint = TechFingerprint()

# Single URL
results = fingerprint.fingerprint("https://example.com")

# Multiple URLs
urls = ['https://example.com', 'https://test.com']
results = fingerprint.fingerprint_multiple(urls)
```

# Parameter Fuzzer
```python
from tools.web_enum import ParamFuzzer

fuzzer = ParamFuzzer()

# Discover hidden parameters
results = fuzzer.discover_params("https://example.com/page")

# Use custom parameters
results = fuzzer.discover_params(
    "https://example.com/page",
    params=['id', 'file', 'path', 'debug']
)

# Fuzz specific parameter values
results = fuzzer.fuzz_param_values(
    "https://example.com/page",
    param='id',
    fuzz_values=['1', '2', 'admin', 'test']
)
```

### Vulnerability Checker
## Location: tools/vuln_checker/
- Checks services for known vulnerabilities, performs SSL/TLS audits, and matches against CVE database.

# Service Vulnerability Check
```python
from tools.vuln_checker import ServiceVulnChecker

checker = ServiceVulnChecker()

# Check single service
vulns = checker.check_service(
    service='ftp',
    product='vsftpd',
    version='2.3.4',
    port=21,
    host='192.168.1.1'
)

# Check full scan results
results = checker.check_scan_results(scan_results)

# Check from file
results = checker.check_from_file('scan_results.json')
```

# CVE Lookup
```python
from tools.vuln_checker import CVELookup

cve = CVELookup()

# Search by service
results = cve.search_by_service('apache')

# Search with version
results = cve.search_by_service('apache', '2.4.49')

# Lookup specific CVE
info = cve.lookup_cve('CVE-2021-41773')

# Check scan results against CVE database
results = cve.check_vulnerabilities(scan_results)
```

# SSL Checker
```python
from tools.vuln_checker import SSLChecker

ssl_checker = SSLChecker()

# Check SSL/TLS
results = ssl_checker.check_ssl("example.com", port=443)

print(f"Grade: {results['summary']['grade']}")
print(f"Issues: {results['summary']['total_issues']}")
```

# Web Vulnerability Check
```python
from tools.vuln_checker import WebVulnChecker

web_checker = WebVulnChecker()

# Check URL for vulnerabilities
results = web_checker.check_url(
    "https://example.com/page?id=1",
    checks=['sqli', 'xss', 'headers']
)
```

### Exploitation Testing
## Location: tools/exploitation/
- Tests credentials against services and checks for default credentials.

# Credential Tester
```python
from tools.exploitation import CredTester

tester = CredTester()

# Test specific credentials
results = tester.test_credentials(
    "192.168.1.1",
    "ssh",
    credentials=[('admin', 'admin'), ('root', 'root')]
)

# Test from scan results
results = tester.test_from_scan(scan_results)

# Use custom credentials file
results = tester.test_from_scan(
    scan_results,
    credentials_file='credentials.txt'
)
```

# Default Credential Checker
```python
from tools.exploitation import DefaultCredChecker

checker = DefaultCredChecker()

# Check device for default credentials
results = checker.check_device("192.168.1.1", "router")

# Get default credentials for device type
creds = checker.get_default_credentials(device_type='router')

# Scan multiple hosts
hosts = ['192.168.1.1', '192.168.1.2']
results = checker.scan_network(hosts)
```

### Report Builder
## Location: tools/report_builder/
- Generates reports in multiple formats with risk scoring.

# Basic Usage
```python
from tools.report_builder import ReportGenerator

generator = ReportGenerator()

# Generate report
files = generator.generate_report(
    scan_data,
    report_type='full',
    formats=['html', 'pdf', 'csv', 'txt', 'json'],
    report_name='security_assessment'
)

print(f"Generated files: {files}")
```

Report Types
Type	Description
executive	High-level summary for management
technical	Detailed technical report
findings	Focused on security findings
full	Complete comprehensive report

# Risk Calculator
```python
from tools.report_builder import RiskCalculator

calculator = RiskCalculator()

# Calculate overall risk
risk = calculator.calculate_risk_score(scan_data)

print(f"Score: {risk['score']}")
print(f"Level: {risk['level']}")

# Calculate individual port risk
port_risk = calculator.calculate_port_risk(
    port=22,
    service='ssh',
    version='8.0'
)
```

# Diff Reports
```python
from tools.report_builder import DiffReportGenerator

diff_gen = DiffReportGenerator()
diff = diff_gen.generate_diff(current_data, previous_data)
```


### Bash Scripts
## The suite also provides bash scripts for common workflows.

# Quick Scan
```bash
bash scripts/quick_scan.sh -t data/targets/targets.txt
```

# Full Audit
```bash
bash scripts/full_audit.sh -t data/targets/targets.txt
```

# Health Check
```bash
bash scripts/health_check.sh
```

# Update Databases
```bash
bash scripts/update_databases.sh
```

# Main Entry Point
```bash
./suite.sh scan --quick -t data/targets/targets.txt
./suite.sh report -i data/intermediate/scan.json
./suite.sh health
```

Output Files
All tools save results in data/intermediate/ directory:

| File Pattern |	Tool |	Format |
|---|---|---|
| nmap_*.xml	Port Scanner |	Nmap XML |
| nmap_*.txt |	Port Scanner |	Nmap text |
| scan_*.json |	Port Scanner |	Structured JSON |
| dns_*.json |	DNS Enum |	JSON |
| subdomains_*.json |	Subdomain Finder |	JSON |
| discovery_*.json |	Network Discovery |	JSON |
| dirbuster_*.json |	Directory Buster |	JSON |
| fingerprint_*.json |	Tech Fingerprint |	JSON |
| vulns_*.json |	Vulnerability Checker |	JSON |
| creds_*.json |	Credential Tester |	JSON |
##### Reports are saved in `reports/` directory with subdirectories for each format: `html/`, `pdf/`, `csv/`, `txt/`, `json/`.


## Error Handling
All tools raise ScanError or ValidationError exceptions on failure. Wrap operations in try-catch blocks:

```python
from core.exceptions import ScanError, ValidationError

try:
    results = scanner.quick_scan(target)
except ValidationError as e:
    print(f"Invalid target: {e}")
except ScanError as e:
    print(f"Scan failed: {e}")
```

## Best Practices
- Use quick scans first — Get initial results before running full scans
- Run service detection — Version info is essential for vulnerability matching
- Keep databases updated — Regular searchsploit -u for latest CVEs
- Save results — Always keep JSON files for later analysis
- Use scan differ — Compare scans over time to track changes
- Test safely — Start with localhost or authorized test systems
- Monitor progress — Use callbacks for long-running scans
- Handle errors — Wrap in try-catch for graceful failure



