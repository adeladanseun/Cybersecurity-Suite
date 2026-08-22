## Port Scanner

**Module:** `tools.port_scanner`

### Class: PortScanner

#### Nmap-based port scanning with progress tracking.

#### Constructor

```python
PortScanner(config=None, output_dir=None)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | Config | None | Configuration object |
| `output_dir` | str | None | Output directory for results |

---

#### Methods

##### scan

```python
scan(target, scan_type='tcp', ports=None, timing='T4',
     service_detection=True, script_scan=False, ping_first=True,
     sudo=True, callback=None) -> dict
```

Performs port scan on target.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | str | - | IP, CIDR, or domain |
| `scan_type` | str | 'tcp' | 'tcp', 'udp', or 'both' |
| `ports` | str | None | Port specification |
| `timing` | str | 'T4' | T0 (slow) to T5 (fast) |
| `service_detection` | bool | True | Enable version detection |
| `script_scan` | bool | False | Run NSE scripts |
| `ping_first` | bool | True | Ping before scan |
| `sudo` | bool | True | Use sudo for SYN scan |
| `callback` | function | None | Progress callback |

**Returns:**
```python
{
    'scan_metadata': {...},
    'hosts': [...],
    'ports': [...],
    'summary': {
        'total_open_ports': int,
        'hosts_up': int,
        'service_counts': dict
    }
}
```

---

##### quick_scan

```python
quick_scan(target, ports='top-1000', timing='T4') -> dict
```

Quick scan of common ports.

---

##### full_scan

```python
full_scan(target, timing='T3') -> dict
```

Full port scan with service detection.

---

##### udp_scan

```python
udp_scan(target, ports='top-100', timing='T4') -> dict
```

UDP port scan.

---

##### scan_multiple

```python
scan_multiple(targets, **kwargs) -> list
```

Scans multiple targets.

| Parameter | Type | Description |
|-----------|------|-------------|
| `targets` | list | List of target strings |
| `**kwargs` | - | Passed to scan() |

**Returns:** List of result dicts

---

##### is_tool_available

```python
is_tool_available() -> bool
```

Checks if nmap is installed.

---

### Class: ScanParser

#### Parses nmap XML output.

#### Methods

##### parse_xml

```python
parse_xml(xml_file) -> dict
```

Parses nmap XML file.

---

##### parse_text

```python
parse_text(text_file) -> dict
```

Parses nmap text output.

---

##### export_to_csv

```python
export_to_csv(results, output_file) -> str
```

Exports results to CSV.

---

### Class: ScanDiffer

#### Compares two scans.

#### Methods

##### compare_scans

```python
compare_scans(current_scan, previous_scan) -> dict
```

Compares two scan results.

**Returns:**
```python
{
    'new_ports': [...],
    'closed_ports': [...],
    'changed_ports': [...],
    'unchanged_ports': [...],
    'summary': {
        'total_new': int,
        'total_closed': int,
        'total_changed': int,
        'total_unchanged': int,
        'risk_level': str
    }
}
```

---

##### generate_diff_report

```python
generate_diff_report(diff, output_file=None) -> str
```

Generates readable diff report.

---

## DNS Enumeration

**Module:** `tools.dns_enum`

### Class: DNSEnumerator

#### DNS record enumeration.

#### Constructor

```python
DNSEnumerator(config=None, output_dir=None)
```

---

#### Methods

##### enumerate

```python
enumerate(domain, record_types=None, dns_servers=None) -> dict
```

Enumerates DNS records.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `domain` | str | - | Domain to enumerate |
| `record_types` | list | None | Record types to query |
| `dns_servers` | list | None | Custom DNS servers |

**Record Types:** 'A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV'

---

##### reverse_lookup

```python
reverse_lookup(ip) -> dict
```

Performs reverse DNS lookup.

---

##### get_mail_servers

```python
get_mail_servers(domain) -> list
```

Gets mail servers for domain.

---

##### get_name_servers

```python
get_name_servers(domain) -> list
```

Gets name servers for domain.

---

##### check_dnssec

```python
check_dnssec(domain) -> dict
```

Checks DNSSEC status.

---

##### get_txt_records

```python
get_txt_records(domain) -> list
```

Gets TXT records.

---

##### enumerate_multiple

```python
enumerate_multiple(domains, **kwargs) -> list
```

Enumerates multiple domains.

---

### Class: ZoneTransfer

#### DNS zone transfer testing.

#### Methods

##### attempt_transfer

```python
attempt_transfer(domain, nameserver=None) -> dict
```

Attempts zone transfer.

**Returns:**
```python
{
    'domain': str,
    'vulnerable': bool,
    'nameservers_tested': list,
    'records': list,
    'vulnerable_nameserver': str
}
```

---

##### test_multiple

```python
test_multiple(domains, nameserver=None) -> list
```

Tests zone transfer for multiple domains.

---

### Class: SubdomainFinder

#### Subdomain discovery.

#### Methods

##### find_subdomains

```python
find_subdomains(domain, wordlist=None, max_threads=10) -> dict
```

Finds subdomains using wordlist.

---

##### find_from_file

```python
find_from_file(domain, wordlist_file) -> dict
```

Finds subdomains using wordlist file.

---

##### load_wordlist

```python
load_wordlist(wordlist_file) -> list
```

Loads wordlist from file.

---

##### passive_discovery

```python
passive_discovery(domain) -> list
```

Passive subdomain discovery (certificate transparency).

---

## Network Discovery

**Module:** `tools.network_discovery`

### Class: NetworkDiscovery

#### Host discovery on networks.

#### Constructor

```python
NetworkDiscovery(config=None, output_dir=None)
```

---

#### Methods

##### discover_network

```python
discover_network(network, method='auto', ping_first=True) -> dict
```

Discovers hosts on network.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `network` | str | - | CIDR or IP range |
| `method` | str | 'auto' | 'arp', 'ping', 'nmap', or 'auto' |
| `ping_first` | bool | True | Ping before discovery |

---

##### get_network_interfaces

```python
get_network_interfaces() -> list
```

Gets local network interfaces.

---

##### get_local_networks

```python
get_local_networks() -> list
```

Gets local networks for discovery.

---

### Class: ARPScanner

#### ARP-based scanning.

#### Methods

##### scan_network

```python
scan_network(network, timeout=2) -> list
```

Performs ARP scan.

---

##### scan_single

```python
scan_single(ip, timeout=1) -> bool
```

Checks if single host is alive.

---

##### get_mac_vendor

```python
get_mac_vendor(mac_address) -> str
```

Gets vendor from MAC address.

---

##### enrich_with_vendor

```python
enrich_with_vendor(hosts) -> list
```

Adds vendor info to hosts.

---

### Class: NetworkMapper

#### Network topology mapping.

#### Methods

##### create_network_map

```python
create_network_map(discovery_results) -> dict
```

Creates network map.

---

##### export_network_map

```python
export_network_map(network_map, format='json') -> str
```

Exports network map.

| Format | Description |
|--------|-------------|
| 'json' | JSON format |
| 'txt' | Text format |
| 'csv' | CSV format |
| 'html' | HTML format |

---

##### find_gateway

```python
find_gateway(hosts) -> str
```

Identifies network gateway.

---

## Web Enumeration

**Module:** `tools.web_enum`

### Class: DirBuster

#### Directory brute forcing.

#### Constructor

```python
DirBuster(output_dir=None)
```

---

#### Methods

##### brute_force

```python
brute_force(url, wordlist=None, extensions=None, threads=10,
            timeout=5, follow_redirects=False) -> dict
```

Brute forces directories.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | str | - | Base URL |
| `wordlist` | list | None | Paths to test |
| `extensions` | list | None | Extensions to append |
| `threads` | int | 10 | Concurrent threads |
| `timeout` | int | 5 | Request timeout |

---

##### brute_force_with_file

```python
brute_force_with_file(url, wordlist_file, **kwargs) -> dict
```

Brute force with wordlist file.

---

##### load_wordlist

```python
load_wordlist(wordlist_file) -> list
```

Loads wordlist.

---

### Class: TechFingerprint

#### Technology detection.

#### Methods

##### fingerprint

```python
fingerprint(url, timeout=10) -> dict
```

Fingerprints technologies.

---

##### fingerprint_multiple

```python
fingerprint_multiple(urls, **kwargs) -> list
```

Fingerprints multiple URLs.

---

### Class: ParamFuzzer

#### Parameter discovery.

#### Methods

##### discover_params

```python
discover_params(url, params=None, threads=10, timeout=5) -> dict
```

Discovers hidden parameters.

---

##### fuzz_param_values

```python
fuzz_param_values(url, param, fuzz_values, threads=5, timeout=5) -> dict
```

Fuzzes parameter values.

---

## Vulnerability Checker

**Module:** `tools.vuln_checker`

### Class: ServiceVulnChecker

#### Service vulnerability checking.

#### Methods

##### check_scan_results

```python
check_scan_results(scan_results) -> dict
```

Checks scan results for vulnerabilities.

---

##### check_service

```python
check_service(service, product, version, port=None, host=None) -> list
```

Checks single service.

---

##### check_from_file

```python
check_from_file(scan_file) -> dict
```

Checks from scan results file.

---

### Class: CVELookup

#### Offline CVE database lookup.

#### Methods

##### lookup_cve

```python
lookup_cve(cve_id) -> dict
```

Looks up specific CVE.

---

##### search_by_service

```python
search_by_service(service_name, version=None) -> list
```

Searches CVEs by service.

---

##### search_by_platform

```python
search_by_platform(platform) -> list
```

Searches CVEs by platform.

---

##### check_vulnerabilities

```python
check_vulnerabilities(scan_results) -> dict
```

Checks scan results against CVE database.

---

##### export_database

```python
export_database(output_format='json') -> str
```

Exports loaded CVE database.

---

### Class: SSLChecker

SSL/TLS configuration audit.

#### Methods

##### check_ssl

```python
check_ssl(host, port=443, timeout=10) -> dict
```

Checks SSL/TLS configuration.

---

### Class: WebVulnChecker

#### Web vulnerability checking.

#### Methods

##### check_url

```python
check_url(url, checks=None, timeout=10) -> dict
```

Checks URL for vulnerabilities.

| Check | Description |
|-------|-------------|
| 'sqli' | SQL injection testing |
| 'xss' | XSS testing |
| 'headers' | Security headers check |
| 'all' | All checks |

---

##### check_sql_injection

```python
check_sql_injection(url, timeout=10) -> list
```

Tests for SQL injection.

---

##### check_xss

```python
check_xss(url, timeout=10) -> list
```

Tests for XSS.

---

##### check_security_headers

```python
check_security_headers(url, timeout=10) -> list
```

Checks security headers.

---

## Exploitation

**Module:** `tools.exploitation`

### Class: CredTester

#### Credential testing.

#### Methods

##### test_credentials

```python
test_credentials(target, service, credentials=None, port=None,
                 timeout=10, threads=5) -> dict
```

Tests credentials against service.

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | str | Hostname or IP |
| `service` | str | ssh, ftp, mysql, etc. |
| `credentials` | list | List of (username, password) tuples |

---

##### test_from_scan

```python
test_from_scan(scan_results, credentials_file=None) -> list
```

Tests credentials from scan results.

---

### Class: DefaultCredChecker

Default credential checking.

#### Methods

##### check_device

```python
check_device(target, device_type, credentials=None, timeout=5) -> dict
```

Checks device for default credentials.

---

##### get_default_credentials

```python
get_default_credentials(device_type=None, service_type=None) -> list
```

Gets default credentials for device/service.

---

##### scan_network

```python
scan_network(hosts, device_types=None) -> list
```

Scans multiple hosts.

---

##### generate_credential_report

```python
generate_credential_report(results) -> dict
```

Generates credential report.

---

## Report Builder

**Module:** `tools.report_builder`

### Class: ReportGenerator

Multi-format report generation.

#### Constructor

```python
ReportGenerator(output_dir=None, template_dir=None)
```

---

#### Methods

##### generate_report

```python
generate_report(data, report_type='full', formats=None,
                report_name=None) -> dict
```

Generates reports.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `data` | dict | - | Scan results data |
| `report_type` | str | 'full' | 'executive', 'technical', 'findings', 'full' |
| `formats` | list | None | ['html', 'pdf', 'csv', 'txt', 'json'] |
| `report_name` | str | None | Custom report name |

**Returns:** Dict of generated file paths

---

##### generate_from_file

```python
generate_from_file(input_file, **kwargs) -> dict
```

Generates report from JSON file.

---

##### generate_comparison_report

```python
generate_comparison_report(current_data, previous_data, name=None) -> dict
```

Generates comparison report.

---

### Class: RiskCalculator

Risk scoring.

#### Methods

##### calculate_risk_score

```python
calculate_risk_score(data) -> dict
```

Calculates overall risk score.

**Returns:**
```python
{
    'score': int,
    'level': str,
    'factors': list,
    'summary': str
}
```

---

##### calculate_port_risk

```python
calculate_port_risk(port, service, version='') -> dict
```

Calculates individual port risk.

---

### Class: DiffReportGenerator

Comparison report generation.

#### Methods

##### generate_diff

```python
generate_diff(current_data, previous_data) -> dict
```

Generates diff between two scans.
