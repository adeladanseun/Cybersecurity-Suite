# DNS Enumeration Tool

Comprehensive DNS reconnaissance and enumeration.

## Features
- DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV)
- Zone transfer testing
- Subdomain discovery
- Reverse DNS lookup
- DNSSEC validation
- Mail server discovery
- Passive subdomain discovery (certificate transparency)

## Usage

### Python API
```python
from tools.dns_enum import DNSEnumerator

enumerator = DNSEnumerator()
results = enumerator.enumerate("example.com")
print(f"Found {results['summary']['total_records']} records")