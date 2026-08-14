# Network Discovery Tool

Internal network mapping and host discovery.

## Features
- ARP-based host discovery
- ICMP ping sweep
- Nmap integration
- MAC address vendor lookup
- Reverse DNS resolution
- Network topology mapping
- Multiple export formats

## Usage

### Python API
```python
from tools.network_discovery import NetworkDiscovery

discovery = NetworkDiscovery()
results = discovery.discover_network("192.168.1.0/24")
print(f"Found {results['summary']['live_hosts']} hosts")