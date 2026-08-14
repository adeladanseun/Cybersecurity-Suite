# Port Scanner Tool

Network port scanning module using nmap for reconnaissance.

## Features
- TCP and UDP port scanning
- Service version detection
- OS fingerprinting
- Scan differential analysis
- Multiple output formats (JSON, CSV, XML, TXT)
- Progress tracking with notifications

## Usage

### Command Line
```bash
python3 -m tools.port_scanner.scanner --target 192.168.1.1
python3 -m tools.port_scanner.scanner --target example.com --scan-type full