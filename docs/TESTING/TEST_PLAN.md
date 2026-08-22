# Test Plan

This document outlines the testing strategy for CyberSecurity Suite.

---

## Test Objectives

1. Verify all core modules function correctly
2. Ensure all tools produce expected results
3. Validate web app features end-to-end
4. Confirm integration between CLI and web app
5. Test against known vulnerable systems

---

## Test Environments

### Development Environment

- Ubuntu 22.04 LTS
- Python 3.10
- SQLite database
- Local virtual environments

### Test Targets

- Localhost (127.0.0.1)
- Metasploitable VM (192.168.43.58)
- Example domains (example.com, google.com)
- Local network devices

---

## Test Categories

### 1. Unit Tests

Test individual functions and methods in isolation.

**Coverage:**
- Validator functions (IP, domain, URL, port validation)
- File Manager operations (read, write, JSON, CSV)
- Config management (get, set, save)
- Database operations (insert, query, export)

### 2. Integration Tests

Test modules working together.

**Coverage:**
- Core modules interaction
- Tool pipeline (scan → check → report)
- Web app with core modules

### 3. Functional Tests

Test complete workflows.

**Coverage:**
- Quick scan workflow
- Full audit workflow
- Report generation pipeline
- Vulnerability management

### 4. End-to-End Tests

Test entire system from input to output.

**Coverage:**
- Target creation → Scan → Results → Report
- Web app full workflow
- CLI full workflow

### 5. Performance Tests

Test system under load.

**Metrics:**
- Scan completion time
- Database query performance
- Web page load time
- Report generation time

---

## Test Data

### Sample Targets
- 192.168.1.1 # Internal IP
- 10.0.0.1 # Private IP
- 8.8.8.8 # Public IP
- example.com # Domain
- https://test.com # URL
- 192.168.1.0/24 # Network range

### Sample Scan Results

```json
{
    "ports": [
        {"port": 80, "state": "open", "service": "http"},
        {"port": 443, "state": "open", "service": "https"},
        {"port": 22, "state": "open", "service": "ssh"}
    ],
    "summary": {
        "total_open_ports": 3,
        "hosts_up": 1
    }
}
```
### Sample Vulnerabilities
```json
{
    "vulnerabilities": [
        {
            "cve": "CVE-2021-41773",
            "severity": "critical",
            "title": "Path Traversal"
        }
    ]
}
```
### Test Execution Schedule
| Phase	| Tests	|Frequency |
|---|---|---|
| Development	| Unit tests	| After each change |
| Pre-release	| Integration tests	| Before merge |
| Release	| Full test suite	| Final verification |
| Maintenance	| Regression tests	| Monthly |
## Pass/Fail Criteria
### Pass Criteria
- All unit tests pass
- All integration tests pass
- No critical bugs
- All workflows complete successfully
- Reports generate correctly
- Database operations work

### Fail Criteria
- Any unit test fails
- Scan produces incorrect results
- Report missing data
- Database corruption
- Web app crashes

### Bug Severity Levels
| Severity	| Description	| Example |
|---|---|---|
| Critical | System unusable	| Scan fails entirely |
| High	| Major feature broken	| Reports empty |
| Medium	| Feature partially working	| Progress bar not updating |
| Low	| Cosmetic issue	| Wrong color badge |
## Test Reporting
### Bug Report Template
```text
Title: [Brief description]
Severity: [Critical/High/Medium/Low]
Environment: [OS, Python version]
Steps to Reproduce:
1. ...
2. ...
Expected Result:
Actual Result:
Additional Information:
Regression Testing
After fixing bugs, run:
```
```bash
# Main project
python3 tests/test_validator.py
python3 tests/test_file_manager.py
python3 tests/test_database.py
python3 tests/test_port_scanner.py
python3 tests/test_report_builder.py

# Web app
cd web_viewer
python manage.py test
```
## Metasploitable Testing Checklist
- Port scan finds 20+ open ports
- Service detection identifies vsftpd 2.3.4
- Vulnerability scan finds CVE-2011-2523
- CVE lookup returns 4+ vsftpd results
- Report contains vulnerability data
- Results saved to database
- Web app displays findings
- Export works in all formats
