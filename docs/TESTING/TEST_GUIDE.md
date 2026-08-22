# Testing Guide

This guide explains how to run tests for CyberSecurity Suite.

---

## Overview

The project has two test suites:
1. **Main Project Tests** — Python tests for CLI tools and core modules
2. **Django Tests** — Web application tests

---

## Main Project Tests

### Location

Tests are in the `tests/` directory at the project root.

### Prerequisites

```bash
cd /path/to/cybersec-suite
source .venv/bin/activate
```
### Running All Tests
Run each test file individually:

```bash
# Core Framework Tests
python3 tests/test_validator.py
python3 tests/test_file_manager.py
python3 tests/test_config.py
python3 tests/test_logger.py
python3 tests/test_notifier.py
python3 tests/test_database.py
python3 tests/test_integration.py

# Tool Tests
python3 tests/test_port_scanner.py
python3 tests/test_report_builder.py
python3 tests/test_dns_enum.py
python3 tests/test_network_discovery.py
python3 tests/test_web_enum.py
python3 tests/test_vuln_checker.py
python3 tests/test_exploitation.py
```
### Running a Single Test
```bash
python3 tests/test_validator.py
```
### Expected Output
```text
============================================================
VALIDATOR MODULE TESTS
============================================================

[*] Testing IP Validation...
  ✓ IP validation passed

[*] Testing Private/Public IP Detection...
  ✓ Private/Public detection passed

============================================================
✅ All validator tests passed!
============================================================
```
### Django Tests
Location
Tests are in web_viewer/tests/ directory.

Prerequisites
```bash
cd web_viewer
source venv/bin/activate
```
Running All Tests
```bash
python manage.py test
```
Running Specific Test Files
```bash
python manage.py test tests.test_targets
python manage.py test tests.test_scans
python manage.py test tests.test_results
python manage.py test tests.test_reports
python manage.py test tests.test_vulnerabilities
python manage.py test tests.test_advanced
```
Running a Specific Test Class
```bash
python manage.py test tests.test_targets.TargetModelTest
python manage.py test tests.test_scans.ScanModelTest
```
Running a Single Test Method
```bash
python manage.py test tests.test_targets.TargetModelTest.test_target_creation
```
Expected Output
```text
Found 43 test(s).
Creating test database for alias 'default'...
System check identified no issues (0 silenced).
...........................................
----------------------------------------------------------------------
Ran 43 tests in 110.986s

OK
```
### Test Coverage Summary
| Module	| Test File	| Test Groups	| Status |
|----|----|----|----|
| Validator	| test_validator.py	| 9	| ✅ Passing |
| File Manager	| test_file_manager.py	| 9	| ✅ Passing |
| Config	| test_config.py	| 4	| ✅ Passing |
| Logger	| test_logger.py	| 3	| ✅ Passing |
| Notifier	| test_notifier.py	| 4	| ✅ Passing |
| Database	| test_database.py	| 5	| ✅ Passing |
| Integration	| test_integration.py	| 6	| ✅ Passing |
| Port Scanner	| test_port_scanner.py	| 9	| ✅ Passing |
| Report Builder	| test_report_builder.py	| 10	| ✅ Passing |
| DNS Enum	| test_dns_enum.py	| 8	| ✅ Passing |
| Network Discovery	| test_network_discovery.py	| 7	| ✅ Passing |
| Web Enum	| test_web_enum.py	| 7	| ✅ Passing |
| Vuln Checker	| test_vuln_checker.py	| 8	| ✅ Passing |
| Exploitation	| test_exploitation.py	| 7	| ✅ Passing |
##### Total: 96 test-groups passing

### Django Test Coverage
| App	| Tests	| Status |
|----|----|----|
| Targets	| 5	| ✅ Passing |
| Scans	| 7	| ✅ Passing |
| Results	| 6	| ✅ Passing |
| Reports	| 7	| ✅ Passing |
| Vulnerabilities	| 7	| ✅ Passing |
| Advanced (API, Dashboard, Notifications)	| 11	| ✅ Passing |
##### Total: 43 Django tests passing

## Writing New Tests
#### Main Project Test Template
```python
"""
Tests for My Module
Run: python3 tests/test_my_module.py
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.my_tool import MyTool


def test_initialization():
    """Test tool initialization"""
    tool = MyTool()
    assert tool is not None
    print("  ✓ Initialization passed")


def test_basic_operation():
    """Test basic operation"""
    tool = MyTool()
    result = tool.run("localhost")
    assert result is not None
    print("  ✓ Basic operation passed")


def run_all_tests():
    print("=" * 60)
    print("MY MODULE TESTS")
    print("=" * 60)
    
    try:
        test_initialization()
        test_basic_operation()
        
        print("\n" + "=" * 60)
        print("✅ All tests passed!")
        print("=" * 60)
        return True
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
```
#### Django Test Template
```python
"""
Tests for My App
Run: cd web_viewer && python manage.py test tests.test_my_app
"""

from django.test import TestCase
from django.contrib.auth.models import User
from my_app.models import MyModel


class MyModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
    
    def test_creation(self):
        obj = MyModel.objects.create(name='Test', created_by=self.user)
        self.assertEqual(obj.name, 'Test')
```
### Troubleshooting Tests
Test fails with ImportError
```bash
# Ensure you're in the correct directory
cd /path/to/cybersec-suite

# Check Python path
python3 -c "import sys; print(sys.path)"

# Add project root to path
export PYTHONPATH=/path/to/cybersec-suite:$PYTHONPATH
Django test fails with "No module named config"
bash
# Run from web_viewer directory
cd web_viewer

# Ensure virtual environment is activated
source venv/bin/activate

# Run tests
python manage.py test
```
Test fails with "No module named dnspython"
```bash
pip install dnspython
```
Test fails with "No module named requests"
```bash
pip install requests
```
Test fails with "No module named scapy"
```bash
pip install scapy
```
Test fails with "No module named paramiko"
```bash
pip install paramiko
```
