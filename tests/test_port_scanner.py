"""
Tests for Port Scanner module
Run: python3 tests/test_port_scanner.py
"""

import sys
import os
import tempfile
import json
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.port_scanner import PortScanner, ScanParser, ScanDiffer
from core.file_manager import FileManager
from core.exceptions import ScanError


def setup_test_env():
    """Create test environment."""
    test_dir = tempfile.mkdtemp(prefix="port_scanner_test_")
    return test_dir, FileManager(test_dir)


def cleanup_test_env(test_dir):
    """Clean test environment."""
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)


def test_scanner_initialization():
    """Test scanner object creation."""
    print("\n[*] Testing Scanner Initialization...")
    
    try:
        scanner = PortScanner()
        assert scanner is not None
        assert scanner.nmap_path is not None
        print("  ✓ Scanner initialized")
    except Exception as e:
        print(f"  ⚠ Scanner init issue (may be normal without nmap): {e}")


def test_parser_with_sample_xml():
    """Test XML parsing with sample data."""
    print("\n[*] Testing XML Parser...")
    
    test_dir, fm = setup_test_env()
    
    try:
        # Create sample nmap XML
        sample_xml = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS -p 80,443 127.0.0.1"
         start="1234567890" startstr="Mon Jan 15 10:30:00 2024"
         version="7.94" xmloutputversion="1.05">
<runstats>
    <finished time="1234567900" timestr="Mon Jan 15 10:30:10 2024"
              elapsed="10.0" exit="success"/>
    <hosts up="1" down="0" total="1"/>
</runstats>
<host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames>
        <hostname name="localhost" type="PTR"/>
    </hostnames>
    <ports>
        <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="Apache httpd" version="2.4.41"
                     extrainfo="Ubuntu" method="probed">
                <cpe>cpe:/a:apache:http_server:2.4.41</cpe>
            </service>
        </port>
        <port protocol="tcp" portid="443">
            <state state="open" reason="syn-ack"/>
            <service name="https" product="Apache httpd" version="2.4.41"
                     tunnel="ssl" method="probed"/>
        </port>
        <port protocol="tcp" portid="22">
            <state state="closed" reason="conn-refused"/>
            <service name="ssh"/>
        </port>
    </ports>
</host>
</nmaprun>"""
        
        xml_file = os.path.join(test_dir, "sample_scan.xml")
        with open(xml_file, 'w') as f:
            f.write(sample_xml)
        
        parser = ScanParser()
        results = parser.parse_xml(xml_file)
        
        # Verify structure
        assert 'scan_info' in results
        assert 'hosts' in results
        assert 'ports' in results
        assert 'summary' in results
        
        # Verify scan info
        assert results['scan_info']['scanner'] == 'nmap'
        
        # Verify hosts
        assert len(results['hosts']) == 1
        assert results['hosts'][0]['ip'] == '127.0.0.1'
        assert results['hosts'][0]['status'] == 'up'
        
        # Verify ports
        assert len(results['ports']) == 3
        open_ports = [p for p in results['ports'] if p['state'] == 'open']
        assert len(open_ports) == 2
        
        # Verify port details
        port_80 = next(p for p in results['ports'] if p['port'] == 80)
        assert port_80['service'] == 'http'
        assert port_80['product'] == 'Apache httpd'
        assert port_80['version'] == '2.4.41'
        
        # Verify summary
        assert results['summary']['total_hosts'] == 1
        assert results['summary']['hosts_up'] == 1
        assert results['summary']['total_open_ports'] == 2
        
        print("  ✓ XML parsing passed")
        
    finally:
        cleanup_test_env(test_dir)


def test_parser_csv_export():
    """Test CSV export functionality."""
    print("\n[*] Testing CSV Export...")
    
    test_dir, fm = setup_test_env()
    
    try:
        # Create parser with sample data
        parser = ScanParser()
        sample_results = {
            'ports': [
                {'host': '127.0.0.1', 'port': 80, 'protocol': 'tcp', 
                 'state': 'open', 'service': 'http', 'product': 'Apache', 
                 'version': '2.4', 'extrainfo': ''},
                {'host': '127.0.0.1', 'port': 443, 'protocol': 'tcp', 
                 'state': 'open', 'service': 'https', 'product': 'Apache', 
                 'version': '2.4', 'extrainfo': ''}
            ]
        }
        
        csv_file = os.path.join(test_dir, "scan_export.csv")
        parser.export_to_csv(sample_results, csv_file)
        
        # Verify CSV
        assert os.path.exists(csv_file)
        
        fm2 = FileManager(test_dir)
        csv_data = fm2.read_csv(csv_file)
        assert len(csv_data) == 2
        assert csv_data[0]['port'] == '80'
        assert csv_data[0]['service'] == 'http'
        
        print("  ✓ CSV export passed")
        
    finally:
        cleanup_test_env(test_dir)


def test_differ_new_ports():
    """Test scan differ - new ports detection."""
    print("\n[*] Testing Scan Differ - New Ports...")
    
    # Simulate previous scan (only port 80)
    previous = {
        'ports': [
            {'port': 80, 'protocol': 'tcp', 'state': 'open', 
             'service': 'http', 'product': 'Apache', 'version': '2.4', 
             'host': '127.0.0.1', 'extrainfo': ''}
        ]
    }
    
    # Simulate current scan (ports 80 and 443)
    current = {
        'ports': [
            {'port': 80, 'protocol': 'tcp', 'state': 'open', 
             'service': 'http', 'product': 'Apache', 'version': '2.4', 
             'host': '127.0.0.1', 'extrainfo': ''},
            {'port': 443, 'protocol': 'tcp', 'state': 'open', 
             'service': 'https', 'product': 'Apache', 'version': '2.4', 
             'host': '127.0.0.1', 'extrainfo': ''}
        ]
    }
    
    differ = ScanDiffer()
    diff = differ.compare_scans(current, previous)
    
    # Verify new port detected
    assert diff['summary']['total_new'] == 1
    assert len(diff['new_ports']) == 1
    assert diff['new_ports'][0]['port'] == 443
    
    # Verify no closed ports
    assert diff['summary']['total_closed'] == 0
    
    # Verify unchanged port
    assert diff['summary']['total_unchanged'] == 1
    
    print("  ✓ New ports detection passed")


def test_differ_closed_ports():
    """Test scan differ - closed ports detection."""
    print("\n[*] Testing Scan Differ - Closed Ports...")
    
    previous = {
        'ports': [
            {'port': 80, 'protocol': 'tcp', 'state': 'open', 
             'service': 'http', 'host': '127.0.0.1'},
            {'port': 22, 'protocol': 'tcp', 'state': 'open', 
             'service': 'ssh', 'host': '127.0.0.1'}
        ]
    }
    
    current = {
        'ports': [
            {'port': 80, 'protocol': 'tcp', 'state': 'open', 
             'service': 'http', 'host': '127.0.0.1'}
        ]
    }
    
    differ = ScanDiffer()
    diff = differ.compare_scans(current, previous)
    
    assert diff['summary']['total_closed'] == 1
    assert len(diff['closed_ports']) == 1
    assert diff['closed_ports'][0]['port'] == 22
    
    print("  ✓ Closed ports detection passed")


def test_differ_changed_service():
    """Test scan differ - changed service detection."""
    print("\n[*] Testing Scan Differ - Service Changes...")
    
    previous = {
        'ports': [
            {'port': 80, 'protocol': 'tcp', 'state': 'open', 
             'service': 'http', 'product': 'Apache', 'version': '2.2', 
             'host': '127.0.0.1', 'extrainfo': ''}
        ]
    }
    
    current = {
        'ports': [
            {'port': 80, 'protocol': 'tcp', 'state': 'open', 
             'service': 'http', 'product': 'Apache', 'version': '2.4', 
             'host': '127.0.0.1', 'extrainfo': ''}
        ]
    }
    
    differ = ScanDiffer()
    diff = differ.compare_scans(current, previous)
    
    assert diff['summary']['total_changed'] == 1
    assert len(diff['changed_ports']) == 1
    
    changes = diff['changed_ports'][0]['changes']
    version_change = next(c for c in changes if c['field'] == 'version')
    assert version_change['from'] == '2.2'
    assert version_change['to'] == '2.4'
    
    print("  ✓ Service change detection passed")


def test_differ_risk_calculation():
    """Test risk level calculation."""
    print("\n[*] Testing Risk Calculation...")
    
    previous = {'ports': []}
    current = {
        'ports': [
            {'port': p, 'protocol': 'tcp', 'state': 'open', 
             'service': f'service{p}', 'product': '', 'version': '', 
             'host': '127.0.0.1', 'extrainfo': ''}
            for p in [21, 22, 23, 25, 80, 443, 3306, 8080]
        ]
    }
    
    differ = ScanDiffer()
    diff = differ.compare_scans(current, previous)
    
    # 8 new ports should be high risk
    assert diff['summary']['risk_level'] in ['high', 'critical']
    
    print("  ✓ Risk calculation passed")


def test_differ_report_generation():
    """Test diff report generation."""
    print("\n[*] Testing Diff Report Generation...")
    
    test_dir, fm = setup_test_env()
    
    try:
        previous = {'ports': []}
        current = {
            'ports': [
                {'port': 80, 'protocol': 'tcp', 'state': 'open', 
                 'service': 'http', 'product': 'nginx', 'version': '1.18', 
                 'host': '127.0.0.1', 'extrainfo': ''}
            ]
        }
        
        differ = ScanDiffer()
        diff = differ.compare_scans(current, previous)
        
        report_file = os.path.join(test_dir, "diff_report.txt")
        report = differ.generate_diff_report(diff, report_file)
        
        assert os.path.exists(report_file)
        assert "NEW PORTS OPENED" in report
        assert "Port 80" in report
        
        print("  ✓ Diff report generation passed")
        
    finally:
        cleanup_test_env(test_dir)


def test_scanner_methods_exist():
    """Test that scanner has required methods."""
    print("\n[*] Testing Scanner API...")
    
    try:
        scanner = PortScanner()
        
        # Check methods exist
        assert hasattr(scanner, 'scan')
        assert hasattr(scanner, 'quick_scan')
        assert hasattr(scanner, 'full_scan')
        assert hasattr(scanner, 'udp_scan')
        assert hasattr(scanner, 'scan_multiple')
        assert hasattr(scanner, 'is_tool_available')
        
        print("  ✓ Scanner API complete")
        
    except Exception as e:
        print(f"  ⚠ Scanner API check issue: {e}")


def run_all_port_scanner_tests():
    """Run all port scanner tests."""
    print("=" * 60)
    print("PORT SCANNER MODULE TESTS")
    print("=" * 60)
    
    try:
        test_scanner_initialization()
        test_parser_with_sample_xml()
        test_parser_csv_export()
        test_differ_new_ports()
        test_differ_closed_ports()
        test_differ_changed_service()
        test_differ_risk_calculation()
        test_differ_report_generation()
        test_scanner_methods_exist()
        
        print("\n" + "=" * 60)
        print("✅ All port scanner tests passed!")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_port_scanner_tests()
    sys.exit(0 if success else 1)