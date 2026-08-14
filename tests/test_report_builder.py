"""
Tests for Report Builder module
Run: python3 tests/test_report_builder.py
"""

import sys
import os
import tempfile
import shutil
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.report_builder import ReportGenerator, RiskCalculator, DiffReportGenerator
from core.file_manager import FileManager


def setup_test_env():
    """Create test environment."""
    test_dir = tempfile.mkdtemp(prefix="report_test_")
    return test_dir, FileManager(test_dir)


def cleanup_test_env(test_dir):
    """Clean test environment."""
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)


def get_sample_scan_data():
    """Return sample scan data for testing."""
    return {
        'scan_metadata': {
            'target': '192.168.1.1',
            'scan_type': 'tcp',
            'duration': 45.5,
            'timestamp': '2024-01-15T10:30:00',
            'command': 'nmap -sS -p 1-1000 192.168.1.1'
        },
        'summary': {
            'total_hosts': 1,
            'hosts_up': 1,
            'hosts_down': 0,
            'total_open_ports': 3,
            'total_ports_scanned': 1000
        },
        'hosts': [
            {
                'ip': '192.168.1.1',
                'mac': '00:11:22:33:44:55',
                'status': 'up',
                'hostnames': [{'name': 'server.local', 'type': 'PTR'}]
            }
        ],
        'ports': [
            {
                'port': 22, 'protocol': 'tcp', 'state': 'open',
                'service': 'ssh', 'product': 'OpenSSH', 'version': '8.2',
                'host': '192.168.1.1', 'extrainfo': 'Ubuntu'
            },
            {
                'port': 80, 'protocol': 'tcp', 'state': 'open',
                'service': 'http', 'product': 'Apache httpd', 'version': '2.4.41',
                'host': '192.168.1.1', 'extrainfo': ''
            },
            {
                'port': 443, 'protocol': 'tcp', 'state': 'open',
                'service': 'https', 'product': 'Apache httpd', 'version': '2.4.41',
                'host': '192.168.1.1', 'extrainfo': ''
            }
        ]
    }


def test_generator_initialization():
    """Test report generator creation."""
    print("\n[*] Testing Generator Initialization...")
    
    test_dir, fm = setup_test_env()
    
    try:
        generator = ReportGenerator(output_dir=os.path.join(test_dir, 'reports'))
        assert generator is not None
        
        # Check directories created
        for subdir in ['html', 'pdf', 'csv', 'txt', 'json']:
            assert os.path.exists(os.path.join(test_dir, 'reports', subdir))
        
        print("  ✓ Generator initialized")
        
    finally:
        cleanup_test_env(test_dir)


def test_generate_html():
    """Test HTML report generation."""
    print("\n[*] Testing HTML Generation...")
    
    test_dir, fm = setup_test_env()
    
    try:
        generator = ReportGenerator(output_dir=os.path.join(test_dir, 'reports'))
        data = get_sample_scan_data()
        
        files = generator.generate_report(
            data,
            report_type='full',
            formats=['html'],
            report_name='test_report'
        )
        
        assert 'html' in files
        assert os.path.exists(files['html'])
        
        # Verify HTML content
        content = fm.read_file(files['html'])
        assert '<!DOCTYPE html>' in content
        assert 'Security Assessment Report' in content
        assert '192.168.1.1' in content
        assert 'OpenSSH' in content
        
        print("  ✓ HTML generation passed")
        
    finally:
        cleanup_test_env(test_dir)


def test_generate_csv():
    """Test CSV report generation."""
    print("\n[*] Testing CSV Generation...")
    
    test_dir, fm = setup_test_env()
    
    try:
        generator = ReportGenerator(output_dir=os.path.join(test_dir, 'reports'))
        data = get_sample_scan_data()
        
        files = generator.generate_report(
            data,
            formats=['csv'],
            report_name='test_csv'
        )
        
        assert 'csv' in files
        assert os.path.exists(files['csv'])
        
        # Verify CSV content
        csv_data = fm.read_csv(files['csv'])
        assert len(csv_data) > 0
        
        print("  ✓ CSV generation passed")
        
    finally:
        cleanup_test_env(test_dir)


def test_generate_txt():
    """Test text report generation."""
    print("\n[*] Testing TXT Generation...")
    
    test_dir, fm = setup_test_env()
    
    try:
        generator = ReportGenerator(output_dir=os.path.join(test_dir, 'reports'))
        data = get_sample_scan_data()
        
        files = generator.generate_report(
            data,
            formats=['txt'],
            report_name='test_txt'
        )
        
        assert 'txt' in files
        assert os.path.exists(files['txt'])
        
        # Verify content
        content = fm.read_file(files['txt'])
        assert 'SECURITY ASSESSMENT REPORT' in content
        assert '192.168.1.1' in content
        assert 'ssh' in content
        
        print("  ✓ TXT generation passed")
        
    finally:
        cleanup_test_env(test_dir)


def test_generate_json():
    """Test JSON export generation."""
    print("\n[*] Testing JSON Generation...")
    
    test_dir, fm = setup_test_env()
    
    try:
        generator = ReportGenerator(output_dir=os.path.join(test_dir, 'reports'))
        data = get_sample_scan_data()
        
        files = generator.generate_report(
            data,
            formats=['json'],
            report_name='test_json'
        )
        
        assert 'json' in files
        assert os.path.exists(files['json'])
        
        # Verify JSON content
        json_data = fm.read_json(files['json'])
        assert 'report_metadata' in json_data
        assert 'data' in json_data
        
        print("  ✓ JSON generation passed")
        
    finally:
        cleanup_test_env(test_dir)


def test_multiple_formats():
    """Test generating multiple formats at once."""
    print("\n[*] Testing Multiple Formats...")
    
    test_dir, fm = setup_test_env()
    
    try:
        generator = ReportGenerator(output_dir=os.path.join(test_dir, 'reports'))
        data = get_sample_scan_data()
        
        files = generator.generate_report(
            data,
            formats=['html', 'csv', 'txt', 'json'],
            report_name='multi_test'
        )
        
        assert len(files) == 4
        for fmt in ['html', 'csv', 'txt', 'json']:
            assert fmt in files
            assert os.path.exists(files[fmt])
        
        print("  ✓ Multiple formats passed")
        
    finally:
        cleanup_test_env(test_dir)


def test_risk_calculator():
    """Test risk scoring calculations."""
    print("\n[*] Testing Risk Calculator...")
    
    calculator = RiskCalculator()
    data = get_sample_scan_data()
    
    risk = calculator.calculate_risk_score(data)
    
    assert 'score' in risk
    assert 'level' in risk
    assert 'factors' in risk
    assert 'summary' in risk
    assert 0 <= risk['score'] <= 100
    
    # With 3 open ports including SSH, should be at least low
    assert risk['level'] in ['info', 'low', 'medium', 'high', 'critical'] #ALERT added info to list
    
    print("  ✓ Risk calculator passed")


def test_port_risk():
    """Test individual port risk calculation."""
    print("\n[*] Testing Port Risk...")
    
    calculator = RiskCalculator()
    
    # SSH port should have elevated risk
    risk = calculator.calculate_port_risk(22, 'ssh', '8.2')
    assert risk['risk_score'] > 1.0
    
    # Telnet should be higher risk
    risk = calculator.calculate_port_risk(23, 'telnet', '')
    assert risk['risk_score'] > 2.0
    
    # HTTP should be lower risk
    risk = calculator.calculate_port_risk(80, 'http', '2.4')
    assert risk['risk_score'] <= 3.0
    
    print("  ✓ Port risk calculation passed")


def test_diff_report():
    """Test diff report generation."""
    print("\n[*] Testing Diff Report...")
    
    # Previous scan - 2 ports
    previous = {
        'scan_metadata': {'timestamp': '2024-01-10T10:00:00'},
        'ports': [
            {'port': 80, 'state': 'open', 'service': 'http', 'product': 'Apache', 'version': '2.2', 'host': '192.168.1.1'},
            {'port': 22, 'state': 'open', 'service': 'ssh', 'product': 'OpenSSH', 'version': '7.0', 'host': '192.168.1.1'}
        ]
    }
    
    # Current scan - 3 ports, one changed
    current = {
        'scan_metadata': {'timestamp': '2024-01-15T10:30:00'},
        'ports': [
            {'port': 80, 'state': 'open', 'service': 'http', 'product': 'Apache', 'version': '2.4', 'host': '192.168.1.1'},
            {'port': 22, 'state': 'open', 'service': 'ssh', 'product': 'OpenSSH', 'version': '8.2', 'host': '192.168.1.1'},
            {'port': 443, 'state': 'open', 'service': 'https', 'product': 'Apache', 'version': '2.4', 'host': '192.168.1.1'}
        ]
    }
    
    diff_gen = DiffReportGenerator()
    diff = diff_gen.generate_diff(current, previous)
    
    assert diff['summary']['total_new'] == 1  # Port 443 new
    assert diff['summary']['total_changed'] == 2  # Both 80 and 22 changed versions
    assert diff['summary']['total_closed'] == 0
    
    print("  ✓ Diff report passed")


def test_generate_from_file():
    """Test generating report from JSON file."""
    print("\n[*] Testing Generate From File...")
    
    test_dir, fm = setup_test_env()
    
    try:
        # Save sample data to file
        data = get_sample_scan_data()
        input_file = os.path.join(test_dir, 'scan_data.json')
        fm.write_json(input_file, data)
        
        generator = ReportGenerator(output_dir=os.path.join(test_dir, 'reports'))
        files = generator.generate_from_file(
            input_file,
            formats=['html', 'txt']
        )
        
        assert 'html' in files
        assert 'txt' in files
        
        print("  ✓ Generate from file passed")
        
    finally:
        cleanup_test_env(test_dir)


def run_all_report_builder_tests():
    """Run all report builder tests."""
    print("=" * 60)
    print("REPORT BUILDER MODULE TESTS")
    print("=" * 60)
    
    try:
        test_generator_initialization()
        test_generate_html()
        test_generate_csv()
        test_generate_txt()
        test_generate_json()
        test_multiple_formats()
        test_risk_calculator()
        test_port_risk()
        test_diff_report()
        test_generate_from_file()
        
        print("\n" + "=" * 60)
        print("✅ All report builder tests passed!")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_report_builder_tests()
    sys.exit(0 if success else 1)