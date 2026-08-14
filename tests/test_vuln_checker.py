"""
Tests for Vulnerability Checker module
Run: python3 tests/test_vuln_checker.py
"""

import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.file_manager import FileManager

try:
    from tools.vuln_checker import ServiceVulnChecker, WebVulnChecker, SSLChecker, CVELookup
    VULN_CHECK_AVAILABLE = True
except ImportError as e:
    print(f"Warning: {e}")
    VULN_CHECK_AVAILABLE = False


def setup_test_env():
    """Create test environment."""
    test_dir = tempfile.mkdtemp(prefix="vuln_test_")
    return test_dir, FileManager(test_dir)


def cleanup_test_env(test_dir):
    """Clean test environment."""
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)


def test_service_checker_initialization():
    """Test service vulnerability checker creation."""
    print("\n[*] Testing Service Checker Initialization...")
    
    if not VULN_CHECK_AVAILABLE:
        print("  ⚠ Vulnerability checker not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        checker = ServiceVulnChecker(output_dir=os.path.join(test_dir, 'output'))
        assert checker is not None
        assert hasattr(checker, 'check_service')
        assert hasattr(checker, 'check_scan_results')
        
        print("  ✓ Service checker initialized")
        
    finally:
        cleanup_test_env(test_dir)


def test_check_vulnerable_service():
    """Test checking a known vulnerable service."""
    print("\n[*] Testing Vulnerable Service Detection...")
    
    if not VULN_CHECK_AVAILABLE:
        print("  ⚠ Vulnerability checker not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        checker = ServiceVulnChecker(output_dir=os.path.join(test_dir, 'output'))
        
        # Check Apache 2.4.49 (known vulnerable)
        vulns = checker.check_service(
            service='http',
            product='Apache',
            version='2.4.49',
            port=80,
            host='example.com'
        )
        
        assert len(vulns) > 0
        assert vulns[0]['cve'] == 'CVE-2021-41773'
        assert vulns[0]['severity'] == 'critical'
        assert vulns[0]['exploit_available'] == True
        
        print(f"  ✓ Found {len(vulns)} vulnerabilities")
        print(f"  ✓ CVE: {vulns[0]['cve']}")
        
    finally:
        cleanup_test_env(test_dir)


def test_check_secure_service():
    """Test checking a secure service version."""
    print("\n[*] Testing Secure Service...")
    
    if not VULN_CHECK_AVAILABLE:
        print("  ⚠ Vulnerability checker not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        checker = ServiceVulnChecker(output_dir=os.path.join(test_dir, 'output'))
        
        # Check newer Apache version
        vulns = checker.check_service(
            service='http',
            product='Apache',
            version='2.4.58',
            port=80,
            host='example.com'
        )
        
        # Should not find known vulnerabilities
        assert len(vulns) == 0
        
        print("  ✓ No vulnerabilities for secure version")
        
    finally:
        cleanup_test_env(test_dir)


def test_check_scan_results():
    """Test checking full scan results."""
    print("\n[*] Testing Scan Results Check...")
    
    if not VULN_CHECK_AVAILABLE:
        print("  ⚠ Vulnerability checker not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        checker = ServiceVulnChecker(output_dir=os.path.join(test_dir, 'output'))
        
        # Sample scan results
        scan_results = {
            'ports': [
                {
                    'port': 80, 'state': 'open', 'service': 'http',
                    'product': 'Apache', 'version': '2.4.49', 'host': 'example.com'
                },
                {
                    'port': 443, 'state': 'open', 'service': 'https',
                    'product': 'Apache', 'version': '2.4.49', 'host': 'example.com'
                }
            ]
        }
        
        results = checker.check_scan_results(scan_results)
        
        assert 'vulnerabilities' in results
        assert 'summary' in results
        assert results['summary']['total_vulnerabilities'] > 0
        
        print(f"  ✓ Found {results['summary']['total_vulnerabilities']} vulnerabilities")
        
    finally:
        cleanup_test_env(test_dir)


def test_cve_lookup_initialization():
    """Test CVE lookup creation."""
    print("\n[*] Testing CVE Lookup Initialization...")
    
    if not VULN_CHECK_AVAILABLE:
        print("  ⚠ Vulnerability checker not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        cve_lookup = CVELookup(output_dir=os.path.join(test_dir, 'output'))
        assert cve_lookup is not None
        assert hasattr(cve_lookup, 'lookup_cve')
        assert hasattr(cve_lookup, 'search_by_service')
        
        print("  ✓ CVE lookup initialized")
        
    finally:
        cleanup_test_env(test_dir)


def test_version_matching():
    """Test version matching logic."""
    print("\n[*] Testing Version Matching...")
    
    if not VULN_CHECK_AVAILABLE:
        print("  ⚠ Vulnerability checker not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        checker = ServiceVulnChecker(output_dir=os.path.join(test_dir, 'output'))
        
        # Exact match
        assert checker._version_matches('2.4.49', '2.4.49') == True
        
        # Prefix match
        assert checker._version_matches('2.4.49', '2.4') == True
        
        # No match
        assert checker._version_matches('2.4.58', '2.4.49') == False
        
        # Empty version
        assert checker._version_matches('', '2.4.49') == False
        
        print("  ✓ Version matching passed")
        
    finally:
        cleanup_test_env(test_dir)


def test_ssl_checker_initialization():
    """Test SSL checker creation."""
    print("\n[*] Testing SSL Checker Initialization...")
    
    if not VULN_CHECK_AVAILABLE:
        print("  ⚠ Vulnerability checker not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        ssl_checker = SSLChecker(output_dir=os.path.join(test_dir, 'output'))
        assert ssl_checker is not None
        assert hasattr(ssl_checker, 'check_ssl')
        
        print("  ✓ SSL checker initialized")
        
    finally:
        cleanup_test_env(test_dir)


def test_summary_generation():
    """Test vulnerability summary generation."""
    print("\n[*] Testing Summary Generation...")
    
    if not VULN_CHECK_AVAILABLE:
        print("  ⚠ Vulnerability checker not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        checker = ServiceVulnChecker(output_dir=os.path.join(test_dir, 'output'))
        
        vulnerabilities = [
            {'severity': 'critical', 'exploit_available': True},
            {'severity': 'high', 'exploit_available': False},
            {'severity': 'medium', 'exploit_available': False}
        ]
        
        summary = checker._generate_summary(vulnerabilities)
        
        assert summary['total_vulnerabilities'] == 3
        assert summary['critical'] == 1
        assert summary['high'] == 1
        assert summary['medium'] == 1
        assert summary['exploitable'] == 1
        
        print("  ✓ Summary generation passed")
        
    finally:
        cleanup_test_env(test_dir)


def run_all_vuln_checker_tests():
    """Run all vulnerability checker tests."""
    print("=" * 60)
    print("VULNERABILITY CHECKER MODULE TESTS")
    print("=" * 60)
    
    try:
        test_service_checker_initialization()
        test_check_vulnerable_service()
        test_check_secure_service()
        test_check_scan_results()
        test_cve_lookup_initialization()
        test_version_matching()
        test_ssl_checker_initialization()
        test_summary_generation()
        
        print("\n" + "=" * 60)
        print("✅ All vulnerability checker tests passed!")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_vuln_checker_tests()
    sys.exit(0 if success else 1)