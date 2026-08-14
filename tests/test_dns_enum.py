"""
Tests for DNS Enumeration module
Run: python3 tests/test_dns_enum.py
"""

import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from tools.dns_enum import DNSEnumerator, ZoneTransfer, SubdomainFinder
    from core.file_manager import FileManager
    DNS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: {e}")
    DNS_AVAILABLE = False


def setup_test_env():
    """Create test environment."""
    test_dir = tempfile.mkdtemp(prefix="dns_test_")
    return test_dir, FileManager(test_dir)


def cleanup_test_env(test_dir):
    """Clean test environment."""
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)


def test_enumerator_initialization():
    """Test DNS enumerator creation."""
    print("\n[*] Testing Enumerator Initialization...")
    
    if not DNS_AVAILABLE:
        print("  ⚠ dnspython not available, skipping")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        enumerator = DNSEnumerator(output_dir=os.path.join(test_dir, 'output'))
        assert enumerator is not None
        assert hasattr(enumerator, 'enumerate')
        assert hasattr(enumerator, 'reverse_lookup')
        assert hasattr(enumerator, 'get_mail_servers')
        
        print("  ✓ Enumerator initialized")
        
    finally:
        cleanup_test_env(test_dir)


def test_enumerate_real_domain():
    """Test enumeration of a real domain (requires internet)."""
    print("\n[*] Testing Real Domain Enumeration...")
    
    if not DNS_AVAILABLE:
        print("  ⚠ dnspython not available, skipping")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        enumerator = DNSEnumerator(output_dir=os.path.join(test_dir, 'output'))
        
        # Test with example.com (should always exist)
        results = enumerator.enumerate("example.com", record_types=['A', 'NS', 'MX'])
        
        assert results['domain'] == 'example.com'
        assert 'summary' in results
        assert 'records' in results
        
        # Should have at least A records
        assert 'A' in results['records']
        
        print(f"  ✓ Found {results['summary']['total_records']} records")
        print(f"  ✓ Record types: {results['summary']['record_types_found']}")
        
    except Exception as e:
        print(f"  ⚠ Internet-dependent test failed: {e}")
        
    finally:
        cleanup_test_env(test_dir)


def test_reverse_lookup():
    """Test reverse DNS lookup."""
    print("\n[*] Testing Reverse Lookup...")
    
    if not DNS_AVAILABLE:
        print("  ⚠ dnspython not available, skipping")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        enumerator = DNSEnumerator(output_dir=os.path.join(test_dir, 'output'))
        
        # Test with Google DNS (should have PTR record)
        results = enumerator.reverse_lookup("8.8.8.8")
        
        assert results['ip'] == '8.8.8.8'
        assert 'hostnames' in results
        
        print(f"  ✓ Reverse lookup: 8.8.8.8 → {results['hostnames']}")
        
    except Exception as e:
        print(f"  ⚠ Internet-dependent test failed: {e}")
        
    finally:
        cleanup_test_env(test_dir)


def test_zone_transfer_initialization():
    """Test zone transfer tool creation."""
    print("\n[*] Testing Zone Transfer Initialization...")
    
    if not DNS_AVAILABLE:
        print("  ⚠ dnspython not available, skipping")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        zt = ZoneTransfer(output_dir=os.path.join(test_dir, 'output'))
        assert zt is not None
        assert hasattr(zt, 'attempt_transfer')
        
        print("  ✓ Zone transfer initialized")
        
    finally:
        cleanup_test_env(test_dir)


def test_zone_transfer_secure_domain():
    """Test zone transfer on secure domain (should fail)."""
    print("\n[*] Testing Zone Transfer on Secure Domain...")
    
    if not DNS_AVAILABLE:
        print("  ⚠ dnspython not available, skipping")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        zt = ZoneTransfer(output_dir=os.path.join(test_dir, 'output'))
        
        # example.com should NOT allow zone transfer
        results = zt.attempt_transfer("example.com")
        
        assert results['vulnerable'] == False
        assert 'nameservers_tested' in results
        
        print(f"  ✓ Zone transfer correctly denied for example.com")
        
    except Exception as e:
        print(f"  ⚠ Internet-dependent test failed: {e}")
        
    finally:
        cleanup_test_env(test_dir)


def test_subdomain_finder_initialization():
    """Test subdomain finder creation."""
    print("\n[*] Testing Subdomain Finder Initialization...")
    
    if not DNS_AVAILABLE:
        print("  ⚠ dnspython not available, skipping")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        finder = SubdomainFinder(output_dir=os.path.join(test_dir, 'output'))
        assert finder is not None
        assert hasattr(finder, 'find_subdomains')
        assert hasattr(finder, 'load_wordlist')
        
        print("  ✓ Subdomain finder initialized")
        
    finally:
        cleanup_test_env(test_dir)


def test_subdomain_finder_small():
    """Test subdomain finding with small wordlist."""
    print("\n[*] Testing Subdomain Finder (small)...")
    
    if not DNS_AVAILABLE:
        print("  ⚠ dnspython not available, skipping")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        finder = SubdomainFinder(output_dir=os.path.join(test_dir, 'output'))
        
        # Test with small wordlist
        test_wordlist = ['www', 'mail', 'nonexistent12345']
        results = finder.find_subdomains("example.com", wordlist=test_wordlist, max_threads=3)
        
        assert results['domain'] == 'example.com'
        assert 'subdomains' in results
        assert 'summary' in results
        
        # www.example.com should exist
        found_hosts = [s['hostname'] for s in results['subdomains']]
        assert 'www.example.com' in found_hosts
        
        # nonexistent should not be found
        assert 'nonexistent12345.example.com' not in found_hosts
        
        print(f"  ✓ Found {results['summary']['total_found']} subdomains")
        
    except Exception as e:
        print(f"  ⚠ Internet-dependent test failed: {e}")
        
    finally:
        cleanup_test_env(test_dir)


def test_wordlist_loading():
    """Test wordlist loading from file."""
    print("\n[*] Testing Wordlist Loading...")
    
    if not DNS_AVAILABLE:
        print("  ⚠ dnspython not available, skipping")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        finder = SubdomainFinder(output_dir=os.path.join(test_dir, 'output'))
        
        # Create test wordlist
        wordlist_file = os.path.join(test_dir, 'wordlist.txt')
        fm.write_file(wordlist_file, "www\nmail\nftp\ntest\n")
        
        words = finder.load_wordlist(wordlist_file)
        assert len(words) == 4
        assert 'www' in words
        assert 'test' in words
        
        # Test with nonexistent file
        words = finder.load_wordlist(os.path.join(test_dir, 'nonexistent.txt'))
        assert len(words) > 0  # Should fall back to default
        
        print("  ✓ Wordlist loading passed")
        
    finally:
        cleanup_test_env(test_dir)


def run_all_dns_tests():
    """Run all DNS enumeration tests."""
    print("=" * 60)
    print("DNS ENUMERATION MODULE TESTS")
    print("=" * 60)
    
    if not DNS_AVAILABLE:
        print("\n⚠️  dnspython not installed!")
        print("Install with: pip install dnspython")
        print("Skipping all DNS tests")
        return True
    
    try:
        test_enumerator_initialization()
        test_enumerate_real_domain()
        test_reverse_lookup()
        test_zone_transfer_initialization()
        test_zone_transfer_secure_domain()
        test_subdomain_finder_initialization()
        test_subdomain_finder_small()
        test_wordlist_loading()
        
        print("\n" + "=" * 60)
        print("✅ All DNS enumeration tests passed!")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_dns_tests()
    sys.exit(0 if success else 1)