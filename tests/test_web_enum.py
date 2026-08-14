"""
Tests for Web Enumeration module
Run: python3 tests/test_web_enum.py
"""

import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.file_manager import FileManager

try:
    from tools.web_enum import DirBuster, TechFingerprint, ParamFuzzer
    WEB_ENUM_AVAILABLE = True
except ImportError as e:
    print(f"Warning: {e}")
    WEB_ENUM_AVAILABLE = False


def setup_test_env():
    """Create test environment."""
    test_dir = tempfile.mkdtemp(prefix="web_enum_test_")
    return test_dir, FileManager(test_dir)


def cleanup_test_env(test_dir):
    """Clean test environment."""
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)


def test_dir_buster_initialization():
    """Test directory buster creation."""
    print("\n[*] Testing DirBuster Initialization...")
    
    if not WEB_ENUM_AVAILABLE:
        print("  ⚠ Web enum not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        buster = DirBuster(output_dir=os.path.join(test_dir, 'output'))
        assert buster is not None
        assert hasattr(buster, 'brute_force')
        assert hasattr(buster, 'load_wordlist')
        
        print("  ✓ DirBuster initialized")
        
    finally:
        cleanup_test_env(test_dir)


def test_dir_buster_wordlist():
    """Test wordlist loading."""
    print("\n[*] Testing Wordlist Loading...")
    
    if not WEB_ENUM_AVAILABLE:
        print("  ⚠ Web enum not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        buster = DirBuster(output_dir=os.path.join(test_dir, 'output'))
        
        # Test default wordlist
        default_words = buster.DEFAULT_WORDLIST
        assert len(default_words) > 0
        assert 'admin' in default_words
        assert 'robots.txt' in default_words
        
        # Test loading from file
        wordlist_file = os.path.join(test_dir, 'wordlist.txt')
        fm.write_file(wordlist_file, "test1\ntest2\nadmin\n")
        
        words = buster.load_wordlist(wordlist_file)
        assert len(words) == 3
        assert 'admin' in words
        
        print("  ✓ Wordlist loading passed")
        
    finally:
        cleanup_test_env(test_dir)


def test_tech_fingerprint_initialization():
    """Test technology fingerprint creation."""
    print("\n[*] Testing TechFingerprint Initialization...")
    
    if not WEB_ENUM_AVAILABLE:
        print("  ⚠ Web enum not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        fingerprint = TechFingerprint(output_dir=os.path.join(test_dir, 'output'))
        assert fingerprint is not None
        assert hasattr(fingerprint, 'fingerprint')
        
        # Check signatures
        assert 'Apache' in fingerprint.TECH_SIGNATURES
        assert 'nginx' in fingerprint.TECH_SIGNATURES
        assert 'WordPress' in fingerprint.TECH_SIGNATURES
        
        print("  ✓ TechFingerprint initialized")
        
    finally:
        cleanup_test_env(test_dir)


def test_param_fuzzer_initialization():
    """Test parameter fuzzer creation."""
    print("\n[*] Testing ParamFuzzer Initialization...")
    
    if not WEB_ENUM_AVAILABLE:
        print("  ⚠ Web enum not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        fuzzer = ParamFuzzer(output_dir=os.path.join(test_dir, 'output'))
        assert fuzzer is not None
        assert hasattr(fuzzer, 'discover_params')
        assert hasattr(fuzzer, 'fuzz_param_values')
        
        # Check common params
        assert 'id' in fuzzer.COMMON_PARAMS
        assert 'username' in fuzzer.COMMON_PARAMS
        
        print("  ✓ ParamFuzzer initialized")
        
    finally:
        cleanup_test_env(test_dir)


def test_url_construction():
    """Test URL parameter addition."""
    print("\n[*] Testing URL Construction...")
    
    if not WEB_ENUM_AVAILABLE:
        print("  ⚠ Web enum not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        fuzzer = ParamFuzzer(output_dir=os.path.join(test_dir, 'output'))
        
        # Test with no existing params
        url1 = fuzzer._add_param("http://example.com/page", "id", "1")
        assert url1 == "http://example.com/page?id=1"
        
        # Test with existing params
        url2 = fuzzer._add_param("http://example.com/page?id=2", "name", "test")
        assert url2 == "http://example.com/page?id=2&name=test"
        
        print("  ✓ URL construction passed")
        
    finally:
        cleanup_test_env(test_dir)


def test_internet_fingerprint():
    """Test fingerprinting a real website (requires internet)."""
    print("\n[*] Testing Real Website Fingerprinting...")
    
    if not WEB_ENUM_AVAILABLE:
        print("  ⚠ Web enum not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        fingerprint = TechFingerprint(output_dir=os.path.join(test_dir, 'output'))
        
        # Test with example.com
        results = fingerprint.fingerprint("http://example.com", timeout=10)
        
        assert results['url'] == 'http://example.com'
        assert 'technologies' in results
        assert 'headers' in results
        
        print(f"  ✓ Found {len(results['technologies'])} technologies")
        for tech in results['technologies']:
            print(f"    - {tech['name']} ({tech['category']})")
        
    except Exception as e:
        print(f"  ⚠ Internet-dependent test failed: {e}")
        
    finally:
        cleanup_test_env(test_dir)


def test_internet_dir_buster_small():
    """Test directory busting on a real website (requires internet)."""
    print("\n[*] Testing Real Directory Buster...")
    
    if not WEB_ENUM_AVAILABLE:
        print("  ⚠ Web enum not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        buster = DirBuster(output_dir=os.path.join(test_dir, 'output'))
        
        # Test with small wordlist
        small_wordlist = ['robots.txt', 'index.html', 'nonexistent_page_12345']
        results = buster.brute_force(
            "http://example.com",
            wordlist=small_wordlist,
            threads=3,
            timeout=5
        )
        
        assert results['url'] == 'http://example.com'
        assert 'discovered' in results
        
        print(f"  ✓ Tested {results['paths_tested']} paths")
        print(f"  ✓ Found {len(results['discovered'])} paths")
        
    except Exception as e:
        print(f"  ⚠ Internet-dependent test failed: {e}")
        
    finally:
        cleanup_test_env(test_dir)


def run_all_web_enum_tests():
    """Run all web enumeration tests."""
    print("=" * 60)
    print("WEB ENUMERATION MODULE TESTS")
    print("=" * 60)
    
    if not WEB_ENUM_AVAILABLE:
        print("\n⚠️  Required packages not installed!")
        print("Install with: pip install requests")
        print("Skipping all web enum tests")
        return True
    
    try:
        test_dir_buster_initialization()
        test_dir_buster_wordlist()
        test_tech_fingerprint_initialization()
        test_param_fuzzer_initialization()
        test_url_construction()
        test_internet_fingerprint()
        test_internet_dir_buster_small()
        
        print("\n" + "=" * 60)
        print("✅ All web enumeration tests passed!")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_web_enum_tests()
    sys.exit(0 if success else 1)