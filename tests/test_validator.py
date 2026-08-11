"""
Tests for core.validator module
Run: python3 tests/test_validator.py
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.validator import (
    is_valid_ip, is_valid_ipv4, is_valid_ipv6,
    is_private_ip, is_public_ip, is_valid_cidr,
    is_valid_ip_range, is_valid_domain, is_valid_url,
    is_valid_hostname, is_valid_port, is_valid_port_range,
    classify_target, get_target_type
)


def test_ip_validation():
    """Test IP address validation functions."""
    print("\n[*] Testing IP Validation...")
    
    # Valid IPv4
    assert is_valid_ipv4("192.168.1.1") == True
    assert is_valid_ipv4("10.0.0.1") == True
    assert is_valid_ipv4("8.8.8.8") == True
    
    # Invalid IPv4
    assert is_valid_ipv4("256.256.256.256") == False
    assert is_valid_ipv4("192.168.1") == False
    assert is_valid_ipv4("abc.def.ghi.jkl") == False
    assert is_valid_ipv4("") == False
    assert is_valid_ipv4(None) == False
    
    # Valid IPv6
    assert is_valid_ipv6("::1") == True
    assert is_valid_ipv6("2001:db8::1") == True
    
    # Invalid IPv6
    assert is_valid_ipv6("not:an:ip") == False
    
    # Generic IP check
    assert is_valid_ip("192.168.1.1") == True
    assert is_valid_ip("::1") == True
    assert is_valid_ip("invalid") == False
    
    print("  ✓ IP validation passed")


def test_private_public_ip():
    """Test private/public IP detection."""
    print("\n[*] Testing Private/Public IP Detection...")
    
    # Private IPs
    assert is_private_ip("192.168.1.1") == True
    assert is_private_ip("10.0.0.1") == True
    assert is_private_ip("172.16.0.1") == True
    assert is_private_ip("127.0.0.1") == True  # Loopback is private
    
    # Public IPs
    assert is_public_ip("8.8.8.8") == True
    assert is_public_ip("1.1.1.1") == True
    
    print("  ✓ Private/Public detection passed")


def test_cidr_and_range():
    """Test CIDR and IP range validation."""
    print("\n[*] Testing CIDR and Range Validation...")
    
    # Valid CIDR
    assert is_valid_cidr("192.168.1.0/24") == True
    assert is_valid_cidr("10.0.0.0/8") == True
    
    # Invalid CIDR
    assert is_valid_cidr("192.168.1.0/33") == False
    assert is_valid_cidr("not-a-cidr") == False
    
    # Valid IP range
    assert is_valid_ip_range("192.168.1.1-192.168.1.254") == True
    
    # Invalid IP range
    assert is_valid_ip_range("192.168.1.1") == False
    assert is_valid_ip_range("not-a-range") == False
    
    print("  ✓ CIDR and range validation passed")


def test_domain_validation():
    """Test domain validation."""
    print("\n[*] Testing Domain Validation...")
    
    # Valid domains
    assert is_valid_domain("example.com") == True
    assert is_valid_domain("sub.example.com") == True
    assert is_valid_domain("test.co.uk") == True
    
    # Invalid domains
    assert is_valid_domain("") == False
    assert is_valid_domain("not a domain") == False
    assert is_valid_domain(".com") == False
    
    print("  ✓ Domain validation passed")


def test_url_validation():
    """Test URL validation."""
    print("\n[*] Testing URL Validation...")
    
    # Valid URLs
    assert is_valid_url("http://example.com") == True
    assert is_valid_url("https://example.com/path") == True
    assert is_valid_url("http://192.168.1.1:8080") == True
    
    # Invalid URLs
    assert is_valid_url("") == False
    assert is_valid_url("not-a-url") == False
    assert is_valid_url("ftp://example.com") == False  # Only http/https
    
    print("  ✓ URL validation passed")


def test_hostname_validation():
    """Test hostname validation."""
    print("\n[*] Testing Hostname Validation...")
    
    # Valid hostnames
    assert is_valid_hostname("localhost") == True
    assert is_valid_hostname("web-server") == True
    assert is_valid_hostname("server01") == True
    
    # Invalid hostnames
    assert is_valid_hostname("") == False
    assert is_valid_hostname("host name") == False
    
    print("  ✓ Hostname validation passed")


def test_port_validation():
    """Test port validation."""
    print("\n[*] Testing Port Validation...")
    
    # Valid ports
    assert is_valid_port(80) == True
    assert is_valid_port("443") == True
    assert is_valid_port(1) == True
    assert is_valid_port(65535) == True
    
    # Invalid ports
    assert is_valid_port(0) == False
    assert is_valid_port(65536) == False
    assert is_valid_port("invalid") == False
    assert is_valid_port(None) == False
    
    # Valid port ranges
    assert is_valid_port_range("80-443") == True
    assert is_valid_port_range("80,443,8080") == True
    assert is_valid_port_range("22") == True
    
    # Invalid port ranges
    assert is_valid_port_range("") == False
    assert is_valid_port_range("443-80") == False  # Start > End
    
    print("  ✓ Port validation passed")


def test_classify_target():
    """Test target classification."""
    print("\n[*] Testing Target Classification...")
    
    # IP classification
    assert classify_target("192.168.1.1") == "ipv4"
    assert classify_target("::1") == "ipv6"
    
    # CIDR classification
    assert classify_target("192.168.1.0/24") == "cidr"
    
    # Domain/URL classification
    assert classify_target("example.com") == "domain"
    assert classify_target("https://example.com") == "url"
    assert classify_target("http://192.168.1.1:8080") == "url"
    
    # Hostname
    assert classify_target("web-server") == "hostname"
    
    # Unknown
    assert classify_target("") == "unknown"
    assert classify_target("not a valid target") == "unknown"
    
    print("  ✓ Target classification passed")


def test_get_target_type():
    """Test detailed target type information."""
    print("\n[*] Testing Detailed Target Type...")
    
    # Internal IP
    result = get_target_type("192.168.1.1")
    assert result['type'] == "ipv4"
    assert result['is_internal'] == True
    assert result['is_network_target'] == True
    
    # External IP
    result = get_target_type("8.8.8.8")
    assert result['type'] == "ipv4"
    assert result['is_external'] == True
    
    # URL with internal IP
    result = get_target_type("http://192.168.1.1:8080")
    assert result['type'] == "url"
    assert result['is_web_target'] == True
    assert result['is_internal'] == True
    
    # Domain
    result = get_target_type("example.com")
    assert result['type'] == "domain"
    assert result['is_web_target'] == True
    
    print("  ✓ Detailed target type passed")


def run_all_validator_tests():
    """Run all validator tests."""
    print("=" * 60)
    print("VALIDATOR MODULE TESTS")
    print("=" * 60)
    
    try:
        test_ip_validation()
        test_private_public_ip()
        test_cidr_and_range()
        test_domain_validation()
        test_url_validation()
        test_hostname_validation()
        test_port_validation()
        test_classify_target()
        test_get_target_type()
        
        print("\n" + "=" * 60)
        print("✅ All validator tests passed!")
        print("=" * 60)
        return True
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        return False
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return False


if __name__ == "__main__":
    success = run_all_validator_tests()
    sys.exit(0 if success else 1)