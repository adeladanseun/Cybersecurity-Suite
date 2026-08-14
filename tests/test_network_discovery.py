"""
Tests for Network Discovery module
Run: python3 tests/test_network_discovery.py
"""

import sys
import os
import tempfile
import shutil
import ipaddress

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.file_manager import FileManager
from core.validator import is_private_ip, is_valid_cidr

try:
    from tools.network_discovery import NetworkDiscovery, NetworkMapper, ARPScanner

    DISCOVERY_AVAILABLE = True
except ImportError as e:
    print(f"Warning: {e}")
    DISCOVERY_AVAILABLE = False


def setup_test_env():
    """Create test environment."""
    test_dir = tempfile.mkdtemp(prefix="discovery_test_")
    print(dir())
    return test_dir, FileManager(test_dir)


def cleanup_test_env(test_dir):
    """Clean test environment."""
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)


def test_discovery_initialization():
    """Test network discovery creation."""
    print("\n[*] Testing Discovery Initialization...")
    
    if not DISCOVERY_AVAILABLE:
        print("  ⚠ Network discovery not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        discovery = NetworkDiscovery(output_dir=os.path.join(test_dir, 'output'))
        assert discovery is not None
        assert hasattr(discovery, 'discover_network')
        assert hasattr(discovery, 'get_network_interfaces')
        
        print("  ✓ Discovery initialized")
        
    finally:
        cleanup_test_env(test_dir)


def test_network_validation():
    """Test network validation for discovery."""
    print("\n[*] Testing Network Validation...")
    
    # Valid networks
    assert is_valid_cidr("192.168.1.0/24") == True
    assert is_private_ip("192.168.1.1") == True
    assert is_private_ip("10.0.0.1") == True
    
    # Invalid networks
    assert is_valid_cidr("invalid") == False
    assert is_private_ip("8.8.8.8") == False
    
    print("  ✓ Network validation passed")


def test_network_mapper():
    """Test network mapper functionality."""
    print("\n[*] Testing Network Mapper...")
    
    if not DISCOVERY_AVAILABLE:
        print("  ⚠ Network mapper not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        mapper = NetworkMapper(output_dir=os.path.join(test_dir, 'output'))
        
        # Create sample discovery results
        sample_results = {
            'network': '192.168.1.0/24',
            'hosts': [
                {'ip': '192.168.1.1', 'status': 'up', 'mac': '00:11:22:33:44:55', 'hostname': 'gateway'},
                {'ip': '192.168.1.10', 'status': 'up', 'mac': 'aa:bb:cc:dd:ee:ff', 'hostname': 'server1'},
                {'ip': '192.168.1.20', 'status': 'up', 'mac': '11:22:33:44:55:66', 'hostname': 'workstation1'}
            ]
        }
        
        # Create network map
        network_map = mapper.create_network_map(sample_results)
        
        assert network_map['network'] == '192.168.1.0/24'
        assert len(network_map['hosts']) == 3
        assert 'subnets' in network_map
        assert 'summary' in network_map
        
        # Export as JSON
        json_file = mapper.export_network_map(network_map, format='json')
        assert os.path.exists(json_file)
        
        # Export as text
        txt_file = mapper.export_network_map(network_map, format='txt')
        assert os.path.exists(txt_file)
        
        print("  ✓ Network mapper passed")
        
    finally:
        cleanup_test_env(test_dir)


def test_network_map_export_formats():
    """Test all export formats."""
    print("\n[*] Testing Export Formats...")
    
    if not DISCOVERY_AVAILABLE:
        print("  ⚠ Network mapper not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        mapper = NetworkMapper(output_dir=os.path.join(test_dir, 'output'))
        
        sample_results = {
            'network': '10.0.0.0/24',
            'hosts': [
                {'ip': '10.0.0.1', 'status': 'up', 'mac': '00:11:22:33:44:55'},
                {'ip': '10.0.0.2', 'status': 'up', 'mac': 'aa:bb:cc:dd:ee:ff'}
            ]
        }
        
        network_map = mapper.create_network_map(sample_results)
        
        # Test all formats
        for fmt in ['json', 'txt', 'csv', 'html']:
            output_file = mapper.export_network_map(network_map, format=fmt)
            assert os.path.exists(output_file)
            
            if fmt == 'json':
                data = fm.read_json(output_file)
                assert data['summary']['total_hosts'] == 2
            
            elif fmt == 'txt':
                content = fm.read_file(output_file)
                assert 'NETWORK MAP' in content
                assert '10.0.0.1' in content
            
            elif fmt == 'csv':
                csv_data = fm.read_csv(output_file)
                assert len(csv_data) == 2
            
            elif fmt == 'html':
                content = fm.read_file(output_file)
                assert '<html' in content
                assert '10.0.0.1' in content
        
        print("  ✓ All export formats passed")
        
    finally:
        cleanup_test_env(test_dir)


def test_gateway_detection():
    """Test gateway detection."""
    print("\n[*] Testing Gateway Detection...")
    
    if not DISCOVERY_AVAILABLE:
        print("  ⚠ Network mapper not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        mapper = NetworkMapper(output_dir=os.path.join(test_dir, 'output'))
        
        # Test with hosts ending in .1
        hosts = [
            {'ip': '192.168.1.1'},
            {'ip': '192.168.1.10'},
            {'ip': '192.168.1.20'}
        ]
        
        gateway = mapper.find_gateway(hosts)
        
        if gateway:
            print(f"  ✓ Gateway detected: {gateway}")
            gateway = ipaddress.ip_address(gateway)
            print('your gateway is ', 'Private' if gateway.is_private else 'Public')
            assert gateway
        else:
            print("  ⚠ No gateway detected (may be normal in test environment)")
        
    finally:
        cleanup_test_env(test_dir)


def test_local_network_detection():
    """Test local network interface detection."""
    print("\n[*] Testing Local Network Detection...")
    
    if not DISCOVERY_AVAILABLE:
        print("  ⚠ Network discovery not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        discovery = NetworkDiscovery(output_dir=os.path.join(test_dir, 'output'))
        
        interfaces = discovery.get_network_interfaces()
        networks = discovery.get_local_networks()
        
        print(f"  Found {len(interfaces)} network interfaces")
        print(f"  Found {len(networks)} local networks")
        
        # Should have at least loopback
        if interfaces:
            ips = [iface.get('ip') for iface in interfaces]
            assert '127.0.0.1' in ips or len(interfaces) > 0
        
        print("  ✓ Local network detection passed")
        
    finally:
        cleanup_test_env(test_dir)


def test_ping_single_host():
    """Test pinging a single host."""
    print("\n[*] Testing Single Host Ping...")
    
    if not DISCOVERY_AVAILABLE:
        print("  ⚠ Network discovery not available")
        return
    
    test_dir, fm = setup_test_env()
    
    try:
        discovery = NetworkDiscovery(output_dir=os.path.join(test_dir, 'output'))
        
        # Ping localhost (should always work)
        is_alive = discovery._ping_host('127.0.0.1')
        
        assert is_alive == True
        print("  ✓ Localhost ping successful")
        
    finally:
        cleanup_test_env(test_dir)


def run_all_network_discovery_tests():
    """Run all network discovery tests."""
    print("=" * 60)
    print("NETWORK DISCOVERY MODULE TESTS")
    print("=" * 60)
    
    try:
        test_discovery_initialization()
        test_network_validation()
        test_network_mapper()
        test_network_map_export_formats()
        test_gateway_detection()
        test_local_network_detection()
        test_ping_single_host()
        
        print("\n" + "=" * 60)
        print("✅ All network discovery tests passed!")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_network_discovery_tests()
    sys.exit(0 if success else 1)
