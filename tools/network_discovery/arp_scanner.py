"""
ARP Scanner - ARP-based network scanning
Fast host discovery on local networks
"""

import os
import sys
import ipaddress
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.file_manager import FileManager
from core.validator import is_valid_cidr, is_private_ip
from core.logger import get_logger
from core.notifier import Notifier
from core.exceptions import ScanError, ValidationError

# Try importing scapy
try:
    from scapy.sendrecv import srp
    from scapy.layers.l2 import ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class ARPScanner:
    """ARP-based network scanner for local networks."""
    
    def __init__(self, output_dir=None):
        """Initialize ARP scanner."""
        if not SCAPY_AVAILABLE:
            self.logger = get_logger("arp_scanner")
            self.logger.warning("scapy not installed. ARP scanning disabled.")
            self.logger.warning("Install with: pip install scapy")
            self.scapy_available = False
        else:
            self.scapy_available = True
        
        self.logger = get_logger("arp_scanner")
        self.notifier = Notifier()
        self.fm = FileManager()
        
        self.output_dir = output_dir or "./data/intermediate"
        self.fm.ensure_dir(self.output_dir)
    
    def scan_network(self, network, timeout=2):
        """
        Perform ARP scan on a network.
        
        Args:
            network: Network CIDR (e.g., 192.168.1.0/24)
            timeout: Timeout for ARP responses
        
        Returns:
            list: Discovered hosts
        """
        if not self.scapy_available:
            raise ScanError("scapy not installed", target=network, tool="arp_scanner")
        
        if not is_valid_cidr(network):
            raise ValidationError(f"Invalid network: {network}", field="network", value=network)
        
        # Check if private network
        network_ip = network.split('/')[0]
        if not is_private_ip(network_ip):
            self.logger.warning(f"ARP scanning public network: {network}")
            self.logger.warning("ARP only works on local networks")
        
        self.logger.info(f"Starting ARP scan on: {network}")
        
        start_time = datetime.now()
        hosts = []
        
        try:
            # Create ARP request
            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            
            # Send packet and receive responses
            self.logger.debug("Sending ARP requests...")
            answered, unanswered = srp(
                packet,
                timeout=timeout,
                verbose=0,
                iface=None,
                inter=0.1
            )
            
            # Parse responses
            for sent, received in answered:
                host_info = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'status': 'up',
                    'discovery_method': 'arp',
                    'timestamp': datetime.now().isoformat()
                }
                hosts.append(host_info)
                self.logger.info(f"Found: {host_info['ip']} ({host_info['mac']})")
            
            # Sort by IP
            hosts.sort(key=lambda x: ipaddress.IPv4Address(x['ip']))
            
            duration = (datetime.now() - start_time).total_seconds()
            self.logger.info(f"ARP scan complete: {len(hosts)} hosts in {duration:.2f}s")
            self.notifier.beep_complete()
            
            return hosts
            
        except PermissionError:
            self.logger.error("ARP scan requires root privileges")
            raise ScanError("ARP scan requires sudo", target=network, tool="arp_scanner")
        except Exception as e:
            self.logger.error(f"ARP scan failed: {e}")
            raise ScanError(str(e), target=network, tool="arp_scanner")
    
    def scan_single(self, ip, timeout=1):
        """
        Check if a single host is alive using ARP.
        
        Args:
            ip: IP address to check
            timeout: Response timeout
        
        Returns:
            bool: True if host responded
        """
        if not self.scapy_available:
            return False
        
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            
            answered, _ = srp(packet, timeout=timeout, verbose=0)
            
            return len(answered) > 0
            
        except Exception:
            return False
    
    def get_mac_vendor(self, mac_address):
        """
        Get vendor from MAC address (OUI lookup).
        
        Args:
            mac_address: MAC address
        
        Returns:
            str: Vendor name or 'Unknown'
        """
        # Simplified OUI lookup
        # Full OUI database available from IEEE
        oui_prefix = mac_address.upper()[:8].replace(':', '')
        
        # Common vendors (extended list available offline)
        vendors = {
            '000C29': 'VMware',
            '005056': 'VMware',
            '080027': 'VirtualBox',
            '001C42': 'Parallels',
            '00036C': 'Cisco',
            '001B21': 'Intel',
            '000D93': 'Apple',
            '001C25': 'Apple',
            '0022F3': 'Apple',
            '0019D2': 'Samsung',
            '0018DE': 'Intel',
            '00215D': 'Intel',
            '002268': 'Intel',
            '0050BA': 'D-Link',
            '001FC1': 'D-Link',
            '001E58': 'D-Link',
            '00045A': 'Linksys',
            '001D7E': 'Linksys',
            'C81FEB': 'Microsoft',
            '0050F2': 'Microsoft',
            '001DD8': 'Microsoft',
            '0017FA': 'Microsoft',
            '001B78': 'Hewlett Packard',
            '001CC4': 'Hewlett Packard',
            '001E0B': 'Hewlett Packard'
        }
        
        # Check different OUI lengths
        for prefix_len in [8, 6]:
            oui = oui_prefix[:prefix_len]
            if oui in vendors:
                return vendors[oui]
        
        return 'Unknown'
    
    def enrich_with_vendor(self, hosts):
        """Add vendor information to hosts."""
        for host in hosts:
            if host.get('mac'):
                host['vendor'] = self.get_mac_vendor(host['mac'])
        return hosts