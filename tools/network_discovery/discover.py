"""
Network Discovery - Main discovery logic
Identifies live hosts on internal networks
"""

import os
import sys
import socket
import subprocess
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.file_manager import FileManager
from core.validator import is_valid_cidr, is_valid_ip_range, is_valid_ip, is_private_ip
from core.logger import get_logger, log_scan_start, log_scan_complete
from core.notifier import Notifier
from core.exceptions import ScanError, ValidationError
from .arp_scanner import ARPScanner
from .network_mapper import NetworkMapper

# Try importing optional dependencies
try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

try:
    from scapy.all import srp
    from scapy.layers.l2 import ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class NetworkDiscovery:
    """Network discovery and host identification."""
    
    def __init__(self, config=None, output_dir=None):
        """
        Initialize network discovery.
        
        Args:
            config: Config object (optional)
            output_dir: Output directory
        """
        self.config = config
        self.logger = get_logger("network_discovery")
        self.notifier = Notifier()
        self.fm = FileManager()
        
        # Set output directory
        if output_dir:
            self.output_dir = output_dir
        elif config:
            self.output_dir = config.get("paths.data_dir", "./data") + "/intermediate"
        else:
            self.output_dir = "./data/intermediate"
        
        self.fm.ensure_dir(self.output_dir)
        
        # Initialize scanners
        self.arp_scanner = ARPScanner(output_dir=self.output_dir)
        self.network_mapper = NetworkMapper(output_dir=self.output_dir)
    
    def discover_network(self, network, method='auto', ping_first=True):
        """
        Discover live hosts on a network.
        
        Args:
            network: Network range (CIDR or IP range)
            method: 'auto', 'arp', 'ping', 'nmap'
            ping_first: Ping sweep before detailed discovery
        
        Returns:
            dict: Network discovery results
        """
        # Validate network
        if not (is_valid_cidr(network) or is_valid_ip_range(network) or is_valid_ip(network)):
            raise ValidationError(f"Invalid network: {network}", field="network", value=network)
        
        # Check if internal network
        if is_valid_ip(network) and not is_private_ip(network):
            self.logger.warning(f"Public IP detected: {network}")
            self.logger.warning("Network discovery is designed for internal networks")
        
        self.logger.info(f"Starting network discovery for: {network}")
        log_scan_start(self.logger, network, "network_discovery")
        
        start_time = datetime.now()
        
        results = {
            'network': network,
            'timestamp': datetime.now().isoformat(),
            'method': method,
            'hosts': [],
            'summary': {}
        }
        
        try:
            # Determine discovery method
            if method == 'auto':
                if is_private_ip(network.split('/')[0]) and SCAPY_AVAILABLE:
                    method = 'arp'
                else:
                    method = 'ping'
            
            self.logger.info(f"Using {method.upper()} discovery method")
            
            # Discover hosts
            if method == 'arp' and SCAPY_AVAILABLE:
                hosts = self.arp_scanner.scan_network(network)
            elif method == 'nmap':
                hosts = self._discover_with_nmap(network)
            else:
                hosts = self._discover_with_ping(network)
            
            results['hosts'] = hosts
            results['method'] = method
            
            # Enrich host information
            results['hosts'] = self._enrich_hosts(hosts)
            
            # Generate summary
            results['summary'] = self._generate_summary(results)
            
            # Save results
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_network = self.fm.safe_filename(network.replace('/', '_'))
            output_file = os.path.join(self.output_dir, f"discovery_{safe_network}_{timestamp}.json")
            self.fm.write_json(output_file, results)
            results['output_file'] = output_file
            
            # Save live hosts as simple text file
            live_hosts = [h['ip'] for h in hosts if h.get('status') == 'up']
            txt_file = os.path.join(self.output_dir, f"live_hosts_{safe_network}_{timestamp}.txt")
            self.fm.write_file(txt_file, "\n".join(live_hosts))
            
            duration = (datetime.now() - start_time).total_seconds()
            log_scan_complete(self.logger, network, "network_discovery", duration)
            self.notifier.beep_complete()
            
            self.logger.info(f"Discovery complete: {len(live_hosts)} hosts found")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Network discovery failed: {e}")
            self.notifier.beep_error()
            raise ScanError(str(e), target=network, tool="network_discovery")
    
    def _discover_with_ping(self, network):
        """Discover hosts using ping sweep."""
        hosts = []
        
        try:
            # Generate IP list
            if '/' in network:
                ips = [str(ip) for ip in ipaddress.ip_network(network, strict=False).hosts()]
            elif '-' in network:
                start, end = network.split('-')
                start_ip = ipaddress.IPv4Address(start.strip())
                end_ip = ipaddress.IPv4Address(end.strip())
                ips = [str(ipaddress.IPv4Address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)]
            else:
                ips = [network]
            
            self.logger.info(f"Pinging {len(ips)} potential hosts...")
            
            # Use ThreadPoolExecutor for parallel pinging
            with ThreadPoolExecutor(max_workers=20) as executor:
                future_to_ip = {
                    executor.submit(self._ping_host, ip): ip
                    for ip in ips
                }
                
                completed = 0
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    completed += 1
                    
                    try:
                        is_alive = future.result()
                        if is_alive:
                            hosts.append({
                                'ip': ip,
                                'status': 'up',
                                'discovery_method': 'ping'
                            })
                    except Exception as e:
                        self.logger.debug(f"Error pinging {ip}: {e}")
                    
                    if completed % 25 == 0:
                        progress = int((completed / len(ips)) * 100)
                        if progress in [25, 50, 75]:
                            self.logger.info(f"Progress: {progress}%")
                            self.notifier.beep_progress(progress)
            
        except Exception as e:
            self.logger.error(f"Ping sweep failed: {e}")
        
        return hosts
    
    def _ping_host(self, ip):
        """Ping a single host."""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', ip],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
    
    def _discover_with_nmap(self, network):
        """Discover hosts using nmap."""
        hosts = []
        
        try:
            import shutil
            nmap_path = shutil.which('nmap')
            
            if not nmap_path:
                self.logger.error("nmap not found")
                return self._discover_with_ping(network)
            
            cmd = [nmap_path, '-sn', '-n', network]
            
            if os.geteuid() != 0:
                cmd = ['sudo'] + cmd
            
            self.logger.info(f"Running nmap discovery: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                # Parse nmap output
                for line in stdout.split('\n'):
                    if 'Nmap scan report for' in line:
                        ip = line.split()[-1].strip('()')
                        hosts.append({
                            'ip': ip,
                            'status': 'up',
                            'discovery_method': 'nmap'
                        })
            
        except Exception as e:
            self.logger.error(f"nmap discovery failed: {e}")
        
        return hosts
    
    def _enrich_hosts(self, hosts):
        """Enrich host information with additional details."""
        enriched = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_host = {
                executor.submit(self._get_host_details, host): host
                for host in hosts
            }
            
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    details = future.result()
                    enriched.append(details)
                except Exception as e:
                    self.logger.debug(f"Error enriching host: {e}")
                    enriched.append(host)
        
        return enriched
    
    def _get_host_details(self, host):
        """Get additional details for a host."""
        ip = host.get('ip')
        
        if not ip:
            return host
        
        # Try reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            host['hostname'] = hostname
        except socket.herror:
            host['hostname'] = None
        except Exception:
            host['hostname'] = None
        
        # Try to get MAC address from ARP cache
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        host['mac'] = parts[3]
                        break
        except Exception:
            pass
        
        # Add timestamp
        host['discovered_at'] = datetime.now().isoformat()
        
        return host
    
    def _generate_summary(self, results):
        """Generate summary statistics."""
        hosts = results['hosts']
        live_hosts = [h for h in hosts if h.get('status') == 'up']
        
        summary = {
            'total_hosts_found': len(hosts),
            'live_hosts': len(live_hosts),
            'hosts_with_hostnames': sum(1 for h in live_hosts if h.get('hostname')),
            'hosts_with_mac': sum(1 for h in live_hosts if h.get('mac')),
            'discovery_method': results['method']
        }
        
        return summary
    
    def get_network_interfaces(self):
        """Get local network interfaces."""
        if not NETIFACES_AVAILABLE:
            self.logger.warning("netifaces not installed")
            return self._get_interfaces_fallback()
        
        interfaces = []
        
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    interfaces.append({
                        'name': iface,
                        'ip': addr.get('addr'),
                        'netmask': addr.get('netmask'),
                        'broadcast': addr.get('broadcast')
                    })
        
        return interfaces
    
    def _get_interfaces_fallback(self):
        """Fallback interface detection using system commands."""
        interfaces = []
        
        try:
            result = subprocess.run(
                ['ip', 'addr', 'show'],
                capture_output=True,
                text=True
            )
            
            current_iface = None
            for line in result.stdout.split('\n'):
                if line and not line.startswith(' '):
                    # New interface
                    parts = line.split()
                    if len(parts) >= 2:
                        current_iface = parts[1].rstrip(':')
                
                if 'inet ' in line and current_iface:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        cidr = parts[1]
                        ip = cidr.split('/')[0]
                        interfaces.append({
                            'name': current_iface,
                            'ip': ip,
                            'cidr': cidr
                        })
        
        except Exception as e:
            self.logger.error(f"Interface detection failed: {e}")
        
        return interfaces
    
    def get_local_networks(self):
        """Get local networks for discovery."""
        interfaces = self.get_network_interfaces()
        networks = []
        
        for iface in interfaces:
            ip = iface.get('ip')
            netmask = iface.get('netmask')
            
            if ip and netmask:
                try:
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    networks.append({
                        'interface': iface.get('name'),
                        'network': str(network),
                        'ip': ip
                    })
                except ValueError:
                    continue
        
        return networks