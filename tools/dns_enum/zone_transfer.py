"""
Zone Transfer - Attempt DNS zone transfers
Tests for misconfigured DNS servers
"""

import os
import sys
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.file_manager import FileManager
from core.validator import is_valid_domain
from core.logger import get_logger
from core.notifier import Notifier
from core.exceptions import ValidationError

# Try importing dnspython
try:
    import dns.zone
    import dns.query
    import dns.resolver
    import dns.exception
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False


class ZoneTransfer:
    """DNS Zone Transfer testing and exploitation."""
    
    def __init__(self, output_dir=None):
        """Initialize Zone Transfer tester."""
        if not DNSPYTHON_AVAILABLE:
            raise ImportError("dnspython is required for zone transfer")
        
        self.logger = get_logger("zone_transfer")
        self.notifier = Notifier()
        self.fm = FileManager()
        
        self.output_dir = output_dir or "./data/intermediate"
        self.fm.ensure_dir(self.output_dir)
    
    def attempt_transfer(self, domain, nameserver=None):
        """
        Attempt zone transfer for a domain.
        
        Args:
            domain: Domain to test
            nameserver: Specific nameserver to test (optional)
        
        Returns:
            dict: Zone transfer results
        """
        if not is_valid_domain(domain):
            raise ValidationError(f"Invalid domain: {domain}", field="domain", value=domain)
        
        self.logger.info(f"Attempting zone transfer for: {domain}")
        
        results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'vulnerable': False,
            'nameservers_tested': [],
            'records': [],
            'error': None
        }
        
        try:
            # Get nameservers if not provided
            if nameserver:
                nameservers = [nameserver]
            else:
                ns_records = dns.resolver.resolve(domain, 'NS')
                nameservers = [str(ns).rstrip('.') for ns in ns_records]
            
            results['nameservers_tested'] = nameservers
            
            # Try zone transfer from each nameserver
            for ns in nameservers:
                try:
                    # Resolve nameserver IP
                    ns_ip = socket.gethostbyname(ns)
                    
                    self.logger.info(f"Trying zone transfer from: {ns} ({ns_ip})")
                    
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_ip, domain, timeout=10)
                    )
                    
                    # If successful, collect records
                    records = []
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            for rdata in rdataset:
                                records.append({
                                    'name': str(name),
                                    'type': dns.rdatatype.to_text(rdataset.rdtype),
                                    'value': str(rdata),
                                    'ttl': rdataset.ttl
                                })
                    
                    if records:
                        results['vulnerable'] = True
                        results['records'] = records
                        results['vulnerable_nameserver'] = ns
                        
                        self.logger.warning(
                            f"Zone transfer successful from {ns}! "
                            f"Found {len(records)} records"
                        )
                        
                        # Save results
                        self._save_results(results)
                        
                        # Notify
                        self.notifier.beep_finding()
                        
                        break
                    
                except dns.exception.FormError:
                    self.logger.debug(f"Zone transfer refused by {ns}")
                except dns.query.TransferError as e:
                    self.logger.debug(f"Zone transfer failed from {ns}: {e}")
                except socket.gaierror:
                    self.logger.debug(f"Failed to resolve {ns}")
                except Exception as e:
                    self.logger.debug(f"Error with {ns}: {e}")
            
            if not results['vulnerable']:
                self.logger.info(f"Zone transfer not possible for {domain}")
            
        except dns.resolver.NXDOMAIN:
            results['error'] = f"Domain {domain} does not exist"
        except Exception as e:
            results['error'] = str(e)
            self.logger.error(f"Zone transfer test failed: {e}")
        
        return results
    
    def test_multiple(self, domains, nameserver=None):
        """
        Test zone transfer for multiple domains.
        
        Args:
            domains: List of domains
            nameserver: Optional specific nameserver
        
        Returns:
            list: Results for each domain
        """
        results = []
        total = len(domains)
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_domain = {
                executor.submit(self.attempt_transfer, domain, nameserver): domain
                for domain in domains
            }
            
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result['vulnerable']:
                        self.logger.warning(f"VULNERABLE: {domain}")
                        self.notifier.beep_finding()
                except Exception as e:
                    self.logger.error(f"Failed testing {domain}: {e}")
                    results.append({
                        'domain': domain,
                        'vulnerable': False,
                        'error': str(e)
                    })
        
        return results
    
    def _save_results(self, results):
        """Save successful zone transfer results."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_domain = self.fm.safe_filename(results['domain'])
        output_file = os.path.join(self.output_dir, f"zonetransfer_{safe_domain}_{timestamp}.json")
        self.fm.write_json(output_file, results)
        
        # Also save as text for easy reading
        txt_file = os.path.join(self.output_dir, f"zonetransfer_{safe_domain}_{timestamp}.txt")
        txt_content = self._format_results(results)
        self.fm.write_file(txt_file, txt_content)
    
    def _format_results(self, results):
        """Format zone transfer results as readable text."""
        lines = []
        lines.append("=" * 60)
        lines.append("DNS ZONE TRANSFER RESULTS")
        lines.append("=" * 60)
        lines.append(f"Domain: {results['domain']}")
        lines.append(f"Vulnerable: {results['vulnerable']}")
        lines.append(f"Nameserver: {results.get('vulnerable_nameserver', 'N/A')}")
        lines.append(f"Records Found: {len(results['records'])}")
        lines.append("")
        
        if results['records']:
            lines.append("RECORDS:")
            lines.append("-" * 40)
            for record in results['records']:
                lines.append(
                    f"{record['name']:30} {record['type']:10} {record['value']}"
                )
        
        return "\n".join(lines)