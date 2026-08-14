"""
Subdomain Finder - Discover subdomains through brute force
Uses wordlists and DNS resolution
"""

import os
import sys
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
    import dns.resolver
    import dns.exception
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False


class SubdomainFinder:
    """Subdomain discovery through wordlist brute force."""
    
    # Common subdomain wordlists
    DEFAULT_WORDLIST = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
        'webdisk', 'ns3', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm',
        'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum',
        'news', 'vpn', 'ns4', 'mysql', 'shop', 'api', 'apps', 'support', 'remote',
        'secure', 'server', 'portal', 'stage', 'staging', 'mobile', 'cdn',
        'static', 'assets', 'files', 'download', 'docs', 'wiki', 'help',
        'demo', 'beta', 'alpha', 'old', 'new', 'backup', 'db', 'database',
        'web', 'app', 'intranet', 'internal', 'external', 'public', 'private',
        'login', 'auth', 'sso', 'oauth', 'git', 'svn', 'ci', 'jenkins',
        'jira', 'confluence', 'wiki', 'docs', 'status', 'monitor', 'grafana',
        'kibana', 'elastic', 'rabbitmq', 'redis', 'memcached', 'mongo',
        'postgres', 'mysql', 'oracle', 'mssql', 'ftp', 'sftp', 'ssh',
        'vpn', 'dns', 'ns1', 'ns2', 'mx', 'mail', 'smtp', 'imap', 'pop3'
    ]
    
    def __init__(self, output_dir=None):
        """Initialize Subdomain Finder."""
        if not DNSPYTHON_AVAILABLE:
            raise ImportError("dnspython is required for subdomain finding")
        
        self.logger = get_logger("subdomain_finder")
        self.notifier = Notifier()
        self.fm = FileManager()
        
        self.output_dir = output_dir or "./data/intermediate"
        self.fm.ensure_dir(self.output_dir)
        
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
    
    def find_subdomains(self, domain, wordlist=None, max_threads=10):
        """
        Find subdomains for a domain.
        
        Args:
            domain: Target domain
            wordlist: List of subdomain names to test
            max_threads: Maximum concurrent threads
        
        Returns:
            dict: Subdomain discovery results
        """
        if not is_valid_domain(domain):
            raise ValidationError(f"Invalid domain: {domain}", field="domain", value=domain)
        
        if wordlist is None:
            wordlist = self.DEFAULT_WORDLIST
        
        self.logger.info(f"Starting subdomain discovery for: {domain}")
        self.logger.info(f"Testing {len(wordlist)} potential subdomains")
        
        start_time = datetime.now()
        
        results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'tested': len(wordlist),
            'subdomains': [],
            'summary': {}
        }
        
        discovered = []
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_sub = {
                executor.submit(self._resolve_subdomain, domain, sub): sub
                for sub in wordlist
            }
            
            completed = 0
            for future in as_completed(future_to_sub):
                completed += 1
                
                try:
                    subdomain_info = future.result()
                    if subdomain_info:
                        discovered.append(subdomain_info)
                        self.logger.info(
                            f"Found: {subdomain_info['hostname']} "
                            f"({subdomain_info['ip']})"
                        )
                except Exception as e:
                    self.logger.debug(f"Error resolving subdomain: {e}")
                
                # Progress notification
                if completed % 10 == 0:
                    progress = int((completed / len(wordlist)) * 100)
                    if progress in [25, 50, 75]:
                        self.logger.info(f"Progress: {progress}%")
                        self.notifier.beep_progress(progress)
        
        results['subdomains'] = discovered
        results['summary'] = {
            'total_found': len(discovered),
            'total_tested': len(wordlist),
            'success_rate': f"{(len(discovered) / len(wordlist) * 100):.1f}%"
        }
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_domain = self.fm.safe_filename(domain)
        output_file = os.path.join(self.output_dir, f"subdomains_{safe_domain}_{timestamp}.json")
        self.fm.write_json(output_file, results)
        
        # Also save as simple text list
        txt_file = os.path.join(self.output_dir, f"subdomains_{safe_domain}_{timestamp}.txt")
        subdomain_list = [s['hostname'] for s in discovered]
        self.fm.write_file(txt_file, "\n".join(subdomain_list))
        
        duration = (datetime.now() - start_time).total_seconds()
        self.logger.info(f"Subdomain discovery complete: {len(discovered)} found in {duration:.1f}s")
        self.notifier.beep_complete()
        
        return results
    
    def _resolve_subdomain(self, domain, subdomain):
        """Resolve a single subdomain."""
        hostname = f"{subdomain}.{domain}"
        
        try:
            answers = self.resolver.resolve(hostname, 'A')
            
            ips = [str(answer) for answer in answers]
            
            return {
                'hostname': hostname,
                'subdomain': subdomain,
                'ips': ips,
                'ip': ips[0] if ips else None,
                'record_type': 'A'
            }
            
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            # Try CNAME
            try:
                cname_answers = self.resolver.resolve(hostname, 'CNAME')
                if cname_answers:
                    return {
                        'hostname': hostname,
                        'subdomain': subdomain,
                        'ips': [],
                        'ip': None,
                        'record_type': 'CNAME',
                        'cname': str(cname_answers[0])
                    }
            except Exception:
                pass
            return None
        except Exception:
            return None
    
    def load_wordlist(self, wordlist_file):
        """
        Load subdomain wordlist from file.
        
        Args:
            wordlist_file: Path to wordlist file
        
        Returns:
            list: Subdomain names
        """
        if not os.path.exists(wordlist_file):
            self.logger.warning(f"Wordlist not found: {wordlist_file}")
            return self.DEFAULT_WORDLIST
        
        words = self.fm.read_lines(wordlist_file)
        return words if words else self.DEFAULT_WORDLIST
    
    def find_from_file(self, domain, wordlist_file):
        """Find subdomains using wordlist from file."""
        wordlist = self.load_wordlist(wordlist_file)
        return self.find_subdomains(domain, wordlist)
    
    def passive_discovery(self, domain):
        """
        Passive subdomain discovery using certificate transparency.
        Note: Requires internet access.
        
        Args:
            domain: Target domain
        
        Returns:
            list: Discovered subdomains
        """
        try:
            import requests
            import json
            
            # Certificate transparency search
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                subdomains = set()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for name in name_value.split('\n'):
                        if domain in name:
                            subdomains.add(name.strip())
                
                return sorted(subdomains)
            
        except ImportError:
            self.logger.warning("requests not installed for passive discovery")
        except Exception as e:
            self.logger.debug(f"Passive discovery failed: {e}")
        
        return []