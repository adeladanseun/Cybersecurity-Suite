"""
Scan execution service
Runs CyberSecurity Suite tools from Django
"""

import os
import sys
import json
import threading
from datetime import datetime, timedelta
from pathlib import Path

# Add parent directory to path for core modules
parent_dir = Path(__file__).resolve().parent.parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from django.utils import timezone
from core.logger import get_logger
from core.notifier import Notifier


class ScanService:
    """Service for executing scans"""
    
    logger = get_logger("web_scans")
    notifier = Notifier()
    
    @classmethod
    def start_scan(cls, scan):
        """
        Start a scan in background thread.
        
        Args:
            scan: Scan model instance
        """
        # Update scan status
        scan.status = 'running'
        scan.started_at = timezone.now()
        scan.progress = 5
        scan.save()
        
        # Update target last_scanned
        target = scan.target
        target.last_scanned = timezone.now()
        target.save()
        
        cls.logger.info(f"Starting {scan.scan_type} on {target.address}")
        
        # Start scan in background thread
        thread = threading.Thread(
            target=cls._run_scan,
            args=(scan.id,),
            daemon=True
        )
        thread.start()
    
    @classmethod
    def _run_scan(cls, scan_id):
        """Run the actual scan"""
        from scans.models import Scan
        
        try:
            scan = Scan.objects.get(id=scan_id)
            
            # Update progress
            scan.progress = 10
            scan.save()
            
            # Execute appropriate scan
            if scan.scan_type == 'port_scan':
                results = cls._run_port_scan(scan)
            elif scan.scan_type == 'full_port_scan':
                results = cls._run_full_port_scan(scan)
            elif scan.scan_type == 'service_scan':
                results = cls._run_service_scan(scan)
            elif scan.scan_type == 'dns_enum':
                results = cls._run_dns_scan(scan)
            elif scan.scan_type == 'vuln_scan':
                results = cls._run_vuln_scan(scan)
            elif scan.scan_type == 'ssl_scan':
                results = cls._run_ssl_scan(scan)
            else:
                results = cls._run_default_scan(scan)
            
            # Save results
            if results:
                cls._save_results(scan, results)
            
            # Update scan status
            scan.status = 'completed'
            scan.progress = 100
            scan.completed_at = timezone.now()
            scan.duration = scan.completed_at - scan.started_at
            scan.save()
            
            cls.logger.info(f"Scan completed: {scan.scan_type} on {scan.target.address}")
            cls.notifier.beep_complete()
            
        except Exception as e:
            cls.logger.error(f"Scan failed: {e}")
            
            try:
                scan = Scan.objects.get(id=scan_id)
                scan.status = 'failed'
                scan.error_message = str(e)
                scan.completed_at = timezone.now()
                scan.save()
            except Exception:
                pass
            
            cls.notifier.beep_error()
    
    @classmethod
    def _run_port_scan(cls, scan):
        """Run quick port scan"""
        from tools.port_scanner import PortScanner
        
        scanner = PortScanner()
        target = scan.target.address
        
        # Get parameters
        params = scan.parameters or {}
        ports = params.get('ports', 'top-1000')
        
        scan.progress = 25
        scan.save()
        
        results = scanner.quick_scan(target, ports=ports)
        
        scan.progress = 75
        scan.save()
        
        return results
    
    @classmethod
    def _run_full_port_scan(cls, scan):
        """Run full port scan"""
        from tools.port_scanner import PortScanner
        
        scanner = PortScanner()
        target = scan.target.address
        
        # Get parameters
        params = scan.parameters or {}
        ports = params.get('ports', '1-65535')
        
        scan.progress = 25
        scan.save()
        
        results = scanner.full_scan(target)
        
        scan.progress = 75
        scan.save()
        
        return results
    
    @classmethod
    def _run_service_scan(cls, scan):
        """Run service detection scan"""
        from tools.port_scanner import PortScanner
        
        scanner = PortScanner()
        target = scan.target.address
        
        results = scanner.scan(
            target,
            scan_type='tcp',
            service_detection=True,
            script_scan=False
        )
        
        return results
    
    @classmethod
    def _run_dns_scan(cls, scan):
        """Run DNS enumeration"""
        from tools.dns_enum import DNSEnumerator
        
        enumerator = DNSEnumerator()
        target = scan.target.address
        
        results = enumerator.enumerate(target)
        
        return results
    
    @classmethod
    def _run_vuln_scan(cls, scan):
        """Run vulnerability scan"""
        from tools.vuln_checker import ServiceVulnChecker
        from tools.port_scanner import PortScanner
        
        # First do port scan
        scanner = PortScanner()
        target = scan.target.address
        
        scan.progress = 20
        scan.save()
        
        port_results = scanner.quick_scan(target)
        
        scan.progress = 50
        scan.save()
        
        # Then check for vulnerabilities
        vuln_checker = ServiceVulnChecker()
        vuln_results = vuln_checker.check_scan_results(port_results)
        
        scan.progress = 80
        scan.save()
        
        return {
            'port_scan': port_results,
            'vulnerability_scan': vuln_results
        }
    
    @classmethod
    def _run_ssl_scan(cls, scan):
        """Run SSL/TLS scan"""
        from tools.vuln_checker import SSLChecker
        
        checker = SSLChecker()
        target = scan.target.address
        
        results = checker.check_ssl(target)
        
        return results
    
    @classmethod
    def _run_default_scan(cls, scan):
        """Run default scan"""
        return {
            'status': 'completed',
            'message': f"Scan type {scan.scan_type} completed",
            'target': scan.target.address,
            'timestamp': datetime.now().isoformat()
        }
    
    @classmethod
    def _save_results(cls, scan, results):
        """Save scan results to file"""
        try:
            # Create results directory if needed
            results_dir = os.path.join(os.getcwd(), 'media', 'scans', 'results')
            os.makedirs(results_dir, exist_ok=True)
            
            # Save results
            filename = f"scan_{scan.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join(results_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            # Update scan
            scan.results_file.name = f"scans/results/{filename}"
            scan.save()
            
        except Exception as e:
            cls.logger.error(f"Failed to save results: {e}")
