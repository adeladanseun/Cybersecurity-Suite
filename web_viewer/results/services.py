"""
Services for processing scan results
"""

import os
import sys
import json
from pathlib import Path

# Add parent directory to path
parent_dir = Path(__file__).resolve().parent.parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from django.utils import timezone
from core.logger import get_logger

logger = get_logger("web_results")


class ResultProcessor:
    """Process and store scan results"""
    
    @classmethod
    def process_scan_results(cls, scan, results_data):
        """
        Process scan results and store in database.
        
        Args:
            scan: Scan model instance
            results_data: Dictionary of scan results
        """
        try:
            # Process ports
            cls._process_ports(scan, results_data)
            
            # Process vulnerabilities
            cls._process_vulnerabilities(scan, results_data)
            
            # Process generic results
            cls._process_generic(scan, results_data)
            
            logger.info(f"Results processed for scan {scan.id}")
            
        except Exception as e:
            logger.error(f"Failed to process results: {e}")
    
    @classmethod
    def _process_ports(cls, scan, results_data):
        """Process port results"""
        from results.models import PortResult
        
        ports = results_data.get('ports', [])
        
        for port_data in ports:
            if port_data.get('state') != 'open':
                continue
            
            PortResult.objects.get_or_create(
                scan=scan,
                port=port_data.get('port'),
                protocol=port_data.get('protocol', 'tcp'),
                defaults={
                    'state': port_data.get('state', 'open'),
                    'service': port_data.get('service', ''),
                    'product': port_data.get('product', ''),
                    'version': port_data.get('version', ''),
                    'extra_info': port_data.get('extrainfo', ''),
                }
            )
    
    @classmethod
    def _process_vulnerabilities(cls, scan, results_data):
        """Process vulnerability results"""
        from results.models import VulnerabilityResult, ScanResult
        
        vulns = results_data.get('vulnerabilities', [])
        
        for vuln_data in vulns:
            VulnerabilityResult.objects.get_or_create(
                scan=scan,
                cve_id=vuln_data.get('cve', ''),
                title=vuln_data.get('title', 'Unknown Vulnerability'),
                defaults={
                    'description': vuln_data.get('description', ''),
                    'severity': vuln_data.get('severity', 'info'),
                    'cvss_score': vuln_data.get('cvss_score'),
                    'affected_service': vuln_data.get('service', ''),
                    'port': vuln_data.get('port'),
                    'remediation': vuln_data.get('remediation', ''),
                }
            )
    
    @classmethod
    def _process_generic(cls, scan, results_data):
        """Process generic results"""
        from results.models import ScanResult
        
        # Create summary result
        if 'summary' in results_data:
            ScanResult.objects.create(
                scan=scan,
                result_type='info',
                severity='info',
                data={'summary': results_data['summary']}
            )
        
        # Process findings
        findings = results_data.get('findings', [])
        for finding in findings:
            ScanResult.objects.create(
                scan=scan,
                result_type=finding.get('type', 'info'),
                severity=finding.get('severity', 'info'),
                data=finding
            )
