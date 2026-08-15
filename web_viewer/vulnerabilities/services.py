"""
Services for vulnerability management
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
parent_dir = Path(__file__).resolve().parent.parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from django.utils import timezone
from core.logger import get_logger

logger = get_logger("web_vulns")


class VulnerabilityService:
    """Service for vulnerability operations"""
    
    @classmethod
    def create_from_scan_result(cls, scan, vuln_data):
        """
        Create vulnerability from scan result.
        
        Args:
            scan: Scan model instance
            vuln_data: Vulnerability data dictionary
        """
        from vulnerabilities.models import Vulnerability
        
        vuln, created = Vulnerability.objects.get_or_create(
            scan=scan,
            cve_id=vuln_data.get('cve', ''),
            title=vuln_data.get('title', 'Unknown Vulnerability'),
            defaults={
                'description': vuln_data.get('description', ''),
                'severity': vuln_data.get('severity', 'medium'),
                'cvss_score': vuln_data.get('cvss_score'),
                'affected_service': vuln_data.get('service', ''),
                'port': vuln_data.get('port'),
                'remediation': vuln_data.get('remediation', ''),
            }
        )
        
        if created:
            logger.info(f"Vulnerability created: {vuln.cve_id or vuln.title}")
        
        return vuln
    
    @classmethod
    def bulk_create_from_results(cls, scan, results_data):
        """
        Bulk create vulnerabilities from scan results.
        
        Args:
            scan: Scan model instance
            results_data: Results dictionary with vulnerabilities list
        """
        vulnerabilities = results_data.get('vulnerabilities', [])
        created_count = 0
        
        for vuln_data in vulnerabilities:
            vuln = cls.create_from_scan_result(scan, vuln_data)
            if vuln:
                created_count += 1
        
        logger.info(f"Bulk created {created_count} vulnerabilities for scan {scan.id}")
        return created_count
    
    @classmethod
    def calculate_risk_score(cls, vulnerabilities):
        """
        Calculate overall risk score from vulnerabilities.
        
        Args:
            vulnerabilities: QuerySet or list of vulnerabilities
        
        Returns:
            dict: Risk assessment
        """
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 2,
            'info': 1,
        }
        
        total_score = 0
        severity_counts = {}
        
        for vuln in vulnerabilities:
            weight = severity_weights.get(vuln.severity, 1)
            total_score += weight
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        
        # Normalize to 0-100
        max_score = len(vulnerabilities) * 10
        normalized_score = int((total_score / max_score * 100)) if max_score > 0 else 0
        
        # Determine risk level
        if normalized_score >= 80:
            level = 'critical'
        elif normalized_score >= 60:
            level = 'high'
        elif normalized_score >= 40:
            level = 'medium'
        elif normalized_score >= 20:
            level = 'low'
        else:
            level = 'info'
        
        return {
            'score': normalized_score,
            'level': level,
            'severity_counts': severity_counts,
            'total_vulnerabilities': len(vulnerabilities),
        }
