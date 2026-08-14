"""
Risk Calculator - CVSS-style risk scoring for findings
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.logger import get_logger


class RiskCalculator:
    """Calculate risk scores for security findings."""
    
    # Severity weights
    SEVERITY_WEIGHTS = {
        'critical': 10,
        'high': 7,
        'medium': 4,
        'low': 2,
        'info': 1
    }
    
    # Service risk multipliers
    SERVICE_RISK = {
        'telnet': 3.0,
        'ftp': 2.5,
        'smb': 2.5,
        'rdp': 2.5,
        'mysql': 2.0,
        'mssql': 2.0,
        'oracle': 2.0,
        'ssh': 1.5,
        'http': 1.0,
        'https': 0.5,
        'dns': 0.5
    }
    
    # Port risk modifiers
    PORT_RISK = {
        21: 2.0,    # FTP
        22: 1.5,    # SSH
        23: 3.0,    # Telnet
        25: 1.5,    # SMTP
        53: 0.5,    # DNS
        80: 1.0,    # HTTP
        110: 1.0,   # POP3
        135: 2.5,   # RPC
        139: 2.5,   # NetBIOS
        143: 1.0,   # IMAP
        445: 2.5,   # SMB
        1433: 2.0,  # MSSQL
        1521: 2.0,  # Oracle
        3306: 2.0,  # MySQL
        3389: 2.5,  # RDP
        5432: 2.0,  # PostgreSQL
        5900: 2.0,  # VNC
        6379: 2.0,  # Redis
        8080: 1.0,  # HTTP Alt
        27017: 2.0, # MongoDB
    }
    
    def __init__(self):
        self.logger = get_logger("risk_calculator")
    
    def calculate_risk_score(self, data):
        """
        Calculate overall risk score from scan data.
        
        Args:
            data: Scan results dictionary
        
        Returns:
            dict: Risk assessment with score, level, and factors
        """
        score = 0
        factors = []
        
        # Factor 1: Number of open ports
        open_ports = self._count_open_ports(data)
        port_score = min(open_ports * 5, 50)
        score += port_score
        factors.append({
            'name': 'Open Ports',
            'value': open_ports,
            'score': port_score,
            'description': f'{open_ports} open port(s) found'
        })
        
        # Factor 2: Risky services
        risky_services = self._count_risky_services(data)
        service_score = min(risky_services * 15, 60)
        score += service_score
        factors.append({
            'name': 'Risky Services',
            'value': risky_services,
            'score': service_score,
            'description': f'{risky_services} potentially risky service(s)'
        })
        
        # Factor 3: Outdated versions
        outdated = self._count_outdated_services(data)
        outdated_score = min(outdated * 20, 60)
        score += outdated_score
        factors.append({
            'name': 'Outdated Services',
            'value': outdated,
            'score': outdated_score,
            'description': f'{outdated} potentially outdated service(s)'
        })
        
        # Factor 4: Findings severity
        findings_score = self._calculate_findings_score(data)
        score += findings_score
        factors.append({
            'name': 'Findings Severity',
            'value': 'N/A',
            'score': findings_score,
            'description': 'Based on finding severities'
        })
        
        # Normalize to 0-100
        score = min(score, 100)
        
        # Determine level
        level = self._score_to_level(score)
        
        return {
            'score': score,
            'level': level,
            'max_score': 100,
            'factors': factors,
            'summary': self._generate_risk_summary(level, factors)
        }
    
    def _count_open_ports(self, data):
        """Count open ports from scan data."""
        count = 0
        for port in data.get('ports', []):
            if port.get('state') == 'open':
                count += 1
        
        if 'summary' in data and 'total_open_ports' in data['summary']:
            count = data['summary']['total_open_ports']
        
        return count
    
    def _count_risky_services(self, data):
        """Count services with elevated risk."""
        count = 0
        for port in data.get('ports', []):
            if port.get('state') == 'open':
                service = port.get('service', '').lower()
                port_num = port.get('port')
                
                # Check service risk
                if service in self.SERVICE_RISK and self.SERVICE_RISK[service] >= 2.0:
                    count += 1
                # Check port risk
                elif port_num in self.PORT_RISK and self.PORT_RISK[port_num] >= 2.0:
                    count += 1
        
        return count
    
    def _count_outdated_services(self, data):
        """Count potentially outdated services."""
        count = 0
        for port in data.get('ports', []):
            if port.get('state') == 'open' and port.get('version'):
                version = port['version']
                # Simple check for old versions
                if self._is_potentially_outdated(port.get('product', ''), version):
                    count += 1
        
        return count
    
    def _is_potentially_outdated(self, product, version):
        """Simple heuristic to detect potentially outdated services."""
        product_lower = product.lower()
        
        # Known outdated indicators
        outdated_indicators = [
            ('apache', '2.2'),
            ('apache', '2.0'),
            ('nginx', '0.'),
            ('nginx', '1.0'),
            ('nginx', '1.2'),
            ('openssh', '5.'),
            ('openssh', '6.'),
            ('openssh', '7.0'),
            ('openssh', '7.1'),
            ('mysql', '5.0'),
            ('mysql', '5.1'),
            ('mysql', '5.5'),
            ('php', '5.'),
            ('php', '7.0'),
            ('php', '7.1'),
            ('tomcat', '6.'),
            ('tomcat', '7.0'),
            ('iis', '6.'),
            ('iis', '7.0'),
        ]
        
        for prod, ver_prefix in outdated_indicators:
            if prod in product_lower and version.startswith(ver_prefix):
                return True
        
        return False
    
    def _calculate_findings_score(self, data):
        """Calculate score from finding severities."""
        score = 0
        
        for finding in data.get('findings', []):
            severity = finding.get('severity', 'info').lower()
            score += self.SEVERITY_WEIGHTS.get(severity, 1) * 2
        
        return min(score, 40)
    
    def _score_to_level(self, score):
        """Convert numeric score to risk level."""
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'info'
    
    def _generate_risk_summary(self, level, factors):
        """Generate human-readable risk summary."""
        summaries = {
            'critical': 'CRITICAL RISK: Immediate action required. Multiple high-risk services exposed.',
            'high': 'HIGH RISK: Significant security concerns detected. Prompt remediation recommended.',
            'medium': 'MEDIUM RISK: Several security issues found. Schedule remediation.',
            'low': 'LOW RISK: Minor security concerns. Review and address during maintenance.',
            'info': 'INFO: No significant risks detected. Maintain current security posture.'
        }
        
        return summaries.get(level, 'Risk assessment completed.')
    
    def calculate_port_risk(self, port, service, version=''):
        """
        Calculate individual risk for a specific port.
        
        Returns:
            dict: Port risk assessment
        """
        base_risk = 1.0
        
        # Port-based risk
        if port in self.PORT_RISK:
            base_risk *= self.PORT_RISK[port]
        
        # Service-based risk
        service_lower = service.lower() if service else ''
        if service_lower in self.SERVICE_RISK:
            base_risk *= self.SERVICE_RISK[service_lower]
        
        # Version-based risk
        if version and self._is_potentially_outdated(service_lower, version):
            base_risk *= 1.5
        
        # Normalize to 0-10 scale
        score = min(base_risk * 2, 10)
        
        return {
            'port': port,
            'service': service,
            'version': version,
            'risk_score': round(score, 1),
            'risk_level': self._score_to_level(score * 10)
        }