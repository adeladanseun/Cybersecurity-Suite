"""
Diff Report Generator - Generate comparison reports between scans
"""

import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.file_manager import FileManager
from core.logger import get_logger


class DiffReportGenerator:
    """Generate reports comparing two scan results."""
    
    def __init__(self):
        self.fm = FileManager()
        self.logger = get_logger("diff_report")
    
    def generate_diff(self, current_data, previous_data):
        """
        Generate difference data between two scans.
        
        Args:
            current_data: Current scan results
            previous_data: Previous scan results
        
        Returns:
            dict: Formatted diff data for reporting
        """
        # Extract ports
        current_ports = self._get_port_set(current_data)
        previous_ports = self._get_port_set(previous_data)
        
        current_port_map = {p['port']: p for p in current_ports}
        previous_port_map = {p['port']: p for p in previous_ports}
        
        current_set = set(current_port_map.keys())
        previous_set = set(previous_port_map.keys())
        
        # Build diff
        diff = {
            'comparison_metadata': {
                'current_scan_time': current_data.get('scan_metadata', {}).get('timestamp', 'Unknown'),
                'previous_scan_time': previous_data.get('scan_metadata', {}).get('timestamp', 'Unknown'),
                'generated_at': datetime.now().isoformat()
            },
            'summary': {},
            'findings': [],
            'new_ports': [],
            'closed_ports': [],
            'changed_ports': [],
            'unchanged_ports': []
        }
        
        # New ports
        for port in current_set - previous_set:
            port_info = current_port_map[port]
            diff['new_ports'].append(port_info)
            diff['findings'].append({
                'type': 'new_port',
                'severity': 'medium',
                'title': f"New open port: {port}",
                'description': f"Port {port} ({port_info.get('service', 'unknown')}) "
                             f"is now open. Previously not detected.",
                'port': port,
                'service': port_info.get('service', 'unknown')
            })
        
        # Closed ports
        for port in previous_set - current_set:
            port_info = previous_port_map[port]
            diff['closed_ports'].append(port_info)
            diff['findings'].append({
                'type': 'closed_port',
                'severity': 'info',
                'title': f"Port closed: {port}",
                'description': f"Port {port} ({port_info.get('service', 'unknown')}) "
                             f"is no longer open.",
                'port': port,
                'service': port_info.get('service', 'unknown')
            })
        
        # Changed ports
        for port in current_set & previous_set:
            curr = current_port_map[port]
            prev = previous_port_map[port]
            
            changes = []
            if curr.get('service') != prev.get('service'):
                changes.append(f"Service changed: {prev.get('service')} → {curr.get('service')}")
            if curr.get('version') != prev.get('version'):
                changes.append(f"Version changed: {prev.get('version')} → {curr.get('version')}")
            if curr.get('product') != prev.get('product'):
                changes.append(f"Product changed: {prev.get('product')} → {curr.get('product')}")
            
            if changes:
                diff['changed_ports'].append({
                    'port': port,
                    'current': curr,
                    'previous': prev,
                    'changes': changes
                })
                diff['findings'].append({
                    'type': 'changed_port',
                    'severity': 'high',
                    'title': f"Port {port} configuration changed",
                    'description': '; '.join(changes),
                    'port': port,
                    'service': curr.get('service', 'unknown')
                })
            else:
                diff['unchanged_ports'].append(curr)
        
        # Summary
        diff['summary'] = {
            'total_new': len(diff['new_ports']),
            'total_closed': len(diff['closed_ports']),
            'total_changed': len(diff['changed_ports']),
            'total_unchanged': len(diff['unchanged_ports']),
            'total_findings': len(diff['findings']),
            'risk_change': self._assess_risk_change(diff)
        }
        
        return diff
    
    def _get_port_set(self, data):
        """Extract open ports from scan data."""
        ports = []
        for port in data.get('ports', []):
            if port.get('state') == 'open':
                ports.append({
                    'port': port.get('port'),
                    'protocol': port.get('protocol', ''),
                    'service': port.get('service', ''),
                    'product': port.get('product', ''),
                    'version': port.get('version', ''),
                    'host': port.get('host', '')
                })
        return ports
    
    def _assess_risk_change(self, diff):
        """Assess whether risk increased or decreased."""
        #change = diff['total_new'] - diff['total_closed'] + (diff['total_changed'] * 2) // total_new, closed and changed not in diff data
        change = len(diff['new_ports']) - len(diff['closed_ports']) + (len(diff['changed_ports'])  * 2)
        
        if change > 3:
            return 'increased'
        elif change < -2:
            return 'decreased'
        else:
            return 'stable'