"""
Scan Differ - Compare current scan with previous scans
Detect new, removed, and changed ports/services
"""

import os
import sys
from datetime import datetime
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.file_manager import FileManager
from core.logger import get_logger


class ScanDiffer:
    """Compare scan results and detect changes."""
    
    def __init__(self):
        self.fm = FileManager()
        self.logger = get_logger("scan_differ")
    
    def compare_scans(self, current_scan, previous_scan):
        """
        Compare two scan results and identify differences.
        
        Args:
            current_scan: Current scan results (dict from parser)
            previous_scan: Previous scan results (dict from parser)
        
        Returns:
            dict: Differences between scans
        """
        current_ports = self._build_port_map(current_scan)
        previous_ports = self._build_port_map(previous_scan)
        
        current_port_nums = set(current_ports.keys())
        previous_port_nums = set(previous_ports.keys())
        
        diff = {
            'comparison_time': datetime.now().isoformat(),
            'new_ports': [],       # Ports open now but not before
            'closed_ports': [],    # Ports open before but not now
            'changed_ports': [],   # Ports with changed service/version
            'unchanged_ports': [], # Ports unchanged
            'summary': {}
        }
        
        # New ports
        for port in current_port_nums - previous_port_nums:
            diff['new_ports'].append(current_ports[port])
        
        # Closed ports
        for port in previous_port_nums - current_port_nums:
            diff['closed_ports'].append(previous_ports[port])
        
        # Changed and unchanged ports
        for port in current_port_nums & previous_port_nums:
            curr = current_ports[port]
            prev = previous_ports[port]
            
            changes = self._detect_changes(curr, prev)
            
            if changes:
                diff['changed_ports'].append({
                    'port': port,
                    'current': curr,
                    'previous': prev,
                    'changes': changes
                })
            else:
                diff['unchanged_ports'].append(curr)
        
        # Summary
        diff['summary'] = {
            'total_new': len(diff['new_ports']),
            'total_closed': len(diff['closed_ports']),
            'total_changed': len(diff['changed_ports']),
            'total_unchanged': len(diff['unchanged_ports']),
        }
        diff['summary']['risk_level'] = self._calculate_risk_level(diff)
        
        self.logger.info(
            f"Scan comparison: {diff['summary']['total_new']} new, "
            f"{diff['summary']['total_closed']} closed, "
            f"{diff['summary']['total_changed']} changed"
        )
        
        return diff
    
    def _build_port_map(self, scan_data):
        """Build port-to-data mapping from scan results."""
        port_map = {}
        
        for port in scan_data.get('ports', []):
            if port.get('state') == 'open':
                port_num = port.get('port')
                port_map[port_num] = {
                    'port': port_num,
                    'protocol': port.get('protocol', ''),
                    'service': port.get('service', ''),
                    'product': port.get('product', ''),
                    'version': port.get('version', ''),
                    'host': port.get('host', ''),
                    'extrainfo': port.get('extrainfo', '')
                }
        
        return port_map
    
    def _detect_changes(self, current, previous):
        """Detect specific changes between current and previous port state."""
        changes = []
        
        if current.get('service') != previous.get('service'):
            changes.append({
                'field': 'service',
                'from': previous.get('service'),
                'to': current.get('service')
            })
        
        if current.get('product') != previous.get('product'):
            changes.append({
                'field': 'product',
                'from': previous.get('product'),
                'to': current.get('product')
            })
        
        if current.get('version') != previous.get('version'):
            changes.append({
                'field': 'version',
                'from': previous.get('version'),
                'to': current.get('version')
            })
        
        return changes
    
    def _calculate_risk_level(self, diff):
        """Calculate risk level based on changes."""
        score = 0
        
        # New ports increase risk
        score += diff['summary']['total_new'] * 10
        
        # Changed services increase risk more
        score += diff['summary']['total_changed'] * 15
        
        # Closed ports might be good (services removed)
        score -= diff['summary']['total_closed'] * 5
        
        if score <= 0:
            return 'low'
        elif score <= 30:
            return 'medium'
        elif score <= 60:
            return 'high'
        else:
            return 'critical'
    
    def compare_with_history(self, current_scan, target):
        """
        Compare current scan with last saved scan for target.
        
        Args:
            current_scan: Current scan results
            target: Target identifier
        
        Returns:
            dict: Differences or None if no history
        """
        # Try to load previous scan from database
        try:
            from core.database import Database
            db = Database()
            
            history = db.get_scan_history(target=target, limit=1)
            
            if history and len(history) > 0:
                prev_output = history[0].get('output_file')
                if prev_output and os.path.exists(prev_output):
                    previous_scan = self.fm.read_json(prev_output)
                    return self.compare_scans(current_scan, previous_scan)
        
        except ImportError:
            self.logger.debug("Database not available for history lookup")
        except Exception as e:
            self.logger.warning(f"Failed to load scan history: {e}")
        
        return None
    
    def generate_diff_report(self, diff, output_file=None):
        """
        Generate human-readable diff report.
        
        Args:
            diff: Diff data from compare_scans()
            output_file: Path to save report
        
        Returns:
            str: Diff report text
        """
        report = []
        report.append("=" * 60)
        report.append("PORT SCAN DIFFERENTIAL REPORT")
        report.append("=" * 60)
        report.append(f"Generated: {diff['comparison_time']}")
        report.append(f"Risk Level: {diff['summary']['risk_level'].upper()}")
        report.append("")
        
        # New ports
        if diff['new_ports']:
            report.append(f"🔴 NEW PORTS OPENED ({diff['summary']['total_new']}):")
            for port in diff['new_ports']:
                report.append(f"  Port {port['port']}/{port['protocol']}: {port['service']}")
                if port.get('product'):
                    report.append(f"    Product: {port['product']} {port.get('version', '')}")
            report.append("")
        
        # Closed ports
        if diff['closed_ports']:
            report.append(f"🟢 PORTS CLOSED ({diff['summary']['total_closed']}):")
            for port in diff['closed_ports']:
                report.append(f"  Port {port['port']}/{port['protocol']}: {port['service']}")
            report.append("")
        
        # Changed ports
        if diff['changed_ports']:
            report.append(f"🟡 PORTS CHANGED ({diff['summary']['total_changed']}):")
            for item in diff['changed_ports']:
                report.append(f"  Port {item['port']}:")
                for change in item['changes']:
                    report.append(f"    {change['field']}: {change['from']} → {change['to']}")
            report.append("")
        
        # Unchanged
        report.append(f"⚪ UNCHANGED PORTS: {diff['summary']['total_unchanged']}")
        report.append("")
        report.append("=" * 60)
        
        report_text = "\n".join(report)
        
        if output_file:
            self.fm.write_file(output_file, report_text)
        
        return report_text