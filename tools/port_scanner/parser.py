"""
Scan Parser - Parse nmap XML output into structured data
"""

import xml.etree.ElementTree as ET
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.exceptions import ScanError


class ScanParser:
    """Parse nmap scan output into structured Python dictionaries."""
    
    def parse_xml(self, xml_file):
        """
        Parse nmap XML output file.
        
        Args:
            xml_file: Path to nmap XML output
        
        Returns:
            dict: Structured scan results
        """
        if not os.path.exists(xml_file):
            raise ScanError(f"Scan XML file not found: {xml_file}")
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            results = {
                'scan_info': self._parse_scan_info(root),
                'hosts': [],
                'ports': [],
                'services': {},
                'summary': {}
            }
            
            # Parse each host
            for host in root.findall('host'):
                host_data = self._parse_host(host)
                results['hosts'].append(host_data)
                
                # Collect all ports
                for port in host_data.get('ports', []):
                    results['ports'].append(port)
                    
                    # Organize by service
                    service = port.get('service', 'unknown')
                    if service not in results['services']:
                        results['services'][service] = []
                    results['services'][service].append(port)
            
            # Generate summary
            results['summary'] = self._generate_summary(results)
            
            return results
            
        except ET.ParseError as e:
            raise ScanError(f"Failed to parse XML: {e}")
        except Exception as e:
            raise ScanError(f"Error parsing scan results: {e}")
    
    def _parse_scan_info(self, root):
        """Parse scan information from root element."""
        info = {
            'scanner': root.get('scanner', 'unknown'),
            'args': root.get('args', ''),
            'start_time': root.get('startstr', ''),
            'protocol': root.get('protocol', ''),
            'num_services': root.get('numservices', '0'),
            'num_services_total': root.get('totalServices', '0')
        }
        
        # Get scan stats
        run_stats = root.find('runstats')
        if run_stats is not None:
            finished = run_stats.find('finished')
            if finished is not None:
                info['end_time'] = finished.get('timestr', '')
                info['elapsed'] = finished.get('elapsed', '0')
                info['exit_status'] = finished.get('exit', 'unknown')
            
            hosts_stats = run_stats.find('hosts')
            if hosts_stats is not None:
                info['hosts_up'] = hosts_stats.get('up', '0')
                info['hosts_down'] = hosts_stats.get('down', '0')
                info['hosts_total'] = hosts_stats.get('total', '0')
        
        return info
    
    def _parse_host(self, host_elem):
        """Parse host information."""
        host_data = {
            'ip': '',
            'mac': '',
            'hostnames': [],
            'status': '',
            'ports': [],
            'os': {}
        }
        
        # Address info
        for addr in host_elem.findall('address'):
            if addr.get('addrtype') == 'ipv4':
                host_data['ip'] = addr.get('addr', '')
            elif addr.get('addrtype') == 'mac':
                host_data['mac'] = addr.get('addr', '')
                host_data['vendor'] = addr.get('vendor', '')
        
        # Hostnames
        hostnames_elem = host_elem.find('hostnames')
        if hostnames_elem is not None:
            for hostname in hostnames_elem.findall('hostname'):
                host_data['hostnames'].append({
                    'name': hostname.get('name', ''),
                    'type': hostname.get('type', '')
                })
        
        # Status
        status = host_elem.find('status')
        if status is not None:
            host_data['status'] = status.get('state', 'unknown')
            host_data['reason'] = status.get('reason', '')
        
        # Ports
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                port_data = self._parse_port(port)
                port_data['host'] = host_data['ip']
                host_data['ports'].append(port_data)
        
        # OS detection
        os_elem = host_elem.find('os')
        if os_elem is not None:
            host_data['os'] = self._parse_os(os_elem)
        
        return host_data
    
    def _parse_port(self, port_elem):
        """Parse port information."""
        port_data = {
            'port': int(port_elem.get('portid', 0)),
            'protocol': port_elem.get('protocol', ''),
            'state': '',
            'service': '',
            'product': '',
            'version': '',
            'extrainfo': '',
            'cpe': []
        }
        
        # Port state
        state = port_elem.find('state')
        if state is not None:
            port_data['state'] = state.get('state', 'unknown')
            port_data['reason'] = state.get('reason', '')
        
        # Service info
        service = port_elem.find('service')
        if service is not None:
            port_data['service'] = service.get('name', 'unknown')
            port_data['product'] = service.get('product', '')
            port_data['version'] = service.get('version', '')
            port_data['extrainfo'] = service.get('extrainfo', '')
            port_data['ostype'] = service.get('ostype', '')
            port_data['method'] = service.get('method', '')
            
            # CPE entries
            for cpe in service.findall('cpe'):
                port_data['cpe'].append(cpe.text)
        
        # Scripts
        for script in port_elem.findall('script'):
            if 'scripts' not in port_data:
                port_data['scripts'] = {}
            script_id = script.get('id', 'unknown')
            script_output = script.get('output', '')
            port_data['scripts'][script_id] = script_output
        
        return port_data
    
    def _parse_os(self, os_elem):
        """Parse OS detection information."""
        os_data = {
            'matches': [],
            'accuracy': 0
        }
        
        for osmatch in os_elem.findall('osmatch'):
            match = {
                'name': osmatch.get('name', ''),
                'accuracy': osmatch.get('accuracy', '0'),
                'line': osmatch.get('line', '')
            }
            
            osclasses = []
            for osclass in osmatch.findall('osclass'):
                osclasses.append({
                    'type': osclass.get('type', ''),
                    'vendor': osclass.get('vendor', ''),
                    'family': osclass.get('osfamily', ''),
                    'gen': osclass.get('osgen', ''),
                    'accuracy': osclass.get('accuracy', '0')
                })
            
            match['classes'] = osclasses
            os_data['matches'].append(match)
        
        return os_data
    
    def _generate_summary(self, results):
        """Generate summary statistics from scan results."""
        all_ports = results.get('ports', [])
        
        # Count open ports
        open_ports = [p for p in all_ports if p.get('state') == 'open']
        
        # Count by service
        service_counts = {}
        for port in open_ports:
            service = port.get('service', 'unknown')
            service_counts[service] = service_counts.get(service, 0) + 1
        
        # Count hosts
        hosts_up = sum(1 for h in results.get('hosts', []) if h.get('status') == 'up')
        
        summary = {
            'total_hosts': len(results.get('hosts', [])),
            'hosts_up': hosts_up,
            'hosts_down': len(results.get('hosts', [])) - hosts_up,
            'total_open_ports': len(open_ports),
            'total_ports_scanned': len(all_ports),
            'service_counts': service_counts,
            'top_services': sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            'common_ports': self._get_common_ports(open_ports)
        }
        
        return summary
    
    def _get_common_ports(self, ports, top_n=20):
        """Get most common open ports."""
        port_counts = {}
        for port in ports:
            port_num = port.get('port', 0)
            port_counts[port_num] = port_counts.get(port_num, 0) + 1
        
        return sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    
    def parse_text(self, text_file):
        """Parse nmap text output (basic)."""
        if not os.path.exists(text_file):
            raise ScanError(f"Scan text file not found: {text_file}")
        
        with open(text_file, 'r') as f:
            content = f.read()
        
        result = {
            'raw_output': content,
            'open_ports': []
        }
        
        # Simple parsing for open ports
        for line in content.split('\n'):
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split('/')[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    
                    result['open_ports'].append({
                        'port': int(port),
                        'state': state,
                        'service': service
                    })
        
        return result
    
    def export_to_csv(self, results, output_file):
        """Export scan results to CSV format."""
        from core.file_manager import FileManager
        
        fm = FileManager()
        
        csv_data = []
        for port in results.get('ports', []):
            csv_data.append({
                'host': port.get('host', ''),
                'port': port.get('port', ''),
                'protocol': port.get('protocol', ''),
                'state': port.get('state', ''),
                'service': port.get('service', ''),
                'product': port.get('product', ''),
                'version': port.get('version', ''),
                'extrainfo': port.get('extrainfo', '')
            })
        
        fm.write_csv(output_file, csv_data)
        return output_file