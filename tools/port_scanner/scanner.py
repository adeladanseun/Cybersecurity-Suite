"""
Port Scanner - Main scanning logic
Wraps nmap and masscan for network reconnaissance
"""

import subprocess
import os
import shutil
import time
import json
from datetime import datetime
from pathlib import Path

# Add project root to path
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.file_manager import FileManager
from core.validator import (
    is_valid_ip, is_valid_cidr, is_valid_domain,
    classify_target, get_target_type, is_private_ip
)
from core.logger import get_logger, log_scan_start, log_scan_complete
from core.notifier import Notifier
from core.exceptions import ScanError, ToolNotFoundError


class PortScanner:
    """Network port scanner supporting nmap and masscan."""
    
    SCAN_TYPES = ['tcp', 'udp', 'both']
    TIMING_TEMPLATES = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5']
    
    def __init__(self, config=None, output_dir=None):
        """
        Initialize port scanner.
        
        Args:
            config: Config object (optional)
            output_dir: Output directory for scan results
        """
        self.config = config
        self.logger = get_logger("port_scanner")
        self.notifier = Notifier()
        
        # Set output directory
        if output_dir:
            self.output_dir = output_dir
        elif config:
            self.output_dir = config.get("paths.data_dir", "./data") + "/intermediate"
        else:
            self.output_dir = "./data/intermediate"
        
        self.fm = FileManager()
        self.fm.ensure_dir(self.output_dir)
        
        # Tool paths
        self.nmap_path = self._find_tool("nmap")
        self.masscan_path = self._find_tool("masscan")
    
    def _find_tool(self, tool_name):
        """Find system tool path."""
        tool_path = shutil.which(tool_name)
        if not tool_path:
            # Check config if available
            if self.config:
                config_path = self.config.get(f"tools.{tool_name}.path")
                if config_path and os.path.exists(config_path):
                    return config_path
            raise ToolNotFoundError(f"{tool_name} not found. Install: sudo apt install {tool_name}")
        return tool_path
    
    def scan(self, target, scan_type='tcp', ports=None, timing='T4', 
             service_detection=True, script_scan=False, ping_first=True,
             sudo=True, callback=None):
        """
        Perform port scan on target.
        
        Args:
            target: IP, CIDR, or domain to scan
            scan_type: 'tcp', 'udp', or 'both'
            ports: Port specification (e.g., '80,443' or '1-1000')
            timing: Timing template (T0-T5)
            service_detection: Enable service version detection
            script_scan: Run default NSE scripts
            ping_first: Ping scan before port scan
            sudo: Use sudo for raw socket access
            callback: Function to call with progress updates
        
        Returns:
            dict: Scan results
        """
        # Validate target
        target_info = get_target_type(target)
        if target_info['type'] == 'unknown':
            raise ScanError(f"Invalid target: {target}", target=target, tool="port_scanner")
        
        # Determine scan mode
        is_internal = target_info['is_internal']
        scan_mode = "internal" if is_internal else "external"
        
        self.logger.info(f"Starting {scan_type.upper()} scan on {target} ({scan_mode})")
        log_scan_start(self.logger, target, f"port_scanner_{scan_type}")
        
        start_time = time.time()
        
        try:
            # Build nmap command
            cmd = self._build_nmap_command(
                target, scan_type, ports, timing,
                service_detection, script_scan, ping_first, sudo
            )
            
            # Create output file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_target = self.fm.safe_filename(target)
            xml_output = os.path.join(self.output_dir, f"nmap_{safe_target}_{timestamp}.xml")
            normal_output = os.path.join(self.output_dir, f"nmap_{safe_target}_{timestamp}.txt")
            
            # Add output flags
            cmd.extend(['-oX', xml_output, '-oN', normal_output])
            
            self.logger.debug(f"Running command: {' '.join(cmd)}")
            
            # Notify start
            self.notifier.beep(silent=False)
            
            # Execute scan
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Monitor progress
            output_lines = []
            for line in process.stdout:
                output_lines.append(line)
                if callback:
                    callback(line)
                # Log progress at milestones
                if 'About' in line and '%' in line:
                    try:
                        pct = int(line.split('%')[0].split()[-1])
                        if pct in [25, 50, 75, 100]:
                            self.logger.info(f"Scan progress: {pct}%")
                            self.notifier.beep_progress(pct)
                    except (ValueError, IndexError):
                        pass
            
            process.wait()
            
            if process.returncode != 0:
                stderr = process.stderr.read() if process.stderr else ""
                raise ScanError(f"Scan failed: {stderr}", target=target, tool="nmap")
            
            duration = time.time() - start_time
            
            # Parse results
            from tools.port_scanner.parser import ScanParser
            parser = ScanParser()
            results = parser.parse_xml(xml_output)
            results['scan_metadata'] = {
                'target': target,
                'scan_type': scan_type,
                'scan_mode': scan_mode,
                'duration': duration,
                'timestamp': datetime.now().isoformat(),
                'command': ' '.join(cmd),
                'xml_file': xml_output,
                'normal_file': normal_output
            }
            
            # Save parsed results as JSON
            json_output = os.path.join(self.output_dir, f"scan_{safe_target}_{timestamp}.json")
            self.fm.write_json(json_output, results)
            results['json_file'] = json_output
            
            # Save to database if available
            self._save_to_database(target, target_info, results, duration)
            
            # Log completion
            log_scan_complete(self.logger, target, f"port_scanner_{scan_type}", duration)
            self.notifier.beep_complete()
            
            self.logger.info(
                f"Scan complete: {results['summary']['total_open_ports']} open ports found"
            )
            
            return results
            
        except Exception as e:
            self.logger.error(f"Scan failed for {target}: {str(e)}")
            self.notifier.beep_error()
            raise ScanError(str(e), target=target, tool="port_scanner")
    
    def _build_nmap_command(self, target, scan_type, ports, timing,
                           service_detection, script_scan, ping_first, sudo):
        """Build nmap command from parameters."""
        cmd = []
        
        # Add sudo if requested
        if sudo and os.geteuid() != 0:
            cmd.extend(['sudo', self.nmap_path])
        else:
            cmd.append(self.nmap_path)
        
        # Timing template
        cmd.extend(['-T', timing if timing in self.TIMING_TEMPLATES else 'T4'])
        
        # Port specification
        if ports:
            cmd.extend(['-p', str(ports)])
        else:
            cmd.extend(['-p', 'top-1000'])
        
        # Scan type
        if scan_type == 'udp':
            cmd.append('-sU')
        elif scan_type == 'both':
            cmd.append('-sS')
            cmd.append('-sU')
        else:
            cmd.append('-sS')  # TCP SYN scan (default)
        
        # Service detection
        if service_detection:
            cmd.append('-sV')
            cmd.append('--version-intensity')
            cmd.append('7')
        
        # Script scan
        if script_scan:
            cmd.append('-sC')  # Default safe scripts
        
        # Ping scan first
        if ping_first:
            cmd.append('-Pn')  # Don't ping, assume up (inverted logic)
        else:
            cmd.append('-Pn')
        
        # Additional flags
        cmd.extend([
            '--open',           # Only show open ports
            '--stats-every', '10s',  # Progress updates
            '-n',               # No DNS resolution (faster)
            '--min-rate', '1000' # Minimum packet rate
        ])
        
        # Target
        cmd.append(target)
        
        return cmd
    
    def quick_scan(self, target, ports='top-100', timing='T4'):
        """Perform quick scan of common ports."""
        return self.scan(
            target,
            scan_type='tcp',
            ports=ports,
            timing=timing,
            service_detection=False,
            script_scan=False,
            ping_first=True
        )
    
    def full_scan(self, target, timing='T3'):
        """Perform full port scan with service detection."""
        return self.scan(
            target,
            scan_type='tcp',
            ports='1-65535',
            timing=timing,
            service_detection=True,
            script_scan=True,
            ping_first=True
        )
    
    def udp_scan(self, target, ports='top-100', timing='T4'):
        """Perform UDP port scan."""
        return self.scan(
            target,
            scan_type='udp',
            ports=ports,
            timing=timing,
            service_detection=True,
            script_scan=False,
            ping_first=True
        )
    
    def scan_multiple(self, targets, **kwargs):
        """
        Scan multiple targets.
        
        Args:
            targets: List of targets
            **kwargs: Arguments passed to scan()
        
        Returns:
            list: List of scan results
        """
        results = []
        total = len(targets)
        
        for i, target in enumerate(targets, 1):
            self.logger.info(f"Scanning target {i}/{total}: {target}")
            try:
                result = self.scan(target, **kwargs)
                results.append(result)
            except ScanError as e:
                self.logger.error(f"Failed to scan {target}: {e}")
                results.append({
                    'target': target,
                    'error': str(e),
                    'status': 'failed'
                })
            
            # Progress notification
            pct = int((i / total) * 100)
            self.notifier.beep_progress(pct)
        
        return results
    
    def _save_to_database(self, target, target_info, results, duration):
        """Save scan results to database if available."""
        try:
            from core.database import Database
            db = Database()
            
            scan_id = db.insert_scan(
                target=target,
                tool_name="port_scanner",
                target_type=target_info['type'],
                status="completed",
                output_file=results.get('json_file', ''),
                summary=f"Found {results['summary']['total_open_ports']} open ports"
            )
            
            # Insert findings for each open port
            for port_info in results.get('ports', []):
                db.insert_finding(
                    scan_id=scan_id,
                    target=target,
                    finding_type="open_port",
                    severity="info",
                    title=f"Port {port_info['port']} open - {port_info.get('service', 'unknown')}",
                    port=port_info['port'],
                    service=port_info.get('service', ''),
                    description=f"State: {port_info['state']}, "
                               f"Product: {port_info.get('product', 'N/A')} "
                               f"Version: {port_info.get('version', 'N/A')}"
                )
            
            db.update_scan_status(scan_id, "completed", duration=duration)
            
        except ImportError:
            self.logger.debug("Database module not available, skipping DB storage")
        except Exception as e:
            self.logger.warning(f"Failed to save to database: {e}")
    
    def is_tool_available(self):
        """Check if scanning tools are available."""
        return os.path.exists(self.nmap_path)