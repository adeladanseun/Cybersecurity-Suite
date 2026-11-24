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
import re

import sys
#sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from core.file_manager import FileManager
from core.validator import (
    is_valid_ip, is_valid_cidr, is_valid_domain,
    classify_target, get_target_type, is_private_ip
)
from core.logger import get_logger, log_scan_start, log_scan_complete
from core.notifier import Notifier
from core.exceptions import ScanError, ToolNotFoundError
from core.progress import bar, spinner


class PortScanner:

    """Network port scanner supporting nmap and masscan."""

    SCAN_TYPES = ['tcp', 'udp', 'both']
    TIMING_TEMPLATES = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5']

    def __init__(self, config=None, output_dir=None):
        """
        Initialize port scanner.
        
        # Add project root to path
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
        self.masscan_path = shutil.which("masscan")          # optional, may be None
        #self.masscan_path = self._find_tool("masscan")

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

    def _sanitize_for_filename(self, target: str) -> str:
        """Make any target (IP, CIDR, IPv6, domain, URL) safe for a filename."""
        try:
            safe = self.fm.safe_filename(target)
        except Exception:
            safe = target
        safe = re.sub(r'[/\\:*?"<>|\s]', '_', safe)
        safe = safe.strip('._')
        return safe or "target"

    def scan(self, target, scan_type='tcp', ports=None, timing='T4',
         service_detection=True, script_scan=False, ping_first=True,
         sudo=True, callback=None):
        """
        Perform port scan on target.

        Returns:
            dict: Scan results (also written to JSON on disk).
        """
        # --- validation ---------------------------------------------------------
        target_info = get_target_type(target)
        if target_info['type'] == 'unknown':
            raise ScanError(f"Invalid target: {target}", target=target, tool="port_scanner")

        is_internal = target_info['is_internal']
        scan_mode = "internal" if is_internal else "external"

        self.logger.info(f"Starting {scan_type.upper()} scan on {target} ({scan_mode})")
        log_scan_start(self.logger, target, f"port_scanner_{scan_type}")

        start_time = time.time()

        # --- paths (defined up-front so failures still leave a trace) ----------
        # 2d: microsecond precision + safe target name
        timestamp    = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        safe_target  = self._sanitize_for_filename(target)          # 2c
        xml_output   = os.path.join(self.output_dir, f"nmap_{safe_target}_{timestamp}.xml")
        normal_output= os.path.join(self.output_dir, f"nmap_{safe_target}_{timestamp}.txt")
        json_output  = os.path.join(self.output_dir, f"scan_{safe_target}_{timestamp}.json")
        log_output   = os.path.join(self.output_dir, f"nmap_{safe_target}_{timestamp}.log")

        try:
            # --- build command -------------------------------------------------
            cmd = self._build_nmap_command(
                target, scan_type, ports, timing,
                service_detection, script_scan, ping_first, sudo
            )

            # Put -oX/-oN BEFORE the target (more portable, but not strictly required)
            # _build_nmap_command appends target last, so pop it, add flags, re-append.
            target_arg = cmd.pop()
            cmd.extend(['-oX', xml_output, '-oN', normal_output])
            cmd.append(target_arg)

            self.logger.info(f"Running command: {' '.join(cmd)}")

            # Notifier is best-effort — never abort a scan because beeping failed
            try:
                self.notifier.beep(silent=False)
            except Exception as e:
                self.logger.debug(f"notifier.beep failed: {e}")

            # --- run the scan --------------------------------------------------
            # 2a + 2b: merge stderr into stdout.  This (1) prevents the deadlock
            # from an undrained stderr pipe, and (2) makes --stats-every progress
            # lines (which go to stderr) visible to `callback` and the progress
            # logger below.
            output_lines = []

            with open(log_output, 'w') as logf:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, bufsize=1)
                with bar(total=100, desc=f"nmap {target}", unit="%") as pbar:
                    for line in process.stdout:
                        output_lines.append(line)
                        logf.write(line); logf.flush()
                        pbar.feed_line(line)                    # all parsing, one line
                        if callback:
                            try: callback(line)
                            except Exception: pass
                    returncode = process.wait()

            if returncode != 0:
                # Keep last 50 lines of merged output for the error message
                tail = ''.join(output_lines[-50:]) or "Unknown error"
                self.logger.error(f"Nmap error (rc={returncode}): {tail}")
                raise ScanError(
                    f"Scan failed (rc={returncode}): {tail}",
                    target=target, tool="nmap"
                )

            duration = time.time() - start_time

            # --- parse ---------------------------------------------------------
            # 2f: isolate parsing so a partial/corrupt XML doesn't nuke everything.
            try:
                from tools.port_scanner.parser import ScanParser
                parser = ScanParser()
                results = parser.parse_xml(xml_output)
            except Exception as e:
                self.logger.error(f"Failed to parse {xml_output}: {e}")
                raise ScanError(
                    f"Parse failed: {e} (raw XML kept at {xml_output}, "
                    f"log at {log_output})",
                    target=target, tool="nmap"
                )

            results['scan_metadata'] = {
                'target':        target,
                'scan_type':     scan_type,
                'scan_mode':     scan_mode,
                'duration':      duration,
                'timestamp':     datetime.now().isoformat(),
                'command':       ' '.join(cmd),
                'returncode':    returncode,
                'xml_file':      xml_output,
                'normal_file':   normal_output,
                'log_file':      log_output,
            }

            # 2e: set json_file BEFORE serialising so it's actually in the file
            results['json_file'] = json_output

            # --- save ----------------------------------------------------------
            try:
                self.fm.write_json(json_output, results)
            except Exception as e:
                self.logger.error(f"Failed to write JSON {json_output}: {e}")
                raise ScanError(
                    f"Failed to save results: {e} (XML kept at {xml_output})",
                    target=target, tool="nmap"
                )

            # --- database (best-effort, unchanged) -----------------------------
            self._save_to_database(target, target_info, results, duration)

            log_scan_complete(self.logger, target, f"port_scanner_{scan_type}", duration)
            try:
                self.notifier.beep_complete()
            except Exception:
                pass

            self.logger.info(
                f"Scan complete: {results['summary']['total_open_ports']} open ports found"
            )
            return results

        except ScanError:
            try:
                self.notifier.beep_error()
            except Exception:
                pass
            raise
        except Exception as e:
            self.logger.error(f"Scan failed for {target}: {e}")
            try:
                self.notifier.beep_error()
            except Exception:
                pass
            raise ScanError(str(e), target=target, tool="port_scanner")
    
    def _build_nmap_command(self, target, scan_type, ports, timing,
                           service_detection, script_scan, ping_first, sudo, open_only=False):
        """Build nmap command from parameters."""
        cmd = []

        # Add sudo if requested
        is_root = (os.geteuid() == 0)
        use_sudo = sudo and not is_root and shutil.which("sudo")
        if use_sudo:
            cmd += ['sudo', self.nmap_path]
        else:
            cmd.append(self.nmap_path)

        # Timing template
        timing_value = timing if timing in self.TIMING_TEMPLATES else "T4"
        cmd.append(f"-{timing_value}")

        # Port specification
        if ports:
            if str(ports).startswith("top-"):
                # Handle --top-ports syntax
                cmd.extend(["--top-ports", str(ports).replace("top-", "")])
            else:
                cmd.extend(["-p", str(ports)])
        else:
            cmd.extend(["--top-ports", "1000"])

        # Scan type
        tcp_flag = '-sS' if is_root else '-sT'
        if scan_type == 'udp':
            if not is_root:
                raise ScanError("UDP scan requires root (not available)")
            cmd.append('-sU')
        elif scan_type == 'both':
            if not is_root:
                cmd.append('-sT')        # TCP part only
            else:
                cmd += ['-sS', '-sU']
        else:
            cmd.append(tcp_flag)

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
        stats_interval = "1s" if (ports in (None, "top-1000", "top-100")) else "10s"
        cmd.extend([
            '--stats-every', stats_interval,  # Progress updates
            '-n',               # No DNS resolution (faster)
            '--min-rate', '1000' # Minimum packet rate
        ])

        if open_only:
            cmd.append('--open') #Only show open ports

        # Target
        cmd.append(target)

        return cmd

    def quick_scan(self, target, ports='top-1000', timing='T4'):
        """Perform quick scan of common ports."""
        # parameter ports can also be '80,443,22,8080' etc
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


if __name__ == "__main__":
    sys.exit(_cli())