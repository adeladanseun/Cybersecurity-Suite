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
from django.conf import settings
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
        scan.status = "running"
        scan.started_at = timezone.now()
        scan.progress = 5
        scan.save()

        # Update target last_scanned
        target = scan.target
        target.last_scanned = timezone.now()
        target.save()

        cls.logger.info(f"Starting {scan.scan_type} on {target.address}")

        # Start scan in background thread
        thread = threading.Thread(target=cls._run_scan, args=(scan.id,), daemon=True)
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
            if scan.scan_type == "port_scan":
                results = cls._run_port_scan(scan)
            elif scan.scan_type == "full_port_scan":
                results = cls._run_full_port_scan(scan)
            elif scan.scan_type == "service_scan":
                results = cls._run_service_scan(scan)
            elif scan.scan_type == "dns_enum":
                results = cls._run_dns_scan(scan)
            elif scan.scan_type == "vuln_scan":
                results = cls._run_vuln_scan(scan)
            elif scan.scan_type == "ssl_scan":
                results = cls._run_ssl_scan(scan)
            else:
                results = cls._run_default_scan(scan)

            # Save results
            if results:
                cls._save_results(scan, results)

            # Update scan status
            scan.status = "completed"
            scan.progress = 100
            scan.completed_at = timezone.now()
            scan.duration = scan.completed_at - scan.started_at
            scan.save()

            cls.logger.info(
                f"Scan completed: {scan.scan_type} on {scan.target.address}"
            )
            cls.notifier.beep_complete()

        except Exception as e:
            cls.logger.error(f"Scan failed: {e}")

            try:
                scan = Scan.objects.get(id=scan_id)
                scan.status = "failed"
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

        params = scan.parameters or {}
        ports = params.get("ports", "top-1000")

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

        scan.progress = 25
        scan.save()

        results = scanner.scan(
            target, scan_type="tcp", service_detection=True, script_scan=False
        )

        scan.progress = 75
        scan.save()

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
        from tools.vuln_checker import ServiceVulnChecker, CVELookup
        from tools.port_scanner import PortScanner

        scanner = PortScanner()
        target = scan.target.address

        scan.progress = 20
        scan.save()

        port_results = scanner.scan(
            target, scan_type="tcp", service_detection=True, script_scan=False
        )

        scan.progress = 50
        scan.save()

        # Check built-in vulnerability database
        vuln_checker = ServiceVulnChecker()
        builtin_vulns = vuln_checker.check_scan_results(port_results)

        scan.progress = 70
        scan.save()

        # Check CVE lookup with searchsploit
        cve_lookup = CVELookup()
        cve_vulns = cve_lookup.check_vulnerabilities(port_results)

        scan.progress = 85
        scan.save()

        # Combine results
        combined_vulns = builtin_vulns.get("vulnerabilities", [])

        existing_cves = {v.get("cve") for v in combined_vulns}
        for cve_match in cve_vulns.get("matched_cves", []):
            cve_info = cve_match.get("cve", {})
            cve_id = cve_info.get("cve", "")
            if cve_id and cve_id not in existing_cves:
                combined_vulns.append(
                    {
                        "host": cve_match.get("host"),
                        "port": cve_match.get("port"),
                        "service": cve_match.get("service"),
                        "cve": cve_id,
                        "severity": "medium",
                        "description": cve_info.get("title", ""),
                        "exploit_available": cve_info.get("exploit_available", False),
                        "remediation": "See CVE details for remediation",
                    }
                )

        return {
            "port_scan": port_results,
            "vulnerability_scan": {
                "timestamp": datetime.now().isoformat(),
                "vulnerabilities": combined_vulns,
                "summary": {
                    "total_vulnerabilities": len(combined_vulns),
                    "builtin_found": len(builtin_vulns.get("vulnerabilities", [])),
                    "cve_lookup_found": len(cve_vulns.get("matched_cves", [])),
                },
            },
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
            "status": "completed",
            "message": f"Scan type {scan.scan_type} completed",
            "target": scan.target.address,
            "timestamp": datetime.now().isoformat(),
        }

    @classmethod
    def _save_results(cls, scan, results):
        """Save scan results to file AND database."""
        try:
            # Create results directory if needed
            results_dir = os.path.join(settings.MEDIA_ROOT, "scans", "results")
            os.makedirs(results_dir, exist_ok=True)

            # Save results to file
            filename = f"scan_{scan.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join(results_dir, filename)

            with open(filepath, "w") as f:
                json.dump(results, f, indent=2, default=str)

            # Update scan
            scan.results_file.name = f"scans/results/{filename}"
            scan.save()

            # Process results into database
            cls._process_results_to_db(scan, results)

        except Exception as e:
            cls.logger.error(f"Failed to save results: {e}")

    @classmethod
    def _process_results_to_db(cls, scan, results):
        """Process scan results and save to database."""
        try:
            from results.models import PortResult, ScanResult, VulnerabilityResult

            # Process ports
            ports = results.get("ports", [])
            if not ports and "port_scan" in results:
                ports = results["port_scan"].get("ports", [])

            for port_data in ports:
                if port_data.get("state") == "open":
                    PortResult.objects.get_or_create(
                        scan=scan,
                        port=port_data.get("port"),
                        protocol=port_data.get("protocol", "tcp"),
                        defaults={
                            "state": port_data.get("state", "open"),
                            "service": port_data.get("service", ""),
                            "product": port_data.get("product", ""),
                            "version": port_data.get("version", ""),
                            "extra_info": port_data.get("extrainfo", ""),
                        },
                    )

            # Process summary as generic result
            summary = results.get("summary")
            if not summary and "port_scan" in results:
                summary = results["port_scan"].get("summary")
            if summary:
                ScanResult.objects.create(
                    scan=scan,
                    result_type="info",
                    severity="info",
                    data={"summary": summary},
                )

            # Process vulnerabilities
            vulns = results.get("vulnerabilities", [])
            if not vulns and "vulnerability_scan" in results:
                vulns = results["vulnerability_scan"].get("vulnerabilities", [])

            for vuln_data in vulns:
                VulnerabilityResult.objects.get_or_create(
                    scan=scan,
                    cve_id=vuln_data.get("cve", vuln_data.get("cve_id", "")),
                    title=vuln_data.get(
                        "title", vuln_data.get("description", "Unknown")
                    ),
                    defaults={
                        "description": vuln_data.get("description", ""),
                        "severity": vuln_data.get("severity", "medium"),
                        "cvss_score": vuln_data.get("cvss_score"),
                        "affected_service": vuln_data.get(
                            "service", vuln_data.get("product", "")
                        ),
                        "port": vuln_data.get("port"),
                        "remediation": vuln_data.get("remediation", ""),
                    },
                )
            # Also create in vulnerability management app
            from vulnerabilities.models import Vulnerability as VulnManagement
            
            for vuln_data in vulns:
                VulnManagement.objects.get_or_create(
                    scan=scan,
                    cve_id=vuln_data.get('cve', vuln_data.get('cve_id', '')),
                    title=vuln_data.get('title', vuln_data.get('description', 'Unknown Vulnerability')),
                    defaults={
                        'description': vuln_data.get('description', ''),
                        'severity': vuln_data.get('severity', 'medium'),
                        'cvss_score': vuln_data.get('cvss_score'),
                        'affected_service': vuln_data.get('service', vuln_data.get('product', '')),
                        'port': vuln_data.get('port'),
                        'remediation': vuln_data.get('remediation', ''),
                        'discovered_by': scan.initiated_by,
                    }
                )
                
            cls.logger.info(
                f"Results processed: {len(ports)} ports, {len(vulns)} vulnerabilities"
            )

        except Exception as e:
            cls.logger.error(f"Failed to process results to DB: {e}")
