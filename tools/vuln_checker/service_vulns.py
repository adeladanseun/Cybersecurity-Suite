"""
Service Vulnerability Checker - Checks services for known vulnerabilities
Matches service versions against vulnerability database
"""

import os
import sys
import json
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.file_manager import FileManager
from core.logger import get_logger
from core.notifier import Notifier
from core.exceptions import ScanError


class ServiceVulnChecker:
    """Check services for known vulnerabilities."""

    # Known vulnerable services database (simplified)
    VULN_DATABASE = {
        "apache": [
            {
                "version_pattern": "2.4.49",
                "cve": "CVE-2021-41773",
                "severity": "critical",
                "description": "Path traversal and remote code execution",
                "exploit_available": True,
                "remediation": "Upgrade to Apache 2.4.50 or later",
            },
            {
                "version_pattern": "2.4.50",
                "cve": "CVE-2021-42013",
                "severity": "critical",
                "description": "Path traversal vulnerability",
                "exploit_available": True,
                "remediation": "Upgrade to Apache 2.4.51 or later",
            },
        ],
        "nginx": [
            {
                "version_pattern": "1.20.0",
                "cve": "CVE-2021-23017",
                "severity": "high",
                "description": "DNS resolver off-by-one heap write",
                "exploit_available": False,
                "remediation": "Upgrade to nginx 1.21.0 or later",
            }
        ],
        "openssh": [
            {
                "version_pattern": "8.0",
                "cve": "CVE-2020-15778",
                "severity": "high",
                "description": "Command injection in scp",
                "exploit_available": True,
                "remediation": "Upgrade to OpenSSH 8.1 or later",
            },
            {
                "version_pattern": "7.9",
                "cve": "CVE-2019-6111",
                "severity": "medium",
                "description": "SCP client missing received object validation",
                "exploit_available": False,
                "remediation": "Upgrade to OpenSSH 8.0 or later",
            },
        ],
        "mysql": [
            {
                "version_pattern": "5.7.0",
                "cve": "CVE-2020-14750",
                "severity": "critical",
                "description": "Remote code execution vulnerability",
                "exploit_available": True,
                "remediation": "Upgrade to MySQL 5.7.31 or later",
            }
        ],
        "proftpd": [
            {
                "version_pattern": "1.3.5",
                "cve": "CVE-2019-12815",
                "severity": "high",
                "description": "Arbitrary file copy vulnerability",
                "exploit_available": True,
                "remediation": "Upgrade to ProFTPD 1.3.6 or later",
            }
        ],
        "vsftpd": [
            {
                "version_pattern": "2.3.4",
                "cve": "CVE-2011-2523",
                "severity": "critical",
                "description": "Backdoor command execution",
                "exploit_available": True,
                "remediation": "Remove vsftpd 2.3.4 immediately",
            }
        ],
        "tomcat": [
            {
                "version_pattern": "9.0.0",
                "cve": "CVE-2020-1938",
                "severity": "critical",
                "description": "AJP file read/inclusion vulnerability (Ghostcat)",
                "exploit_available": True,
                "remediation": "Upgrade to Tomcat 9.0.31 or later",
            }
        ],
    }

    def __init__(self, output_dir=None):
        """Initialize service vulnerability checker."""
        self.logger = get_logger("service_vulns")
        self.notifier = Notifier()
        self.fm = FileManager()

        self.output_dir = output_dir or "./data/intermediate"
        self.fm.ensure_dir(self.output_dir)

    def check_scan_results(self, scan_results):
        """
        Check scan results for vulnerable services.

        Args:
            scan_results: Results from port scanner

        Returns:
            dict: Vulnerability check results
        """
        self.logger.info("Checking services for vulnerabilities...")

        results = {
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": [],
            "summary": {},
        }

        # Check each port
        for port_info in scan_results.get("ports", []):
            if port_info.get("state") == "open":
                vulns = self.check_service(
                    port_info.get("service", ""),
                    port_info.get("product", ""),
                    port_info.get("version", ""),
                    port_info.get("port"),
                    port_info.get("host", ""),
                )

                if vulns:
                    results["vulnerabilities"].extend(vulns)

        # Generate summary
        results["summary"] = self._generate_summary(results["vulnerabilities"])

        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.output_dir, f"vulns_{timestamp}.json")
        self.fm.write_json(output_file, results)
        results["output_file"] = output_file

        # Notify if critical vulnerabilities found
        if results["summary"].get("critical", 0) > 0:
            self.notifier.beep_finding()

        self.logger.info(
            f"Vulnerability check complete: {len(results['vulnerabilities'])} found"
        )

        return results

    def check_service(self, service, product, version, port=None, host=None):
        """
        Check a single service for vulnerabilities.

        Args:
            service: Service name
            product: Product name
            version: Product version
            port: Port number
            host: Host IP/domain

        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []

        # Normalize service name
        service_key = (product or service).lower()

        # Check against vulnerability database
        for db_service, vulns in self.VULN_DATABASE.items():
            if db_service in service_key:
                for vuln in vulns:
                    if self._version_matches(version, vuln["version_pattern"]):
                        vulnerabilities.append(
                            {
                                "host": host,
                                "port": port,
                                "service": service,
                                "product": product,
                                "version": version,
                                "cve": vuln["cve"],
                                "severity": vuln["severity"],
                                "description": vuln["description"],
                                "exploit_available": vuln["exploit_available"],
                                "remediation": vuln["remediation"],
                                "detected_at": datetime.now().isoformat(),
                            }
                        )

                        self.logger.warning(
                            f"VULNERABILITY: {vuln['cve']} - {product} {version} "
                            f"({vuln['severity'].upper()})"
                        )

        return vulnerabilities

    def _version_matches(self, current_version, pattern):
        """Check if version matches vulnerability pattern."""
        if not current_version:
            return False

        # Exact match
        if current_version == pattern:
            return True

        # Prefix match (e.g., "2.4.49" matches "2.4")
        if current_version.startswith(pattern):
            return True

        # Version range check (simplified)
        if "-" in pattern:
            min_ver, max_ver = pattern.split("-")
            return min_ver <= current_version <= max_ver

        return False

    def _generate_summary(self, vulnerabilities):
        """Generate summary statistics."""
        severity_counts = {}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_counts": severity_counts,
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "exploitable": sum(
                1 for v in vulnerabilities if v.get("exploit_available")
            ),
        }

    def check_from_file(self, scan_file):
        """Check vulnerabilities from scan results file."""
        scan_results = self.fm.read_json(scan_file)
        return self.check_scan_results(scan_results)
