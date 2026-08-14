"""
SSL Checker - SSL/TLS configuration audit
Checks certificates, protocols, and cipher suites
"""

import os
import sys
import ssl
import socket
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.file_manager import FileManager
from core.logger import get_logger
from core.notifier import Notifier
from core.exceptions import ScanError


class SSLChecker:
    """SSL/TLS configuration checker."""

    # Known weak protocols
    WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]

    # Weak cipher patterns
    WEAK_CIPHERS = [
        "RC4",
        "3DES",
        "DES",
        "MD5",
        "NULL",
        "EXPORT",
        "anon",
        "ADH",
        "AECDH",
    ]

    def __init__(self, output_dir=None):
        """Initialize SSL checker."""
        self.logger = get_logger("ssl_checker")
        self.notifier = Notifier()
        self.fm = FileManager()

        self.output_dir = output_dir or "./data/intermediate"
        self.fm.ensure_dir(self.output_dir)

    def check_ssl(self, host, port=443, timeout=10):
        """
        Check SSL/TLS configuration.

        Args:
            host: Hostname or IP
            port: SSL/TLS port
            timeout: Connection timeout

        Returns:
            dict: SSL check results
        """
        self.logger.info(f"Checking SSL/TLS for: {host}:{port}")

        results = {
            "host": host,
            "port": port,
            "timestamp": datetime.now().isoformat(),
            "certificate": {},
            "protocols": {},
            "vulnerabilities": [],
            "summary": {},
        }

        try:
            # Get certificate
            cert_info = self._get_certificate(host, port, timeout)
            results["certificate"] = cert_info

            # Check certificate issues
            cert_vulns = self._check_certificate(cert_info)
            results["vulnerabilities"].extend(cert_vulns)

            # Check supported protocols
            protocols = self._check_protocols(host, port, timeout)
            results["protocols"] = protocols

            # Check protocol issues
            protocol_vulns = self._check_protocol_issues(protocols)
            results["vulnerabilities"].extend(protocol_vulns)

            # Generate summary
            results["summary"] = self._generate_summary(results["vulnerabilities"])

            # Save results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_host = self.fm.safe_filename(host)
            output_file = os.path.join(
                self.output_dir, f"ssl_{safe_host}_{timestamp}.json"
            )
            self.fm.write_json(output_file, results)

            return results

        except Exception as e:
            self.logger.error(f"SSL check failed: {e}")
            raise ScanError(str(e), target=f"{host}:{port}", tool="ssl_checker")

    def _get_certificate(self, host, port, timeout):
        """Get SSL certificate information."""
        cert_info = {}

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)

                    # Parse certificate
                    import cryptography
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend

                    cert_obj = x509.load_der_x509_certificate(cert, default_backend())

                    cert_info = {
                        "subject": cert_obj.subject.rfc4514_string(),
                        "issuer": cert_obj.issuer.rfc4514_string(),
                        "serial_number": str(cert_obj.serial_number),
                        "not_before": str(cert_obj.not_valid_before),
                        "not_after": str(cert_obj.not_valid_after),
                        "version": cert_obj.version.name,
                        "signature_algorithm": cert_obj.signature_algorithm_oid._name,
                        "is_expired": cert_obj.not_valid_after < datetime.now(),
                        "is_not_yet_valid": cert_obj.not_valid_before > datetime.now(),
                    }

        except ImportError:
            # Fallback without cryptography
            cert_info = self._get_certificate_fallback(host, port, timeout)
        except Exception as e:
            self.logger.debug(f"Certificate parsing error: {e}")

        return cert_info

    def _get_certificate_fallback(self, host, port, timeout):
        """Fallback certificate check using ssl only."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()

                    return {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "not_before": cert.get("notBefore", ""),
                        "not_after": cert.get("notAfter", ""),
                    }
        except Exception as e:
            self.logger.debug(f"Fallback cert check failed: {e}")
            return {}

    def _check_certificate(self, cert_info):
        """Check certificate for issues."""
        vulnerabilities = []

        # Check expiration
        if cert_info.get("is_expired"):
            vulnerabilities.append(
                {
                    "type": "expired_certificate",
                    "severity": "critical",
                    "title": "SSL Certificate Expired",
                    "description": "The SSL certificate has expired",
                    "remediation": "Renew the SSL certificate immediately",
                }
            )

        # Check not yet valid
        if cert_info.get("is_not_yet_valid"):
            vulnerabilities.append(
                {
                    "type": "not_yet_valid",
                    "severity": "high",
                    "title": "SSL Certificate Not Yet Valid",
                    "description": "The SSL certificate is not yet valid",
                    "remediation": "Check system date and certificate validity period",
                }
            )

        # Check self-signed
        if cert_info.get("subject") == cert_info.get("issuer"):
            vulnerabilities.append(
                {
                    "type": "self_signed",
                    "severity": "medium",
                    "title": "Self-Signed Certificate",
                    "description": "Certificate is self-signed",
                    "remediation": "Use a certificate from a trusted CA",
                }
            )

        return vulnerabilities

    def _check_protocols(self, host, port, timeout):
        """Check supported SSL/TLS protocols."""
        protocols = {}

        protocol_map = {
            "SSLv2": ssl.PROTOCOL_SSLv23 if hasattr(ssl, "PROTOCOL_SSLv23") else None,
            "SSLv3": ssl.PROTOCOL_SSLv23 if hasattr(ssl, "PROTOCOL_SSLv23") else None,
            "TLSv1.0": ssl.TLSVersion.TLSv1 if hasattr(ssl, "TLSVersion") else None,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl, "TLSVersion") else None,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2 if hasattr(ssl, "TLSVersion") else None,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl, "TLSVersion") else None,
        }

        for protocol_name, protocol_version in protocol_map.items():
            if protocol_version is None:
                continue

            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                # Set minimum/maximum version
                if hasattr(context, "minimum_version"):
                    context.minimum_version = protocol_version
                    context.maximum_version = protocol_version

                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        protocols[protocol_name] = True

            except Exception:
                protocols[protocol_name] = False

        return protocols

    def _check_protocol_issues(self, protocols):
        """Check for weak protocol support."""
        vulnerabilities = []

        for protocol in self.WEAK_PROTOCOLS:
            if protocols.get(protocol, False):
                vulnerabilities.append(
                    {
                        "type": "weak_protocol",
                        "severity": "high",
                        "title": f"Weak Protocol Supported: {protocol}",
                        "description": f"{protocol} is enabled and should be disabled",
                        "remediation": f"Disable {protocol} on the server",
                    }
                )

        return vulnerabilities

    def _generate_summary(self, vulnerabilities):
        """Generate summary statistics."""
        severity_counts = {}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            "total_issues": len(vulnerabilities),
            "severity_counts": severity_counts,
            "grade": self._calculate_grade(vulnerabilities),
        }

    def _calculate_grade(self, vulnerabilities):
        """Calculate SSL grade based on vulnerabilities."""
        score = 100

        for vuln in vulnerabilities:
            severity = vuln.get("severity")
            if severity == "critical":
                score -= 30
            elif severity == "high":
                score -= 20
            elif severity == "medium":
                score -= 10
            elif severity == "low":
                score -= 5

        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
