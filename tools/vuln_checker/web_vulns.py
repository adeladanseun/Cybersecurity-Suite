"""
Web Vulnerability Checker - Checks web applications for common vulnerabilities
Tests for SQL injection, XSS, and other common web vulnerabilities
"""

import os
import sys
import re
from datetime import datetime
from urllib.parse import urlencode, urlparse, parse_qs

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.file_manager import FileManager
from core.validator import is_valid_url
from core.logger import get_logger
from core.notifier import Notifier
from core.exceptions import ValidationError

# Try importing requests
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class WebVulnChecker:
    """Check web applications for common vulnerabilities."""

    # SQL injection test payloads
    SQLI_PAYLOADS = [
        "'",
        "''",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "1' OR '1'='1",
        "1 OR 1=1",
        "' UNION SELECT NULL--",
        "' AND 1=1--",
        "' AND 1=2--",
    ]

    # XSS test payloads
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        '"><script>alert(1)</script>',
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "'><script>alert(1)</script>",
    ]

    # SQL error patterns
    SQL_ERROR_PATTERNS = [
        r"SQL syntax",
        r"mysql_fetch",
        r"ORA-[0-9]{4,5}",
        r"PostgreSQL.*ERROR",
        r"SQLite.*error",
        r"Microsoft.*SQL Server",
        r"ODBC.*Driver",
        r"You have an error in your SQL",
        r"Unclosed quotation mark",
    ]

    def __init__(self, output_dir=None):
        """Initialize web vulnerability checker."""
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests is required for web vulnerability checking")

        self.logger = get_logger("web_vulns")
        self.notifier = Notifier()
        self.fm = FileManager()

        self.output_dir = output_dir or "./data/intermediate"
        self.fm.ensure_dir(self.output_dir)

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(
            {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        )

    def check_url(self, url, checks=None, timeout=10):
        """
        Check a URL for common vulnerabilities.

        Args:
            url: URL to check
            checks: List of checks to perform ('sqli', 'xss', 'headers', 'all')
            timeout: Request timeout

        Returns:
            dict: Vulnerability check results
        """
        if not is_valid_url(url):
            raise ValidationError(f"Invalid URL: {url}", field="url", value=url)

        if checks is None:
            checks = ["sqli", "xss", "headers"]

        self.logger.info(f"Checking web vulnerabilities for: {url}")

        results = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": [],
            "summary": {},
        }

        vulnerabilities = []

        # Perform checks
        if "sqli" in checks or "all" in checks:
            sqli_vulns = self.check_sql_injection(url, timeout)
            vulnerabilities.extend(sqli_vulns)

        if "xss" in checks or "all" in checks:
            xss_vulns = self.check_xss(url, timeout)
            vulnerabilities.extend(xss_vulns)

        if "headers" in checks or "all" in checks:
            header_vulns = self.check_security_headers(url, timeout)
            vulnerabilities.extend(header_vulns)

        results["vulnerabilities"] = vulnerabilities
        results["summary"] = self._generate_summary(vulnerabilities)

        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_url = self.fm.safe_filename(url.replace("://", "_"))
        output_file = os.path.join(
            self.output_dir, f"webvulns_{safe_url}_{timestamp}.json"
        )
        self.fm.write_json(output_file, results)

        # Notify on critical findings
        if any(v["severity"] == "critical" for v in vulnerabilities):
            self.notifier.beep_finding()

        return results

    def check_sql_injection(self, url, timeout=10):
        """Test for SQL injection vulnerabilities."""
        vulnerabilities = []

        # Check if URL has parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulnerabilities

        self.logger.info(f"Testing SQL injection on {len(params)} parameters")

        for param in params:
            for payload in self.SQLI_PAYLOADS:
                test_url = self._inject_payload(url, param, payload)

                try:
                    response = self.session.get(test_url, timeout=timeout)

                    # Check for SQL errors
                    for error_pattern in self.SQL_ERROR_PATTERNS:
                        if re.search(error_pattern, response.text, re.IGNORECASE):
                            vulnerabilities.append(
                                {
                                    "type": "sql_injection",
                                    "param": param,
                                    "payload": payload,
                                    "severity": "critical",
                                    "title": f"SQL Injection in parameter: {param}",
                                    "description": f"SQL error detected with payload: {payload}",
                                    "url": test_url,
                                    "remediation": "Use parameterized queries and input validation",
                                }
                            )
                            break

                    # Check for boolean-based injection
                    if payload == "' AND 1=1--":
                        true_response = len(response.content)
                        false_url = self._inject_payload(url, param, "' AND 1=2--")
                        false_response = self.session.get(false_url, timeout=timeout)

                        if abs(true_response - len(false_response.content)) > 100:
                            vulnerabilities.append(
                                {
                                    "type": "sql_injection",
                                    "param": param,
                                    "payload": payload,
                                    "severity": "high",
                                    "title": f"Boolean-based SQL Injection in: {param}",
                                    "description": "Different responses for true/false conditions",
                                    "url": test_url,
                                    "remediation": "Use parameterized queries",
                                }
                            )
                            break

                except Exception:
                    continue

        return vulnerabilities

    def check_xss(self, url, timeout=10):
        """Test for XSS vulnerabilities."""
        vulnerabilities = []

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulnerabilities

        self.logger.info(f"Testing XSS on {len(params)} parameters")

        for param in params:
            for payload in self.XSS_PAYLOADS:
                test_url = self._inject_payload(url, param, payload)

                try:
                    response = self.session.get(test_url, timeout=timeout)

                    # Check if payload is reflected
                    if payload in response.text:
                        vulnerabilities.append(
                            {
                                "type": "xss",
                                "param": param,
                                "payload": payload,
                                "severity": "high",
                                "title": f"Reflected XSS in parameter: {param}",
                                "description": f"Payload reflected in response: {payload}",
                                "url": test_url,
                                "remediation": "Implement output encoding and input validation",
                            }
                        )
                        break

                except Exception:
                    continue

        return vulnerabilities

    def check_security_headers(self, url, timeout=10):
        """Check for missing security headers."""
        vulnerabilities = []

        security_headers = {
            "X-Frame-Options": {
                "severity": "medium",
                "description": "Missing clickjacking protection",
                "remediation": "Add X-Frame-Options header",
            },
            "X-XSS-Protection": {
                "severity": "low",
                "description": "XSS filter not explicitly enabled",
                "remediation": "Add X-XSS-Protection: 1; mode=block",
            },
            "X-Content-Type-Options": {
                "severity": "medium",
                "description": "MIME sniffing not prevented",
                "remediation": "Add X-Content-Type-Options: nosniff",
            },
            "Strict-Transport-Security": {
                "severity": "high",
                "description": "HSTS not enabled",
                "remediation": "Add Strict-Transport-Security header",
            },
            "Content-Security-Policy": {
                "severity": "medium",
                "description": "CSP not configured",
                "remediation": "Implement Content Security Policy",
            },
        }

        try:
            response = self.session.get(url, timeout=timeout)

            for header, info in security_headers.items():
                if header not in response.headers:
                    vulnerabilities.append(
                        {
                            "type": "missing_header",
                            "header": header,
                            "severity": info["severity"],
                            "title": f"Missing Security Header: {header}",
                            "description": info["description"],
                            "remediation": info["remediation"],
                        }
                    )

        except Exception as e:
            self.logger.error(f"Header check failed: {e}")

        return vulnerabilities

    def _inject_payload(self, url, param, payload):
        """Inject payload into URL parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]

        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def _generate_summary(self, vulnerabilities):
        """Generate summary statistics."""
        severity_counts = {}
        type_counts = {}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info")
            vtype = vuln.get("type", "unknown")

            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            type_counts[vtype] = type_counts.get(vtype, 0) + 1

        return {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_counts": severity_counts,
            "type_counts": type_counts,
        }
