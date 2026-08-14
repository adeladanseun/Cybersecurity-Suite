"""
Technology Fingerprint - Web technology detection
Identifies web servers, frameworks, and technologies
"""

import os
import sys
import re
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.file_manager import FileManager
from core.validator import is_valid_url
from core.logger import get_logger
from core.notifier import Notifier
from core.exceptions import ValidationError, ScanError

# Try importing requests
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class TechFingerprint:
    """Web technology fingerprinting and detection."""

    # Technology signatures
    TECH_SIGNATURES = {
        "Apache": {
            "headers": ["Server"],
            "patterns": [r"Apache(?:/(\d+\.\d+))?"],
            "category": "Web Server",
        },
        "nginx": {
            "headers": ["Server"],
            "patterns": [r"nginx(?:/(\d+\.\d+))?"],
            "category": "Web Server",
        },
        "IIS": {
            "headers": ["Server"],
            "patterns": [r"Microsoft-IIS(?:/(\d+\.\d+))?"],
            "category": "Web Server",
        },
        "PHP": {
            "headers": ["X-Powered-By"],
            "patterns": [r"PHP(?:/(\d+\.\d+))?"],
            "category": "Programming Language",
        },
        "ASP.NET": {
            "headers": ["X-Powered-By", "X-AspNet-Version"],
            "patterns": [r"ASP\.NET", r"\.NET"],
            "category": "Framework",
        },
        "WordPress": {
            "headers": [],
            "html_patterns": [r"wp-content", r"wp-includes"],
            "meta_patterns": [r'name="generator" content="WordPress'],
            "category": "CMS",
        },
        "Joomla": {
            "html_patterns": [r"/media/system/js/", r"/templates/system/"],
            "meta_patterns": [r'name="generator" content="Joomla'],
            "category": "CMS",
        },
        "Drupal": {
            "headers": ["X-Generator"],
            "patterns": [r"Drupal"],
            "html_patterns": [r"/sites/default/", r"/sites/all/"],
            "category": "CMS",
        },
        "jQuery": {
            "html_patterns": [r"jquery[\.-](\d+\.\d+\.\d+)\.js"],
            "category": "JavaScript Library",
        },
        "Bootstrap": {
            "html_patterns": [r"bootstrap(?:\.min)?\.css", r"bootstrap(?:\.min)?\.js"],
            "category": "CSS Framework",
        },
        "React": {
            "html_patterns": [r"react(?:\.min)?\.js", r"react-dom"],
            "category": "JavaScript Framework",
        },
        "Angular": {
            "html_patterns": [r"angular(?:\.min)?\.js", r"ng-app"],
            "category": "JavaScript Framework",
        },
        "Vue.js": {
            "html_patterns": [r"vue(?:\.min)?\.js", r"v-app"],
            "category": "JavaScript Framework",
        },
        "Laravel": {
            "headers": ["Set-Cookie"],
            "patterns": [r"laravel_session"],
            "category": "Framework",
        },
        "Django": {
            "headers": ["Set-Cookie"],
            "patterns": [r"csrftoken"],
            "category": "Framework",
        },
        "Ruby on Rails": {
            "headers": ["Server", "X-Powered-By"],
            "patterns": [r"Rails", r"Ruby"],
            "category": "Framework",
        },
        "Cloudflare": {
            "headers": ["Server", "CF-Ray"],
            "patterns": [r"cloudflare"],
            "category": "CDN",
        },
        "Amazon CloudFront": {
            "headers": ["X-Cache", "Via"],
            "patterns": [r"CloudFront"],
            "category": "CDN",
        },
    }

    def __init__(self, output_dir=None):
        """Initialize technology fingerprint."""
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests is required for tech fingerprinting")

        self.logger = get_logger("tech_fingerprint")
        self.notifier = Notifier()
        self.fm = FileManager()

        self.output_dir = output_dir or "./data/intermediate"
        self.fm.ensure_dir(self.output_dir)

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(
            {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        )

    def fingerprint(self, url, timeout=10):
        """
        Fingerprint technologies used by a website.

        Args:
            url: URL to fingerprint
            timeout: Request timeout

        Returns:
            dict: Fingerprint results
        """
        if not is_valid_url(url):
            raise ValidationError(f"Invalid URL: {url}", field="url", value=url)

        self.logger.info(f"Fingerprinting technologies for: {url}")

        start_time = datetime.now()

        results = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "technologies": [],
            "headers": {},
            "summary": {},
        }

        try:
            # Make request
            response = self.session.get(url, timeout=timeout)

            # Store headers
            results["headers"] = dict(response.headers)
            results["status_code"] = response.status_code

            # Detect technologies
            technologies = self._detect_technologies(response)
            results["technologies"] = technologies

            # Generate summary
            results["summary"] = self._generate_summary(technologies)

            # Save results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_url = self.fm.safe_filename(url.replace("://", "_"))
            output_file = os.path.join(
                self.output_dir, f"fingerprint_{safe_url}_{timestamp}.json"
            )
            self.fm.write_json(output_file, results)
            results["output_file"] = output_file

            duration = (datetime.now() - start_time).total_seconds()
            self.logger.info(
                f"Fingerprinting complete: {len(technologies)} technologies found"
            )
            self.notifier.beep_complete()

            return results

        except Exception as e:
            self.logger.error(f"Fingerprinting failed: {e}")
            raise ScanError(str(e), target=url, tool="tech_fingerprint")

    def _detect_technologies(self, response):
        """Detect technologies from response."""
        technologies = []

        # Check headers
        for tech_name, signature in self.TECH_SIGNATURES.items():
            if self._check_headers(response.headers, signature):
                version = self._extract_version(response.headers, signature)
                technologies.append(
                    {
                        "name": tech_name,
                        "version": version,
                        "category": signature.get("category", "Unknown"),
                        "detection_method": "headers",
                        "confidence": "high",
                    }
                )

        # Check HTML content
        if "text/html" in response.headers.get("Content-Type", ""):
            for tech_name, signature in self.TECH_SIGNATURES.items():
                if "html_patterns" in signature:
                    for pattern in signature["html_patterns"]:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            version = self._extract_version_from_text(
                                response.text, pattern
                            )
                            technologies.append(
                                {
                                    "name": tech_name,
                                    "version": version,
                                    "category": signature.get("category", "Unknown"),
                                    "detection_method": "html",
                                    "confidence": "medium",
                                }
                            )
                            break

                if "meta_patterns" in signature:
                    for pattern in signature["meta_patterns"]:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            technologies.append(
                                {
                                    "name": tech_name,
                                    "version": None,
                                    "category": signature.get("category", "Unknown"),
                                    "detection_method": "meta",
                                    "confidence": "high",
                                }
                            )
                            break

        # Remove duplicates
        unique_techs = []
        seen = set()
        for tech in technologies:
            key = tech["name"]
            if key not in seen:
                seen.add(key)
                unique_techs.append(tech)

        return unique_techs

    def _check_headers(self, headers, signature):
        """Check if headers match technology signature."""
        for header_name in signature.get("headers", []):
            if header_name in headers:
                for pattern in signature.get("patterns", []):
                    if re.search(pattern, headers[header_name], re.IGNORECASE):
                        return True

        # Check all headers for patterns
        for header_name, header_value in headers.items():
            for pattern in signature.get("patterns", []):
                if re.search(pattern, str(header_value), re.IGNORECASE):
                    return True

        return False

    def _extract_version(self, headers, signature):
        """Extract version from headers."""
        for header_name in signature.get("headers", []):
            if header_name in headers:
                for pattern in signature.get("patterns", []):
                    match = re.search(pattern, headers[header_name], re.IGNORECASE)
                    if match and match.group(1):
                        return match.group(1)

        return None

    def _extract_version_from_text(self, text, pattern):
        """Extract version from text content."""
        match = re.search(pattern, text, re.IGNORECASE)
        if match and match.group(1):
            return match.group(1)
        return None

    def _generate_summary(self, technologies):
        """Generate summary of detected technologies."""
        categories = {}
        for tech in technologies:
            category = tech.get("category", "Unknown")
            categories[category] = categories.get(category, 0) + 1

        return {
            "total_technologies": len(technologies),
            "categories": categories,
            "web_server": next(
                (t for t in technologies if t["category"] == "Web Server"), None
            ),
            "cms": next((t for t in technologies if t["category"] == "CMS"), None),
            "frameworks": [t for t in technologies if t["category"] == "Framework"],
        }

    def fingerprint_multiple(self, urls, **kwargs):
        """Fingerprint multiple URLs."""
        results = []
        for url in urls:
            try:
                result = self.fingerprint(url, **kwargs)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Failed to fingerprint {url}: {e}")
                results.append({"url": url, "error": str(e), "status": "failed"})
        return results
