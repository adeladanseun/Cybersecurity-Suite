"""
Directory Buster - Web directory and file enumeration
Brute forces common paths on web servers
"""

import os
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.file_manager import FileManager
from core.validator import is_valid_url
from core.logger import get_logger, log_scan_start, log_scan_complete
from core.notifier import Notifier
from core.exceptions import ScanError, ValidationError

# Try importing requests
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class DirBuster:
    """Directory and file enumeration for web applications."""

    # Common extensions to test
    COMMON_EXTENSIONS = ["", ".php", ".html", ".txt", ".bak", ".old", ".zip"]

    # Default wordlist for directory discovery
    DEFAULT_WORDLIST = [
        "admin",
        "administrator",
        "backup",
        "backups",
        "config",
        "css",
        "data",
        "db",
        "download",
        "downloads",
        "files",
        "images",
        "img",
        "include",
        "includes",
        "index",
        "js",
        "lib",
        "login",
        "logs",
        "old",
        "panel",
        "phpmyadmin",
        "private",
        "robots.txt",
        "sitemap.xml",
        "static",
        "temp",
        "test",
        "tmp",
        "upload",
        "uploads",
        "user",
        "users",
        "web",
        "wp-admin",
        "wp-content",
        "wp-includes",
        "api",
        "v1",
        "v2",
        "assets",
        "docs",
        "documentation",
        "src",
        "source",
        "bin",
        "conf",
        "etc",
        "var",
        "cgi-bin",
        "scripts",
        "script",
        "css",
        "fonts",
        "media",
        "video",
        "audio",
        "archive",
        "archives",
        "bak",
        "backup.zip",
        "backup.tar.gz",
        ".git",
        ".svn",
        ".env",
        ".htaccess",
        ".htpasswd",
        "web.config",
        "phpinfo.php",
        "info.php",
        "test.php",
        "admin.php",
        "login.php",
        "config.php",
        "database.sql",
        "dump.sql",
        "export.sql",
    ]

    # Status code classifications
    SUCCESS_CODES = [200, 201, 202, 203, 204, 301, 302, 307, 308, 401, 403]

    def __init__(self, output_dir=None):
        """Initialize directory buster."""
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests is required for directory busting")

        self.logger = get_logger("dir_buster")
        self.notifier = Notifier()
        self.fm = FileManager()

        self.output_dir = output_dir or "./data/intermediate"
        self.fm.ensure_dir(self.output_dir)

        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification
        self.session.headers.update(
            {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        )

    def brute_force(
        self,
        url,
        wordlist=None,
        extensions=None,
        threads=10,
        timeout=5,
        follow_redirects=False,
    ):
        """
        Brute force directories and files.

        Args:
            url: Base URL to scan
            wordlist: List of paths to test
            extensions: List of extensions to append
            threads: Number of concurrent threads
            timeout: Request timeout
            follow_redirects: Follow HTTP redirects

        Returns:
            dict: Directory brute force results
        """
        if not is_valid_url(url):
            raise ValidationError(f"Invalid URL: {url}", field="url", value=url)

        # Normalize URL
        url = url.rstrip("/")

        if wordlist is None:
            wordlist = self.DEFAULT_WORDLIST

        if extensions is None:
            extensions = self.COMMON_EXTENSIONS

        self.logger.info(f"Starting directory brute force on: {url}")
        log_scan_start(self.logger, url, "dir_buster")

        start_time = datetime.now()

        # Generate all paths to test
        paths_to_test = []
        for word in wordlist:
            for ext in extensions:
                path = f"/{word}{ext}"
                if path not in paths_to_test:
                    paths_to_test.append(path)

        self.logger.info(f"Testing {len(paths_to_test)} paths with {threads} threads")

        results = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "wordlist_size": len(wordlist),
            "paths_tested": len(paths_to_test),
            "discovered": [],
            "summary": {},
        }

        discovered = []

        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_path = {
                executor.submit(
                    self._check_path, url, path, timeout, follow_redirects
                ): path
                for path in paths_to_test
            }

            completed = 0
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                completed += 1

                try:
                    result = future.result()
                    if result:
                        discovered.append(result)
                        status = result["status_code"]
                        size = result["content_length"]
                        self.logger.info(
                            f"Found: {path} (Status: {status}, Size: {size})"
                        )

                        # Notify on interesting findings
                        if status in [200, 301, 302] and "admin" in path.lower():
                            self.notifier.beep_finding()

                except Exception as e:
                    self.logger.debug(f"Error testing {path}: {e}")

                # Progress updates
                if completed % 50 == 0:
                    progress = int((completed / len(paths_to_test)) * 100)
                    if progress in [25, 50, 75]:
                        self.logger.info(f"Progress: {progress}%")
                        self.notifier.beep_progress(progress)

        # Sort results by status code then path
        discovered.sort(key=lambda x: (x["status_code"], x["path"]))
        results["discovered"] = discovered

        # Generate summary
        results["summary"] = self._generate_summary(discovered)

        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_url = self.fm.safe_filename(url.replace("://", "_"))
        output_file = os.path.join(
            self.output_dir, f"dirbuster_{safe_url}_{timestamp}.json"
        )
        self.fm.write_json(output_file, results)
        results["output_file"] = output_file

        # Save as CSV for easy viewing
        if discovered:
            csv_file = os.path.join(
                self.output_dir, f"dirbuster_{safe_url}_{timestamp}.csv"
            )
            csv_data = [
                {
                    "Path": d["path"],
                    "Status": d["status_code"],
                    "Size": d["content_length"],
                    "Content Type": d.get("content_type", ""),
                    "Redirect": d.get("redirect", ""),
                }
                for d in discovered
            ]
            self.fm.write_csv(csv_file, csv_data)

        duration = (datetime.now() - start_time).total_seconds()
        log_scan_complete(self.logger, url, "dir_buster", duration)
        self.notifier.beep_complete()

        self.logger.info(
            f"Directory brute force complete: {len(discovered)} paths found"
        )

        return results

    def _check_path(self, base_url, path, timeout, follow_redirects):
        """Check a single path for existence."""
        url = f"{base_url}{path}"

        try:
            response = self.session.get(
                url, timeout=timeout, allow_redirects=follow_redirects
            )

            status = response.status_code

            # Consider it found if status is in success codes
            if status in self.SUCCESS_CODES:
                return {
                    "path": path,
                    "url": url,
                    "status_code": status,
                    "content_length": len(response.content),
                    "content_type": response.headers.get("Content-Type", ""),
                    "server": response.headers.get("Server", ""),
                    "redirect": (
                        response.headers.get("Location", "")
                        if status in [301, 302, 307, 308]
                        else ""
                    ),
                    "title": self._extract_title(response),
                }

            return None

        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.TooManyRedirects:
            return None
        except Exception:
            return None

    def _extract_title(self, response):
        """Extract page title from HTML content."""
        try:
            import re

            title_match = re.search(
                r"<title>(.*?)</title>", response.text, re.IGNORECASE | re.DOTALL
            )
            if title_match:
                return title_match.group(1).strip()[:200]
        except Exception:
            pass
        return ""

    def _generate_summary(self, discovered):
        """Generate summary statistics."""
        status_codes = {}
        total_size = 0

        for item in discovered:
            status = item["status_code"]
            status_codes[status] = status_codes.get(status, 0) + 1
            total_size += item.get("content_length", 0)

        return {
            "total_discovered": len(discovered),
            "status_codes": status_codes,
            "total_content_size": total_size,
            "interesting_findings": [
                d
                for d in discovered
                if "admin" in d["path"].lower()
                or "backup" in d["path"].lower()
                or "config" in d["path"].lower()
                or ".git" in d["path"].lower()
                or ".env" in d["path"].lower()
            ],
        }

    def load_wordlist(self, wordlist_file):
        """Load wordlist from file."""
        if not os.path.exists(wordlist_file):
            self.logger.warning(f"Wordlist not found: {wordlist_file}")
            return self.DEFAULT_WORDLIST

        words = self.fm.read_lines(wordlist_file)
        return words if words else self.DEFAULT_WORDLIST

    def brute_force_with_file(self, url, wordlist_file, **kwargs):
        """Brute force using wordlist from file."""
        wordlist = self.load_wordlist(wordlist_file)
        return self.brute_force(url, wordlist=wordlist, **kwargs)
