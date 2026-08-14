"""
Parameter Fuzzer - Web parameter discovery
Finds hidden parameters and endpoints
"""

import os
import sys
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

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


class ParamFuzzer:
    """Web parameter discovery and fuzzing."""

    # Common parameter names
    COMMON_PARAMS = [
        "id",
        "page",
        "user",
        "username",
        "pass",
        "password",
        "email",
        "search",
        "query",
        "q",
        "file",
        "path",
        "dir",
        "action",
        "type",
        "mode",
        "view",
        "display",
        "show",
        "sort",
        "order",
        "limit",
        "offset",
        "start",
        "end",
        "category",
        "cat",
        "product",
        "item",
        "name",
        "firstname",
        "lastname",
        "address",
        "phone",
        "mobile",
        "city",
        "state",
        "country",
        "zip",
        "zipcode",
        "postcode",
        "message",
        "comment",
        "content",
        "body",
        "text",
        "title",
        "url",
        "link",
        "redirect",
        "next",
        "return",
        "ref",
        "referer",
        "session",
        "sid",
        "token",
        "csrf",
        "auth",
        "key",
        "api_key",
        "debug",
        "test",
        "demo",
        "admin",
        "root",
        "config",
        "setting",
    ]

    # Test values for parameter fuzzing
    TEST_VALUES = ["test", "1", "true", "admin", "null", "0"]

    def __init__(self, output_dir=None):
        """Initialize parameter fuzzer."""
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests is required for parameter fuzzing")

        self.logger = get_logger("param_fuzzer")
        self.notifier = Notifier()
        self.fm = FileManager()

        self.output_dir = output_dir or "./data/intermediate"
        self.fm.ensure_dir(self.output_dir)

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(
            {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        )

    def discover_params(self, url, params=None, threads=10, timeout=5):
        """
        Discover hidden parameters.

        Args:
            url: URL to test
            params: List of parameter names to test
            threads: Number of concurrent threads
            timeout: Request timeout

        Returns:
            dict: Parameter discovery results
        """
        if not is_valid_url(url):
            raise ValidationError(f"Invalid URL: {url}", field="url", value=url)

        if params is None:
            params = self.COMMON_PARAMS

        self.logger.info(f"Starting parameter discovery for: {url}")

        start_time = datetime.now()

        # Get baseline response
        try:
            baseline = self.session.get(url, timeout=timeout)
            baseline_status = baseline.status_code
            baseline_length = len(baseline.content)
        except Exception as e:
            self.logger.error(f"Failed to get baseline: {e}")
            raise

        results = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "params_tested": len(params),
            "discovered": [],
            "summary": {},
        }

        discovered = []

        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_param = {
                executor.submit(
                    self._test_param,
                    url,
                    param,
                    timeout,
                    baseline_status,
                    baseline_length,
                ): param
                for param in params
            }

            for future in as_completed(future_to_param):
                param = future_to_param[future]

                try:
                    result = future.result()
                    if result:
                        discovered.append(result)
                        self.logger.info(f"Parameter found: {param}")
                except Exception as e:
                    self.logger.debug(f"Error testing {param}: {e}")

        results["discovered"] = discovered
        results["summary"] = {
            "total_discovered": len(discovered),
            "discovery_rate": f"{(len(discovered) / len(params) * 100):.1f}%",
        }

        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_url = self.fm.safe_filename(url.replace("://", "_"))
        output_file = os.path.join(
            self.output_dir, f"params_{safe_url}_{timestamp}.json"
        )
        self.fm.write_json(output_file, results)

        duration = (datetime.now() - start_time).total_seconds()
        self.logger.info(
            f"Parameter discovery complete: {len(discovered)} found in {duration:.1f}s"
        )
        self.notifier.beep_complete()

        return results

    def _test_param(self, url, param, timeout, baseline_status, baseline_length):
        """Test a single parameter."""
        results = []

        # Test with different values
        for value in self.TEST_VALUES:
            test_url = self._add_param(url, param, value)

            try:
                response = self.session.get(test_url, timeout=timeout)

                # Check if response differs from baseline
                if (
                    response.status_code != baseline_status
                    or abs(len(response.content) - baseline_length) > 100
                ):

                    return {
                        "param": param,
                        "value": value,
                        "url": test_url,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "length_difference": len(response.content) - baseline_length,
                    }

            except Exception:
                continue

        # Test for reflection
        try:
            test_value = "paramtest123"
            test_url = self._add_param(url, param, test_value)
            response = self.session.get(test_url, timeout=timeout)

            if test_value in response.text:
                return {
                    "param": param,
                    "value": test_value,
                    "url": test_url,
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "length_difference": len(response.content) - baseline_length,
                    "reflected": True,
                }
        except Exception:
            pass

        return None

    def _add_param(self, url, param, value):
        """Add parameter to URL."""
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}{param}={value}"

    def fuzz_param_values(self, url, param, fuzz_values, threads=5, timeout=5):
        """
        Fuzz values for a specific parameter.

        Args:
            url: URL with parameter
            param: Parameter name
            fuzz_values: List of values to test
            threads: Number of threads
            timeout: Request timeout

        Returns:
            dict: Fuzzing results
        """
        self.logger.info(f"Fuzzing parameter '{param}' with {len(fuzz_values)} values")

        results = {
            "url": url,
            "param": param,
            "timestamp": datetime.now().isoformat(),
            "responses": [],
        }

        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_value = {
                executor.submit(self._test_value, url, param, value, timeout): value
                for value in fuzz_values
            }

            for future in as_completed(future_to_value):
                value = future_to_value[future]
                try:
                    response = future.result()
                    results["responses"].append(response)
                except Exception as e:
                    self.logger.debug(f"Error fuzzing value {value}: {e}")

        return results

    def _test_value(self, url, param, value, timeout):
        """Test a single value for a parameter."""
        test_url = self._add_param(url, param, value)

        try:
            response = self.session.get(test_url, timeout=timeout)
            return {
                "value": value,
                "url": test_url,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "content_type": response.headers.get("Content-Type", ""),
            }
        except Exception as e:
            return {"value": value, "url": test_url, "error": str(e)}
