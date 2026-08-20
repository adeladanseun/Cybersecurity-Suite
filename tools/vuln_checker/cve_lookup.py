"""
CVE Lookup - Offline CVE database search
Matches services and versions to known CVEs
"""

import os
import sys
import json
import csv
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.file_manager import FileManager
from core.logger import get_logger
from core.notifier import Notifier


class CVELookup:
    """Offline CVE database lookup."""

    def __init__(self, database_dir=None, output_dir=None):
        """Initialize CVE lookup."""
        self.logger = get_logger("cve_lookup")
        self.notifier = Notifier()
        self.fm = FileManager()

        # Set database directory
        if database_dir:
            self.database_dir = database_dir
        else:
            self.database_dir = os.path.join(os.getcwd(), "data", "databases")

        self.output_dir = output_dir or "./data/intermediate"
        self.fm.ensure_dir(self.output_dir)

        self.cve_database = {}
        self._load_database()

    def _load_database(self):
        """Load CVE database from files."""
        # Try loading from searchsploit
        searchsploit_paths = [
            os.path.join('/usr/share/exploitdb', 'exploits.csv'),
            os.path.join('/usr/share/exploitdb', 'files_exploits.csv'),
            os.path.join('/opt/exploitdb', 'exploits.csv'),
            os.path.join('/opt/exploitdb', 'files_exploits.csv'),
        ]
        
        for searchsploit_db in searchsploit_paths:
            if os.path.exists(searchsploit_db):
                self._load_searchsploit(searchsploit_db)
                break
        
        # Try loading from local JSON database
        local_db = os.path.join(self.database_dir, 'cve_database.json')
        if os.path.exists(local_db):
            self._load_json_database(local_db)
        
        # Try loading Wappalyzer data if available
        self._load_wappalyzer()

    def _load_searchsploit(self, csv_file):
        """Load searchsploit database."""
        try:
            with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)

                for row in reader:
                    codes = row.get("codes", "")
                    description = row.get("description", "")
                    
                    if codes and "CVE-" in str(codes):
                        cve_list = str(codes).split(';')
                        
                        for cve in cve_list:
                            cve = cve.strip()
                            if cve and 'CVE-' in cve:
                                self.cve_database[cve] = {
                                    "cve": cve,
                                    "title": description,
                                    "type": row.get("type", ""),
                                    "platform": row.get("platform", ""),
                                    "exploit_available": True,
                                }
                    elif description:
                        # Store by description for service matching
                        key = f"EXPLOIT_{description[:50]}"
                        self.cve_database[key] = {
                            "cve": codes or "N/A",
                            "title": description,
                            "type": row.get("type", ""),
                            "platform": row.get("platform", ""),
                            "exploit_available": True,
                        }

            self.logger.info(f"Loaded {len(self.cve_database)} CVEs from searchsploit")

        except Exception as e:
            self.logger.debug(f"Failed to load searchsploit: {e}")

    def _load_json_database(self, json_file):
        """Load CVE database from JSON file."""
        try:
            data = self.fm.read_json(json_file)

            if isinstance(data, list):
                for cve in data:
                    self.cve_database[cve.get("cve", "")] = cve
            elif isinstance(data, dict):
                self.cve_database.update(data)

            self.logger.info(f"Loaded {len(data)} CVEs from JSON database")

        except Exception as e:
            self.logger.debug(f"Failed to load JSON database: {e}")

    def _load_wappalyzer(self):
        """Load Wappalyzer technology signatures if available."""
        wappalyzer_paths = [
            os.path.join(self.database_dir, 'wappalyzer', 'src', 'technologies'),
            os.path.join(self.database_dir, 'wappalyzer', 'technologies'),
            os.path.join('/opt/exploitdb', 'wappalyzer', 'src', 'technologies'),
        ]
        
        for wapp_dir in wappalyzer_paths:
            if os.path.isdir(wapp_dir):
                try:
                    self._parse_wappalyzer_technologies(wapp_dir)
                    self.logger.info(f"Loaded Wappalyzer technologies from: {wapp_dir}")
                    break
                except Exception as e:
                    self.logger.debug(f"Failed to load Wappalyzer from {wapp_dir}: {e}")
    
    def _parse_wappalyzer_technologies(self, tech_dir):
        """Parse Wappalyzer technology JSON files."""
        import glob
        
        for json_file in glob.glob(os.path.join(tech_dir, '*.json')):
            try:
                with open(json_file, 'r') as f:
                    tech_data = json.load(f)
                
                tech_name = os.path.splitext(os.path.basename(json_file))[0]
                
                self.cve_database[f"TECH_{tech_name}"] = {
                    'cve': f"TECH_{tech_name}",
                    'title': tech_name,
                    'type': 'technology_signature',
                    'platform': 'web',
                    'exploit_available': False,
                    'wappalyzer_data': tech_data
                }
            except Exception as e:
                self.logger.debug(f"Failed to parse {json_file}: {e}")

    def lookup_cve(self, cve_id):
        """
        Lookup a specific CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            dict: CVE information or None
        """
        return self.cve_database.get(cve_id.upper())

    def search_by_service(self, service_name, version=None):
        """
        Search CVEs by service name.

        Args:
            service_name: Service/product name
            version: Service version (optional)

        Returns:
            list: Matching CVEs
        """
        results = []
        service_lower = service_name.lower()

        for cve_id, cve_info in self.cve_database.items():
            title = cve_info.get("title", "").lower()

            if service_lower in title:
                if version and version not in title:
                    continue
                results.append(cve_info)

        return results

    def search_by_platform(self, platform):
        """
        Search CVEs by platform.

        Args:
            platform: Platform name

        Returns:
            list: Matching CVEs
        """
        results = []
        platform_lower = platform.lower()

        for cve_id, cve_info in self.cve_database.items():
            if platform_lower in cve_info.get("platform", "").lower():
                results.append(cve_info)

        return results

    def check_vulnerabilities(self, scan_results):
        """
        Check scan results against CVE database.

        Args:
            scan_results: Port scanner results

        Returns:
            dict: CVE lookup results
        """
        results = {
            "timestamp": datetime.now().isoformat(),
            "matched_cves": [],
            "summary": {},
        }

        for port_info in scan_results.get("ports", []):
            if port_info.get("state") == "open":
                product = port_info.get("product", "")
                version = port_info.get("version", "")

                if product:
                    cves = self.search_by_service(product, version)

                    for cve in cves:
                        results["matched_cves"].append(
                            {
                                "host": port_info.get("host"),
                                "port": port_info.get("port"),
                                "service": port_info.get("service"),
                                "product": product,
                                "version": version,
                                "cve": cve,
                            }
                        )

        results["summary"] = {
            "total_matches": len(results["matched_cves"]),
            "unique_cves": len(
                set(c["cve"].get("cve", "") for c in results["matched_cves"])
            ),
        }

        return results

    def export_database(self, output_format="json"):
        """Export loaded CVE database."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if output_format == "json":
            output_file = os.path.join(
                self.output_dir, f"cve_database_{timestamp}.json"
            )
            self.fm.write_json(output_file, self.cve_database)
        elif output_format == "csv":
            output_file = os.path.join(self.output_dir, f"cve_database_{timestamp}.csv")
            csv_data = list(self.cve_database.values())
            self.fm.write_csv(output_file, csv_data)
        else:
            raise ValueError(f"Unsupported format: {output_format}")

        return output_file
