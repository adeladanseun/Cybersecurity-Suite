"""
DNS Enumerator - Main DNS enumeration logic
Performs comprehensive DNS record gathering
"""

import os
import sys
import socket
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.file_manager import FileManager
from core.validator import is_valid_domain, is_valid_ip, classify_target
from core.logger import get_logger, log_scan_start, log_scan_complete
from core.notifier import Notifier
from core.exceptions import ScanError, ValidationError

# Try importing dnspython
try:
    import dns.resolver
    import dns.reversename
    import dns.zone
    import dns.query
    import dns.exception
    import dns.rdatatype

    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False
    print("Warning: dnspython not installed. Install with: pip install dnspython")


class DNSEnumerator:
    """Comprehensive DNS enumeration tool."""

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "SRV"]

    def __init__(self, config=None, output_dir=None):
        """
        Initialize DNS enumerator.

        Args:
            config: Config object (optional)
            output_dir: Output directory
        """
        if not DNSPYTHON_AVAILABLE:
            raise ImportError("dnspython is required for DNS enumeration")

        self.config = config
        self.logger = get_logger("dns_enum")
        self.notifier = Notifier()
        self.fm = FileManager()

        # Set output directory
        if output_dir:
            self.output_dir = output_dir
        elif config:
            self.output_dir = config.get("paths.data_dir", "./data") + "/intermediate"
        else:
            self.output_dir = "./data/intermediate"

        self.fm.ensure_dir(self.output_dir)

        # Default DNS servers
        self.dns_servers = []
        self._load_default_dns_servers()

    def _load_default_dns_servers(self):
        """Load system default DNS servers."""
        try:
            resolver = dns.resolver.Resolver()
            self.dns_servers = resolver.nameservers
        except Exception:
            self.dns_servers = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]

    def enumerate(self, domain, record_types=None, dns_servers=None):
        """
        Enumerate DNS records for a domain.

        Args:
            domain: Domain to enumerate
            record_types: List of record types to query
            dns_servers: Custom DNS servers to use

        Returns:
            dict: DNS enumeration results
        """
        if not is_valid_domain(domain) and not is_valid_ip(domain):
            raise ValidationError(
                f"Invalid domain: {domain}", field="domain", value=domain
            )

        if record_types is None:
            record_types = self.RECORD_TYPES

        # Set custom DNS servers if provided
        custom_resolver = None
        if dns_servers:
            custom_resolver = dns.resolver.Resolver()
            custom_resolver.nameservers = dns_servers

        self.logger.info(f"Starting DNS enumeration for: {domain}")
        log_scan_start(self.logger, domain, "dns_enumeration")

        start_time = datetime.now()

        results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "dns_servers_used": dns_servers or self.dns_servers,
            "records": {},
            "summary": {},
        }

        # Use ThreadPoolExecutor for parallel record queries
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_type = {
                executor.submit(
                    self._query_record, domain, rtype, custom_resolver
                ): rtype
                for rtype in record_types
            }

            for future in as_completed(future_to_type):
                rtype = future_to_type[future]
                try:
                    records = future.result()
                    if records:
                        results["records"][rtype] = records
                except Exception as e:
                    self.logger.debug(f"Error querying {rtype} records: {e}")

        # Generate summary
        results["summary"] = self._generate_summary(results)

        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = self.fm.safe_filename(domain)
        output_file = os.path.join(
            self.output_dir, f"dns_{safe_domain}_{timestamp}.json"
        )
        self.fm.write_json(output_file, results)
        results["output_file"] = output_file

        duration = (datetime.now() - start_time).total_seconds()
        log_scan_complete(self.logger, domain, "dns_enumeration", duration)
        self.notifier.beep_complete()

        return results

    def _query_record(self, domain, record_type, resolver=None):
        """Query a specific DNS record type."""
        try:
            if resolver:
                answers = resolver.resolve(domain, record_type)
            else:
                answers = dns.resolver.resolve(domain, record_type)

            records = []
            for answer in answers:
                record_data = {
                    "type": record_type,
                    "value": str(answer),
                    "ttl": answer.ttl if hasattr(answer, "ttl") else None,
                }

                # Add type-specific data
                if record_type == "MX":
                    record_data["preference"] = answer.preference
                    record_data["exchange"] = str(answer.exchange)
                elif record_type == "SOA":
                    record_data["mname"] = str(answer.mname)
                    record_data["rname"] = str(answer.rname)
                    record_data["serial"] = answer.serial
                elif record_type == "SRV":
                    record_data["priority"] = answer.priority
                    record_data["weight"] = answer.weight
                    record_data["port"] = answer.port
                    record_data["target"] = str(answer.target)

                records.append(record_data)

            return records

        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            self.logger.debug(f"Domain {domain} does not exist")
            return []
        except dns.exception.Timeout:
            self.logger.warning(f"Timeout querying {record_type} for {domain}")
            return []
        except Exception as e:
            self.logger.debug(f"Error querying {record_type}: {e}")
            return []

    def reverse_lookup(self, ip):
        """
        Perform reverse DNS lookup.

        Args:
            ip: IP address to lookup

        Returns:
            dict: Reverse lookup results
        """
        if not is_valid_ip(ip):
            raise ValidationError(f"Invalid IP: {ip}", field="ip", value=ip)

        self.logger.info(f"Performing reverse lookup for: {ip}")

        try:
            reverse_name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(reverse_name, "PTR")

            results = {
                "ip": ip,
                "hostnames": [str(answer) for answer in answers],
                "timestamp": datetime.now().isoformat(),
            }

            return results

        except dns.resolver.NXDOMAIN:
            return {"ip": ip, "hostnames": [], "timestamp": datetime.now().isoformat()}
        except Exception as e:
            self.logger.error(f"Reverse lookup failed for {ip}: {e}")
            return {"ip": ip, "hostnames": [], "error": str(e)}

    def get_mail_servers(self, domain):
        """Get mail servers for a domain."""
        self.logger.info(f"Getting mail servers for: {domain}")

        try:
            mx_records = dns.resolver.resolve(domain, "MX")

            mail_servers = []
            for mx in sorted(mx_records, key=lambda x: x.preference):
                mail_servers.append(
                    {
                        "preference": mx.preference,
                        "server": str(mx.exchange).rstrip("."),
                    }
                )

            return mail_servers

        except Exception as e:
            self.logger.error(f"Failed to get mail servers: {e}")
            return []

    def get_name_servers(self, domain):
        """Get name servers for a domain."""
        self.logger.info(f"Getting name servers for: {domain}")

        try:
            ns_records = dns.resolver.resolve(domain, "NS")

            name_servers = []
            for ns in ns_records:
                name_servers.append(str(ns).rstrip("."))

            return name_servers

        except Exception as e:
            self.logger.error(f"Failed to get name servers: {e}")
            return []

    def check_dnssec(self, domain):
        """Check if DNSSEC is enabled for a domain."""
        self.logger.info(f"Checking DNSSEC for: {domain}")

        try:
            # Query for DNSKEY records
            dnskey_records = dns.resolver.resolve(domain, "DNSKEY")
            ds_records = dns.resolver.resolve(domain, "DS")

            return {
                "enabled": True,
                "dnskey_count": len(dnskey_records),
                "ds_count": len(ds_records),
            }

        except dns.resolver.NoAnswer:
            return {"enabled": False, "reason": "No DNSSEC records found"}
        except Exception as e:
            return {"enabled": False, "reason": str(e)}

    def get_txt_records(self, domain):
        """Get all TXT records for a domain."""
        self.logger.info(f"Getting TXT records for: {domain}")

        try:
            txt_records = dns.resolver.resolve(domain, "TXT")

            records = []
            for txt in txt_records:
                records.append("".join(txt.strings))

            return records

        except Exception as e:
            self.logger.error(f"Failed to get TXT records: {e}")
            return []

    def _generate_summary(self, results):
        """Generate summary statistics from enumeration results."""
        summary = {
            "total_record_types": len(results["records"]),
            "total_records": sum(
                len(records) for records in results["records"].values()
            ),
            "record_types_found": list(results["records"].keys()),
            "has_mx": "MX" in results["records"],
            "has_ns": "NS" in results["records"],
            "has_txt": "TXT" in results["records"],
        }

        return summary

    def enumerate_multiple(self, domains, **kwargs):
        """
        Enumerate multiple domains.

        Args:
            domains: List of domains
            **kwargs: Arguments for enumerate()

        Returns:
            list: Results for each domain
        """
        results = []
        total = len(domains)

        for i, domain in enumerate(domains, 1):
            self.logger.info(f"Enumerating domain {i}/{total}: {domain}")
            try:
                result = self.enumerate(domain, **kwargs)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Failed to enumerate {domain}: {e}")
                results.append({"domain": domain, "error": str(e), "status": "failed"})

        return results
