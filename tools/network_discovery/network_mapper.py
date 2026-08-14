"""
Network Mapper - Creates network topology maps
Visualizes discovered networks
"""

import os
import sys
import json
import ipaddress
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.file_manager import FileManager
from core.logger import get_logger
from core.notifier import Notifier


class NetworkMapper:
    """Creates network topology information."""

    def __init__(self, output_dir=None):
        """Initialize network mapper."""
        self.logger = get_logger("network_mapper")
        self.notifier = Notifier()
        self.fm = FileManager()

        self.output_dir = output_dir or "./data/intermediate"
        self.fm.ensure_dir(self.output_dir)

    def create_network_map(self, discovery_results):
        """
        Create network map from discovery results.

        Args:
            discovery_results: Results from NetworkDiscovery

        Returns:
            dict: Network map structure
        """
        self.logger.info("Creating network map...")

        network_map = {
            "generated_at": datetime.now().isoformat(),
            "network": discovery_results.get("network"),
            "subnets": [],
            "hosts": {},
            "relationships": [],
            "summary": {},
        }

        # Group hosts by subnet
        hosts = discovery_results.get("hosts", [])

        for host in hosts:
            if host.get("status") != "up":
                continue

            ip = host.get("ip")
            if not ip:
                continue

            # Determine subnet
            subnet = self._determine_subnet(ip, discovery_results.get("network"))

            if subnet not in network_map["subnets"]:
                network_map["subnets"].append(subnet)

            # Add host
            host_data = {
                "ip": ip,
                "mac": host.get("mac"),
                "hostname": host.get("hostname"),
                "vendor": host.get("vendor"),
                "discovery_method": host.get("discovery_method"),
                "status": "up",
            }

            network_map["hosts"][ip] = host_data

        # Create relationships (hosts in same subnet)
        for subnet in network_map["subnets"]:
            subnet_hosts = [
                ip
                for ip, host in network_map["hosts"].items()
                if self._determine_subnet(ip, discovery_results.get("network"))
                == subnet
            ]

            # Connect first host to others (star topology representation)
            if len(subnet_hosts) > 1:
                gateway = subnet_hosts[0]
                for host in subnet_hosts[1:]:
                    network_map["relationships"].append(
                        {"from": gateway, "to": host, "type": "same_subnet"}
                    )

        # Summary
        network_map["summary"] = {
            "total_subnets": len(network_map["subnets"]),
            "total_hosts": len(network_map["hosts"]),
            "total_relationships": len(network_map["relationships"]),
            "hosts_per_subnet": {},
        }

        for subnet in network_map["subnets"]:
            count = sum(
                1
                for ip in network_map["hosts"]
                if self._determine_subnet(ip, discovery_results.get("network"))
                == subnet
            )
            network_map["summary"]["hosts_per_subnet"][subnet] = count

        return network_map

    def _determine_subnet(self, ip, network_range):
        """Determine subnet for an IP."""
        try:
            ip_obj = ipaddress.IPv4Address(ip)

            if "/" in str(network_range):
                # CIDR notation
                network = ipaddress.IPv4Network(network_range, strict=False)
                if ip_obj in network:
                    return str(network)

            # Default /24 subnet
            return f"{ip_obj.packed[0]}.{ip_obj.packed[1]}.{ip_obj.packed[2]}.0/24"

        except Exception:
            return "unknown"

    def export_network_map(self, network_map, format="json"):
        """
        Export network map in various formats.

        Args:
            network_map: Network map structure
            format: 'json', 'txt', 'csv', 'html'

        Returns:
            str: Path to exported file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = self.fm.safe_filename(network_map.get("network", "network"))

        if format == "json":
            output_file = os.path.join(
                self.output_dir, f"network_map_{safe_name}_{timestamp}.json"
            )
            self.fm.write_json(output_file, network_map)

        elif format == "txt":
            output_file = os.path.join(
                self.output_dir, f"network_map_{safe_name}_{timestamp}.txt"
            )
            content = self._format_as_text(network_map)
            self.fm.write_file(output_file, content)

        elif format == "csv":
            output_file = os.path.join(
                self.output_dir, f"network_map_{safe_name}_{timestamp}.csv"
            )
            csv_data = []
            for ip, host in network_map["hosts"].items():
                csv_data.append(
                    {
                        "IP": ip,
                        "MAC": host.get("mac", ""),
                        "Hostname": host.get("hostname", ""),
                        "Vendor": host.get("vendor", ""),
                        "Subnet": self._determine_subnet(
                            ip, network_map.get("network")
                        ),
                    }
                )
            self.fm.write_csv(output_file, csv_data)

        elif format == "html":
            output_file = os.path.join(
                self.output_dir, f"network_map_{safe_name}_{timestamp}.html"
            )
            content = self._format_as_html(network_map)
            self.fm.write_file(output_file, content)

        else:
            raise ValueError(f"Unsupported format: {format}")

        return output_file

    def _format_as_text(self, network_map):
        """Format network map as text."""
        lines = []
        lines.append("=" * 60)
        lines.append("NETWORK MAP")
        lines.append("=" * 60)
        lines.append(f"Network: {network_map.get('network', 'N/A')}")
        lines.append(f"Generated: {network_map.get('generated_at')}")
        lines.append("")

        for subnet in network_map["subnets"]:
            lines.append(f"SUBNET: {subnet}")
            lines.append("-" * 40)

            for ip, host in network_map["hosts"].items():
                if self._determine_subnet(ip, network_map.get("network")) == subnet:
                    hostname = host.get("hostname") or "N/A"
                    mac = host.get("mac") or "N/A"
                    vendor = host.get("vendor") or "N/A"
                    lines.append(f"  {ip:15} {hostname:25} {mac:17} {vendor}")

            lines.append("")

        lines.append("=" * 60)
        lines.append(
            f"Summary: {network_map['summary']['total_hosts']} hosts in "
            f"{network_map['summary']['total_subnets']} subnet(s)"
        )

        return "\n".join(lines)

    def _format_as_html(self, network_map):
        """Format network map as HTML."""
        html = f"""<!DOCTYPE html>
        <html>
        <head>
            <title>Network Map</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th {{ background: #1a1a2e; color: white; padding: 10px; text-align: left; }}
                td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
                .subnet {{ margin: 20px 0; padding: 15px; background: #f5f5f5; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>Network Map</h1>
            <p>Network: {network_map.get("network", "N/A")}</p>
            <p>Generated: {network_map.get("generated_at")}</p>
        """ 

        for subnet in network_map["subnets"]:
            html += f"""
    <div class="subnet">
        <h3>Subnet: {subnet}</h3>
        <table>
            <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>MAC Address</th>
                <th>Vendor</th>
            </tr>"""

            for ip, host in network_map["hosts"].items():
                if self._determine_subnet(ip, network_map.get("network")) == subnet:
                    html += f"""
            <tr>
                <td>{ip}</td>
                <td>{host.get('hostname', 'N/A')}</td>
                <td>{host.get('mac', 'N/A')}</td>
                <td>{host.get('vendor', 'N/A')}</td>
            </tr>"""

            html += """
        </table>
    </div>"""

        html += """
</body>
</html>"""

        return html

    def find_gateway(self, hosts):
        """
        Attempt to identify network gateway.

        Args:
            hosts: List of discovered hosts

        Returns:
            str: Gateway IP or None
        """
        try:
            # Read route table
            with open("/proc/net/route", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        destination = parts[1]
                        gateway = parts[2]

                        # Gateway is usually 00000000 for default route
                        if destination == "00000000":
                            # Convert hex to IP
                            gw_hex = gateway
                            gw_bytes = bytes.fromhex(gw_hex)[::-1]
                            gw_ip = ".".join(str(b) for b in gw_bytes)
                            return gw_ip

        except Exception as e:
            self.logger.debug(f"Failed to find gateway: {e}")

        # Fallback: assume first host ending in .1
        for host in hosts:
            ip = host.get("ip", "")
            if ip.endswith(".1") or ip.endswith(".254"):
                return ip

        return None
