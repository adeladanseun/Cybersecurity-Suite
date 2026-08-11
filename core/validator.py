"""
Input validation utilities for CyberSecurity Suite.
Handles IP addresses, domains, URLs, ports, and target classification.
"""

import ipaddress
import re
import os
import json
from urllib.parse import urlparse
from core.exceptions import ValidationError


def is_valid_ip(ip):
    """Check if string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_ipv4(ip):
    """Check if string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_ipv6(ip):
    """Check if string is a valid IPv6 address."""
    try:
        ipaddress.IPv6Address(ip)
        return True
    except (ValueError, TypeError):
        return False


def is_private_ip(ip):
    """Check if IP address is private/internal."""
    try:
        return ipaddress.ip_address(ip).is_private
    except (ValueError, TypeError):
        return False


def is_public_ip(ip):
    """Check if IP address is public/external."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)
    except (ValueError, TypeError):
        return False


def is_valid_cidr(cidr):
    """Check if string is a valid CIDR notation (e.g., 192.168.1.0/24)."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True and '/' in cidr
    except (ValueError, TypeError):
        return False


def is_valid_ip_range(ip_range):
    """Check if string is a valid IP range (e.g., 192.168.1.1-192.168.1.254)."""
    if not ip_range or '-' not in ip_range:
        return False
    
    parts = ip_range.split('-')
    if len(parts) != 2:
        return False
    
    start_ip = parts[0].strip()
    end_ip = parts[1].strip()
    
    return is_valid_ip(start_ip) and is_valid_ip(end_ip)


def is_valid_domain(domain):
    """Check if string is a valid domain name."""
    if not domain or len(domain) > 253:
        return False
    
    # Domain regex pattern
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    
    # Allow wildcard domains
    if domain.startswith('*.'):
        domain = domain[2:]
    
    return re.match(pattern, domain) is not None


def is_valid_url(url):
    """Check if string is a valid URL."""
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except (ValueError, TypeError):
        return False


def is_valid_hostname(hostname):
    """Check if string is a valid hostname."""
    if not hostname or len(hostname) > 255:
        return False
    
    # Allow single-label hostnames for internal networks
    if '.' not in hostname:
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        return re.match(pattern, hostname) is not None
    
    return is_valid_domain(hostname)


def is_valid_port(port):
    """Check if port number is valid (1-65535)."""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def is_valid_port_range(port_range):
    """Check if port range is valid (e.g., '80-443' or '80,443,8080')."""
    if not port_range:
        return False
    
    # Handle comma-separated list
    if ',' in port_range:
        ports = port_range.split(',')
        return all(is_valid_port(p.strip()) for p in ports)
    
    # Handle range
    if '-' in port_range:
        parts = port_range.split('-')
        if len(parts) != 2:
            return False
        start = parts[0].strip()
        end = parts[1].strip()
        return is_valid_port(start) and is_valid_port(end) and int(start) <= int(end)
    
    return is_valid_port(port_range)


def classify_target(target):
    """
    Classify a target string into its type.
    
    Returns:
        str: 'ipv4', 'ipv6', 'cidr', 'domain', 'url', 'ip_range', or 'unknown'
    """
    if not target or not isinstance(target, str):
        return 'unknown'
    
    target = target.strip()
    
    if is_valid_url(target):
        return 'url'
    elif is_valid_cidr(target):
        return 'cidr'
    elif is_valid_ip_range(target):
        return 'ip_range'
    elif is_valid_ipv4(target):
        return 'ipv4'
    elif is_valid_ipv6(target):
        return 'ipv6'
    elif is_valid_domain(target):
        return 'domain'
    elif is_valid_hostname(target):
        return 'hostname'
    else:
        return 'unknown'


def get_target_type(target):
    """
    Get detailed classification of a target.
    
    Returns:
        dict: {
            'type': str,
            'is_internal': bool,
            'is_external': bool,
            'is_web_target': bool,
            'is_network_target': bool
        }
    """
    target_type = classify_target(target)
    
    result = {
        'type': target_type,
        'is_internal': False,
        'is_external': False,
        'is_web_target': False,
        'is_network_target': False,
        'original': target
    }
    
    # Determine internal/external
    if target_type in ['ipv4', 'ipv6']:
        if is_private_ip(target):
            result['is_internal'] = True
        elif is_public_ip(target):
            result['is_external'] = True
        result['is_network_target'] = True
        
    elif target_type == 'cidr':
        try:
            network = ipaddress.ip_network(target, strict=False)
            if network.is_private:
                result['is_internal'] = True
            else:
                result['is_external'] = True
        except ValueError:
            pass
        result['is_network_target'] = True
        
    elif target_type == 'url':
        result['is_web_target'] = True
        # Extract hostname/IP from URL
        parsed = urlparse(target)
        host = parsed.hostname
        if host:
            if is_valid_ip(host):
                if is_private_ip(host):
                    result['is_internal'] = True
                else:
                    result['is_external'] = True
            else:
                result['is_external'] = True  # Assume external for domains
    
    elif target_type in ['domain', 'hostname']:
        result['is_external'] = True  # Domains assumed external by default
        result['is_web_target'] = True
    
    return result


def is_valid_file(filepath):
    """Check if file exists and is readable."""
    if not filepath:
        return False
    return os.path.isfile(filepath) and os.access(filepath, os.R_OK)


def is_valid_json(filepath):
    """Check if file contains valid JSON."""
    if not is_valid_file(filepath):
        return False
    
    try:
        with open(filepath, 'r') as f:
            json.load(f)
        return True
    except (json.JSONDecodeError, IOError):
        return False