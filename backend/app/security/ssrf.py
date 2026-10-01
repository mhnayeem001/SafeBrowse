import ipaddress
import socket
from typing import Tuple, Optional, List
from urllib.parse import urlparse
import httpx
from backend.app.config import settings

# Blocked IP ranges (Private, Loopback, Link-Local, Cloud Metadata, Multicast, Reserved)
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),       # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),         # Loopback IPv4
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local / AWS/GCP/Azure Metadata
    ipaddress.ip_network("172.16.0.0/12"),       # Private RFC 1918
    ipaddress.ip_network("192.0.0.0/24"),        # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),        # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),      # Private RFC 1918
    ipaddress.ip_network("198.18.0.0/15"),       # Network Benchmark
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),         # Multicast
    ipaddress.ip_network("240.0.0.0/4"),         # Reserved
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    # IPv6 ranges
    ipaddress.ip_network("::/128"),              # Unspecified
    ipaddress.ip_network("::1/128"),             # Loopback
    ipaddress.ip_network("::ffff:0:0/96"),       # IPv4-mapped IPv6
    ipaddress.ip_network("64:ff9b::/96"),        # IPv4/IPv6 translation
    ipaddress.ip_network("100::/64"),            # Discard prefix
    ipaddress.ip_network("2001:db8::/32"),       # Documentation
    ipaddress.ip_network("fc00::/7"),            # Unique Local (ULA)
    ipaddress.ip_network("fe80::/10"),           # Link-local IPv6
    ipaddress.ip_network("ff00::/8"),            # Multicast IPv6
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata.gcp.internal",
    "instance-data",
}

class SSRFSecurityError(Exception):
    """Raised when a URL is determined to be an SSRF hazard."""
    pass

def is_ip_blocked(ip_str: str) -> bool:
    """Check if an IP address string belongs to any blocked/private/internal subnet."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in BLOCKED_NETWORKS:
            if ip in net:
                return True
        return False
    except ValueError:
        return True

def resolve_and_validate_hostname(hostname: str) -> Tuple[bool, str, List[str]]:
    """
    Resolves hostname to IP addresses and checks every IP against the SSRF blacklist.
    Returns (is_safe, error_message, list_of_ips).
    """
    clean_host = hostname.strip().lower().rstrip(".")
    if clean_host in BLOCKED_HOSTNAMES:
        return False, f"Hostname '{clean_host}' is a forbidden internal host", []

    # Check if host is direct IP
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        if is_ip_blocked(str(ip_obj)):
            return False, f"Direct IP address {clean_host} is in a reserved/internal network", [str(ip_obj)]
        return True, "", [str(ip_obj)]
    except ValueError:
        pass

    try:
        # Resolve via standard DNS
        addr_info = socket.getaddrinfo(clean_host, None)
        resolved_ips = list({item[4][0] for item in addr_info})
        if not resolved_ips:
            return False, f"Hostname '{clean_host}' could not be resolved", []

        for ip in resolved_ips:
            if is_ip_blocked(ip):
                return False, f"Hostname '{clean_host}' resolves to forbidden internal IP: {ip}", resolved_ips

        return True, "", resolved_ips
    except socket.gaierror as e:
        return False, f"DNS resolution failed for '{clean_host}': {str(e)}", []
    except Exception as e:
        return False, f"Validation failed: {str(e)}", []

def validate_url_for_safe_fetch(url: str) -> Tuple[bool, str]:
    """
    Validates scheme and target IP to prevent SSRF before initiating any outbound HTTP call.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, f"Unsupported or unsafe scheme: '{parsed.scheme}'. Only HTTP/HTTPS allowed."

        hostname = parsed.hostname
        if not hostname:
            return False, "URL has no hostname"

        # Check port if explicitly specified
        if parsed.port and parsed.port not in (80, 443, 8080, 8443):
            return False, f"Port {parsed.port} is restricted for security reasons"

        is_safe, reason, _ = resolve_and_validate_hostname(hostname)
        if not is_safe:
            return False, reason

        return True, ""
    except Exception as e:
        return False, f"Invalid URL format: {str(e)}"

async def safe_fetch_head(url: str, timeout: float = 3.0) -> Optional[httpx.Response]:
    """
    Performs a safe HEAD request validating every redirect target against SSRF rules.
    """
    is_safe, reason = validate_url_for_safe_fetch(url)
    if not is_safe:
        raise SSRFSecurityError(reason)

    current_url = url
    redirect_count = 0

    async with httpx.AsyncClient(verify=True, follow_redirects=False, timeout=timeout) as client:
        while redirect_count <= settings.MAX_REDIRECTS:
            is_safe, reason = validate_url_for_safe_fetch(current_url)
            if not is_safe:
                raise SSRFSecurityError(f"Redirect target blocked: {reason}")

            response = await client.head(current_url)
            if response.is_redirect and "location" in response.headers:
                redirect_count += 1
                location = response.headers["location"]
                current_url = str(response.url.join(location))
            else:
                return response

        raise SSRFSecurityError(f"Exceeded max redirects ({settings.MAX_REDIRECTS})")
