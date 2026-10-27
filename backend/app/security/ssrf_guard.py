import ipaddress
import socket
import urllib.parse
from typing import Tuple, Optional


class SSRFBlockedException(Exception):
    def __init__(self, message: str, ip: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.ip = ip


# Additional IP networks to block beyond standard is_private / is_loopback
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),         # Current network (only valid as source address)
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-grade NAT (RFC 6598)
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved for future use (Class E)
    ipaddress.ip_network("255.255.255.255/32"),# Limited Broadcast
    ipaddress.ip_network("::/128"),            # Unspecified IPv6
    ipaddress.ip_network("::ffff:0:0/96"),     # IPv4-mapped IPv6 (must check embedded IPv4)
    ipaddress.ip_network("100::/64"),          # Discard-Only Address Block
    ipaddress.ip_network("2001:db8::/32"),     # Documentation IPv6
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "127.0.0.1",
    "::1",
    "metadata.google.internal",
    "169.254.169.254",
}


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    if ip.is_loopback:
        return True, f"Loopback IP ({ip}) is blocked"
    if ip.is_private:
        return True, f"Private RFC 1918/RFC 4193 IP ({ip}) is blocked"
    if ip.is_link_local:
        return True, f"Link-local IP ({ip}) is blocked"
    if ip.is_multicast:
        return True, f"Multicast IP ({ip}) is blocked"
    if ip.is_reserved:
        return True, f"Reserved IP ({ip}) is blocked"
    if ip.is_unspecified:
        return True, f"Unspecified IP ({ip}) is blocked"

    # Check for IPv4-mapped IPv6
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return is_ip_blocked(ip.ipv4_mapped)

    for net in BLOCKED_NETWORKS:
        if ip in net:
            return True, f"IP ({ip}) belongs to blocked network ({net})"

    return False, ""


def validate_url_for_ssrf(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        raise SSRFBlockedException("URL has no valid hostname", ip=None)

    hostname_lower = hostname.lower().strip(".")

    if hostname_lower in BLOCKED_HOSTNAMES:
        raise SSRFBlockedException(f"Explicitly blocked hostname: {hostname}", ip=None)

    if hostname_lower.endswith(".localhost") or hostname_lower.endswith(".local") or hostname_lower.endswith(".internal"):
        raise SSRFBlockedException(f"Internal domain name pattern blocked: {hostname}", ip=None)

    # If hostname is already an IP literal
    try:
        literal_ip = ipaddress.ip_address(hostname_lower)
        blocked, reason = is_ip_blocked(literal_ip)
        if blocked:
            raise SSRFBlockedException(reason, ip=str(literal_ip))
        return
    except ValueError:
        # Not a raw IP literal, proceed to DNS resolution
        pass

    # Resolve hostname via DNS
    try:
        addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise SSRFBlockedException(f"DNS resolution failed for hostname '{hostname}': {e}", ip=None)
    except Exception as e:
        raise SSRFBlockedException(f"Failed resolving hostname '{hostname}': {e}", ip=None)

    if not addr_info:
        raise SSRFBlockedException(f"No IP addresses resolved for hostname '{hostname}'", ip=None)

    for item in addr_info:
        sockaddr = item[4]
        ip_str = sockaddr[0]
        try:
            resolved_ip = ipaddress.ip_address(ip_str)
            blocked, reason = is_ip_blocked(resolved_ip)
            if blocked:
                raise SSRFBlockedException(f"Hostname '{hostname}' resolved to prohibited IP {ip_str}: {reason}", ip=ip_str)
        except ValueError:
            raise SSRFBlockedException(f"Unparseable resolved IP address: {ip_str}", ip=ip_str)
