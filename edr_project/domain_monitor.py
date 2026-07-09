"""
domain_monitor.py
-------------------
Extends network monitoring to show WHICH WEBSITES are being visited,
not just raw IP connections - by reverse-DNS-resolving the remote IPs
that browser processes are connected to.

Each resolved domain is then classified:
    - High risk   -> matches a known-malicious domain (local signature list)
    - Low risk    -> matches a small built-in list of well-known, trusted domains
    - Medium risk -> anything else (unrecognized domain - not necessarily
                      dangerous, just "not yet known to be safe")

This is an educational heuristic, not a real threat-intelligence feed.
Reverse DNS only reveals the *hostname serving that IP*, which for
CDN-hosted content may not always match what a human would call "the
website" (e.g. some subresource domains) - a known simplification.
"""

import ipaddress
import socket
import time
import psutil

BROWSER_PROCESS_NAMES = {
    "chrome.exe", "chrome", "msedge.exe", "msedge", "firefox.exe", "firefox",
    "brave.exe", "brave", "opera.exe", "opera",
}

# A small allow-list of well-known, broadly trusted domains -> Low risk.
# Extend this as needed; it's intentionally small for an educational project.
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
    "wikipedia.org", "github.com", "githubusercontent.com", "microsoft.com", "live.com",
    "office.com", "amazon.com", "amazonaws.com", "apple.com", "icloud.com",
    "cloudflare.com", "akamai.net", "akamaized.net", "facebook.com", "fbcdn.net",
    "instagram.com", "twitter.com", "x.com", "linkedin.com", "wordpress.com",
    "mozilla.org", "bing.com", "yahoo.com", "netflix.com", "spotify.com",
    "anthropic.com", "claude.ai", "1e100.net", "googlevideo.com",
}

# RFC 6052 well-known NAT64 prefix - some networks/DNS64 setups route IPv4
# traffic to browsers over a synthesized IPv6 address in this range. The
# real IPv4 address is embedded in the last 32 bits, so we extract it and
# reverse-DNS that instead (IPv4 PTR records are far more commonly set).
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")


def _extract_nat64_ipv4(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr in _NAT64_PREFIX:
        # last 32 bits of the IPv6 address are the embedded IPv4 address
        packed = addr.packed[-4:]
        return str(ipaddress.IPv4Address(packed))
    return None

# Cache IP -> resolved hostname (or None if it failed) so we don't re-resolve
# the same IP every poll tick - reverse DNS can be slow.
_dns_cache = {}
_dns_cache_max_age = 600  # seconds
_dns_cache_time = {}


def _reverse_dns(ip, timeout=1.2):
    now = time.time()
    if ip in _dns_cache and (now - _dns_cache_time.get(ip, 0)) < _dns_cache_max_age:
        return _dns_cache[ip]

    # If this is a NAT64-synthesized address, resolve the embedded IPv4
    # address instead - it's much more likely to have a PTR record.
    lookup_ip = _extract_nat64_ipv4(ip) or ip

    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        hostname, _, _ = socket.gethostbyaddr(lookup_ip)
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        hostname = None
    finally:
        socket.setdefaulttimeout(old_timeout)

    _dns_cache[ip] = hostname
    _dns_cache_time[ip] = now
    return hostname


def _root_domain(hostname):
    """Reduce 'cdn.static.example.co.in' style hostnames to a comparable root
    ('example.co.in') well enough for matching against TRUSTED_DOMAINS - this
    is a simple heuristic (last two labels), not a full public-suffix-list
    implementation."""
    if not hostname:
        return None
    parts = hostname.strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def classify_domain(hostname):
    """Returns (risk_level, reason)."""
    if not hostname:
        return "Medium", "No reverse-DNS record for this IP (common for CDN/cloud-hosted services)"

    root = _root_domain(hostname)

    import database
    known = database.is_known_malicious_domain(hostname) or database.is_known_malicious_domain(root)
    if known:
        return "High", f"Matches known-malicious domain signature ({known})"

    if root in TRUSTED_DOMAINS:
        return "Low", "Recognized trusted domain"

    return "Medium", "Unrecognized domain - not on the trusted list"


def snapshot():
    """
    Look at active outbound connections belonging to known browser
    processes, resolve their remote IPs to hostnames, and return a list
    of {pid, process_name, domain, ip} for each unique resolved site.
    """
    results = []
    seen_domains_this_tick = set()

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        connections = []

    for conn in connections:
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr or not conn.pid:
            continue

        try:
            proc = psutil.Process(conn.pid)
            pname = proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        if pname.lower() not in BROWSER_PROCESS_NAMES:
            continue

        ip = conn.raddr.ip
        hostname = _reverse_dns(ip)
        domain_key = hostname or ip

        dedupe_key = (conn.pid, domain_key)
        if dedupe_key in seen_domains_this_tick:
            continue
        seen_domains_this_tick.add(dedupe_key)

        results.append({
            "pid": conn.pid,
            "process_name": pname,
            "domain": domain_key,
            "ip": ip,
        })

    return results