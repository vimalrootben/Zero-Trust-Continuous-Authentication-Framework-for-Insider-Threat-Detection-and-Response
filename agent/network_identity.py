"""Network identity detection for ZTA Agent endpoints."""

import os
import platform
import socket
from typing import Any, Dict, List, Tuple


def get_all_interfaces() -> List[Dict[str, Any]]:
    """Discovers all local network adapters and addresses."""
    interfaces: List[Dict[str, Any]] = []
    hostname = platform.node()

    try:
        # Resolve address info for local hostname
        addr_info = socket.getaddrinfo(hostname, None)
        seen_ips = set()
        for item in addr_info:
            family, _, _, _, sockaddr = item
            ip = sockaddr[0]
            if ip in seen_ips:
                continue
            seen_ips.add(ip)

            is_ipv6 = family == socket.AF_INET6
            is_loopback = ip.startswith("127.") or ip == "::1"

            interfaces.append({
                "name": "Localhost" if is_loopback else ("IPv6 Adapter" if is_ipv6 else "Primary Adapter"),
                "ip": ip,
                "family": "IPv6" if is_ipv6 else "IPv4",
                "is_loopback": is_loopback,
                "state": "UP",
            })
    except Exception:
        pass

    if not interfaces:
        interfaces.append({
            "name": "Loopback",
            "ip": "127.0.0.1",
            "family": "IPv4",
            "is_loopback": True,
            "state": "UP",
        })

    return interfaces


def get_active_network_identity(manager_url: str = "") -> Dict[str, Any]:
    """Determines the exact active IP, primary interface, and route on this endpoint."""
    hostname = platform.node()
    interfaces = get_all_interfaces()

    primary_ipv4 = None
    primary_ipv6 = None
    active_interface_name = "Primary Adapter"

    # Use UDP connect probe to discover OS routing table's chosen local source IP
    probe_host = "1.1.1.1"
    if manager_url:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(manager_url)
            if parsed.hostname and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
                probe_host = parsed.hostname
        except Exception:
            pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((probe_host, 80))
        sock_ip = s.getsockname()[0]
        s.close()
        if sock_ip and not sock_ip.startswith("127."):
            primary_ipv4 = sock_ip
    except Exception:
        pass

    # If socket probe didn't find non-loopback, search discovered interfaces
    if not primary_ipv4:
        for iface in interfaces:
            if iface["family"] == "IPv4" and not iface["is_loopback"]:
                primary_ipv4 = iface["ip"]
                active_interface_name = iface["name"]
                break

    for iface in interfaces:
        if iface["family"] == "IPv6" and not iface["is_loopback"]:
            primary_ipv6 = iface["ip"]
            break

    if not primary_ipv4:
        primary_ipv4 = "127.0.0.1"
        active_interface_name = "Loopback"

    return {
        "hostname": hostname,
        "local_ipv4": primary_ipv4,
        "local_ipv6": primary_ipv6,
        "active_interface": f"{active_interface_name} ({primary_ipv4})",
        "interface_name": active_interface_name,
        "ip": primary_ipv4,
        "interfaces": interfaces,
    }
