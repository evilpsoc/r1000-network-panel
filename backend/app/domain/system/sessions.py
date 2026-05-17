import re

from app.core.cache import cached_read
from app.core.host import run_command
from app.domain.network.state import current_interfaces


def known_port_names() -> dict[str, str]:
    return {
        "22": "SSH",
        "53": "DNS",
        "67": "DHCP",
        "80": "HTTP",
        "137": "NetBIOS",
        "138": "NetBIOS Datagram",
        "139": "Samba",
        "445": "Samba",
        "3000": "Grafana",
        "7575": "VirtualHere",
        "8080": "LocalPlane",
        "8081": "Pi-hole",
        "9000": "Portainer",
        "9090": "Cockpit",
        "9091": "Prometheus",
        "9100": "Node Exporter",
        "9443": "Portainer HTTPS",
        "20211": "NetAlertX",
        "41641": "Tailscale",
    }


def get_active_sessions() -> list[dict[str, str]]:
    return cached_read("active_sessions", 10, _get_active_sessions_uncached)


def _get_active_sessions_uncached() -> list[dict[str, str]]:
    output = run_command(["ss", "-H", "-tnp", "state", "established"])
    if not output:
        return []

    interfaces = current_interfaces()
    ip_to_interface = {}
    for iface in interfaces:
        for addr in iface.get("ipv4", []):
            ip_to_interface[addr] = iface["name"]
        for addr in iface.get("ipv6", []):
            ip_to_interface[addr] = iface["name"]

    port_names = known_port_names()
    sessions = []
    seen: set[tuple[str, str, str, str]] = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[2]
        peer = parts[3]
        process = " ".join(parts[4:]) if len(parts) > 4 else ""
        local_host, _, local_port = local.rpartition(":")
        peer_host, _, peer_port = peer.rpartition(":")
        local_host = local_host.strip("[]")
        peer_host = peer_host.strip("[]")
        if local_host.startswith("127.") or local_host == "::1":
            continue
        entry = port_names.get(local_port, f"Port {local_port}")
        if local_port not in port_names:
            continue
        process_match = re.search(r'"([^"]+)"', process)
        session = {
            "interface": ip_to_interface.get(local_host, "unknown"),
            "local_address": local_host,
            "local_port": local_port,
            "peer_address": peer_host,
            "peer_port": peer_port,
            "service": entry,
            "entry": entry,
            "process": process_match.group(1) if process_match else "",
            "family": "ipv6" if ":" in local_host else "ipv4",
        }
        key = (
            session["entry"],
            session["interface"],
            session["peer_address"],
            session["family"],
        )
        if key in seen:
            continue
        seen.add(key)
        sessions.append(session)
    sessions.sort(key=lambda item: (item["entry"], item["interface"], item["peer_address"], item["local_port"]))
    return sessions
