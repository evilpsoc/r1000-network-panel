import socket
import time

from app.core.host import read_text
from app.providers import docker_detect, firewall_detect, iproute2, networkmanager, resolvectl, tailscale
from app.providers.common import candidate_command, provider_command, run


UPLINK_ROLES = {"ethernet", "wifi", "cellular", "overlay"}
UPLINK_PRIORITY = {
    "ethernet": 0,
    "wifi": 1,
    "cellular": 2,
    "overlay": 3,
}
DEFAULT_CONNECTIVITY_TARGETS = {
    "ipv4": "1.1.1.1",
    "ipv6": "2606:4700:4700::1111",
}
_COUNTER_RATE_SAMPLES: dict[str, dict[str, float]] = {}
_COUNTER_RATE_VALUES: dict[str, dict[str, float]] = {}


def interface_role(name: str) -> str:
    if name == "lo":
        return "loopback"
    if name.startswith("wwan"):
        return "cellular"
    if name.startswith("wl"):
        return "wifi"
    if name.startswith("tailscale"):
        return "overlay"
    if name.startswith(("docker", "br-", "veth")):
        return "container"
    if name.startswith(("en", "eth")):
        return "ethernet"
    return "other"


def default_route(routes: list[dict[str, object]]) -> dict[str, object]:
    for route in routes:
        if route.get("dst") == "default" or route.get("dst") is None:
            return route
    return {}


def interface_counters() -> dict[str, dict[str, int]]:
    raw = read_text("/host/proc/net/dev") or read_text("/proc/net/dev")
    counters: dict[str, dict[str, int]] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        name, values = line.split(":", 1)
        fields = values.split()
        if len(fields) < 16:
            continue
        counters[name.strip()] = {
            "rx_bytes": int(fields[0]),
            "rx_packets": int(fields[1]),
            "rx_errors": int(fields[2]),
            "rx_dropped": int(fields[3]),
            "tx_bytes": int(fields[8]),
            "tx_packets": int(fields[9]),
            "tx_errors": int(fields[10]),
            "tx_dropped": int(fields[11]),
        }
    return counters


def interface_counter_rates(name: str, counters: dict[str, int], now: float) -> dict[str, float]:
    previous = _COUNTER_RATE_SAMPLES.get(name)
    if not previous:
        _COUNTER_RATE_SAMPLES[name] = {
            "rx_bytes": float(counters.get("rx_bytes", 0)),
            "tx_bytes": float(counters.get("tx_bytes", 0)),
            "at": now,
        }
        rates = {"rx_bytes_per_sec": 0.0, "tx_bytes_per_sec": 0.0, "sample_seconds": 0.0}
        _COUNTER_RATE_VALUES[name] = rates
        return rates

    elapsed = max(now - previous.get("at", now), 0.0)
    if elapsed < 0.5:
        return _COUNTER_RATE_VALUES.get(
            name,
            {"rx_bytes_per_sec": 0.0, "tx_bytes_per_sec": 0.0, "sample_seconds": elapsed},
        )

    rx = float(counters.get("rx_bytes", 0))
    tx = float(counters.get("tx_bytes", 0))
    rx_rate = max(0.0, rx - previous.get("rx_bytes", rx)) / elapsed
    tx_rate = max(0.0, tx - previous.get("tx_bytes", tx)) / elapsed
    rates = {
        "rx_bytes_per_sec": rx_rate,
        "tx_bytes_per_sec": tx_rate,
        "sample_seconds": elapsed,
    }
    _COUNTER_RATE_SAMPLES[name] = {"rx_bytes": rx, "tx_bytes": tx, "at": now}
    _COUNTER_RATE_VALUES[name] = rates
    return rates


def normalize_interfaces(addr: list[dict[str, object]], links: list[dict[str, object]]) -> list[dict[str, object]]:
    link_by_index = {item.get("ifindex"): item for item in links}
    counters = interface_counters()
    now = time.time()
    interfaces: list[dict[str, object]] = []
    for iface in addr:
        name = str(iface.get("ifname", ""))
        if not name or name.startswith(("veth", "br-")) or name == "docker0":
            continue
        link = link_by_index.get(iface.get("ifindex"), {})
        ipv4: list[str] = []
        ipv6: list[str] = []
        for address in iface.get("addr_info", []):
            if address.get("family") == "inet":
                ipv4.append(str(address.get("local", "")))
            if address.get("family") == "inet6":
                ipv6.append(str(address.get("local", "")))
        state = iface.get("operstate") or link.get("operstate") or "UNKNOWN"
        if state == "UNKNOWN" and (ipv4 or ipv6):
            state = "UP"
        role = interface_role(name)
        iface_counters = dict(counters.get(name, {}))
        iface_counters.update(interface_counter_rates(name, iface_counters, now))
        interfaces.append(
            {
                "name": name,
                "role": role,
                "state": state,
                "mac": iface.get("address") or link.get("address") or "",
                "mtu": iface.get("mtu") or link.get("mtu"),
                "ipv4": [item for item in ipv4 if item],
                "ipv6": [item for item in ipv6 if item],
                "flags": iface.get("flags", []),
                "physical": role in {"ethernet", "wifi", "cellular"},
                "counters": iface_counters,
            }
        )
    return interfaces


def mark_default_route_interfaces(interfaces: list[dict[str, object]], routes_v4: list[dict[str, object]], routes_v6: list[dict[str, object]]) -> list[dict[str, object]]:
    default_devices = {
        str(route.get("dev"))
        for route in [default_route(routes_v4), default_route(routes_v6)]
        if route.get("dev")
    }
    for iface in interfaces:
        iface["default_route"] = str(iface.get("name", "")) in default_devices
    return interfaces


def command_unavailable(message: str) -> dict[str, object]:
    return {"ok": False, "stdout": "", "stderr": message, "command": [], "duration_ms": 0}


def network_snapshot() -> dict[str, object]:
    addr = iproute2.addresses()
    links = iproute2.links()
    routes_v4 = iproute2.routes(4)
    routes_v6 = iproute2.routes(6)
    interfaces = mark_default_route_interfaces(normalize_interfaces(addr, links), routes_v4, routes_v6)
    commands = {
        "ip_rule": iproute2.rules(),
        "resolvectl": resolvectl.status(),
        "nmcli_devices": networkmanager.device_status(),
        "nmcli_active": networkmanager.active_connections(),
        "ipv4_forward": provider_command("sysctl", ["-n", "net.ipv4.ip_forward"], "sysctl not available"),
        "ipv6_forward": provider_command("sysctl", ["-n", "net.ipv6.conf.all.forwarding"], "sysctl not available"),
        "nft_ruleset": firewall_detect.nft_ruleset(),
        "iptables_save": firewall_detect.iptables_save(),
        "docker_networks": docker_detect.networks(),
        "tailscale_status": tailscale.status(),
    }
    return {
        "generated_at": time.time(),
        "hostname": socket.gethostname(),
        "interfaces": interfaces,
        "routes": {
            "ipv4": routes_v4,
            "ipv6": routes_v6,
            "default_ipv4": default_route(routes_v4),
            "default_ipv6": default_route(routes_v6),
        },
        "commands": commands,
    }


def current_interfaces() -> list[dict[str, object]]:
    return mark_default_route_interfaces(
        normalize_interfaces(iproute2.addresses(), iproute2.links()),
        iproute2.routes(4),
        iproute2.routes(6),
    )


def network_state_from_snapshot(snapshot: dict[str, object]) -> dict[str, object]:
    interfaces = snapshot.get("interfaces", [])
    routes = snapshot.get("routes", {})
    default_v4 = routes.get("default_ipv4", {})
    default_v6 = routes.get("default_ipv6", {})
    active_uplink = default_v4.get("dev") or default_v6.get("dev") or ""
    route_metrics: dict[str, int] = {}
    for route in list(routes.get("ipv4", []) or []) + list(routes.get("ipv6", []) or []):
        dev = str(route.get("dev", "") or "")
        if not dev:
            continue
        metric = route.get("metric", 0)
        try:
            metric_value = int(metric)
        except (TypeError, ValueError):
            metric_value = 0
        current = route_metrics.get(dev)
        if current is None or metric_value < current:
            route_metrics[dev] = metric_value

    candidates = []
    for iface in interfaces:
        role = iface.get("role")
        if role not in UPLINK_ROLES:
            continue
        has_ip = bool(iface.get("ipv4") or iface.get("ipv6"))
        is_default = iface.get("name") == active_uplink
        state_up = str(iface.get("state", "")).upper() == "UP"
        score = 0
        if state_up:
            score += 30
        if has_ip:
            score += 30
        if is_default:
            score += 30
        if role in {"ethernet", "wifi", "cellular"}:
            score += max(0, 12 - (UPLINK_PRIORITY.get(str(role), 9) * 3))
        if role == "overlay":
            score += 5
        candidates.append(
            {
                "interface": iface.get("name"),
                "role": role,
                "state": iface.get("state"),
                "has_ip": has_ip,
                "default_route": is_default,
                "route_metric": route_metrics.get(str(iface.get("name", ""))),
                "link_ready": state_up and has_ip,
                "counters": iface.get("counters", {}),
                "score": score,
            }
        )
    candidates = sorted(
        candidates,
        key=lambda item: (
            not bool(item["default_route"]),
            not bool(item["link_ready"]),
            UPLINK_PRIORITY.get(str(item["role"]), 9),
            item["route_metric"] if item["route_metric"] is not None else 9999,
            str(item["interface"]),
        ),
    )
    failover_candidates = [
        item for item in candidates
        if item.get("role") in {"ethernet", "wifi", "cellular"} and item.get("link_ready")
    ]
    commands = snapshot.get("commands", {})
    return {
        "active_uplink": active_uplink,
        "default_ipv4": default_v4,
        "default_ipv6": default_v6,
        "uplink_candidates": candidates,
        "failover_order": [item.get("interface") for item in failover_candidates],
        "failover_roles": [item.get("role") for item in failover_candidates],
        "ipv4_forwarding": commands.get("ipv4_forward", {}).get("stdout", ""),
        "ipv6_forwarding": commands.get("ipv6_forward", {}).get("stdout", ""),
        "dns_provider_ok": bool(commands.get("resolvectl", {}).get("ok")),
        "firewall_provider": "nftables" if commands.get("nft_ruleset", {}).get("ok") else ("iptables" if commands.get("iptables_save", {}).get("ok") else "unknown"),
        "network_manager_ok": bool(commands.get("nmcli_devices", {}).get("ok")),
    }


def network_state() -> dict[str, object]:
    return network_state_from_snapshot(network_snapshot())


def has_global_ipv6(addresses: list[str]) -> bool:
    for address in addresses:
        value = address.split("/", 1)[0].lower()
        if value and not value.startswith("fe80:"):
            return True
    return False


def ping_interface(interface: str, family: int, target: str) -> dict[str, object]:
    command = candidate_command("ping", [f"-{family}", "-I", interface, "-c", "1", "-W", "2", target])
    if not command:
        return {
            "ok": False,
            "returncode": 127,
            "stdout": "",
            "stderr": "ping provider not available",
            "command": [],
            "timed_out": False,
            "duration_ms": 0,
        }
    return run(command)


def connectivity_test(payload: dict[str, object] | None = None) -> dict[str, object]:
    payload = payload or {}
    snapshot = network_snapshot()
    state = network_state_from_snapshot(snapshot)
    requested = {str(item) for item in payload.get("interfaces", []) if str(item).strip()}
    targets = dict(DEFAULT_CONNECTIVITY_TARGETS)
    payload_targets = payload.get("targets", {})
    if isinstance(payload_targets, dict):
        for key in ("ipv4", "ipv6"):
            value = str(payload_targets.get(key, "")).strip()
            if value:
                targets[key] = value

    results: list[dict[str, object]] = []
    for iface in snapshot.get("interfaces", []):
        name = str(iface.get("name", ""))
        role = str(iface.get("role", ""))
        if not name:
            continue
        if requested and name not in requested:
            continue
        if not requested and role not in UPLINK_ROLES:
            continue

        checks: list[dict[str, object]] = []
        ipv4 = [str(item) for item in iface.get("ipv4", []) if str(item)]
        ipv6 = [str(item) for item in iface.get("ipv6", []) if str(item)]
        if ipv4:
            probe = ping_interface(name, 4, targets["ipv4"])
            checks.append({"family": "ipv4", "target": targets["ipv4"], **probe})
        if has_global_ipv6(ipv6):
            probe = ping_interface(name, 6, targets["ipv6"])
            checks.append({"family": "ipv6", "target": targets["ipv6"], **probe})
        if not checks:
            checks.append({
                "family": "none",
                "target": "",
                "ok": False,
                "returncode": 0,
                "stdout": "",
                "stderr": "interface has no testable global IP address",
                "command": [],
                "timed_out": False,
                "duration_ms": 0,
            })
        results.append({
            "interface": name,
            "role": role,
            "state": iface.get("state", ""),
            "ipv4": ipv4,
            "ipv6": ipv6,
            "checks": checks,
            "ok": any(check.get("ok") for check in checks),
        })

    return {
        "generated_at": time.time(),
        "active_uplink": state.get("active_uplink", ""),
        "targets": targets,
        "results": results,
    }
