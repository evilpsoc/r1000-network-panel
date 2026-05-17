import shlex
import re

from app.core.cache import cached_read
from app.domain.system.services import service_inventory

from .profiles import interface_profiles
from .state import network_snapshot, network_state_from_snapshot


PANEL_TABLE_PATTERNS = (
    r"service_lan",
    r"service_lan_nat",
    r"service_lan_nat_v4",
    r"service_lan_nat_v6",
    r"service_lan_block",
    r"wifi_hotspot_nat",
    r"portal_block_",
    r"network_panel",
)


def nft_tables(ruleset: str) -> list[dict[str, str]]:
    tables = []
    for family, name in re.findall(r"(?m)^table\s+(\S+)\s+(\S+)\s+\{", ruleset or ""):
        managed = any(re.search(pattern, name) for pattern in PANEL_TABLE_PATTERNS)
        tables.append({"family": family, "name": name, "managed_by_panel": managed})
    return tables


def nft_chains(ruleset: str) -> list[dict[str, str]]:
    chains = []
    current_table = ""
    current_family = ""
    for line in (ruleset or "").splitlines():
        table_match = re.match(r"table\s+(\S+)\s+(\S+)\s+\{", line.strip())
        if table_match:
            current_family, current_table = table_match.groups()
            continue
        chain_match = re.match(r"chain\s+(\S+)\s+\{", line.strip())
        if chain_match and current_table:
            chains.append({"family": current_family, "table": current_table, "name": chain_match.group(1)})
    return chains


def nat_summary(ruleset: str, iptables: str) -> dict[str, object]:
    nft_masquerade = [line.strip() for line in (ruleset or "").splitlines() if "masquerade" in line]
    iptables_masquerade = [line.strip() for line in (iptables or "").splitlines() if "MASQUERADE" in line]
    return {
        "nft_masquerade_rules": nft_masquerade,
        "iptables_masquerade_rules": iptables_masquerade,
        "has_nat": bool(nft_masquerade or iptables_masquerade),
        "legacy_iptables_present": bool(iptables_masquerade),
    }


def forwarding_state(commands: dict[str, object]) -> dict[str, object]:
    return {
        "ipv4": str(commands.get("ipv4_forward", {}).get("stdout", "")).strip() == "1",
        "ipv6": str(commands.get("ipv6_forward", {}).get("stdout", "")).strip() == "1",
    }


def nft_input_policies(ruleset: str) -> list[dict[str, str]]:
    policies: list[dict[str, str]] = []
    current_family = ""
    current_table = ""
    current_chain = ""
    in_chain = False
    depth = 0
    for raw_line in (ruleset or "").splitlines():
        line = raw_line.strip()
        table_match = re.match(r"table\s+(\S+)\s+(\S+)\s+\{", line)
        if table_match:
            current_family, current_table = table_match.groups()
            continue
        chain_match = re.match(r"chain\s+(\S+)\s+\{", line)
        if chain_match:
            current_chain = chain_match.group(1)
            in_chain = True
            depth = 1
            continue
        if in_chain and "hook input" in line:
            policy_match = re.search(r"\bpolicy\s+(\w+)", line)
            policies.append({
                "family": current_family,
                "table": current_table,
                "chain": current_chain,
                "policy": policy_match.group(1) if policy_match else "unknown",
            })
        if in_chain:
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                in_chain = False
                current_chain = ""
    return policies


def nft_ports_with_verdict(ruleset: str, verdict: str) -> set[int]:
    ports: set[int] = set()
    for line in (ruleset or "").splitlines():
        if verdict not in line:
            continue
        for match in re.findall(r"\b(?:tcp|udp)\s+dport\s+(\d+)\b", line):
            ports.add(int(match))
    return ports


def nft_docker_published_ports(ruleset: str) -> set[int]:
    ports: set[int] = set()
    in_docker_chain = False
    depth = 0
    for raw_line in (ruleset or "").splitlines():
        line = raw_line.strip()
        if re.match(r"chain\s+DOCKER\s+\{", line):
            in_docker_chain = True
            depth = 1
            continue
        if in_docker_chain:
            if " accept" in line:
                for match in re.findall(r"\b(?:tcp|udp)\s+dport\s+(\d+)\b", line):
                    ports.add(int(match))
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                in_docker_chain = False
    return ports


def firewall_reachability(service: dict[str, object], scopes: set[str], ruleset: str) -> dict[str, object]:
    ports = set(listener_port_numbers(service))
    input_policies = nft_input_policies(ruleset)
    accept_ports = nft_ports_with_verdict(ruleset, "accept")
    drop_ports = nft_ports_with_verdict(ruleset, "drop")
    docker_ports = nft_docker_published_ports(ruleset)
    has_accept_default = any(item.get("policy") == "accept" for item in input_policies)
    has_drop_default = any(item.get("policy") == "drop" for item in input_policies)
    matched_accept = sorted(ports & (accept_ports | docker_ports))
    matched_drop = sorted(ports & drop_ports)

    if scopes == {"loopback"}:
        status = "loopback_only"
        detail = "Bound only to loopback; external firewall exposure is not expected."
    elif matched_accept:
        status = "likely_reachable"
        detail = f"Firewall has accept/published-port rules for: {', '.join(map(str, matched_accept))}."
    elif has_accept_default:
        status = "likely_reachable"
        detail = "Input hook default policy is accept; bind scope controls reachability more than firewall rules."
    elif has_drop_default and matched_drop:
        status = "probably_blocked"
        detail = f"Drop policy/rules mention: {', '.join(map(str, matched_drop))}."
    elif has_drop_default:
        status = "unknown"
        detail = "Input hook default policy is drop, but no simple matching accept/drop verdict was found."
    else:
        status = "unknown"
        detail = "No input hook policy was detected in nftables output."

    return {
        "status": status,
        "detail": detail,
        "input_policies": input_policies,
        "matched_accept_ports": matched_accept,
        "matched_drop_ports": matched_drop,
        "docker_published": sorted(ports & docker_ports),
    }


def listener_port_numbers(service: dict[str, object]) -> list[int]:
    ports: list[int] = []
    for item in service.get("ports", []) or []:
        _, _, raw_port = str(item).partition("/")
        try:
            ports.append(int(raw_port))
        except ValueError:
            continue
    return sorted(set(ports))


def bind_scope(bind: str) -> str:
    value = str(bind or "").strip().lower()
    if value in {"", "*", "0.0.0.0", "::", "[::]"}:
        return "all_interfaces"
    if value in {"127.0.0.1", "::1", "localhost"}:
        return "loopback"
    if value.startswith("100."):
        return "overlay"
    if value.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "fd", "fe80:")):
        return "local"
    return "specific"


def service_exposure_risk(service: dict[str, object], scopes: set[str], reachability: dict[str, object]) -> tuple[str, str]:
    name = str(service.get("name", ""))
    ports = set(listener_port_numbers(service))
    sensitive_ports = {22, 139, 445, 3000, 9000, 9090, 9091, 9100, 9443}
    management_names = {"LocalPlane", "Cockpit", "Portainer", "Portainer HTTPS", "Grafana", "Prometheus", "Node Exporter", "SSH"}
    reachable = reachability.get("status") == "likely_reachable"
    if "all_interfaces" in scopes and reachable and (ports & sensitive_ports or name in management_names):
        return "high", "management or file/service port is bound on all interfaces"
    if "all_interfaces" in scopes and reachable:
        return "medium", "listener is reachable from every interface unless firewall policy blocks it"
    if "all_interfaces" in scopes:
        return "medium", "listener is broadly bound, but firewall reachability needs deeper chain evaluation"
    if "specific" in scopes:
        return "medium", "listener is bound to a specific non-loopback address"
    if "local" in scopes or "overlay" in scopes:
        return "low", "listener is scoped to local or tunnel addresses"
    return "info", "listener is loopback-only"


def exposure_summary(ruleset: str) -> dict[str, object]:
    services = [service for service in service_inventory() if service.get("ports")]
    exposed = []
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    reachability_counts: dict[str, int] = {}
    for service in services:
        binds = [str(item) for item in service.get("binds", []) or []]
        scopes = {bind_scope(bind) for bind in binds} or {"unknown"}
        reachability = firewall_reachability(service, scopes, ruleset)
        reachability_status = str(reachability.get("status", "unknown"))
        reachability_counts[reachability_status] = reachability_counts.get(reachability_status, 0) + 1
        risk, reason = service_exposure_risk(service, scopes, reachability)
        counts[risk] = counts.get(risk, 0) + 1
        exposed.append({
            "name": service.get("name", "Unknown"),
            "source": service.get("source", "system"),
            "ports": service.get("ports", []),
            "binds": binds,
            "scopes": sorted(scopes),
            "risk": risk,
            "reason": reason,
            "reachability": reachability,
        })
    risk_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    exposed.sort(key=lambda item: (risk_order.get(str(item.get("risk")), 9), str(item.get("name", ""))))
    return {
        "listeners": exposed,
        "counts": counts,
        "reachability_counts": reachability_counts,
        "input_policies": nft_input_policies(ruleset),
        "notes": [
            "Read-only exposure view based on listening sockets, bind addresses and simple nftables input/published-port analysis.",
            "This does not apply rules; deeper per-interface packet path simulation is still a future hardening step.",
        ],
    }


def desired_policy_from_profiles(profiles: dict[str, object]) -> dict[str, object]:
    interfaces = profiles.get("interfaces", [])
    def behavior(item: dict[str, object]) -> str:
        return str(
            item.get("effective_behavior")
            or item.get("effective_profile")
            or item.get("suggested_behavior")
            or item.get("suggested_profile")
            or ""
        )

    management = [item for item in interfaces if behavior(item) == "management_lan"]
    device_lan = [item for item in interfaces if behavior(item) == "device_lan"]
    uplinks = [
        item for item in interfaces
        if behavior(item) in {"uplink_ethernet", "uplink_wifi", "uplink_cellular"}
    ]
    hotspots = [
        item for item in interfaces
        if behavior(item) == "hotspot_wifi"
    ]
    management_tunnels = [
        item for item in interfaces
        if behavior(item) == "management_tunnel"
    ]
    behaviors = {
        "trusted_local_network": [item.get("interface") for item in management],
        "isolated_client_network": [item.get("interface") for item in device_lan],
        "uplinks": [item.get("interface") for item in uplinks],
        "wifi_hotspots": [item.get("interface") for item in hotspots],
        "management_tunnels": [item.get("interface") for item in management_tunnels],
    }
    return {
        "behaviors": behaviors,
        "roles": {
            "management_lan": [item.get("interface") for item in management],
            "device_lan": [item.get("interface") for item in device_lan],
            "uplinks": [item.get("interface") for item in uplinks],
            "hotspot_wifi": [item.get("interface") for item in hotspots],
            "management_tunnel": [item.get("interface") for item in management_tunnels],
        },
        "source": "effective behavior from runtime config when present, otherwise discovery suggestion",
        "routing": {
            "active_uplink": "default route device",
            "client_network_egress": "allow via active_uplink after explicit preview/apply",
            "trusted_local_access": "allow local admin services when explicitly configured",
            "management_tunnel_access": "allow local admin services when explicitly configured",
        },
        "firewall": {
            "provider": "nftables",
            "owned_table": "inet network_panel",
            "owned_nat_tables": ["ip network_panel_nat_v4", "ip6 network_panel_nat_v6"],
            "rule": "only manage tables/chains owned by LocalPlane",
        },
        "dns": {
            "source": "NetworkManager/systemd-resolved when available",
            "interface_policy": "per-interface DNS behavior, optional Pi-hole forwarding",
        },
    }


def policy_gaps(snapshot: dict[str, object], state: dict[str, object], profiles: dict[str, object]) -> list[dict[str, str]]:
    commands = snapshot.get("commands", {})
    ruleset = str(commands.get("nft_ruleset", {}).get("stdout", ""))
    tables = nft_tables(ruleset)
    nat = nat_summary(ruleset, str(commands.get("iptables_save", {}).get("stdout", "")))
    forwarding = forwarding_state(commands)
    gaps: list[dict[str, str]] = []

    if not commands.get("nft_ruleset", {}).get("ok"):
        gaps.append({
            "severity": "high",
            "title": "nftables snapshot unavailable",
            "detail": "Firewall/NAT cannot be safely reconciled without nftables visibility.",
        })
    elif not any(table["name"] == "network_panel" and table["family"] == "inet" for table in tables):
        gaps.append({
            "severity": "medium",
            "title": "Panel-owned nftables table missing",
            "detail": "Future apply should create inet network_panel and manage only owned chains.",
        })

    if nat["legacy_iptables_present"]:
        gaps.append({
            "severity": "medium",
            "title": "Legacy iptables NAT detected",
            "detail": "NAT may be split between iptables and nftables; migrate to a panel-owned nftables table before reconcile.",
        })

    desired = desired_policy_from_profiles(profiles)
    if desired["behaviors"]["isolated_client_network"] and not forwarding["ipv4"] and not forwarding["ipv6"]:
        gaps.append({
            "severity": "medium",
            "title": "Client network exists but forwarding is disabled",
            "detail": "Clients can be isolated locally, but internet egress needs explicit forwarding plus NAT policy.",
        })

    if not state.get("active_uplink"):
        gaps.append({
            "severity": "high",
            "title": "No active uplink route",
            "detail": "Routing policy cannot choose egress until a default route exists.",
        })

    if not desired["behaviors"]["isolated_client_network"]:
        gaps.append({
            "severity": "info",
            "title": "No isolated client network configured",
            "detail": "Discovery did not find a client-facing network yet; interface behavior should stay flexible.",
        })

    configured_warnings = [
        warning
        for item in profiles.get("interfaces", [])
        for warning in item.get("warnings", [])
        if isinstance(warning, str)
    ]
    for warning in configured_warnings:
        gaps.append({
            "severity": "medium",
            "title": "Configured profile warning",
            "detail": warning,
        })

    if not gaps:
        gaps.append({
            "severity": "info",
            "title": "No blocking read-only policy gaps",
            "detail": "Preview/apply can be designed on top of this observed state.",
        })
    return gaps


def route_firewall_policy() -> dict[str, object]:
    return cached_read("network_route_firewall_policy", 15, _route_firewall_policy_uncached)


def shell_join(command: list[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in command)


def add_command(commands: list[str], command: list[str]) -> None:
    commands.append(shell_join(command))


def preview_route_firewall_reconcile(payload: dict | None = None) -> dict[str, object]:
    policy = route_firewall_policy()
    current = policy.get("current", {})
    desired = policy.get("desired", {})
    behaviors = desired.get("behaviors", {})
    roles = desired.get("roles", {})
    active_uplink = str(current.get("active_uplink", "") or "")
    failover_order = [str(item) for item in current.get("failover_order", []) if item]
    device_lans = [str(item) for item in behaviors.get("isolated_client_network", roles.get("device_lan", [])) if item]
    management_lans = [str(item) for item in behaviors.get("trusted_local_network", roles.get("management_lan", [])) if item]
    commands: list[str] = []
    verify: list[str] = []
    rollback: list[str] = []
    warnings: list[str] = [
        "Preview only. These commands are not executed by this endpoint.",
        "Apply must create/delete only LocalPlane owned nftables tables.",
    ]

    add_command(commands, ["nft", "add", "table", "inet", "network_panel"])
    add_command(
        commands,
        ["nft", "add", "chain", "inet", "network_panel", "forward", "{", "type", "filter", "hook", "forward", "priority", "0", ";", "policy", "accept", ";", "}"],
    )
    add_command(
        commands,
        ["nft", "add", "rule", "inet", "network_panel", "forward", "ct", "state", "established,related", "accept"],
    )

    if device_lans and active_uplink:
        if failover_order:
            warnings.append(f"Current failover order is observed as: {', '.join(failover_order)}.")
        add_command(commands, ["sysctl", "-w", "net.ipv4.ip_forward=1"])
        add_command(commands, ["nft", "add", "table", "ip", "network_panel_nat_v4"])
        add_command(
            commands,
            ["nft", "add", "chain", "ip", "network_panel_nat_v4", "postrouting", "{", "type", "nat", "hook", "postrouting", "priority", "100", ";", "policy", "accept", ";", "}"],
        )
        for device_lan in device_lans:
            add_command(
                commands,
                ["nft", "add", "rule", "inet", "network_panel", "forward", "iifname", device_lan, "oifname", active_uplink, "accept"],
            )
            add_command(
                commands,
                ["nft", "add", "rule", "ip", "network_panel_nat_v4", "postrouting", "oifname", active_uplink, "counter", "masquerade"],
            )
    elif device_lans and not active_uplink:
        warnings.append("Client network exists, but no active uplink was detected; egress/NAT rules are not planned.")
    else:
        warnings.append("No client-facing network behavior is configured; egress/NAT rules are not planned.")

    for management_lan in management_lans:
        add_command(
            commands,
            ["nft", "add", "rule", "inet", "network_panel", "forward", "iifname", management_lan, "accept"],
        )

    add_command(verify, ["ip", "route", "show", "default"])
    add_command(verify, ["sysctl", "-n", "net.ipv4.ip_forward"])
    add_command(verify, ["nft", "list", "table", "inet", "network_panel"])
    add_command(verify, ["nft", "list", "table", "ip", "network_panel_nat_v4"])

    add_command(rollback, ["nft", "delete", "table", "inet", "network_panel"])
    add_command(rollback, ["nft", "delete", "table", "ip", "network_panel_nat_v4"])

    return {
        "ok": True,
        "mode": "preview_only",
        "commands": commands,
        "verify": verify,
        "rollback": rollback,
        "warnings": warnings,
        "policy_gaps": policy.get("gaps", []),
        "payload": payload or {},
    }


def _route_firewall_policy_uncached() -> dict[str, object]:
    snapshot = network_snapshot()
    state = network_state_from_snapshot(snapshot)
    profiles = interface_profiles()
    commands = snapshot.get("commands", {})
    ruleset = str(commands.get("nft_ruleset", {}).get("stdout", ""))
    iptables = str(commands.get("iptables_save", {}).get("stdout", ""))
    return {
        "current": {
            "active_uplink": state.get("active_uplink", ""),
            "uplink_candidates": state.get("uplink_candidates", []),
            "failover_order": state.get("failover_order", []),
            "failover_roles": state.get("failover_roles", []),
            "default_ipv4": snapshot.get("routes", {}).get("default_ipv4", {}),
            "default_ipv6": snapshot.get("routes", {}).get("default_ipv6", {}),
            "forwarding": forwarding_state(commands),
            "nft_tables": nft_tables(ruleset),
            "nft_chains": nft_chains(ruleset),
            "nat": nat_summary(ruleset, iptables),
            "exposure": exposure_summary(ruleset),
            "dns_provider_ok": state.get("dns_provider_ok", False),
            "network_manager_ok": state.get("network_manager_ok", False),
        },
        "desired": desired_policy_from_profiles(profiles),
        "gaps": policy_gaps(snapshot, state, profiles),
        "next_steps": [
            "Keep this model read-only until interface behavior assignment is explicit.",
            "Add preview commands for creating panel-owned nftables tables only.",
            "Add verify checks after every apply: default route, forwarding, NAT, DNS and client reachability.",
            "Add rollback by deleting only panel-owned tables/chains and restoring previous sysctl values.",
        ],
    }
