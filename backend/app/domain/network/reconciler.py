from __future__ import annotations

import ipaddress
import shlex
from typing import Any

from app.core.cache import cached_read

from .policy import desired_policy_from_profiles, forwarding_state, nft_tables
from .profiles import interface_profiles
from .state import network_snapshot, network_state_from_snapshot


PANEL_TABLE = "network_panel"
PANEL_NAT_V4 = "network_panel_nat_v4"
PANEL_NAT_V6 = "network_panel_nat_v6"


def shell_join(command: list[object]) -> str:
    return " ".join(shlex.quote(str(part)) for part in command)


def _command(command: list[object], reason: str, risk: str = "medium") -> dict[str, str]:
    return {
        "command": shell_join(command),
        "reason": reason,
        "risk": risk,
    }


def _role_items(profiles: dict[str, Any], role: str) -> list[dict[str, Any]]:
    return [
        item
        for item in profiles.get("interfaces", []) or []
        if (item.get("effective_profile") or item.get("suggested_profile")) == role
    ]


def _prefix_to_source(prefix: str) -> str:
    try:
        return str(ipaddress.ip_network(prefix, strict=False))
    except ValueError:
        return prefix


def _default_ipv4_prefix(item: dict[str, Any], fallback: str) -> str:
    policy = item.get("configured_policy", {}) if isinstance(item.get("configured_policy", {}), dict) else {}
    for key in ("ipv4_subnet", "ipv4", "addressing"):
        raw = str(policy.get(key, "")).strip()
        if "/" in raw:
            return _prefix_to_source(raw)
    for address in item.get("ipv4", []) or []:
        raw = str(address)
        if raw:
            return _prefix_to_source(raw)
    return fallback


def _default_ipv6_prefix(item: dict[str, Any], fallback: str) -> str:
    policy = item.get("configured_policy", {}) if isinstance(item.get("configured_policy", {}), dict) else {}
    for key in ("ipv6_prefix", "ipv6", "addressing"):
        raw = str(policy.get(key, "")).strip()
        if ":" in raw and "/" in raw:
            return _prefix_to_source(raw)
    for address in item.get("ipv6", []) or []:
        raw = str(address)
        if ":" in raw and not raw.lower().startswith("fe80:"):
            return _prefix_to_source(raw)
    return fallback


def _rule_table_present(tables: list[dict[str, str]], family: str, name: str) -> bool:
    return any(table.get("family") == family and table.get("name") == name for table in tables)


def _plan_firewall_tables(tables: list[dict[str, str]]) -> list[dict[str, str]]:
    commands: list[dict[str, str]] = []
    if not _rule_table_present(tables, "inet", PANEL_TABLE):
        commands.append(_command(["nft", "add", "table", "inet", PANEL_TABLE], "Create panel-owned filter table."))
        commands.append(_command(
            ["nft", "add", "chain", "inet", PANEL_TABLE, "forward", "{", "type", "filter", "hook", "forward", "priority", "0", ";", "policy", "accept", ";", "}"],
            "Create panel-owned forward chain.",
        ))
        commands.append(_command(
            ["nft", "add", "rule", "inet", PANEL_TABLE, "forward", "ct", "state", "established,related", "accept"],
            "Allow return traffic through the panel chain.",
        ))
    if not _rule_table_present(tables, "ip", PANEL_NAT_V4):
        commands.append(_command(["nft", "add", "table", "ip", PANEL_NAT_V4], "Create panel-owned IPv4 NAT table."))
        commands.append(_command(
            ["nft", "add", "chain", "ip", PANEL_NAT_V4, "postrouting", "{", "type", "nat", "hook", "postrouting", "priority", "100", ";", "policy", "accept", ";", "}"],
            "Create panel-owned IPv4 postrouting chain.",
        ))
    if not _rule_table_present(tables, "ip6", PANEL_NAT_V6):
        commands.append(_command(["nft", "add", "table", "ip6", PANEL_NAT_V6], "Create panel-owned IPv6 NAT table.", "high"))
        commands.append(_command(
            ["nft", "add", "chain", "ip6", PANEL_NAT_V6, "postrouting", "{", "type", "nat", "hook", "postrouting", "priority", "100", ";", "policy", "accept", ";", "}"],
            "Create panel-owned IPv6 postrouting chain.",
            "high",
        ))
    return commands


def _plan_device_lan_egress(device_lans: list[dict[str, Any]], active_uplink: str) -> list[dict[str, str]]:
    commands: list[dict[str, str]] = []
    if not active_uplink:
        return commands
    for item in device_lans:
        interface = str(item.get("interface", "") or "")
        if not interface:
            continue
        ipv4_prefix = _default_ipv4_prefix(item, "192.0.2.0/24")
        ipv6_prefix = _default_ipv6_prefix(item, "fd00:10::/64")
        commands.append(_command(
            ["nft", "add", "rule", "inet", PANEL_TABLE, "forward", "iifname", interface, "oifname", active_uplink, "accept"],
            f"Allow Device LAN {interface} to egress through active uplink {active_uplink}.",
        ))
        commands.append(_command(
            ["nft", "add", "rule", "ip", PANEL_NAT_V4, "postrouting", "oifname", active_uplink, "ip", "saddr", ipv4_prefix, "counter", "masquerade"],
            f"Masquerade IPv4 traffic from {interface}.",
        ))
        commands.append(_command(
            ["nft", "add", "rule", "ip6", PANEL_NAT_V6, "postrouting", "oifname", active_uplink, "ip6", "saddr", ipv6_prefix, "counter", "masquerade"],
            f"Masquerade IPv6 traffic from {interface}. Prefer routed IPv6 later when upstream prefix delegation exists.",
            "high",
        ))
    return commands


def _plan_management_lan(management_lans: list[dict[str, Any]]) -> list[dict[str, str]]:
    commands: list[dict[str, str]] = []
    for item in management_lans:
        interface = str(item.get("interface", "") or "")
        if not interface:
            continue
        commands.append(_command(
            ["nft", "add", "rule", "inet", PANEL_TABLE, "forward", "iifname", interface, "accept"],
            f"Allow Management LAN {interface} forwarding according to trusted role behavior.",
            "medium",
        ))
    return commands


def _verify_commands(active_uplink: str, device_lans: list[dict[str, Any]]) -> list[str]:
    verify = [
        "ip route show default",
        "sysctl -n net.ipv4.ip_forward",
        "sysctl -n net.ipv6.conf.all.forwarding",
        f"nft list table inet {PANEL_TABLE}",
        f"nft list table ip {PANEL_NAT_V4}",
        f"nft list table ip6 {PANEL_NAT_V6}",
    ]
    if active_uplink:
        verify.append(f"ip link show dev {shlex.quote(active_uplink)}")
    for item in device_lans:
        interface = str(item.get("interface", "") or "")
        if interface:
            verify.append(f"ip addr show dev {shlex.quote(interface)}")
    return verify


def _rollback_commands() -> list[str]:
    return [
        f"nft delete table inet {PANEL_TABLE}",
        f"nft delete table ip {PANEL_NAT_V4}",
        f"nft delete table ip6 {PANEL_NAT_V6}",
    ]


def network_reconcile_plan(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    snapshot = network_snapshot()
    state = network_state_from_snapshot(snapshot)
    profiles = interface_profiles()
    desired = desired_policy_from_profiles(profiles)
    commands = snapshot.get("commands", {}) if isinstance(snapshot.get("commands", {}), dict) else {}
    ruleset = str(commands.get("nft_ruleset", {}).get("stdout", ""))
    tables = nft_tables(ruleset)
    active_uplink = str(state.get("active_uplink", "") or "")
    device_lans = _role_items(profiles, "device_lan")
    management_lans = _role_items(profiles, "management_lan")
    forwarding = forwarding_state(commands)

    plan_commands: list[dict[str, str]] = []
    warnings = [
        "Preview only. This endpoint does not execute host changes.",
        "This is the replacement path for legacy service-lan helper scripts.",
        "Apply must backup current runtime config, NetworkManager profiles and panel-owned nftables tables first.",
    ]

    if not commands.get("nft_ruleset", {}).get("ok"):
        warnings.append("nftables is not readable; firewall/NAT apply must stay disabled.")
    else:
        plan_commands.extend(_plan_firewall_tables(tables))

    if device_lans and not active_uplink:
        warnings.append("Device LAN exists but no active uplink was detected; egress rules are not planned.")
    if device_lans and active_uplink:
        if not forwarding.get("ipv4"):
            plan_commands.append(_command(["sysctl", "-w", "net.ipv4.ip_forward=1"], "Enable IPv4 forwarding for Device LAN egress.", "high"))
        if not forwarding.get("ipv6"):
            plan_commands.append(_command(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], "Enable IPv6 forwarding for Device LAN egress.", "high"))
        plan_commands.extend(_plan_device_lan_egress(device_lans, active_uplink))
    if management_lans:
        plan_commands.extend(_plan_management_lan(management_lans))

    if not device_lans:
        warnings.append("No Device LAN role is assigned. Add a role binding before planning client egress.")

    return {
        "ok": True,
        "mode": "preview_only",
        "generated_from": "observed_state_and_effective_roles",
        "payload": payload,
        "current": {
            "active_uplink": active_uplink,
            "forwarding": forwarding,
            "nft_tables": tables,
        },
        "desired": desired,
        "plan": {
            "commands": plan_commands,
            "verify": _verify_commands(active_uplink, device_lans),
            "rollback": _rollback_commands(),
            "warnings": warnings,
        },
        "legacy_replacement": {
            "old_helpers": [
                "backend/scripts/service-lan-inet-on.sh",
                "backend/scripts/service-lan-inet-off.sh",
                "backend/scripts/service-lan-ra.py",
            ],
            "target": "NetworkManager + dnsmasq/radvd + panel-owned nftables reconciler",
        },
    }


def cached_network_reconcile_plan(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    if payload:
        return network_reconcile_plan(payload)
    return cached_read("network_reconcile_plan", 15, lambda: network_reconcile_plan({}))
