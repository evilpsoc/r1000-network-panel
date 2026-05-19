from __future__ import annotations

import shlex
from typing import Any

from .interface_configs import interface_rules_preview


def _string(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    return str(value).strip()


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _shell_join(command: list[object]) -> str:
    return " ".join(shlex.quote(str(part)) for part in command)


def _step(
    *,
    rule: dict[str, Any],
    provider: str,
    action: str,
    summary: str,
    risk: str = "medium",
    command_preview: list[object] | None = None,
    details: dict[str, Any] | None = None,
    verify: list[str] | None = None,
    rollback: list[str] | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": f"{provider}:{action}:{_string(rule.get('interface'), 'unknown')}",
        "provider": provider,
        "action": action,
        "interface": _string(rule.get("interface")),
        "risk": risk,
        "summary": summary,
        "rule": rule,
        "apply_enabled": False,
        "preview_only": True,
    }
    if command_preview:
        item["command_preview"] = _shell_join(command_preview)
    if details:
        item["details"] = details
    if verify:
        item["verify"] = verify
    if rollback:
        item["rollback"] = rollback
    return item


def _addressing_steps(rule: dict[str, Any]) -> list[dict[str, Any]]:
    interface = _string(rule.get("interface"))
    mode = _string(rule.get("mode"), "preserve_existing")
    family = "IPv6" if rule.get("type") == "addressing.ipv6" else "IPv4"
    if mode in {"disabled", "ignore"}:
        method = "disabled"
    elif mode in {"shared", "routed", "manual", "static"}:
        method = "manual" if mode != "shared" else "shared"
    elif mode in {"auto", "dhcp"}:
        method = "auto"
    else:
        method = mode or "preserve"

    nm_setting = "ipv6.method" if family == "IPv6" else "ipv4.method"
    command = ["nmcli", "connection", "modify", "<profile-for-interface>", nm_setting, method]
    if rule.get("address"):
        command.extend(["+ipv6.addresses" if family == "IPv6" else "+ipv4.addresses", rule.get("address")])

    steps = [
        _step(
            rule=rule,
            provider="networkmanager",
            action=f"set_{family.lower()}_method",
            summary=f"Plan {family} {mode} behavior for {interface}.",
            risk="high" if mode in {"disabled", "shared"} else "medium",
            command_preview=command,
            details={
                "mode": mode,
                "address": rule.get("address", ""),
                "subnet": rule.get("subnet", ""),
                "prefix": rule.get("prefix", ""),
                "dhcp_range": rule.get("dhcp_range", ""),
            },
            verify=[
                f"nmcli -g GENERAL.STATE device show {shlex.quote(interface)}",
                f"ip addr show dev {shlex.quote(interface)}",
            ],
            rollback=[
                "Restore the saved NetworkManager connection profile for this interface.",
                f"nmcli connection reload && nmcli device reapply {shlex.quote(interface)}",
            ],
        )
    ]
    if mode == "shared" and rule.get("dhcp_range"):
        steps.append(_step(
            rule=rule,
            provider="dhcp",
            action="plan_client_range",
            summary=f"Reserve DHCP service planning for {interface}.",
            risk="medium",
            details={"range": rule.get("dhcp_range")},
            verify=[f"Check DHCP lease allocation on {interface} after apply."],
            rollback=["Restore previous DHCP service config snapshot."],
        ))
    return steps


def _dns_steps(rule: dict[str, Any]) -> list[dict[str, Any]]:
    interface = _string(rule.get("interface"))
    mode = _string(rule.get("mode"), "preserve_existing")
    servers = _string(rule.get("servers"))
    command = ["nmcli", "connection", "modify", "<profile-for-interface>", "ipv4.ignore-auto-dns", "yes"]
    if servers:
        command.extend(["ipv4.dns", servers])
    return [
        _step(
            rule=rule,
            provider="dns",
            action="set_dns_policy",
            summary=f"Plan DNS mode {mode} for {interface}.",
            risk="medium",
            command_preview=command,
            details={"mode": mode, "servers": servers, "search": _string(rule.get("search"))},
            verify=[
                f"resolvectl dns {shlex.quote(interface)}",
                f"resolvectl domain {shlex.quote(interface)}",
            ],
            rollback=["Restore the saved DNS section of the NetworkManager profile."],
        )
    ]


def _uplink_steps(rule: dict[str, Any]) -> list[dict[str, Any]]:
    interface = _string(rule.get("interface"))
    priority = rule.get("priority")
    metric = 100 if priority in {"", None} else max(10, min(900, int(priority) if str(priority).isdigit() else 100))
    return [
        _step(
            rule=rule,
            provider="routing",
            action="register_uplink_candidate",
            summary=f"Register {interface} as a candidate internet uplink.",
            risk="medium",
            command_preview=["nmcli", "connection", "modify", "<profile-for-interface>", "ipv4.route-metric", metric],
            details={
                "priority": priority,
                "route_metric_preview": metric,
                "requires_probe": True,
                "failover_safe_apply_required": True,
            },
            verify=[
                "ip route show default",
                f"ip route get 1.1.1.1 oif {shlex.quote(interface)}",
            ],
            rollback=[
                "Restore previous route metrics from the saved NetworkManager profile.",
                "Run connectivity probes before allowing failback.",
            ],
        )
    ]


def _link_steps(rule: dict[str, Any]) -> list[dict[str, Any]]:
    interface = _string(rule.get("interface"))
    if _string(rule.get("type")) == "link.mtu":
        mtu = _string(rule.get("mtu"))
        return [
            _step(
                rule=rule,
                provider="networkmanager",
                action="set_interface_mtu",
                summary=f"Plan MTU {mtu or 'default'} for {interface}.",
                risk="medium",
                command_preview=["nmcli", "connection", "modify", "<profile-for-interface>", "802-3-ethernet.mtu", mtu],
                details={
                    "mtu": mtu,
                    "note": "Wi-Fi and modem MTU support varies by driver/provider; provider apply must validate capabilities first.",
                },
                verify=[
                    f"ip link show dev {shlex.quote(interface)}",
                    f"nmcli -g 802-3-ethernet.mtu connection show <profile-for-interface>",
                ],
                rollback=["Restore the previous MTU from the saved connection profile."],
            )
        ]

    enabled = _string(rule.get("enabled"), "preserve_existing")
    return [
        _step(
            rule=rule,
            provider="networkmanager",
            action="set_autoconnect",
            summary=f"Plan autoconnect={enabled} for {interface}.",
            risk="medium",
            command_preview=["nmcli", "connection", "modify", "<profile-for-interface>", "connection.autoconnect", "yes" if enabled in {"yes", "true", "on", "enabled"} else "no"],
            details={"autoconnect": enabled},
            verify=[f"nmcli -g connection.autoconnect connection show <profile-for-interface>"],
            rollback=["Restore the previous autoconnect value from the saved connection profile."],
        )
    ]


def _route_policy_steps(rule: dict[str, Any]) -> list[dict[str, Any]]:
    interface = _string(rule.get("interface"))
    rule_type = _string(rule.get("type"))
    if rule_type == "routing.route_metric":
        metric = _string(rule.get("metric"))
        return [
            _step(
                rule=rule,
                provider="routing",
                action="set_route_metric",
                summary=f"Plan route metric {metric} for {interface}.",
                risk="medium",
                command_preview=["nmcli", "connection", "modify", "<profile-for-interface>", "ipv4.route-metric", metric, "ipv6.route-metric", metric],
                details={
                    "metric": metric,
                    "note": "Lower route metrics win. Connectivity probes should confirm failover/failback before apply.",
                },
                verify=[
                    "ip route show default",
                    "ip -6 route show default",
                ],
                rollback=["Restore previous route metrics from the saved NetworkManager profile."],
            )
        ]

    enabled = _string(rule.get("enabled"), "preserve_existing")
    ignore_auto_routes = _string(rule.get("ignore_auto_routes"), "preserve_existing")
    never_default_value = "yes" if enabled in {"yes", "true", "on", "enabled"} else "no"
    steps = [
        _step(
            rule=rule,
            provider="routing",
            action="set_never_default",
            summary=f"Plan never-default={enabled} for {interface}.",
            risk="high" if never_default_value == "no" else "medium",
            command_preview=[
                "nmcli",
                "connection",
                "modify",
                "<profile-for-interface>",
                "ipv4.never-default",
                never_default_value,
                "ipv6.never-default",
                never_default_value,
            ],
            details={"never_default": enabled, "ignore_auto_routes": ignore_auto_routes},
            verify=["ip route show default", "ip -6 route show default"],
            rollback=["Restore previous default-route policy from the saved NetworkManager profile."],
        )
    ]
    if ignore_auto_routes != "preserve_existing":
        ignore_value = "yes" if ignore_auto_routes in {"yes", "true", "on", "enabled"} else "no"
        steps.append(_step(
            rule=rule,
            provider="routing",
            action="set_ignore_auto_routes",
            summary=f"Plan ignore-auto-routes={ignore_auto_routes} for {interface}.",
            risk="medium",
            command_preview=[
                "nmcli",
                "connection",
                "modify",
                "<profile-for-interface>",
                "ipv4.ignore-auto-routes",
                ignore_value,
                "ipv6.ignore-auto-routes",
                ignore_value,
            ],
            details={"ignore_auto_routes": ignore_auto_routes},
            verify=["nmcli connection show <profile-for-interface> | grep ignore-auto-routes"],
            rollback=["Restore previous auto-route policy from the saved NetworkManager profile."],
        ))
    return steps


def _client_egress_steps(rule: dict[str, Any]) -> list[dict[str, Any]]:
    interface = _string(rule.get("interface"))
    return [
        _step(
            rule=rule,
            provider="sysctl",
            action="enable_forwarding",
            summary=f"Plan forwarding visibility for clients on {interface}.",
            risk="high",
            command_preview=["sysctl", "-w", "net.ipv4.ip_forward=1"],
            details={"also_requires": ["net.ipv6.conf.all.forwarding when IPv6 is enabled"]},
            verify=[
                "sysctl -n net.ipv4.ip_forward",
                "sysctl -n net.ipv6.conf.all.forwarding",
            ],
            rollback=["Restore saved sysctl forwarding values."],
        ),
        _step(
            rule=rule,
            provider="nftables",
            action="plan_managed_nat",
            summary=f"Plan panel-owned NAT/forwarding rules for clients on {interface}.",
            risk="high",
            command_preview=["nft", "-f", "<generated-panel-ruleset.nft>"],
            details={
                "managed_tables": ["inet localplane", "ip localplane_nat_v4", "ip6 localplane_nat_v6"],
                "active_uplink_required": True,
            },
            verify=[
                "nft list table inet localplane",
                "nft list table ip localplane_nat_v4",
                "nft list table ip6 localplane_nat_v6",
            ],
            rollback=[
                "Delete only panel-owned nftables tables created by this plan.",
                "Restore saved nftables ruleset snapshot if panel-owned cleanup fails.",
            ],
        ),
    ]


def _firewall_steps(rule: dict[str, Any]) -> list[dict[str, Any]]:
    interface = _string(rule.get("interface"))
    mode = _string(rule.get("mode"), "limited")
    return [
        _step(
            rule=rule,
            provider="nftables",
            action="plan_interface_isolation",
            summary=f"Plan {mode} isolation policy for {interface}.",
            risk="high" if mode == "on" else "medium",
            command_preview=["nft", "-f", "<generated-panel-isolation-ruleset.nft>"],
            details={"mode": mode, "exposed_services": _list(rule.get("exposed_services"))},
            verify=[
                "nft list table inet localplane",
                f"nft list ruleset | grep -F {shlex.quote(interface)}",
            ],
            rollback=[
                "Remove panel-owned isolation rules for this interface.",
                "Restore saved nftables ruleset snapshot if required.",
            ],
        )
    ]


def _wireless_steps(rule: dict[str, Any]) -> list[dict[str, Any]]:
    interface = _string(rule.get("interface"))
    mode = _string(rule.get("mode"), "preserve_existing")
    ssid = _string(rule.get("ssid"))
    country = _string(rule.get("country"))
    band = _string(rule.get("band"))
    channel = _string(rule.get("channel"))
    security = _string(rule.get("security"))
    command = ["nmcli", "connection", "modify", "<wifi-profile-for-interface>"]
    if ssid:
        command.extend(["802-11-wireless.ssid", ssid])
    if band and band != "preserve_existing":
        command.extend(["802-11-wireless.band", band])
    if channel and channel.lower() != "auto":
        command.extend(["802-11-wireless.channel", channel])
    return [
        _step(
            rule=rule,
            provider="networkmanager",
            action="plan_wifi_profile",
            summary=f"Plan Wi-Fi {mode} profile intent for {interface}.",
            risk="high" if mode == "hotspot" else "medium",
            command_preview=command,
            details={
                "mode": mode,
                "ssid": ssid,
                "country": country,
                "band": band,
                "channel": channel,
                "security": security,
                "secrets": "not included in generic interface desired state",
            },
            verify=[
                f"nmcli device wifi list ifname {shlex.quote(interface)}",
                f"iw dev {shlex.quote(interface)} info",
            ],
            rollback=["Restore the saved NetworkManager Wi-Fi profile snapshot."],
        )
    ]


def _cellular_steps(rule: dict[str, Any]) -> list[dict[str, Any]]:
    interface = _string(rule.get("interface"))
    auto_apn = bool(rule.get("auto_apn"))
    apn = _string(rule.get("apn"))
    return [
        _step(
            rule=rule,
            provider="modemmanager",
            action="plan_cellular_apn",
            summary=f"Plan {'automatic' if auto_apn else 'manual'} APN intent for {interface}.",
            risk="high",
            command_preview=["mmcli", "-m", "<modem>", "--simple-connect", f"apn={apn or '<auto-detected>'}"],
            details={
                "auto_apn": auto_apn,
                "apn": apn,
                "note": "Apply must verify SIM, registration, carrier and active bearer before changing the live profile.",
            },
            verify=[
                "mmcli -L",
                "mmcli -m <modem>",
                "nmcli connection show --active",
            ],
            rollback=["Restore previous cellular NetworkManager profile and reconnect after modem settles."],
        )
    ]


def _steps_for_rule(rule: dict[str, Any]) -> list[dict[str, Any]]:
    rule_type = _string(rule.get("type"))
    if rule_type in {"link.mtu", "connection.autoconnect"}:
        return _link_steps(rule)
    if rule_type in {"addressing.ipv4", "addressing.ipv6"}:
        return _addressing_steps(rule)
    if rule_type == "dns":
        return _dns_steps(rule)
    if rule_type == "routing.uplink_candidate":
        return _uplink_steps(rule)
    if rule_type in {"routing.route_metric", "routing.never_default"}:
        return _route_policy_steps(rule)
    if rule_type == "routing.client_egress":
        return _client_egress_steps(rule)
    if rule_type == "firewall.isolation":
        return _firewall_steps(rule)
    if rule_type == "wireless.profile":
        return _wireless_steps(rule)
    if rule_type == "cellular.apn":
        return _cellular_steps(rule)
    return [
        _step(
            rule=rule,
            provider="unknown",
            action="manual_review",
            summary=f"Rule type {rule_type or 'unknown'} needs manual planner support.",
            risk="medium",
        )
    ]


def interface_plan_preview(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    rules_payload = interface_rules_preview(payload or {})
    rules = [rule for rule in rules_payload.get("rules", []) if isinstance(rule, dict)]
    steps: list[dict[str, Any]] = []
    for rule in rules:
        steps.extend(_steps_for_rule(rule))

    readiness = rules_payload.get("readiness", {})
    summary = {
        "rules": len(rules),
        "steps": len(steps),
        "high_risk_steps": sum(1 for item in steps if item.get("risk") == "high"),
        "providers": sorted({str(item.get("provider")) for item in steps if item.get("provider")}),
    }
    warnings = [
        "Preview only. This plan does not execute host changes.",
        "Command previews are intentionally incomplete until provider-specific apply code exists.",
        "Apply must stay disabled while this planner is used as a design and review surface.",
    ]
    if not rules_payload.get("ok"):
        warnings.append("Readiness reported blockers; generated steps are for explanation only.")

    return {
        "ok": bool(rules_payload.get("ok")),
        "mode": "preview_only",
        "apply_enabled": False,
        "generated_from": "interface_configs_and_neutral_rules",
        "summary": summary,
        "readiness": readiness,
        "rules": rules,
        "steps": steps,
        "warnings": warnings,
        "next": [
            "Add interface backup snapshots before any apply path.",
            "Replace command previews with idempotent provider operations.",
            "Attach generated backups to each step before enabling apply.",
        ],
    }
