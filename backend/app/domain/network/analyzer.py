from app.domain.network.state import network_snapshot, network_state_from_snapshot


def finding(severity: str, title: str, impact: str, suggested_fix: str) -> dict[str, object]:
    return {
        "severity": severity,
        "title": title,
        "impact": impact,
        "suggested_fix": suggested_fix,
    }


def network_findings_from_snapshot(snapshot: dict[str, object], state: dict[str, object]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    commands = snapshot.get("commands", {})
    routes = snapshot.get("routes", {})
    interfaces = snapshot.get("interfaces", [])

    if not state.get("active_uplink"):
        findings.append(finding(
            "high",
            "No default route detected",
            "The device may not have a stable internet uplink.",
            "Inspect uplink interfaces and NetworkManager connection metrics.",
        ))

    default_routes = [route for route in routes.get("ipv4", []) if route.get("dst") == "default" or route.get("dst") is None]
    if len(default_routes) > 1:
        findings.append(finding(
            "medium",
            "Multiple IPv4 default routes detected",
            "Uplink choice may depend on metrics and can behave unexpectedly during failover.",
            "Review route metrics and make the preferred uplink explicit.",
        ))

    for candidate in state.get("uplink_candidates", []):
        if candidate.get("state") == "UP" and not candidate.get("has_ip") and candidate.get("role") in {"wifi", "cellular", "ethernet"}:
            findings.append(finding(
                "medium",
                f"{candidate.get('interface')} is up without an IP address",
                "Link exists but routing/DNS cannot rely on this interface yet.",
                "Check DHCP/static addressing for this interface.",
            ))

    if state.get("ipv4_forwarding") == "1" and state.get("firewall_provider") == "unknown":
        findings.append(finding(
            "medium",
            "IPv4 forwarding is enabled but firewall/NAT provider is unknown",
            "LAN clients may depend on rules that the panel cannot inspect safely.",
            "Expose nftables/iptables-save to the panel and migrate to panel-managed nftables chains.",
        ))

    if not commands.get("resolvectl", {}).get("ok"):
        findings.append(finding(
            "info",
            "DNS provider status is not available",
            "The panel cannot fully explain DNS routing or split DNS behavior.",
            "Install or expose systemd-resolved/resolvectl, or add a DNS provider adapter.",
        ))

    if not commands.get("nmcli_devices", {}).get("ok"):
        findings.append(finding(
            "info",
            "NetworkManager provider is not available",
            "Wi-Fi and Ethernet profile state may be read-only or incomplete.",
            "Install NetworkManager/nmcli or expose the host provider path.",
        ))

    if commands.get("nft_ruleset", {}).get("ok") is False and commands.get("iptables_save", {}).get("ok") is False:
        findings.append(finding(
            "info",
            "No firewall provider is available to snapshot",
            "Firewall/NAT visibility is degraded.",
            "Install nftables or expose host firewall tools to the panel provider.",
        ))

    overlay_interfaces = [iface for iface in interfaces if iface.get("role") == "overlay"]
    if overlay_interfaces and not commands.get("tailscale_status", {}).get("ok"):
        findings.append(finding(
            "info",
            "Overlay interface detected without Tailscale provider status",
            "Tunnel routes may exist, but peer state cannot be explained yet.",
            "Expose tailscale status or add a WireGuard provider for this tunnel.",
        ))

    return findings


def network_findings() -> list[dict[str, object]]:
    snapshot = network_snapshot()
    state = network_state_from_snapshot(snapshot)
    return network_findings_from_snapshot(snapshot, state)


def network_diagnostics() -> dict[str, object]:
    snapshot = network_snapshot()
    state = network_state_from_snapshot(snapshot)
    findings = network_findings_from_snapshot(snapshot, state)
    return {
        "snapshot": snapshot,
        "state": state,
        "findings": findings,
    }
