import re
import urllib.error
import urllib.request

from app.core.host import read_text, run_command_full
from app.domain.system.status import docker_cli_command


def local_http_probe(url: str, timeout: float = 3.0) -> dict[str, object]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return {"ok": True, "code": getattr(response, "status", 200), "url": url}
    except urllib.error.HTTPError as exc:
        return {"ok": True, "code": exc.code, "url": url}
    except Exception as exc:
        return {"ok": False, "code": 0, "url": url, "error": str(exc)}


def container_ip(container_name: str = "pihole") -> str:
    code, stdout, _ = run_command_full(
        docker_cli_command(["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container_name])
    )
    if code != 0:
        return ""
    candidate = stdout.strip()
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", candidate):
        return candidate
    return ""


def forwarding_enabled(config_path: str, pihole_ip: str = "") -> bool:
    config = read_text(config_path, "")
    ip = pihole_ip or container_ip()
    if not config or not ip:
        return False
    return f"server={ip}" in config


def dns_health(
    *,
    admin_probe: dict[str, object],
    root_probe: dict[str, object],
    dns_listener: dict[str, object],
    dns_binds: list[str],
    pihole_ip: str,
    forwarding_active: bool,
    prefs: dict[str, bool],
    active_networks: list[str],
) -> dict[str, object]:
    expected_networks = [name for name, enabled in prefs.items() if enabled]
    issues: list[str] = []
    warnings: list[str] = []
    checks = {
        "admin_reachable": bool(admin_probe.get("ok")),
        "root_reachable": bool(root_probe.get("ok")),
        "dns_listener_detected": bool(dns_listener),
        "container_ip_detected": bool(pihole_ip),
        "forwarding_enabled": bool(forwarding_active),
        "active_dns_binds": bool(dns_binds),
    }
    if not checks["admin_reachable"]:
        issues.append("Pi-hole admin UI is not reachable on port 8081.")
    if not checks["dns_listener_detected"]:
        issues.append("No Pi-hole DNS listener was detected.")
    if not checks["container_ip_detected"]:
        warnings.append("Pi-hole container IP could not be detected.")
    if (prefs.get("main_lan") or prefs.get("wifi")) and not forwarding_active:
        issues.append("Shared dnsmasq forwarding to Pi-hole is disabled while Main LAN or Wi-Fi Pi-hole mode is enabled.")
    if expected_networks and not active_networks:
        warnings.append("Pi-hole is enabled for at least one network, but no active DNS bind matched those networks.")
    if issues:
        state = "broken"
    elif warnings:
        state = "partial"
    elif checks["admin_reachable"] and checks["dns_listener_detected"]:
        state = "ok"
    else:
        state = "unknown"
    return {
        "state": state,
        "checks": checks,
        "issues": issues,
        "warnings": warnings,
        "expected_networks": expected_networks,
        "active_networks": active_networks,
    }
