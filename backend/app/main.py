from fastapi import FastAPI, HTTPException, Body
from app.api.routers import auth as auth_router
from app.api.routers import actions as actions_router
from app.api.routers import cellular as cellular_router
from app.api.routers import backups as backups_router
from app.api.routers import device_io as device_io_router
from app.api.routers import events as events_router
from app.api.routers import frontend as frontend_router
from app.api.routers import interfaces as interfaces_router
from app.api.routers import network as network_router
from app.api.routers import providers as providers_router
from app.api.routers import samba as samba_router
from app.api.routers import settings as settings_router
from app.api.routers import sessions as sessions_router
from app.api.routers import storage as storage_router
from app.api.routers import system as system_router
from app.core.auth import require_panel_auth
from app.core.cache import cached_read
from app.core.backups import create_backup
from app.core.events import EventLog
from app.core.frontend import mount_frontend_assets
from app.core.host import (
    command_exists,
    host_command_available,
    host_nmcli_available,
    host_nmcli_command,
    nmcli_available,
    nmcli_command,
    read_text,
    run_command,
    run_command_full,
    run_command_input,
    run_nmcli,
    run_nmcli_full,
)
from app.core.runtime_config import runtime_config, write_runtime_config
from app.domain.device_io.status import device_act_disk_activity_loop, device_led_policy_loop
from app.domain.dns.pihole import (
    container_ip as pihole_container_ip,
    dns_health,
    forwarding_enabled as pihole_dns_forwarding_enabled,
    local_http_probe,
)
from app.domain.lte.apn import (
    LTE_AUTO_APN,
    LTE_SIM_OVERRIDES,
    get_active_cellular_connection,
    get_cellular_connection,
    get_modem_id,
)
from app.domain.network.legacy_config import (
    cfg_flag,
    humanize_wifi_security,
    normalize_country_code,
    normalize_lan_role,
    normalize_wifi_band,
    normalize_wifi_channel,
    normalize_wifi_client_trust_mode,
    normalize_wifi_config_values,
    normalize_wifi_ipv4_method,
    normalize_wifi_ipv6_method,
    normalize_wifi_mode,
    normalize_wifi_security,
    normalize_wifi_uplink_preference,
    role_description,
    same_physical_lan_interface,
    slugify,
    wifi_band_from_nm,
    wifi_band_to_nm,
    wifi_channel_value,
)
from app.domain.system.services import is_process_running, parse_service_listeners
from app.domain.system.status import (
    docker_available,
    docker_cli_command,
)
from pathlib import Path
import subprocess
import json
import os
import re
import time
import shlex
import ipaddress
import sqlite3
import socket
import threading


app = FastAPI(title="LocalPlane")
app.middleware("http")(require_panel_auth)
mount_frontend_assets(app)
app.include_router(auth_router.router)
app.include_router(actions_router.router)
app.include_router(backups_router.router)
app.include_router(cellular_router.router)
app.include_router(device_io_router.router)
app.include_router(events_router.router)
app.include_router(frontend_router.router)
app.include_router(interfaces_router.router)
app.include_router(network_router.router)
app.include_router(providers_router.router)
app.include_router(samba_router.router)
app.include_router(settings_router.router)
app.include_router(sessions_router.router)
app.include_router(storage_router.router)
app.include_router(system_router.router)
event_log = EventLog()
SERVICE_LAN_DNSMASQ_IPV6_CONF = "/etc/NetworkManager/dnsmasq-shared.d/99-service-lan-ipv6.conf"
PIHOLE_DNSMASQ_FORWARD_CONF = "/etc/NetworkManager/dnsmasq-shared.d/98-pihole-upstream.conf"
WIFI_DNSMASQ_IPV6_CONF = "/etc/NetworkManager/dnsmasq-shared.d/99-wifi-hotspot-ipv6.conf"
WIFI_RA_PID = "/run/wifi-hotspot-ra.pid"
WIFI_RA_LOG = "/tmp/wifi-hotspot-ra.log"
NETALERTX_COMPOSE_FILE = "/home/evil/netalertx-stack/docker-compose.yml"
RUNTIME_CONFIG_PATH = "/app/data/runtime-config.json"
NETALERTX_SYNC_STATE_PATH = "/app/data/netalertx-sync-state.json"

def env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


SERVICE_LAN_INTERFACE = os.getenv("SERVICE_LAN_INTERFACE", "")
SERVICE_LAN_IPV4_GATEWAY = os.getenv("SERVICE_LAN_IPV4_GATEWAY", "")
SERVICE_LAN_IPV4_SUBNET = os.getenv("SERVICE_LAN_IPV4_SUBNET", "")
SERVICE_LAN_DHCP_RANGE = os.getenv("SERVICE_LAN_DHCP_RANGE", "")
SERVICE_LAN_IPV6_GATEWAY = os.getenv("SERVICE_LAN_IPV6_GATEWAY", "")
SERVICE_LAN_IPV6_PREFIX = os.getenv("SERVICE_LAN_IPV6_PREFIX", "")
SERVICE_LAN_ENABLE_IPV4 = env_flag("SERVICE_LAN_ENABLE_IPV4", False)
SERVICE_LAN_ENABLE_IPV6 = env_flag("SERVICE_LAN_ENABLE_IPV6", False)
SERVICE_LAN_ROLE = os.getenv("SERVICE_LAN_ROLE", "isolated")
SERVICE_LAN_DNS_SERVERS = os.getenv("SERVICE_LAN_DNS_SERVERS", "")
SERVICE_LAN_DNS_SEARCH = os.getenv("SERVICE_LAN_DNS_SEARCH", "")
FALLBACK_SERVICE_LAN_INTERFACE = ""
LAN_PROFILE_NAME = os.getenv("LAN_PROFILE_NAME", "Management LAN")
LAN_TARGET_INTERFACE = os.getenv("LAN_TARGET_INTERFACE", "")
LAN_ROLE = os.getenv("LAN_ROLE", "internal")
LAN_IPV4_MODE = os.getenv("LAN_IPV4_MODE", "disabled")
LAN_IPV4_ADDRESS = os.getenv("LAN_IPV4_ADDRESS", "")
LAN_IPV4_SUBNET = os.getenv("LAN_IPV4_SUBNET", "")
LAN_DHCP_RANGE = os.getenv("LAN_DHCP_RANGE", "")
LAN_IPV6_MODE = os.getenv("LAN_IPV6_MODE", "disabled")
LAN_IPV6_ADDRESS = os.getenv("LAN_IPV6_ADDRESS", "")
LAN_IPV6_PREFIX = os.getenv("LAN_IPV6_PREFIX", "")
LAN_DNS_SERVERS = os.getenv("LAN_DNS_SERVERS", "1.1.1.1,8.8.8.8")
LAN_DNS_SEARCH = os.getenv("LAN_DNS_SEARCH", "")
LAN_ROLE_OPTIONS = ["isolated", "internal", "external"]
DEFAULT_LAN_ROUTE_POLICY = {
    "mtu": "",
    "autoconnect": "yes",
    "route_metric": "",
    "never_default": "yes",
    "ignore_auto_routes": "yes",
}
MAIN_LAN_CONFIG = {
    "name": "Main LAN",
    "target_interface": LAN_TARGET_INTERFACE,
    "role": LAN_ROLE,
    "ipv4_mode": LAN_IPV4_MODE,
    "ipv4_address": LAN_IPV4_ADDRESS,
    "ipv4_subnet": LAN_IPV4_SUBNET,
    "dhcp_range": LAN_DHCP_RANGE,
    "ipv6_mode": LAN_IPV6_MODE,
    "ipv6_address": LAN_IPV6_ADDRESS,
    "ipv6_prefix": LAN_IPV6_PREFIX,
    "dns_servers": LAN_DNS_SERVERS,
    "dns_search": LAN_DNS_SEARCH,
    "use_pihole_dns": "true",
    **DEFAULT_LAN_ROUTE_POLICY,
}
SERVICE_LAN_CONFIG = {
    "name": "Device LAN",
    "interface": SERVICE_LAN_INTERFACE,
    "role": SERVICE_LAN_ROLE,
    "ipv4_gateway": SERVICE_LAN_IPV4_GATEWAY,
    "ipv4_subnet": SERVICE_LAN_IPV4_SUBNET,
    "dhcp_range": SERVICE_LAN_DHCP_RANGE,
    "ipv6_gateway": SERVICE_LAN_IPV6_GATEWAY,
    "ipv6_prefix": SERVICE_LAN_IPV6_PREFIX,
    "enable_ipv4": "true" if SERVICE_LAN_ENABLE_IPV4 else "false",
    "enable_ipv6": "true" if SERVICE_LAN_ENABLE_IPV6 else "false",
    "dns_servers": SERVICE_LAN_DNS_SERVERS,
    "dns_search": SERVICE_LAN_DNS_SEARCH,
    "use_pihole_dns": "false",
    **DEFAULT_LAN_ROUTE_POLICY,
}
WIFI_CONFIG = {
    "interface": os.getenv("WIFI_INTERFACE", "wlan0"),
    "mode": os.getenv("WIFI_MODE", "client"),
    "client_trust_mode": os.getenv("WIFI_CLIENT_TRUST_MODE", "normal"),
    "uplink_preference": os.getenv("WIFI_UPLINK_PREFERENCE", "prefer-lte"),
    "ssid": os.getenv("WIFI_SSID", ""),
    "password": os.getenv("WIFI_PASSWORD", ""),
    "hotspot_ssid": os.getenv("WIFI_HOTSPOT_SSID", "R1000-Hotspot"),
    "hotspot_password": os.getenv("WIFI_HOTSPOT_PASSWORD", ""),
    "hotspot_security": os.getenv("WIFI_HOTSPOT_SECURITY", "wpa2-personal"),
    "country": os.getenv("WIFI_COUNTRY", "DE"),
    "band": os.getenv("WIFI_BAND", "2.4ghz"),
    "channel": os.getenv("WIFI_CHANNEL", "auto"),
    "ipv4_method": os.getenv("WIFI_IPV4_METHOD", "auto"),
    "ipv4_address": os.getenv("WIFI_IPV4_ADDRESS", ""),
    "ipv6_method": os.getenv("WIFI_IPV6_METHOD", "disabled"),
    "ipv6_address": os.getenv("WIFI_IPV6_ADDRESS", ""),
    "use_pihole_dns": "true",
}
WIFI_RESTORE_ON_STARTUP = env_flag("WIFI_RESTORE_ON_STARTUP", False)
WIFI_SECRET_KEYS = {"password", "hotspot_password"}
WIFI_SCAN_CACHE = {"interface": "", "timestamp": 0.0, "scan": []}
def runtime_config_snapshot() -> dict[str, object]:
    existing = runtime_config()
    wifi_persisted = {
        key: value
        for key, value in WIFI_CONFIG.items()
        if key not in WIFI_SECRET_KEYS
    }
    snapshot = {
        "main_lan": dict(MAIN_LAN_CONFIG),
        "service_lan": dict(SERVICE_LAN_CONFIG),
        "wifi": wifi_persisted,
        "lte": {
            "auto_apn_enabled": LTE_AUTO_APN["enabled"],
            "sim_overrides": dict(LTE_SIM_OVERRIDES),
        },
    }
    for key, value in existing.items():
        if key not in snapshot:
            snapshot[key] = value
    if "settings" in existing:
        snapshot["settings"] = existing["settings"]
    return snapshot


def save_runtime_config() -> None:
    write_runtime_config(runtime_config_snapshot())


def create_prewrite_backup(label: str) -> dict[str, object]:
    backup = create_backup(label, include_host_snapshots=True)
    event_log.append(
        source="backups",
        action="prewrite_backup",
        message=f"Safety backup created before {label}",
        details={
            "label": label,
            "path": backup.get("path", ""),
            "items": len(backup.get("items", []) or []),
        },
    )
    return backup


def save_netalertx_sync_state(state: dict[str, object]) -> None:
    path = Path(NETALERTX_SYNC_STATE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2))


def load_netalertx_sync_state() -> dict[str, object]:
    raw = read_text(NETALERTX_SYNC_STATE_PATH, "")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def load_runtime_config() -> None:
    raw = read_text(RUNTIME_CONFIG_PATH, "")
    if not raw:
        return
    try:
        data = json.loads(raw)
    except Exception:
        return

    for key, value in data.get("main_lan", {}).items():
        if key in MAIN_LAN_CONFIG and isinstance(value, str):
            MAIN_LAN_CONFIG[key] = value.strip()
    MAIN_LAN_CONFIG["role"] = normalize_lan_role(MAIN_LAN_CONFIG.get("role", "internal"))
    for key, value in data.get("service_lan", {}).items():
        if key in SERVICE_LAN_CONFIG and isinstance(value, str):
            SERVICE_LAN_CONFIG[key] = value.strip()
    SERVICE_LAN_CONFIG["role"] = normalize_lan_role(SERVICE_LAN_CONFIG.get("role", "isolated"))
    for key, value in data.get("wifi", {}).items():
        if key in WIFI_CONFIG and key not in WIFI_SECRET_KEYS and isinstance(value, str):
            WIFI_CONFIG[key] = value.strip()
    normalize_wifi_config()
    lte_data = data.get("lte", {})
    auto_apn_enabled = lte_data.get("auto_apn_enabled")
    if isinstance(auto_apn_enabled, bool):
        LTE_AUTO_APN["enabled"] = auto_apn_enabled
    sim_overrides = lte_data.get("sim_overrides", {})
    if isinstance(sim_overrides, dict):
        LTE_SIM_OVERRIDES.clear()
        for sim_key, override in sim_overrides.items():
            if not isinstance(sim_key, str) or not isinstance(override, dict):
                continue
            sanitized = {}
            for key in ("id", "apn", "ipv4_method", "ipv6_method"):
                value = override.get(key, "")
                if isinstance(value, str):
                    sanitized[key] = value.strip()
            if sanitized.get("apn"):
                LTE_SIM_OVERRIDES[sim_key] = sanitized


def lan_cfg(key: str) -> str:
    return str(MAIN_LAN_CONFIG.get(key, ""))


def service_lan_cfg(key: str) -> str:
    return str(SERVICE_LAN_CONFIG.get(key, ""))


def wifi_cfg(key: str) -> str:
    return str(WIFI_CONFIG.get(key, ""))


def nm_bool(value: str, default: str = "yes") -> str:
    normalized = str(value or default).strip().lower()
    if normalized in {"1", "true", "yes", "on", "enabled"}:
        return "yes"
    if normalized in {"0", "false", "no", "off", "disabled"}:
        return "no"
    return default


def nm_optional_int(value: str, min_value: int, max_value: int) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        number = int(text)
    except ValueError:
        return ""
    if number < min_value or number > max_value:
        return ""
    return str(number)


def normalize_wifi_config() -> None:
    normalize_wifi_config_values(WIFI_CONFIG)


def netalertx_available() -> bool:
    return (
        Path(NETALERTX_COMPOSE_FILE).exists()
        and Path("/home/evil/netalertx-data/config/app.conf").exists()
        and Path("/home/evil/netalertx-data/db/app.db").exists()
    )


def get_interface_prefixlen(interface: str, address: str) -> int | None:
    output = run_command(["ip", "-j", "addr", "show", "dev", interface])
    if not output:
        return None
    try:
        data = json.loads(output)
    except Exception:
        return None
    for iface in data:
        for addr in iface.get("addr_info", []):
            if addr.get("family") == "inet" and addr.get("local") == address:
                value = addr.get("prefixlen")
                return int(value) if value is not None else None
    return None


def netalertx_scan_subnets() -> list[str]:
    subnets: list[str] = []

    main_interface = get_main_lan_interface()
    main_subnet = lan_cfg("ipv4_subnet")
    if main_interface and main_subnet and get_interface_data(main_interface).get("name"):
        subnets.append(f"{main_subnet} --interface={main_interface}")

    service_interface = get_service_lan_interface()
    service_subnet = service_lan_cfg("ipv4_subnet")
    service_state = str(get_interface_data(service_interface).get("state", "")).upper()
    if service_interface and service_subnet and service_state == "UP":
        subnets.append(f"{service_subnet} --interface={service_interface}")

    wifi_interface = wifi_cfg("interface")
    wifi_mode = normalize_wifi_mode(wifi_cfg("mode"))
    wifi_state = str(get_interface_data(wifi_interface).get("state", "")).upper()
    if wifi_interface and wifi_mode == "hotspot" and wifi_state == "UP":
        wifi_data = get_interface_data(wifi_interface)
        wifi_ip = next(iter(wifi_data.get("ipv4", []) or []), "")
        prefixlen = get_interface_prefixlen(wifi_interface, wifi_ip) if wifi_ip else None
        if wifi_ip and prefixlen is not None:
            subnet = ipaddress.ip_network(f"{wifi_ip}/{prefixlen}", strict=False)
            subnets.append(f"{subnet} --interface={wifi_interface}")
        elif normalize_wifi_ipv4_method("hotspot", wifi_cfg("ipv4_method")) == "shared":
            subnets.append(f"10.42.0.0/24 --interface={wifi_interface}")

    return subnets


def sync_netalertx_topology(restart: bool = True) -> dict[str, object]:
    if not docker_available():
        return {"ok": False, "reason": "Docker is not available"}

    settings = {
        "SCAN_SUBNETS": repr(netalertx_scan_subnets()),
        "NETWORK_DEVICE_TYPES": repr([
            "AP",
            "Access Point",
            "Gateway",
            "Firewall",
            "Hypervisor",
            "Powerline",
            "Switch",
            "WLAN",
            "PLC",
            "Router",
            "USB LAN Adapter",
            "USB WIFI Adapter",
            "Hotspot",
            "Cellular Uplink",
            "Overlay",
            "internet",
        ]),
        "UI_DEV_SECTIONS": repr(["Tile Cards", "Device Presence"]),
        "UI_TOPOLOGY_ORDER": repr(["Name"]),
    }

    main_data = get_interface_data(get_main_lan_interface())
    wifi_data = get_interface_data(wifi_cfg("interface"))
    service_data = get_interface_data(get_service_lan_interface())
    cellular_data = get_interface_data("wwan0")
    overlay_data = get_interface_data("tailscale0")

    main_mac = str(main_data.get("mac", "") or "")
    wifi_mac = str(wifi_data.get("mac", "") or "")
    service_mac = str(service_data.get("mac", "") or "")
    main_ip = next(iter(main_data.get("ipv4", []) or []), "")
    wifi_ip = next(iter(wifi_data.get("ipv4", []) or []), "")
    cellular_ip = next(iter(cellular_data.get("ipv4", []) or []), "")
    overlay_ip = next(iter(overlay_data.get("ipv4", []) or []), "")

    core_nodes = [
        ("r1000-core", "R1000 Device", "Router", "", "wwan0-uplink", "R1000"),
        ("wwan0-uplink", "Cellular Uplink", "Gateway", cellular_ip, "internet", "R1000"),
        ("tailscale-overlay", "Tailscale Overlay", "Gateway", overlay_ip, "r1000-core", "R1000"),
    ]
    if main_mac:
        core_nodes.append((main_mac, "Main LAN", "Switch", main_ip, "r1000-core", "Core Gateway"))
    if wifi_mac:
        wifi_mode = normalize_wifi_mode(wifi_cfg("mode"))
        wifi_name = "Wi-Fi Hotspot" if wifi_mode == "hotspot" else "Wi-Fi Client"
        wifi_type = "AP" if wifi_mode == "hotspot" else "WLAN"
        core_nodes.append((wifi_mac, wifi_name, wifi_type, wifi_ip, "r1000-core", "R1000"))
    if service_mac:
        core_nodes.append((service_mac, "Device LAN", "Switch", "", "r1000-core", "R1000"))

    parent_targets: list[tuple[ipaddress.IPv4Network, str, str]] = []
    if lan_cfg("ipv4_subnet") and main_mac:
        try:
            parent_targets.append((ipaddress.ip_network(lan_cfg("ipv4_subnet"), strict=False), main_mac, "Main LAN"))
        except ValueError:
            pass
    if service_lan_cfg("ipv4_subnet") and service_mac and str(service_data.get("state", "")).upper() == "UP":
        try:
            parent_targets.append((ipaddress.ip_network(service_lan_cfg("ipv4_subnet"), strict=False), service_mac, "Device LAN"))
        except ValueError:
            pass
    if normalize_wifi_mode(wifi_cfg("mode")) == "hotspot" and wifi_mac and wifi_ip:
        prefixlen = get_interface_prefixlen(wifi_cfg("interface"), wifi_ip) or 24
        try:
            parent_targets.append((ipaddress.ip_network(f"{wifi_ip}/{prefixlen}", strict=False), wifi_mac, "Wi-Fi Hotspot"))
        except ValueError:
            pass

    payload = {
        "settings": settings,
        "core_nodes": core_nodes,
        "parent_targets": [(str(subnet), parent_mac, site_name) for subnet, parent_mac, site_name in parent_targets],
        "skip_macs": ["internet", "r1000-core", "wwan0-uplink", "tailscale-overlay", main_mac, wifi_mac, service_mac],
    }
    helper_script = r"""
import json
import ipaddress
import re
import sqlite3
import time
import os
from pathlib import Path

payload = json.loads(os.environ['PAYLOAD_JSON'])
config_path = Path('/config/app.conf')
db_path = Path('/db/app.db')

config_text = config_path.read_text()
for key, value in payload['settings'].items():
    pattern = rf"^{re.escape(key)}=.*$"
    replacement = f"{key}={value}"
    if re.search(pattern, config_text, flags=re.M):
        config_text = re.sub(pattern, replacement, config_text, flags=re.M)
    else:
        config_text += f"\n{replacement}\n"
config_path.write_text(config_text)

conn = sqlite3.connect(db_path)
cur = conn.cursor()
for key, value in payload['settings'].items():
    cur.execute("UPDATE Settings SET setValue = ? WHERE setKey = ?", (value, key))

for dev_mac, dev_name, dev_type, dev_ip, parent_mac, site in payload['core_nodes']:
    cur.execute("SELECT 1 FROM Devices WHERE devMac = ?", (dev_mac,))
    if cur.fetchone():
        cur.execute(
            '''
            UPDATE Devices
            SET devName = ?, devType = ?, devLastIP = ?, devParentMAC = ?, devSite = ?,
                devFavorite = 1, devGroup = 'infra', devPresentLastScan = 1, devIsNew = 0,
                devNameSource = 'USER', devLastIPSource = 'USER', devParentMACSource = 'USER'
            WHERE devMac = ?
            ''',
            (dev_name, dev_type, dev_ip, parent_mac, site, dev_mac),
        )
    else:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        cur.execute(
            '''
            INSERT INTO Devices (
                devMac, devName, devOwner, devType, devFavorite, devGroup, devFirstConnection,
                devLastConnection, devLastIP, devScan, devLogEvents, devAlertEvents,
                devPresentLastScan, devIsNew, devIsArchived, devParentMAC, devSite,
                devNameSource, devLastIPSource, devParentMACSource
            ) VALUES (?, ?, 'portal', ?, 1, 'infra', ?, ?, ?, 1, 1, 0, 1, 0, 0, ?, ?, 'USER', 'USER', 'USER')
            ''',
            (dev_mac, dev_name, dev_type, now, now, dev_ip, parent_mac, site),
        )

parent_targets = [(ipaddress.ip_network(subnet, strict=False), parent_mac, site_name) for subnet, parent_mac, site_name in payload['parent_targets']]
skip_macs = set(payload['skip_macs'])
cur.execute("SELECT devMac, devLastIP FROM Devices")
for device_mac, device_ip in cur.fetchall():
    if device_mac in skip_macs or not device_ip:
        continue
    try:
        ip_value = ipaddress.ip_address(device_ip)
    except ValueError:
        continue
    for subnet, parent_mac, site_name in parent_targets:
        if ip_value in subnet:
            cur.execute(
                '''
                UPDATE Devices
                SET devParentMAC = ?, devParentRelType = 'downlink', devSite = ?,
                    devParentMACSource = 'USER', devParentRelTypeSource = 'USER'
                WHERE devMac = ?
                ''',
                (parent_mac, site_name, device_mac),
            )
            break

conn.commit()
conn.close()
print('ok')
"""
    helper_cmd = docker_cli_command([
        "run",
        "--rm",
        "-e",
        f"PAYLOAD_JSON={json.dumps(payload)}",
        "-v",
        "/home/evil/netalertx-data/config:/config",
        "-v",
        "/home/evil/netalertx-data/db:/db",
        "python:3.12-slim",
        "python3",
        "-c",
        helper_script,
    ])
    apply_code, apply_stdout, apply_stderr = run_command_full(helper_cmd)
    if apply_code != 0:
        save_netalertx_sync_state({
            "ok": False,
            "scan_subnets": netalertx_scan_subnets(),
            "last_sync_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        return {
            "ok": False,
            "reason": "Failed to apply NetAlertX topology helper",
            "scan_subnets": netalertx_scan_subnets(),
            "stdout": apply_stdout,
            "stderr": apply_stderr,
        }

    restart_code = 0
    restart_stdout = ""
    restart_stderr = ""
    if restart and docker_available():
        restart_code, restart_stdout, restart_stderr = run_command_full(docker_cli_command(["restart", "netalertx"]))

    result = {
        "ok": restart_code == 0,
        "scan_subnets": netalertx_scan_subnets(),
        "restart_code": restart_code,
        "stdout": "\n".join(part for part in [apply_stdout, restart_stdout] if part).strip(),
        "stderr": restart_stderr,
    }
    save_netalertx_sync_state({
        "ok": result["ok"],
        "scan_subnets": result["scan_subnets"],
        "last_sync_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    })
    return result


def sync_netalertx_topology_safe(restart: bool = True) -> None:
    try:
        sync_netalertx_topology(restart=restart)
    except Exception:
        pass


normalize_wifi_config()
load_runtime_config()
save_runtime_config()


def wifi_client_route_policy() -> tuple[str, str]:
    preference = normalize_wifi_uplink_preference(wifi_cfg("uplink_preference"))
    if preference == "prefer-wifi":
        return "600", "no"
    if preference == "prefer-wired":
        return "850", "no" if has_active_wired_uplink() is False else "yes"
    if preference == "failover-only":
        return "900", "yes" if get_active_cellular_connection() or has_active_wired_uplink() else "no"
    return "900", "no"


def has_active_wired_uplink() -> bool:
    for iface in get_interfaces_data():
        if iface.get("role") != "ethernet":
            continue
        if str(iface.get("state", "")).upper() != "UP":
            continue
        if interface_has_default_route(str(iface.get("name", ""))):
            return True
    return False


def list_wifi_connections() -> list[dict[str, str]]:
    if not nmcli_available():
        return []
    output = run_nmcli(["-t", "-f", "NAME,TYPE,DEVICE", "connection", "show"])
    connections = []
    for line in output.splitlines():
        parts = line.split(":")
        if len(parts) < 2 or parts[1] != "802-11-wireless":
            continue
        name = parts[0]
        connections.append(
            {
                "name": name,
                "type": parts[1],
                "ssid": run_nmcli(["-g", "802-11-wireless.ssid", "connection", "show", name]).strip(),
                "device": parts[2] if len(parts) > 2 else "",
            }
        )
    return connections


def find_wifi_connection_for_ssid(ssid: str, interface: str = "") -> str:
    for connection in list_wifi_connections():
        if connection.get("ssid") != ssid:
            continue
        device = connection.get("device", "")
        if not interface or device in {"", "--", interface}:
            return connection.get("name", "")
    return ""


def set_wifi_autoconnect_for_mode(active_connection: str = "") -> None:
    mode = normalize_wifi_mode(wifi_cfg("mode"))
    hotspot_connection = "portal-hotspot"
    active = active_connection or (hotspot_connection if mode == "hotspot" else find_wifi_connection_for_ssid(wifi_cfg("ssid"), wifi_cfg("interface")))
    for connection in list_wifi_connections():
        name = connection.get("name", "")
        if not name:
            continue
        should_autoconnect = name == active
        if mode == "hotspot" and name != hotspot_connection:
            should_autoconnect = False
        if mode == "client" and name == hotspot_connection:
            should_autoconnect = False
        run_nmcli_full(["connection", "modify", name, "connection.autoconnect", "yes" if should_autoconnect else "no"])


def apply_wifi_route_policy_to_connection(connection: str) -> tuple[int, str, str]:
    if not connection:
        return 0, "", ""
    route_metric, never_default = wifi_client_route_policy()
    return run_nmcli_full(
        [
            "connection",
            "modify",
            connection,
            "ipv4.route-metric",
            route_metric,
            "ipv4.never-default",
            never_default,
            "ipv6.route-metric",
            route_metric,
            "ipv6.never-default",
            never_default,
        ]
    )


def apply_wifi_route_policy_to_active_client() -> tuple[int, str, str]:
    if normalize_wifi_mode(wifi_cfg("mode")) != "client":
        return 0, "", ""
    interface = wifi_cfg("interface")
    active_connection = get_nmcli_device_status(interface).get("nm_connection", "")
    if not active_connection or active_connection == "--":
        active_connection = find_wifi_connection_for_ssid(wifi_cfg("ssid"), interface)
    return apply_wifi_route_policy_to_connection(active_connection)


def set_cellular_link_state(interface: str, enabled: bool) -> tuple[int, str, str]:
    outputs: list[str] = []
    errors: list[str] = []
    connection = get_cellular_connection(interface)
    modem_id = get_modem_id()

    if nmcli_available():
        radio_code, radio_stdout, radio_stderr = run_nmcli_full(["radio", "wwan", "on" if enabled else "off"])
        append_command_output(outputs, errors, radio_stdout, radio_stderr)
        if radio_code != 0:
            combined = " ".join(part.lower() for part in [radio_stdout, radio_stderr] if part)
            if "argument 'wwan' not understood" not in combined and "invalid" not in combined:
                return radio_code, "\n".join(outputs).strip(), "\n".join(errors).strip()

        if connection:
            auto_code, auto_stdout, auto_stderr = run_nmcli_full(
                ["connection", "modify", connection, "connection.autoconnect", "yes" if enabled else "no"]
            )
            append_command_output(outputs, errors, auto_stdout, auto_stderr)
            if auto_code != 0:
                return auto_code, "\n".join(outputs).strip(), "\n".join(errors).strip()

            if enabled:
                conn_code, conn_stdout, conn_stderr = run_nmcli_full(["connection", "up", connection])
            else:
                conn_code, conn_stdout, conn_stderr = run_nmcli_full(["connection", "down", connection])
                if conn_code != 0 and interface:
                    disconnect_code, disconnect_stdout, disconnect_stderr = run_nmcli_full(["device", "disconnect", interface])
                    append_command_output(outputs, errors, disconnect_stdout, disconnect_stderr)
                    if disconnect_code == 0:
                        conn_code, conn_stdout, conn_stderr = 0, "", ""
                    elif "not active" in (disconnect_stderr or "").lower():
                        conn_code, conn_stdout, conn_stderr = 0, "", ""
            append_command_output(outputs, errors, conn_stdout, conn_stderr)
            if conn_code != 0:
                return conn_code, "\n".join(outputs).strip(), "\n".join(errors).strip()

    if modem_id and command_exists("mmcli"):
        mmcli_code, mmcli_stdout, mmcli_stderr = run_command_full(["mmcli", "-m", modem_id, "--enable" if enabled else "--disable"])
        append_command_output(outputs, errors, mmcli_stdout, mmcli_stderr)
        if mmcli_code != 0:
            lower_err = (mmcli_stderr or "").lower()
            if not enabled and ("already disabled" in lower_err or "not enabled" in lower_err):
                mmcli_code = 0
            elif enabled and "already enabled" in lower_err:
                mmcli_code = 0
            if mmcli_code != 0:
                return mmcli_code, "\n".join(outputs).strip(), "\n".join(errors).strip()

    return 0, "\n".join(outputs).strip(), "\n".join(errors).strip()


def get_service_lan_connection_mode() -> str:
    ruleset = run_command(["nft", "list", "ruleset"])
    interface = get_service_lan_interface(ruleset)
    if interface and has_nft_table(ruleset, "ip", f"nm-shared-{interface}"):
        return "shared"
    return "manual"


def dhcp_listener_active() -> bool:
    output = run_command(["ss", "-ulpn"])
    if not output:
        return False

    for line in output.splitlines():
        if ":67 " in line or line.endswith(":67"):
            return True
    return False


def ipv6_ra_active() -> bool:
    return (
        is_process_running("service-lan-ra.py")
        or (
            is_process_running("dnsmasq")
            and Path(SERVICE_LAN_DNSMASQ_IPV6_CONF).exists()
            and "enable-ra" in read_text(SERVICE_LAN_DNSMASQ_IPV6_CONF)
        )
    )


def forwarding_active(family: int) -> bool:
    if family == 4:
        return read_text("/proc/sys/net/ipv4/ip_forward", "0") == "1"
    if family == 6:
        return read_text("/proc/sys/net/ipv6/conf/all/forwarding", "0") == "1"
    return False


def interface_ipv6_disabled(interface: str) -> bool:
    return read_text(f"/proc/sys/net/ipv6/conf/{interface}/disable_ipv6", "1") == "1"


def has_default_route(family: int) -> bool:
    if family == 4:
        return bool(run_command(["ip", "route", "show", "default"]))
    if family == 6:
        return bool(run_command(["ip", "-6", "route", "show", "default"]))
    return False


def interface_has_default_route(interface: str) -> bool:
    if not interface:
        return False
    for command in (["ip", "route", "show", "default"], ["ip", "-6", "route", "show", "default"]):
        for line in run_command(command).splitlines():
            if f" dev {interface} " in f" {line} ":
                return True
    return False


def has_nft_table(ruleset: str, family: str, name: str) -> bool:
    pattern = rf"(^|\n)table\s+{re.escape(family)}\s+{re.escape(name)}\s*\{{"
    return re.search(pattern, ruleset) is not None


def detect_shared_interfaces(ruleset: str) -> list[str]:
    return re.findall(r"table\s+ip\s+nm-shared-([^\s{]+)", ruleset)


def get_service_lan_interface(ruleset: str = "") -> str:
    _, resolved = resolve_lan_interfaces()
    if resolved:
        return resolved

    if not ruleset:
        ruleset = run_command(["nft", "list", "ruleset"])

    shared = detect_shared_interfaces(ruleset)
    if shared:
        return shared[0]

    return FALLBACK_SERVICE_LAN_INTERFACE


def get_docker_service_names() -> set[str]:
    if not docker_available():
        return set()
    code, stdout, stderr = run_command_full(
        docker_cli_command(["ps", "--format", "{{.Names}}\t{{.Image}}"])
    )
    if code != 0:
        return set()
    service_names: set[str] = set()
    known = {
        "pihole": "Pi-hole",
        "grafana": "Grafana",
        "prometheus": "Prometheus",
        "portainer": "Portainer",
        "node-exporter": "Node Exporter",
        "netalertx": "NetAlertX",
        "network-panel-backend": "LocalPlane",
        "nodus-backend": "LocalPlane",
        "localplane-backend": "LocalPlane",
    }
    for line in stdout.splitlines():
        name = line.split("\t", 1)[0].strip().lower()
        if name in known:
            service_names.add(known[name])
    return service_names


def get_pihole_container_ip() -> str:
    return pihole_container_ip("pihole")


def pihole_forwarding_enabled() -> bool:
    return pihole_dns_forwarding_enabled(PIHOLE_DNSMASQ_FORWARD_CONF)


def pihole_network_preferences() -> dict[str, bool]:
    return {
        "main_lan": cfg_flag(lan_cfg("use_pihole_dns")),
        "service_lan": cfg_flag(service_lan_cfg("use_pihole_dns")),
        "wifi": cfg_flag(wifi_cfg("use_pihole_dns")),
    }


def remove_pihole_dns_forwarding() -> tuple[int, str, str]:
    try:
        Path(PIHOLE_DNSMASQ_FORWARD_CONF).unlink(missing_ok=True)
    except Exception as exc:
        return 1, "", f"Failed to remove {PIHOLE_DNSMASQ_FORWARD_CONF}: {exc}"
    outputs = []
    errors = []
    for connection in ("main-lan", "portal-hotspot"):
        code, stdout, stderr = run_nmcli_full(["connection", "show", connection])
        if code != 0:
            continue
        _, down_stdout, down_stderr = run_nmcli_full(["connection", "down", connection])
        up_code, up_stdout, up_stderr = run_nmcli_full(["connection", "up", connection])
        if down_stdout:
            outputs.append(down_stdout)
        if up_stdout:
            outputs.append(up_stdout)
        if down_stderr:
            errors.append(down_stderr)
        if up_stderr:
            errors.append(up_stderr)
        if up_code != 0:
            return up_code, "\n".join(outputs).strip(), "\n".join(errors).strip()
    return 0, "\n".join(outputs).strip(), "\n".join(errors).strip()


def configure_pihole_dns_forwarding() -> tuple[int, str, str]:
    pihole_ip = get_pihole_container_ip()
    if not pihole_ip:
        return 1, "", "Pi-hole container IP not found"

    contents = (
        "# Managed by LocalPlane\n"
        "# Forward shared dnsmasq queries into Pi-hole so FTL sees and blocks LAN traffic.\n"
        "no-resolv\n"
        "cache-size=0\n"
        f"server={pihole_ip}\n"
    )
    try:
        Path(PIHOLE_DNSMASQ_FORWARD_CONF).write_text(contents)
    except Exception as exc:
        return 1, "", f"Failed to write {PIHOLE_DNSMASQ_FORWARD_CONF}: {exc}"

    outputs = []
    errors = []
    for connection in ("main-lan", "portal-hotspot"):
        code, stdout, stderr = run_nmcli_full(["connection", "show", connection])
        if code != 0:
            continue
        down_code, down_stdout, down_stderr = run_nmcli_full(["connection", "down", connection])
        up_code, up_stdout, up_stderr = run_nmcli_full(["connection", "up", connection])
        if down_stdout:
            outputs.append(down_stdout)
        if up_stdout:
            outputs.append(up_stdout)
        if down_stderr:
            errors.append(down_stderr)
        if up_stderr:
            errors.append(up_stderr)
        if up_code != 0:
            return up_code, "\n".join(outputs).strip(), "\n".join(errors).strip()

    return 0, "\n".join(outputs).strip(), "\n".join(errors).strip()


def apply_pihole_preferences() -> tuple[int, str, str]:
    prefs = pihole_network_preferences()
    main_ipv4 = get_main_lan_ipv4()
    service_ipv4 = service_lan_cfg("ipv4_gateway")
    public_dns = "1.1.1.1,8.8.8.8"

    MAIN_LAN_CONFIG["dns_servers"] = main_ipv4 if prefs["main_lan"] and main_ipv4 else public_dns
    SERVICE_LAN_CONFIG["dns_servers"] = service_ipv4 if prefs["service_lan"] and service_ipv4 else public_dns
    WIFI_CONFIG["dns_servers"] = "local-gateway" if prefs["wifi"] else public_dns

    enable_forwarding = prefs["main_lan"] or prefs["wifi"]
    if enable_forwarding:
        return configure_pihole_dns_forwarding()
    return remove_pihole_dns_forwarding()


def get_pihole_status() -> dict[str, object]:
    listeners = parse_service_listeners()
    services_by_name = {service["name"]: service for service in listeners}
    pihole_listener = services_by_name.get("Pi-hole", {})
    dns_listener = services_by_name.get("DNS", {})
    admin_probe = local_http_probe("http://127.0.0.1:8081/admin/")
    root_probe = local_http_probe("http://127.0.0.1:8081/")
    dns_binds = [
        bind for bind in dns_listener.get("binds", [])
        if bind not in {"127.0.0.53%lo", "127.0.0.54", "::1"}
    ]
    main_ipv4 = get_main_lan_ipv4()
    service_ipv4 = service_lan_cfg("ipv4_gateway")
    wifi_ipv4 = get_wifi_status().get("device", {}).get("ipv4", [])
    wifi_bind = wifi_ipv4[0] if wifi_ipv4 else ""
    active_networks = []
    if main_ipv4 and main_ipv4 in dns_binds:
        active_networks.append("Main LAN")
    if service_ipv4 and service_ipv4 in dns_binds:
        active_networks.append("Device LAN")
    if wifi_bind and wifi_bind in dns_binds:
        active_networks.append("Wi-Fi Hotspot")
    pihole_ip = get_pihole_container_ip()
    forwarding_enabled = pihole_forwarding_enabled()
    prefs = pihole_network_preferences()
    health = dns_health(
        admin_probe=admin_probe,
        root_probe=root_probe,
        dns_listener=dns_listener,
        dns_binds=dns_binds,
        pihole_ip=pihole_ip,
        forwarding_active=forwarding_enabled,
        prefs=prefs,
        active_networks=active_networks,
    )
    return {
        "active": bool(pihole_listener) or admin_probe["ok"],
        "web_port": "8081",
        "admin_reachable": admin_probe["ok"],
        "admin_status_code": admin_probe.get("code", 0),
        "root_reachable": root_probe["ok"],
        "root_status_code": root_probe.get("code", 0),
        "dns_listener_detected": bool(dns_listener),
        "dns_binds": dns_binds,
        "container_ip": pihole_ip,
        "dns_forwarding_enabled": forwarding_enabled,
        "network_preferences": prefs,
        "active_networks": active_networks,
        "health": health,
        "notes": [
            "Main LAN and Wi-Fi hotspot clients use the local gateway as DNS in shared mode",
            "Shared dnsmasq needs forwarding into Pi-hole for query statistics and blocking to appear in FTL",
        ],
    }


@app.post("/api/pihole/activate")
def pihole_activate():
    status = get_pihole_status()
    if not status.get("active") or not status.get("dns_listener_detected"):
        raise HTTPException(status_code=500, detail="Pi-hole DNS is not ready")
    create_prewrite_backup("pihole-activate")
    code, stdout, stderr = apply_pihole_preferences()
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": stdout, "stderr": stderr or "Failed to forward shared DNS into Pi-hole"},
        )
    main_ipv4 = get_main_lan_ipv4()
    if main_ipv4:
        MAIN_LAN_CONFIG["dns_servers"] = main_ipv4
    service_ipv4 = service_lan_cfg("ipv4_gateway")
    if service_ipv4:
        SERVICE_LAN_CONFIG["dns_servers"] = service_ipv4
    save_runtime_config()
    return {
        "ok": True,
        "main_lan_dns": MAIN_LAN_CONFIG.get("dns_servers", ""),
        "service_lan_dns": SERVICE_LAN_CONFIG.get("dns_servers", ""),
        "pihole_forwarding_enabled": pihole_forwarding_enabled(),
        "stdout": stdout,
        "stderr": stderr,
        "active_networks": status.get("active_networks", []),
    }


def get_netalert_status() -> dict[str, object]:
    listeners = parse_service_listeners()
    detected = None
    for service in listeners:
        if service["name"] in {"NetAlertX", "NetAlert"}:
            detected = service
            break
        if "tcp/20211" in service.get("ports", []):
            detected = service
            break

    web_probe = local_http_probe("http://127.0.0.1:20211/")
    sync_state = load_netalertx_sync_state()
    scan_subnets = sync_state.get("scan_subnets", netalertx_scan_subnets())
    if not isinstance(scan_subnets, list):
        scan_subnets = netalertx_scan_subnets()
    active_segments: list[str] = []
    for item in scan_subnets:
        if not isinstance(item, str):
            continue
        if "--interface=eth" in item or "--interface=en" in item:
            active_segments.append("Main LAN" if item.startswith(lan_cfg("ipv4_subnet")) else "Device LAN")
        elif "--interface=wl" in item:
            active_segments.append("Wi-Fi Hotspot")
        elif "--interface=wwan" in item:
            active_segments.append("Cellular")
        elif "--interface=tailscale" in item:
            active_segments.append("Tailscale")
    return {
        "detected": bool(detected) or web_probe["ok"],
        "web_reachable": web_probe["ok"],
        "status_code": web_probe.get("code", 0),
        "port": "20211",
        "name": detected["name"] if detected else "NetAlertX",
        "scan_subnets": scan_subnets,
        "active_segments": active_segments,
        "last_sync_at": sync_state.get("last_sync_at", ""),
        "last_sync_ok": bool(sync_state.get("ok", False)),
    }


def guess_interface_role(name: str) -> str:
    if name == "lo":
        return "loopback"
    if name.startswith("wwan"):
        return "cellular"
    if name.startswith("wl"):
        return "wifi"
    if name.startswith("tailscale"):
        return "overlay"
    if name.startswith("docker") or name.startswith("br-") or name.startswith("veth"):
        return "container"
    if name.startswith("en") or name.startswith("eth"):
        return "ethernet"
    return "other"


def get_interfaces_data() -> list[dict[str, object]]:
    def load() -> list[dict[str, object]]:
        output = run_command(["ip", "-j", "addr"])
        if not output:
            return []

        try:
            data = json.loads(output)
        except Exception:
            return []

        result = []
        for iface in data:
            name = iface.get("ifname", "")
            if name.startswith("veth") or name.startswith("br-") or name == "docker0":
                continue

            ipv4 = []
            ipv6 = []

            for addr in iface.get("addr_info", []):
                if addr.get("family") == "inet":
                    ipv4.append(addr.get("local"))
                elif addr.get("family") == "inet6":
                    ipv6.append(addr.get("local"))

            state = iface.get("operstate")
            if state == "UNKNOWN" and (ipv4 or ipv6):
                state = "UP"

            role = guess_interface_role(name)
            result.append(
                {
                    "name": name,
                    "state": state,
                    "mac": iface.get("address"),
                    "ipv4": ipv4,
                    "ipv6": ipv6,
                    "mtu": iface.get("mtu"),
                    "role": role,
                    "flags": iface.get("flags", []),
                    "physical": role in {"ethernet", "wifi", "cellular"},
                }
            )

        return result
    return cached_read("interfaces_data", 3, load)


def parse_colon_kv(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data


def get_interface_data(name: str) -> dict[str, object]:
    for iface in get_interfaces_data():
        if iface["name"] == name:
            return iface
    return {
        "name": name,
        "state": "missing",
        "mac": "",
        "ipv4": [],
        "ipv6": [],
        "mtu": None,
        "role": guess_interface_role(name),
        "flags": [],
    }


def get_main_lan_ipv4() -> str:
    iface = get_interface_data(get_main_lan_interface())
    ipv4 = iface.get("ipv4", [])
    return ipv4[0] if ipv4 else ""


def get_nmcli_device_status(interface: str) -> dict[str, str]:
    if not nmcli_available():
        return {}

    output = run_nmcli(["-t", "-f", "GENERAL.STATE,GENERAL.CONNECTION,GENERAL.TYPE", "device", "show", interface])
    if not output:
        return {}

    status = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        status[key] = value
    return {
        "nm_state": status.get("GENERAL.STATE", ""),
        "nm_connection": status.get("GENERAL.CONNECTION", ""),
        "nm_type": status.get("GENERAL.TYPE", ""),
    }


def get_nmcli_connection_status(connection_name: str) -> dict[str, str]:
    if not nmcli_available():
        return {}

    fields = [
        "connection.id",
        "connection.interface-name",
        "ipv4.method",
        "ipv4.addresses",
        "ipv4.dns",
        "ipv4.dns-search",
        "ipv6.method",
        "ipv6.addresses",
        "ipv6.dns",
    ]
    output = run_nmcli(["-g", ",".join(fields), "connection", "show", connection_name])
    if not output:
        return {}

    values = output.splitlines()
    data = {}
    for index, field in enumerate(fields):
        data[field] = values[index] if index < len(values) else ""
    return data


def get_wifi_radio_state() -> dict[str, str]:
    output = run_nmcli(["radio", "wifi"])
    enabled = output.strip().lower() == "enabled"
    return {"wifi_radio": output.strip() or "unknown", "wifi_radio_enabled": "true" if enabled else "false"}


def get_wifi_regdom() -> str:
    return read_text("/host/sys/module/cfg80211/parameters/ieee80211_regdom", "")


def can_set_wifi_regdom() -> bool:
    path = Path("/host/sys/module/cfg80211/parameters/ieee80211_regdom")
    return path.exists() and os.access(path, os.W_OK)


def set_wifi_regdom(country: str) -> tuple[int, str, str]:
    path = Path("/host/sys/module/cfg80211/parameters/ieee80211_regdom")
    if not path.exists() or not can_set_wifi_regdom():
        return 0, "", ""
    try:
        path.write_text(normalize_country_code(country))
        return 0, normalize_country_code(country), ""
    except Exception as exc:
        return 0, "", f"Country override could not be written on the host, keeping current regdom: {exc}"


def get_wifi_capabilities(interface: str) -> dict[str, str]:
    data = parse_colon_kv(
        run_nmcli(
            [
                "-t",
                "-f",
                "WIFI-PROPERTIES.AP,WIFI-PROPERTIES.2GHZ,WIFI-PROPERTIES.5GHZ,WIFI-PROPERTIES.WPA,WIFI-PROPERTIES.WPA2",
                "device",
                "show",
                interface,
            ]
        )
    )
    return {
        "ap": data.get("WIFI-PROPERTIES.AP", ""),
        "band_2ghz": data.get("WIFI-PROPERTIES.2GHZ", ""),
        "band_5ghz": data.get("WIFI-PROPERTIES.5GHZ", ""),
        "wpa": data.get("WIFI-PROPERTIES.WPA", ""),
        "wpa2": data.get("WIFI-PROPERTIES.WPA2", ""),
    }


def get_connection_secret(connection: str, key: str) -> str:
    if not connection:
        return ""
    value = run_nmcli(["--show-secrets", "-g", key, "connection", "show", connection]).strip()
    if value:
        return value

    # Some NetworkManager builds return an empty value for -g even when the
    # secret is present. The formatted field output still includes it.
    output = run_nmcli(["--show-secrets", "-f", key, "connection", "show", connection])
    for line in output.splitlines():
        left, _, right = line.partition(":")
        if left.strip() == key:
            return right.strip()
    return ""


def connection_profile_exists(connection: str) -> bool:
    if not connection:
        return False
    code, _, _ = run_nmcli_full(["connection", "show", connection])
    return code == 0


def resolve_hotspot_password(connection: str, interface: str) -> str:
    submitted = wifi_cfg("hotspot_password").strip()
    if submitted:
        return submitted

    saved = get_connection_secret(connection, "802-11-wireless-security.psk")
    if saved:
        return saved

    active = get_nmcli_device_status(interface)
    active_connection = active.get("nm_connection", "")
    if active_connection and active_connection != "--" and active_connection != connection:
        saved = get_connection_secret(active_connection, "802-11-wireless-security.psk")
        if saved:
            return saved
    return ""


def get_wifi_active_connection(interface: str) -> dict[str, str]:
    iface = get_nmcli_device_status(interface)
    connection = iface.get("nm_connection", "")
    if not connection or connection == "--":
        return {}

    fields = [
        "connection.id",
        "connection.interface-name",
        "802-11-wireless.ssid",
        "802-11-wireless.mode",
        "802-11-wireless.band",
        "802-11-wireless.channel",
        "802-11-wireless-security.key-mgmt",
        "802-11-wireless-security.proto",
        "ipv4.method",
        "ipv4.addresses",
        "ipv6.method",
        "ipv6.addresses",
    ]
    output = run_nmcli(["-g", ",".join(fields), "connection", "show", connection])
    if not output:
        return {"connection": connection}

    values = output.splitlines()
    data = {field: values[index] if index < len(values) else "" for index, field in enumerate(fields)}
    mode_map = {"ap": "hotspot", "infrastructure": "client"}
    mode = mode_map.get(data.get("802-11-wireless.mode", ""), data.get("802-11-wireless.mode", ""))
    security = humanize_wifi_security(
        data.get("802-11-wireless-security.key-mgmt", ""),
        data.get("802-11-wireless-security.proto", ""),
    )
    return {
        "connection": data.get("connection.id", connection),
        "ssid": data.get("802-11-wireless.ssid", ""),
        "mode": mode or "unknown",
        "raw_mode": data.get("802-11-wireless.mode", ""),
        "band": wifi_band_from_nm(data.get("802-11-wireless.band", "")),
        "channel": "Auto" if data.get("802-11-wireless.channel", "") in {"", "0", "--"} else data.get("802-11-wireless.channel", ""),
        "security": security,
        "key_mgmt": data.get("802-11-wireless-security.key-mgmt", ""),
        "ipv4_method": data.get("ipv4.method", ""),
        "ipv4_addresses": data.get("ipv4.addresses", ""),
        "ipv6_method": data.get("ipv6.method", ""),
        "ipv6_addresses": data.get("ipv6.addresses", ""),
    }


def wifi_config_candidate(payload: dict | None = None) -> dict[str, str]:
    config = dict(WIFI_CONFIG)
    if payload:
        for key, value in payload.items():
            if key in config and isinstance(value, str):
                config[key] = value.strip()
    config["mode"] = normalize_wifi_mode(config.get("mode", "client"))
    config["client_trust_mode"] = normalize_wifi_client_trust_mode(config.get("client_trust_mode", "normal"))
    config["uplink_preference"] = normalize_wifi_uplink_preference(config.get("uplink_preference", "prefer-lte"))
    config["hotspot_security"] = normalize_wifi_security(config.get("hotspot_security", "wpa2-personal"))
    config["band"] = normalize_wifi_band(config.get("band", "auto"))
    config["channel"] = normalize_wifi_channel(config.get("channel", "auto"), config["band"])
    config["country"] = normalize_country_code(config.get("country", "DE"))
    config["ipv4_method"] = normalize_wifi_ipv4_method(config["mode"], config.get("ipv4_method", "auto"))
    config["ipv6_method"] = normalize_wifi_ipv6_method(config["mode"], config.get("ipv6_method", "disabled"))
    return {key: str(value) for key, value in config.items()}


def recent_brcmfmac_errors() -> list[str]:
    commands = [
        ["journalctl", "-k", "-n", "200", "-g", "brcmfmac", "--no-pager"],
        ["dmesg", "-T"],
    ]
    errors: list[str] = []
    for command in commands:
        output = run_command(command)
        if not output:
            continue
        for line in output.splitlines()[-200:]:
            if "brcmfmac" in line and ("fail" in line.lower() or "error" in line.lower()):
                errors.append(line.strip())
        if errors:
            break
    return errors[-8:]


def wifi_plan(payload: dict | None = None) -> dict[str, object]:
    config = wifi_config_candidate(payload)
    interface = config.get("interface", "")
    iface = get_interface_data(interface)
    nm = get_nmcli_device_status(interface)
    active = get_wifi_active_connection(interface)
    radio = get_wifi_radio_state()
    errors: list[str] = []
    warnings: list[str] = []
    notes: list[str] = []
    driver_errors = recent_brcmfmac_errors()

    if not interface:
        errors.append("Wi-Fi interface is not configured.")
    elif not iface.get("name") or iface.get("state") == "missing":
        errors.append(f"Wi-Fi interface {interface} is not present.")

    if not nmcli_available():
        errors.append("NetworkManager/nmcli is required for Wi-Fi apply.")

    if radio.get("wifi_radio_enabled") == "false":
        warnings.append("Wi-Fi radio is currently off; apply will try to enable it first.")
    if str(nm.get("nm_state", "")).startswith("20"):
        warnings.append(f"{interface} is visible but NetworkManager reports it unavailable.")

    if config["mode"] == "hotspot":
        if not config.get("hotspot_ssid"):
            errors.append("Hotspot SSID is required.")
        if config.get("hotspot_security") != "open":
            password = config.get("hotspot_password", "").strip() or resolve_hotspot_password("portal-hotspot", interface)
            if len(password) < 8:
                errors.append("Hotspot password must be at least 8 characters, or an existing saved password must be present.")
        if driver_errors and config.get("band") == "5ghz" and config.get("channel") == "auto":
            warnings.append("Recent brcmfmac channel errors detected; use 2.4 GHz channel 1/6/11 before retrying 5 GHz auto channel.")
        if config.get("ipv6_method") == "shared":
            warnings.append("Hotspot IPv6 shared mode uses runtime RA/NAT helpers; disabled is simpler until hotspot is stable.")
        if active.get("mode") == "hotspot" and active.get("ssid") and active.get("ssid") != config.get("hotspot_ssid"):
            warnings.append("Active hotspot SSID differs from the saved config; apply will restart the hotspot profile so the new SSID is broadcast.")
        notes.append("Hotspot apply creates/updates only the portal-hotspot NetworkManager profile.")
    else:
        if not config.get("ssid"):
            errors.append("Client SSID is required.")
        if config.get("uplink_preference") == "prefer-wifi":
            warnings.append("Wi-Fi client is configured to prefer the default route when connected.")
        if config.get("uplink_preference") == "prefer-wired":
            warnings.append("Wi-Fi client is configured behind wired uplinks and will stay secondary while wired is active.")
        if config.get("client_trust_mode") == "isolated":
            notes.append("Isolated client mode adds panel-owned nftables policy for local-network exposure reduction.")

    return {
        "ok": not errors,
        "mode": config.get("mode"),
        "interface": interface,
        "config": {key: value for key, value in config.items() if key not in WIFI_SECRET_KEYS},
        "errors": errors,
        "warnings": warnings,
        "notes": notes,
        "driver_errors": driver_errors,
    }


def is_physical_interface(iface: dict[str, object]) -> bool:
    role = iface.get("role")
    return role in {"ethernet", "wifi", "cellular"}


def get_physical_interfaces() -> list[dict[str, object]]:
    return [iface for iface in get_interfaces_data() if is_physical_interface(iface)]


def get_lan_interfaces() -> list[dict[str, object]]:
    result = []
    target_name = get_main_lan_interface()
    service_name = get_service_lan_interface()
    for iface in get_interfaces_data():
        if iface["role"] != "ethernet":
            continue
        if iface["name"] in {target_name, service_name} or iface["state"] == "UP":
            result.append(iface)
    return result


def ethernet_candidates() -> list[dict[str, object]]:
    candidates = [iface for iface in get_interfaces_data() if iface["role"] == "ethernet" and iface["physical"]]
    return sorted(
        candidates,
        key=lambda iface: (
            0 if iface["state"] == "UP" else 1,
            iface.get("mac") or "",
            iface["name"],
        ),
    )


def choose_interface(preferred: str, exclude: set[str], purpose: str) -> str:
    candidates = ethernet_candidates()
    candidate_names = {iface["name"] for iface in candidates}
    if preferred and preferred in candidate_names and preferred not in exclude:
        return preferred

    for iface in candidates:
        if iface["name"] not in exclude:
            return iface["name"]
    return preferred or (candidates[0]["name"] if candidates else "")


def resolve_lan_interfaces() -> tuple[str, str]:
    main_preferred = lan_cfg("target_interface")
    service_preferred = service_lan_cfg("interface")
    main_interface = choose_interface(main_preferred, set(), "main")
    service_interface = choose_interface(service_preferred, {main_interface} if main_interface else set(), "service")
    if main_interface == service_interface:
        service_interface = choose_interface("", {main_interface} if main_interface else set(), "service")
    if main_interface == service_interface:
        main_interface = choose_interface("", {service_interface} if service_interface else set(), "main")
    return main_interface, service_interface


def get_main_lan_interface() -> str:
    main_interface, _ = resolve_lan_interfaces()
    return main_interface


def interface_block_table_name(interface: str) -> str:
    return f"portal_block_{slugify(interface)}"


def interface_block_active(ruleset: str, interface: str) -> bool:
    return has_nft_table(ruleset, "inet", interface_block_table_name(interface))


def interface_role_table_name(interface: str) -> str:
    return f"portal_role_{slugify(interface)}"


def local_interface_names(exclude: set[str] | None = None) -> list[str]:
    exclude = exclude or set()
    names: list[str] = []
    for iface in get_interfaces_data():
        name = iface.get("name", "")
        role = iface.get("role", "")
        if not name or name in exclude:
            continue
        if role in {"ethernet", "wifi", "overlay"}:
            names.append(name)
    return names


def local_destination_subnets(exclude: set[str] | None = None) -> tuple[list[str], list[str]]:
    exclude = exclude or set()
    ipv4: list[str] = []
    ipv6: list[str] = []
    for iface in get_interfaces_data():
        name = iface.get("name", "")
        if not name or name in exclude:
            continue
        for addr in iface.get("ipv4", []):
            if "/" in addr:
                ipv4.append(addr)
        for addr in iface.get("ipv6", []):
            if "/" in addr and not addr.startswith("fe80:"):
                ipv6.append(addr)
    return ipv4, ipv6


def apply_interface_role_policy(interface: str, role: str) -> tuple[int, str, str]:
    table = interface_role_table_name(interface)
    run_command_full(["nft", "delete", "table", "inet", table])
    normalized = normalize_lan_role(role)
    if normalized == "internal" or not interface:
        return 0, "", ""

    local_ifaces = local_interface_names({interface})
    local_ipv4, local_ipv6 = local_destination_subnets({interface})
    commands = [
        ["nft", "add", "table", "inet", table],
        ["nft", f"add chain inet {table} input {{ type filter hook input priority -2; policy accept; }}"],
        ["nft", f"add chain inet {table} forward {{ type filter hook forward priority 0; policy accept; }}"],
        ["nft", "add", "rule", "inet", table, "input", "iifname", interface, "ct", "state", "established,related", "accept"],
        ["nft", "add", "rule", "inet", table, "forward", "iifname", interface, "ct", "state", "established,related", "accept"],
        ["nft", "add", "rule", "inet", table, "input", "iifname", interface, "udp", "dport", "53", "accept"],
        ["nft", "add", "rule", "inet", table, "input", "iifname", interface, "tcp", "dport", "53", "accept"],
        ["nft", "add", "rule", "inet", table, "input", "iifname", interface, "udp", "dport", "67", "accept"],
        ["nft", "add", "rule", "inet", table, "input", "iifname", interface, "udp", "dport", "68", "accept"],
        ["nft", "add", "rule", "inet", table, "input", "iifname", interface, "icmp", "type", "{", "echo-request", ",", "destination-unreachable", ",", "time-exceeded", ",", "parameter-problem", "}", "accept"],
        ["nft", "add", "rule", "inet", table, "input", "iifname", interface, "icmpv6", "type", "{", "echo-request", ",", "nd-neighbor-solicit", ",", "nd-neighbor-advert", ",", "nd-router-solicit", ",", "nd-router-advert", ",", "destination-unreachable", ",", "packet-too-big", ",", "time-exceeded", ",", "parameter-problem", "}", "accept"],
    ]
    if normalized == "isolated":
        commands.append(["nft", f"add chain inet {table} output {{ type filter hook output priority -2; policy accept; }}"])
        commands.extend(
            [
                ["nft", "add", "rule", "inet", table, "output", "oifname", interface, "ct", "state", "established,related", "accept"],
                ["nft", "add", "rule", "inet", table, "output", "oifname", interface, "udp", "sport", "68", "udp", "dport", "67", "accept"],
                ["nft", "add", "rule", "inet", table, "output", "oifname", interface, "udp", "sport", "546", "udp", "dport", "547", "accept"],
                ["nft", "add", "rule", "inet", table, "output", "oifname", interface, "udp", "dport", "53", "accept"],
                ["nft", "add", "rule", "inet", table, "output", "oifname", interface, "tcp", "dport", "53", "accept"],
                ["nft", "add", "rule", "inet", table, "output", "oifname", interface, "udp", "dport", "123", "accept"],
                ["nft", "add", "rule", "inet", table, "output", "oifname", interface, "icmp", "type", "{", "echo-request", ",", "destination-unreachable", ",", "time-exceeded", ",", "parameter-problem", "}", "accept"],
                ["nft", "add", "rule", "inet", table, "output", "oifname", interface, "icmpv6", "type", "{", "echo-request", ",", "nd-neighbor-solicit", ",", "nd-neighbor-advert", ",", "nd-router-solicit", ",", "nd-router-advert", ",", "destination-unreachable", ",", "packet-too-big", ",", "time-exceeded", ",", "parameter-problem", "}", "accept"],
                # Suppress service discovery and local name resolution leakage on hostile upstream Wi-Fi.
                ["nft", "add", "rule", "inet", table, "output", "oifname", interface, "ip", "daddr", "224.0.0.0/4", "drop"],
                ["nft", "add", "rule", "inet", table, "output", "oifname", interface, "ip", "daddr", "255.255.255.255", "drop"],
                ["nft", "add", "rule", "inet", table, "output", "oifname", interface, "ip6", "daddr", "ff00::/8", "drop"],
                ["nft", "add", "rule", "inet", table, "output", "oifname", interface, "udp", "dport", "{", "137", ",", "138", ",", "1900", ",", "5353", ",", "5355", ",", "7575", "}", "drop"],
                ["nft", "add", "rule", "inet", table, "output", "oifname", interface, "tcp", "dport", "{", "139", ",", "445", ",", "5355", ",", "7575", "}", "drop"],
            ]
        )
    if normalized == "external":
        commands.append(["nft", "add", "rule", "inet", table, "input", "iifname", interface, "tcp", "dport", "443", "accept"])
        commands.append(["nft", "add", "rule", "inet", table, "input", "iifname", interface, "tcp", "dport", "80", "accept"])
    commands.append(["nft", "add", "rule", "inet", table, "input", "iifname", interface, "drop"])
    for local_iface in local_ifaces:
        commands.append(["nft", "add", "rule", "inet", table, "forward", "iifname", interface, "oifname", local_iface, "drop"])
    for subnet in local_ipv4:
        commands.append(["nft", "add", "rule", "inet", table, "forward", "iifname", interface, "ip", "daddr", subnet, "drop"])
    for subnet in local_ipv6:
        commands.append(["nft", "add", "rule", "inet", table, "forward", "iifname", interface, "ip6", "daddr", subnet, "drop"])
    stdout_parts = []
    stderr_parts = []
    for cmd in commands:
        code, stdout, stderr = run_command_full(cmd)
        if stdout:
            stdout_parts.append(stdout)
        if stderr:
            stderr_parts.append(stderr)
        if code != 0:
            return code, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()
    return 0, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()


def apply_wifi_client_trust_policy() -> tuple[int, str, str]:
    interface = wifi_cfg("interface")
    mode = normalize_wifi_mode(wifi_cfg("mode"))
    trust_mode = normalize_wifi_client_trust_mode(wifi_cfg("client_trust_mode"))
    role = "isolated" if interface and mode == "client" and trust_mode == "isolated" else "internal"
    return apply_interface_role_policy(interface, role)


def set_interface_block(interface: str, blocked: bool) -> tuple[int, str, str]:
    table = interface_block_table_name(interface)
    run_command_full(["nft", "delete", "table", "inet", table])
    if not blocked:
        return 0, "", ""

    commands = [
        ["nft", "add", "table", "inet", table],
        ["nft", f"add chain inet {table} forward {{ type filter hook forward priority -5; policy accept; }}"],
        ["nft", "add", "rule", "inet", table, "forward", "iifname", interface, "drop"],
        ["nft", "add", "rule", "inet", table, "forward", "oifname", interface, "drop"],
    ]
    stdout_parts = []
    stderr_parts = []
    for cmd in commands:
        code, stdout, stderr = run_command_full(cmd)
        if stdout:
            stdout_parts.append(stdout)
        if stderr:
            stderr_parts.append(stderr)
        if code != 0:
            return code, "\n".join(stdout_parts), "\n".join(stderr_parts)
    return 0, "\n".join(stdout_parts), "\n".join(stderr_parts)


def parse_ip_neighbors(interface: str, family: str) -> dict[str, dict[str, str]]:
    cmd = ["ip"]
    if family == "ipv6":
        cmd.append("-6")
    cmd.extend(["neigh", "show", "dev", interface])

    neigh_raw = run_command(cmd)
    neighbors = {}
    for line in neigh_raw.splitlines():
        parts = line.split()
        if not parts:
            continue

        address = parts[0]
        state = parts[-1]
        mac = ""
        if "lladdr" in parts:
            lladdr_index = parts.index("lladdr")
            if lladdr_index + 1 < len(parts):
                mac = parts[lladdr_index + 1]

        neighbors[address] = {"mac": mac, "state": state, "family": family, "interface": interface}

    return neighbors


def parse_proc_arp(interfaces: set[str]) -> dict[tuple[str, str], dict[str, str]]:
    raw = read_text("/host/proc/net/arp", "") or read_text("/proc/net/arp", "")
    entries: dict[tuple[str, str], dict[str, str]] = {}
    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip_addr, _, flags, mac, _, iface = parts[:6]
        if interfaces and iface not in interfaces:
            continue
        if mac == "00:00:00:00:00:00":
            continue
        state = "REACHABLE" if flags.lower() in {"0x2", "0x6"} else "STALE"
        entries[(iface, ip_addr)] = {
            "mac": mac.lower(),
            "state": state,
            "family": "ipv4",
            "interface": iface,
        }
    return entries


def collect_clients_for_interfaces(interfaces: list[dict[str, object]], default_lease_interface: str) -> list[dict[str, str]]:
    now = int(time.time())
    leases = []
    leases_raw = read_text("/host/var/lib/misc/dnsmasq.leases", "")
    for line in leases_raw.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            try:
                expires_at = int(parts[0])
            except ValueError:
                expires_at = 0
            if expires_at and expires_at < now:
                continue
            leases.append(
                {
                    "expires_at": expires_at,
                    "mac": parts[1].lower(),
                    "ip": parts[2],
                    "hostname": parts[3] if parts[3] != "*" else "",
                    "family": "ipv4",
                    "interface": default_lease_interface,
                }
            )

    lease_by_mac = {}
    for lease in leases:
        current = lease_by_mac.get(lease["mac"])
        if current is None or lease["expires_at"] >= current["expires_at"]:
            lease_by_mac[lease["mac"]] = lease

    result = []
    seen = set()
    interface_names = {str(iface.get("name", "")) for iface in interfaces if iface.get("name")}
    arp_entries = parse_proc_arp(interface_names)
    for iface in interfaces:
        neighbors = {}
        neighbors.update(parse_ip_neighbors(iface["name"], "ipv4"))
        neighbors.update(parse_ip_neighbors(iface["name"], "ipv6"))
        for (arp_iface, arp_ip), arp in arp_entries.items():
            if arp_iface == iface["name"] and arp_ip not in neighbors:
                neighbors[arp_ip] = arp
        for address, neigh in neighbors.items():
            mac = (neigh.get("mac") or "").lower()
            lease = lease_by_mac.get(mac, {})
            seen.add((iface["name"], mac, address))
            result.append(
                {
                    "interface": iface["name"],
                    "ip": address,
                    "family": neigh["family"],
                    "mac": neigh.get("mac", ""),
                    "hostname": lease.get("hostname", ""),
                    "state": neigh.get("state", "unknown"),
                }
            )

    for lease in lease_by_mac.values():
        key = (lease["interface"], lease["mac"], lease["ip"])
        if key in seen:
            continue
        result.append(
            {
                "interface": lease["interface"],
                "ip": lease["ip"],
                "family": lease["family"],
                "mac": lease["mac"],
                "hostname": lease["hostname"],
                "state": "lease",
            }
        )

    return result


def is_link_local_ipv6(address: str) -> bool:
    try:
        ip_value = ipaddress.ip_address(address)
    except ValueError:
        return False
    return isinstance(ip_value, ipaddress.IPv6Address) and ip_value.is_link_local


def client_address_rank(client: dict[str, str]) -> tuple[int, int]:
    address = client.get("ip", "")
    family = client.get("family", "")
    state = str(client.get("state", "")).upper()
    if family == "ipv4":
        return (0, 0 if state in {"REACHABLE", "DELAY", "PROBE", "LEASE"} else 1)
    if family == "ipv6" and is_link_local_ipv6(address):
        return (3, 1)
    return (1, 0 if state in {"REACHABLE", "DELAY", "PROBE"} else 1)


def summarize_wifi_clients(clients: list[dict[str, str]]) -> list[dict[str, str]]:
    grouped: dict[tuple[str, str], list[dict[str, str]]] = {}
    passthrough: list[dict[str, str]] = []
    for client in clients:
        mac = (client.get("mac", "") or "").lower()
        interface = client.get("interface", "") or ""
        if not mac:
            if client.get("family") == "ipv6" and is_link_local_ipv6(client.get("ip", "")):
                continue
            passthrough.append(client)
            continue
        grouped.setdefault((interface, mac), []).append(client)

    result: list[dict[str, str]] = []
    for _, entries in grouped.items():
        filtered = [entry for entry in entries if not (entry.get("family") == "ipv6" and is_link_local_ipv6(entry.get("ip", "")))]
        if not filtered:
            continue
        filtered.sort(key=client_address_rank)
        primary = dict(filtered[0])
        secondary = [entry.get("ip", "") for entry in filtered[1:] if entry.get("ip")]
        if secondary:
            primary["secondary_ips"] = ", ".join(secondary[:2])
            if len(secondary) > 2:
                primary["secondary_ips"] += f" +{len(secondary) - 2}"
        result.append(primary)

    result.extend(passthrough)
    result.sort(key=lambda item: (item.get("interface", ""), item.get("hostname", ""), item.get("mac", ""), client_address_rank(item)))
    return result


def get_all_lan_clients() -> list[dict[str, str]]:
    return collect_clients_for_interfaces(get_lan_interfaces(), get_service_lan_interface())


def get_wifi_clients() -> list[dict[str, str]]:
    interface = wifi_cfg("interface")
    def load() -> list[dict[str, str]]:
        active = get_wifi_active_connection(interface)
        if active.get("mode") != "hotspot":
            return []
        wifi_iface = get_interface_data(interface)
        if not wifi_iface.get("name"):
            return []
        clients = collect_clients_for_interfaces([wifi_iface], interface)
        clients = [client for client in clients if client.get("state", "").upper() != "FAILED"]
        clients = summarize_wifi_clients(clients)
        for client in clients:
            client["link"] = "wifi"
        return clients
    return cached_read(f"wifi_clients:{interface}", 10, load)


def get_wifi_scan(interface: str, force_rescan: bool = False) -> list[dict[str, str]]:
    if not nmcli_available():
        return []
    now = time.time()
    cached_scan = WIFI_SCAN_CACHE.get("scan", [])
    if (
        not force_rescan
        and WIFI_SCAN_CACHE.get("interface") == interface
        and isinstance(cached_scan, list)
        and now - float(WIFI_SCAN_CACHE.get("timestamp", 0.0)) < 60
    ):
        return cached_scan
    if force_rescan:
        run_nmcli_full(["device", "set", interface, "managed", "yes"])
        run_command_full(["ip", "link", "set", "dev", interface, "up"])
        run_nmcli_full(["radio", "wifi", "on"])
        run_nmcli_full(["dev", "wifi", "rescan", "ifname", interface])
    output = run_nmcli(["-t", "-f", "SSID,CHAN,SIGNAL,SECURITY,IN-USE", "dev", "wifi", "list", "ifname", interface])
    networks = []
    for line in output.splitlines():
        parts = line.split(":")
        if len(parts) < 5:
            continue
        ssid, channel, signal, security, in_use = parts[0], parts[1], parts[2], parts[3], parts[4]
        if not ssid:
            continue
        networks.append(
            {
                "ssid": ssid,
                "channel": channel,
                "signal": signal,
                "security": security,
                "in_use": in_use == "*",
            }
        )
    WIFI_SCAN_CACHE.update({"interface": interface, "timestamp": now, "scan": networks})
    return networks


def get_rfkill_status() -> list[dict[str, str]]:
    results = []
    base = Path("/sys/class/rfkill")
    if not base.exists():
        return results
    for entry in base.iterdir():
        rf_type = read_text(str(entry / "type"), "")
        name = read_text(str(entry / "name"), "")
        soft = read_text(str(entry / "soft"), "")
        hard = read_text(str(entry / "hard"), "")
        results.append({"type": rf_type, "name": name, "soft": soft, "hard": hard})
    return results


def get_wifi_status() -> dict[str, object]:
    interface = wifi_cfg("interface")
    normalize_wifi_config()
    if wifi_cfg("mode") == "hotspot" and wifi_cfg("ipv6_method") in {"shared", "manual"} and not wifi_ra_helper_running():
        enable_wifi_hotspot_ipv6_runtime(interface)
    iface = get_interface_data(interface)
    iface.update(get_nmcli_device_status(interface))
    iface.update(get_wifi_radio_state())
    active = get_wifi_active_connection(interface)
    clients = get_wifi_clients()
    scan = get_wifi_scan(interface, force_rescan=False)
    live_scan_entry = next((entry for entry in scan if entry.get("in_use")), None)
    if live_scan_entry:
        if active.get("channel") in {"", "Auto", "--"} and live_scan_entry.get("channel"):
            active["channel"] = str(live_scan_entry.get("channel"))
        if not active.get("ssid") and live_scan_entry.get("ssid"):
            active["ssid"] = str(live_scan_entry.get("ssid"))
        if active.get("security"):
            live_scan_entry["security"] = str(active.get("security"))
        if active.get("channel") and active.get("channel") not in {"", "--"}:
            live_scan_entry["channel"] = str(active.get("channel"))
    public_wifi_config = dict(WIFI_CONFIG)
    for key in WIFI_SECRET_KEYS:
        public_wifi_config[key] = ""
    notes = [
        "client mode joins an upstream Wi-Fi network",
        "hotspot mode creates a local AP from wlan0",
    ]
    if wifi_cfg("mode") == "client" and wifi_cfg("client_trust_mode") == "isolated":
        notes.append("isolated client mode blocks inbound and local-network reachability from the upstream Wi-Fi")
        notes.append("isolated client mode reduces exposure on unsafe Wi-Fi, but upstream MITM protection still depends on TLS, certificate validation, and ideally a VPN")
    if wifi_cfg("mode") == "client":
        preference = normalize_wifi_uplink_preference(wifi_cfg("uplink_preference"))
        if preference == "prefer-wifi":
            notes.append("uplink preference is set to prefer Wi-Fi, so Wi-Fi can become the default route when connected")
        elif preference == "prefer-wired":
            notes.append("uplink preference is set to prefer wired Ethernet, so Wi-Fi stays secondary while a wired uplink is active")
        elif preference == "failover-only":
            notes.append("uplink preference is failover only, so Wi-Fi stays off the default route while cellular or wired uplink is active")
        else:
            notes.append("uplink preference is set to prefer cellular, so Wi-Fi stays secondary while cellular is available")
    if active.get("mode") == "hotspot":
        notes.append("hotspot scans are manual to avoid disrupting connected devices")
    if active.get("mode") == "hotspot" and active.get("ipv6_method") == "auto":
        notes.append("hotspot IPv6 auto mode can confuse client captive checks; disabled is usually more stable")
    if iface.get("wifi_radio_enabled") == "false":
        notes.append("Wi-Fi radio is off")
    if iface.get("nm_state", "").startswith("30"):
        notes.append("wlan0 is managed by NetworkManager and ready to scan or connect")
    elif iface.get("nm_state", "").startswith("20"):
        notes.append("wlan0 is visible but still unavailable at the OS or driver level")
    notes.append("one radio can use either 2.4 GHz or 5 GHz at a time; choose the band explicitly for predictable behavior")
    notes.append("hotspot security uses WPA2-PSK when enabled; WPS is not used by this portal")
    if not can_set_wifi_regdom():
        notes.append("host regulatory domain is read-only right now, so country selection is stored in the portal but not enforced on the host")
    plan = wifi_plan()
    return {
        "interface": interface,
        "config": public_wifi_config,
        "device": iface,
        "active": active,
        "clients": clients,
        "country": get_wifi_regdom(),
        "capabilities": get_wifi_capabilities(interface),
        "scan": scan,
        "rfkill": get_rfkill_status(),
        "notes": notes,
        "plan": plan,
        "warnings": plan.get("warnings", []),
        "errors": plan.get("errors", []),
    }


def set_nmcli_managed(interface: str) -> tuple[int, str, str]:
    return run_nmcli_full(["device", "set", interface, "managed", "yes"])


def append_command_output(stdout_parts: list[str], stderr_parts: list[str], stdout: str, stderr: str) -> None:
    if stdout:
        stdout_parts.append(stdout)
    if stderr:
        stderr_parts.append(stderr)


def wifi_ipv4_addresses_for_mode(mode: str, method: str) -> str:
    if method != "manual":
        return ""
    if mode == "hotspot":
        return wifi_cfg("ipv4_address") or "10.42.0.1/24"
    return wifi_cfg("ipv4_address")


def wifi_ipv6_addresses_for_mode(mode: str, method: str) -> str:
    if method != "manual":
        return ""
    if mode == "hotspot":
        return wifi_cfg("ipv6_address") or "fd42:42::1/64"
    return wifi_cfg("ipv6_address")


def wifi_hotspot_ipv6_prefix() -> str:
    if wifi_cfg("ipv6_method") == "manual" and wifi_cfg("ipv6_address"):
        address = wifi_cfg("ipv6_address")
        try:
            iface = ipaddress.IPv6Interface(address)
            return str(ipaddress.IPv6Network((iface.network.network_address, iface.network.prefixlen), strict=False))
        except Exception:
            pass
    return "fd42:42::/64"


def wifi_hotspot_ipv6_gateway() -> str:
    if wifi_cfg("ipv6_method") == "manual" and wifi_cfg("ipv6_address"):
        return wifi_cfg("ipv6_address").split("/", 1)[0]
    prefix = ipaddress.IPv6Network(wifi_hotspot_ipv6_prefix(), strict=False)
    return str(prefix.network_address + 1)


def wifi_hotspot_nat_table() -> str:
    return "portal_wifi_nat_v6"


def wifi_dnsmasq_shared_pid(interface: str) -> str:
    return run_command(["pgrep", "-f", f"nm-dnsmasq-{interface}"]).splitlines()[0] if run_command(["pgrep", "-f", f"nm-dnsmasq-{interface}"]) else ""


def reload_shared_dnsmasq(interface: str) -> None:
    pid = wifi_dnsmasq_shared_pid(interface)
    if pid:
        run_command_full(["kill", "-HUP", pid])


def wifi_ra_helper_running() -> bool:
    pid_text = read_text(WIFI_RA_PID, "").strip()
    if not pid_text.isdigit():
        return False
    proc = Path("/proc") / pid_text
    if not proc.exists():
        return False
    cmdline = read_text(str(proc / "cmdline"), "")
    return "service-lan-ra.py" in cmdline and "wlan0" in cmdline


def stop_wifi_ra_helper() -> None:
    pid_text = read_text(WIFI_RA_PID, "")
    if pid_text:
        run_command_full(["kill", pid_text])
    Path(WIFI_RA_PID).unlink(missing_ok=True)


def disable_wifi_hotspot_ipv6_runtime(interface: str) -> tuple[int, str, str]:
    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    stop_wifi_ra_helper()
    Path(WIFI_DNSMASQ_IPV6_CONF).unlink(missing_ok=True)
    reload_shared_dnsmasq(interface)
    run_command_full(["nft", "delete", "table", "ip6", wifi_hotspot_nat_table()])
    return 0, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()


def enable_wifi_hotspot_ipv6_runtime(interface: str) -> tuple[int, str, str]:
    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    prefix = wifi_hotspot_ipv6_prefix()
    gateway = wifi_hotspot_ipv6_gateway()
    prefix_len = prefix.split("/", 1)[1]
    run_command_full(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"])
    run_command_full(["sysctl", "-w", f"net.ipv6.conf.{interface}.disable_ipv6=0"])
    code, stdout, stderr = run_command_full(["ip", "-6", "addr", "replace", f"{gateway}/{prefix_len}", "dev", interface])
    append_command_output(stdout_parts, stderr_parts, stdout, stderr)
    if code != 0:
        return code, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()

    Path(WIFI_DNSMASQ_IPV6_CONF).write_text(
        "\n".join(
            [
                "enable-ra",
                f"dhcp-range=::,constructor:{interface},ra-stateless,ra-names,12h",
                "dhcp-option=option6:dns-server,[2606:4700:4700::1111],[2001:4860:4860::8888]",
                "",
            ]
        )
    )
    reload_shared_dnsmasq(interface)

    run_command_full(["nft", "delete", "table", "ip6", wifi_hotspot_nat_table()])
    code, stdout, stderr = run_command_full(["nft", "add", "table", "ip6", wifi_hotspot_nat_table()])
    append_command_output(stdout_parts, stderr_parts, stdout, stderr)
    if code != 0:
        return code, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()
    code, stdout, stderr = run_command_full(["nft", f"add chain ip6 {wifi_hotspot_nat_table()} postrouting {{ type nat hook postrouting priority 110; policy accept; }}"])
    append_command_output(stdout_parts, stderr_parts, stdout, stderr)
    if code != 0:
        return code, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()
    code, stdout, stderr = run_command_full(["nft", "add", "rule", "ip6", wifi_hotspot_nat_table(), "postrouting", "oifname", "!=", interface, "ip6", "saddr", prefix, "counter", "masquerade"])
    append_command_output(stdout_parts, stderr_parts, stdout, stderr)
    if code != 0:
        return code, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()

    stop_wifi_ra_helper()
    env = os.environ.copy()
    env["SERVICE_LAN_IPV6_GATEWAY"] = gateway
    log_handle = open(WIFI_RA_LOG, "ab")
    process = subprocess.Popen(
        ["/usr/local/bin/service-lan-ra.py", interface, prefix, "2606:4700:4700::1111"],
        stdout=log_handle,
        stderr=log_handle,
        env=env,
        start_new_session=True,
    )
    log_handle.close()
    Path(WIFI_RA_PID).write_text(str(process.pid))
    return 0, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()


def configure_wifi_hotspot(connection: str, nmcli_cmd) -> tuple[int, str, str]:
    interface = wifi_cfg("interface")
    band = wifi_band_to_nm(wifi_cfg("band"))
    channel = wifi_channel_value(wifi_cfg("channel"), wifi_cfg("band"))
    hotspot_security = wifi_cfg("hotspot_security") or "wpa2-personal"
    submitted_password = wifi_cfg("hotspot_password").strip()
    connection_exists = connection_profile_exists(connection)
    password = resolve_hotspot_password(connection, interface)
    if hotspot_security != "open" and len(password) < 8:
        return 1, "", "Hotspot password must be at least 8 characters for WPA2/WPA3-Personal, or keep the existing saved password"

    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    regdom_code, regdom_stdout, regdom_stderr = set_wifi_regdom(wifi_cfg("country"))
    append_command_output(stdout_parts, stderr_parts, regdom_stdout, regdom_stderr)
    if regdom_code != 0:
        return regdom_code, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()

    if not connection_exists:
        code, stdout, stderr = run_command_full(
            nmcli_cmd(["connection", "add", "type", "wifi", "ifname", interface, "con-name", connection, "autoconnect", "yes", "ssid", wifi_cfg("hotspot_ssid")])
        )
        append_command_output(stdout_parts, stderr_parts, stdout, stderr)
        if code != 0:
            return code, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()

    modify_args = [
        "connection",
        "modify",
        connection,
        "connection.interface-name",
        interface,
        "connection.autoconnect",
        "yes",
        "802-11-wireless.mode",
        "ap",
        "802-11-wireless.ssid",
        wifi_cfg("hotspot_ssid"),
        "802-11-wireless.band",
        band,
        "802-11-wireless.channel",
        channel,
        "802-11-wireless.powersave",
        "2",
        "ipv4.method",
        wifi_cfg("ipv4_method") or "shared",
        "ipv4.addresses",
        wifi_ipv4_addresses_for_mode("hotspot", wifi_cfg("ipv4_method")),
        "ipv4.never-default",
        "yes",
        "ipv4.ignore-auto-routes",
        "yes",
        "ipv6.method",
        wifi_cfg("ipv6_method") or "disabled",
        "ipv6.addresses",
        wifi_ipv6_addresses_for_mode("hotspot", wifi_cfg("ipv6_method")),
        "ipv6.never-default",
        "yes",
        "ipv6.ignore-auto-routes",
        "yes",
    ]
    code, stdout, stderr = run_command_full(nmcli_cmd(modify_args))
    append_command_output(stdout_parts, stderr_parts, stdout, stderr)
    if code != 0:
        return code, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()

    if hotspot_security != "open":
        key_mgmt = "sae" if hotspot_security == "wpa3-personal" else "wpa-psk"
        security_args = [
            "connection",
            "modify",
            connection,
            "802-11-wireless-security.key-mgmt",
            key_mgmt,
            "802-11-wireless-security.proto",
            "rsn",
            "802-11-wireless-security.pairwise",
            "ccmp",
            "802-11-wireless-security.group",
            "ccmp",
            "802-11-wireless-security.pmf",
            "3" if hotspot_security == "wpa3-personal" else "2",
        ]
        if submitted_password or not connection_exists:
            security_args.extend(["802-11-wireless-security.psk", password])
        elif not get_connection_secret(connection, "802-11-wireless-security.psk"):
            return 1, "\n".join(stdout_parts).strip(), "Hotspot profile has no saved password. Enter a new hotspot password and apply again."
        code, stdout, stderr = run_command_full(nmcli_cmd(security_args))
        append_command_output(stdout_parts, stderr_parts, stdout, stderr)
        if code != 0:
            return code, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()
    else:
        code, stdout, stderr = run_command_full(
            nmcli_cmd(
                [
                    "connection",
                    "modify",
                    connection,
                    "802-11-wireless-security.key-mgmt",
                    "",
                    "802-11-wireless-security.proto",
                    "",
                    "802-11-wireless-security.pairwise",
                    "",
                    "802-11-wireless-security.group",
                    "",
                    "802-11-wireless-security.pmf",
                    "0",
                    "802-11-wireless-security.psk",
                    "",
                ]
            )
        )
        append_command_output(stdout_parts, stderr_parts, stdout, stderr)
        if code != 0:
            return code, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()

    set_wifi_autoconnect_for_mode(connection)
    down_code, down_stdout, down_stderr = run_command_full(nmcli_cmd(["connection", "down", connection]))
    append_command_output(stdout_parts, stderr_parts, down_stdout, "")
    if down_code != 0 and "not active" not in down_stderr.lower() and "no active connection" not in down_stderr.lower():
        append_command_output(stdout_parts, stderr_parts, "", down_stderr)
    code, stdout, stderr = run_command_full(nmcli_cmd(["connection", "up", connection]))
    append_command_output(stdout_parts, stderr_parts, stdout, stderr)
    if code != 0:
        return code, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()
    if wifi_cfg("ipv6_method") in {"shared", "manual"}:
        runtime_code, runtime_stdout, runtime_stderr = enable_wifi_hotspot_ipv6_runtime(interface)
    else:
        runtime_code, runtime_stdout, runtime_stderr = disable_wifi_hotspot_ipv6_runtime(interface)
    append_command_output(stdout_parts, stderr_parts, runtime_stdout, runtime_stderr)
    return runtime_code, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()


def configure_wifi_client(nmcli_cmd) -> tuple[int, str, str]:
    interface = wifi_cfg("interface")
    disable_wifi_hotspot_ipv6_runtime(interface)
    ssid = wifi_cfg("ssid")
    if not ssid:
        return 1, "", "No Wi-Fi SSID configured"
    password = wifi_cfg("password").strip()
    existing_connection = find_wifi_connection_for_ssid(ssid, interface)
    if existing_connection and not password:
        cmd = nmcli_cmd(["connection", "up", existing_connection])
    else:
        cmd = nmcli_cmd(["device", "wifi", "connect", ssid, "ifname", interface])
        if password:
            cmd.extend(["password", password])
    code, stdout, stderr = run_command_full(cmd)
    if code != 0:
        return code, stdout, stderr

    active_connection = get_nmcli_device_status(interface).get("nm_connection", "")
    if not active_connection or active_connection == "--":
        active_connection = existing_connection
    if not active_connection or active_connection == "--":
        return 0, stdout, stderr
    ipv4_method = wifi_cfg("ipv4_method") or "auto"
    ipv6_method = wifi_cfg("ipv6_method") or "auto"
    ipv4_addresses = wifi_ipv4_addresses_for_mode("client", ipv4_method)
    ipv6_addresses = wifi_ipv6_addresses_for_mode("client", ipv6_method)
    route_metric, never_default = wifi_client_route_policy()
    modify_args = [
        "connection",
        "modify",
        active_connection,
        "connection.interface-name",
        interface,
        "connection.autoconnect",
        "yes",
        "802-11-wireless.powersave",
        "2",
        "ipv4.method",
        ipv4_method,
        "ipv4.addresses",
        ipv4_addresses,
        "ipv4.gateway",
        "",
        "ipv4.routes",
        "",
        "ipv4.route-metric",
        route_metric,
        "ipv4.never-default",
        never_default,
        "ipv4.ignore-auto-routes",
        "no",
        "ipv4.ignore-auto-dns",
        "no",
        "ipv4.dns",
        "",
        "ipv4.dns-search",
        "",
        "ipv6.method",
        ipv6_method,
        "ipv6.addresses",
        ipv6_addresses,
        "ipv6.gateway",
        "",
        "ipv6.routes",
        "",
        "ipv6.route-metric",
        route_metric,
        "ipv6.never-default",
        never_default,
        "ipv6.ignore-auto-routes",
        "no",
        "ipv6.ignore-auto-dns",
        "no",
        "ipv6.dns",
        "",
        "ipv6.dns-search",
        "",
    ]
    code2, stdout2, stderr2 = run_command_full(nmcli_cmd(modify_args))
    if code2 != 0:
        return code2, "\n".join(filter(None, [stdout, stdout2])).strip(), "\n".join(filter(None, [stderr, stderr2])).strip()

    set_wifi_autoconnect_for_mode(active_connection)
    down_code, down_stdout, down_stderr = run_command_full(nmcli_cmd(["connection", "down", active_connection]))
    up_code, up_stdout, up_stderr = run_command_full(nmcli_cmd(["connection", "up", active_connection]))
    final_code = up_code if up_code != 0 else down_code
    return (
        final_code,
        "\n".join(filter(None, [stdout, stdout2, down_stdout, up_stdout])).strip(),
        "\n".join(filter(None, [stderr, stderr2, down_stderr, up_stderr])).strip(),
    )


def apply_wifi_mode() -> tuple[int, str, str]:
    interface = wifi_cfg("interface")
    normalize_wifi_config()
    mode = wifi_cfg("mode")
    code, stdout, stderr = set_nmcli_managed(interface)
    if code != 0:
        return code, stdout, stderr

    use_host_nmcli = host_nmcli_available()
    nmcli_cmd = host_nmcli_command if use_host_nmcli else lambda args: ["nmcli"] + args
    run_command_full(["ip", "link", "set", "dev", interface, "up"])
    run_command_full(nmcli_cmd(["radio", "wifi", "on"]))

    if mode == "hotspot":
        return configure_wifi_hotspot("portal-hotspot", nmcli_cmd)
    return configure_wifi_client(nmcli_cmd)


def set_wifi_power(state: str) -> tuple[int, str, str]:
    interface = wifi_cfg("interface")
    use_host_nmcli = host_nmcli_available()
    nmcli_cmd = host_nmcli_command if use_host_nmcli else lambda args: ["nmcli"] + args

    if state == "off":
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        disable_wifi_hotspot_ipv6_runtime(interface)
        for cmd in (
            nmcli_cmd(["device", "disconnect", interface]),
            ["ip", "link", "set", "dev", interface, "down"],
            nmcli_cmd(["radio", "wifi", "off"]),
        ):
            code, stdout, stderr = run_command_full(cmd)
            if stdout:
                stdout_parts.append(stdout)
            if stderr:
                stderr_parts.append(stderr)
            if code != 0 and "not active" not in stderr.lower():
                return code, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()
        return 0, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()

    stdout_parts = []
    stderr_parts = []
    for cmd in (
        nmcli_cmd(["radio", "wifi", "on"]),
        nmcli_cmd(["device", "set", interface, "managed", "yes"]),
        ["ip", "link", "set", "dev", interface, "up"],
    ):
        code, stdout, stderr = run_command_full(cmd)
        if stdout:
            stdout_parts.append(stdout)
        if stderr:
            stderr_parts.append(stderr)
        if code != 0:
            return code, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()
    return 0, "\n".join(stdout_parts).strip(), "\n".join(stderr_parts).strip()


def restore_wifi_mode_after_startup() -> None:
    time.sleep(8)
    try:
        apply_wifi_mode()
        apply_wifi_client_trust_policy()
    except Exception:
        pass


@app.on_event("startup")
def startup_restore_wifi_mode() -> None:
    if WIFI_RESTORE_ON_STARTUP:
        threading.Thread(target=restore_wifi_mode_after_startup, daemon=True).start()
    threading.Thread(target=device_led_policy_loop, daemon=True).start()
    threading.Thread(target=device_act_disk_activity_loop, daemon=True).start()


def configure_main_lan() -> tuple[int, str, str]:
    interface = get_main_lan_interface()
    nmcli_cmd = host_nmcli_command if host_nmcli_available() else (lambda args: ["nmcli"] + args)

    def apply_static_fallback(reason: str) -> tuple[int, str, str]:
        commands = [
            ["ip", "link", "set", "dev", interface, "up"],
            ["ip", "-4", "addr", "flush", "dev", interface],
            ["ip", "-4", "addr", "add", lan_cfg("ipv4_address"), "dev", interface],
        ]
        if lan_cfg("ipv6_mode") != "disabled":
            commands.extend(
                [
                    ["ip", "-6", "addr", "flush", "dev", interface, "scope", "global"],
                    ["ip", "-6", "addr", "add", lan_cfg("ipv6_address"), "dev", interface],
                ]
            )

        stdout_parts = []
        stderr_parts = [reason]
        for cmd in commands:
            code, stdout, stderr = run_command_full(cmd)
            if stdout:
                stdout_parts.append(stdout)
            if stderr:
                stderr_parts.append(stderr)
            if code != 0:
                return code, "\n".join(stdout_parts), "\n".join(stderr_parts)

        stderr_parts.append("Applied static fallback. DHCP/shared automation still needs host-side NetworkManager compatibility.")
        return 0, "\n".join(stdout_parts), "\n".join(stderr_parts)

    if not host_nmcli_available() and not command_exists("nmcli"):
        return apply_static_fallback("nmcli is not available in the backend container")

    connection_name = "main-lan"
    dns_servers = lan_cfg("dns_servers")
    dns_search = lan_cfg("dns_search")

    run_command_full(nmcli_cmd(["device", "set", interface, "managed", "yes"]))

    existing = run_command(nmcli_cmd(["-g", "connection.id", "connection", "show", connection_name]))
    base_cmd = nmcli_cmd(["connection", "modify" if existing else "add"])
    if existing:
        cmd = base_cmd + [connection_name]
    else:
        cmd = base_cmd + ["type", "ethernet", "ifname", interface, "con-name", connection_name]

    settings = [
        "connection.autoconnect", nm_bool(lan_cfg("autoconnect"), "yes"),
        "connection.interface-name", interface,
        "ipv4.method", lan_cfg("ipv4_mode"),
        "ipv4.addresses", lan_cfg("ipv4_address"),
        "ipv4.never-default", nm_bool(lan_cfg("never_default"), "yes"),
        "ipv4.ignore-auto-routes", nm_bool(lan_cfg("ignore_auto_routes"), "yes"),
        "ipv6.method", "manual" if lan_cfg("ipv6_mode") != "disabled" else "disabled",
        "ipv6.addresses", lan_cfg("ipv6_address") if lan_cfg("ipv6_mode") != "disabled" else "",
        "ipv6.never-default", nm_bool(lan_cfg("never_default"), "yes"),
        "ipv6.ignore-auto-routes", nm_bool(lan_cfg("ignore_auto_routes"), "yes"),
    ]
    mtu = nm_optional_int(lan_cfg("mtu"), 68, 9000)
    route_metric = nm_optional_int(lan_cfg("route_metric"), 1, 9999)
    if mtu:
        settings.extend(["802-3-ethernet.mtu", mtu])
    if route_metric:
        settings.extend(["ipv4.route-metric", route_metric, "ipv6.route-metric", route_metric])
    if lan_cfg("ipv4_mode") != "shared":
        settings.extend(["ipv4.dns", dns_servers, "ipv4.dns-search", dns_search])
    code, stdout, stderr = run_command_full(cmd + settings)
    if code != 0:
        return apply_static_fallback(stderr or "NetworkManager profile apply failed")

    code, stdout, stderr = run_command_full(nmcli_cmd(["connection", "up", connection_name]))
    if code != 0:
        return apply_static_fallback(stderr or "Failed to bring main-lan up")
    return code, stdout, stderr

@app.post("/api/main-lan/preview")
def main_lan_preview(payload: dict = Body(default={})):
    return {"ok": True, "commands": build_main_lan_preview(payload)}


@app.post("/api/service-lan/preview")
def service_lan_preview(payload: dict = Body(default={})):
    return {"ok": True, "commands": build_service_lan_preview(payload)}


@app.post("/api/wifi/preview")
def wifi_preview(payload: dict = Body(default={})):
    plan = wifi_plan(payload)
    return {"ok": bool(plan.get("ok")), "commands": build_wifi_preview(payload), "warnings": plan.get("warnings", []), "errors": plan.get("errors", []), "notes": plan.get("notes", [])}


def shell_preview(cmd: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in cmd)


def build_main_lan_preview(payload: dict | None = None) -> list[str]:
    config = dict(MAIN_LAN_CONFIG)
    if payload:
        for key, value in payload.items():
            if key in config and isinstance(value, str):
                config[key] = value.strip()
    interface = get_main_lan_interface()
    return [
        shell_preview(nmcli_command(["device", "set", interface, "managed", "yes"])),
        shell_preview(
            nmcli_command(
                [
                    "connection",
                    "modify",
                    "main-lan",
                    "connection.autoconnect",
                    nm_bool(config.get("autoconnect", "yes"), "yes"),
                    "connection.interface-name",
                    interface,
                    "ipv4.method",
                    config.get("ipv4_mode", ""),
                    "ipv4.addresses",
                    config.get("ipv4_address", ""),
                    "ipv4.never-default",
                    nm_bool(config.get("never_default", "yes"), "yes"),
                    "ipv4.ignore-auto-routes",
                    nm_bool(config.get("ignore_auto_routes", "yes"), "yes"),
                    "ipv6.method",
                    "manual" if config.get("ipv6_mode") != "disabled" else "disabled",
                    "ipv6.addresses",
                    config.get("ipv6_address", "") if config.get("ipv6_mode") != "disabled" else "",
                    "ipv6.never-default",
                    nm_bool(config.get("never_default", "yes"), "yes"),
                    "ipv6.ignore-auto-routes",
                    nm_bool(config.get("ignore_auto_routes", "yes"), "yes"),
                ]
                + (["802-3-ethernet.mtu", nm_optional_int(config.get("mtu", ""), 68, 9000)] if nm_optional_int(config.get("mtu", ""), 68, 9000) else [])
                + (
                    ["ipv4.route-metric", nm_optional_int(config.get("route_metric", ""), 1, 9999), "ipv6.route-metric", nm_optional_int(config.get("route_metric", ""), 1, 9999)]
                    if nm_optional_int(config.get("route_metric", ""), 1, 9999)
                    else []
                )
            )
        ),
        shell_preview(nmcli_command(["connection", "up", "main-lan"])),
    ]


def build_service_lan_preview(payload: dict | None = None) -> list[str]:
    env = service_lan_command_env()
    config = dict(SERVICE_LAN_CONFIG)
    if payload:
        mapping = {
            "ipv4_gateway": "SERVICE_LAN_IPV4_GATEWAY",
            "ipv4_subnet": "SERVICE_LAN_IPV4_SUBNET",
            "dhcp_range": "SERVICE_LAN_DHCP_RANGE",
            "ipv6_gateway": "SERVICE_LAN_IPV6_GATEWAY",
            "ipv6_prefix": "SERVICE_LAN_IPV6_PREFIX",
            "enable_ipv4": "SERVICE_LAN_ENABLE_IPV4",
            "enable_ipv6": "SERVICE_LAN_ENABLE_IPV6",
        }
        for key, env_key in mapping.items():
            value = payload.get(key)
            if isinstance(value, str):
                env[env_key] = value.strip()
        for key, value in payload.items():
            if key in config and isinstance(value, str):
                config[key] = value.strip()
    interface = config.get("interface") or get_service_lan_interface()
    ipv4_enabled = config.get("enable_ipv4") == "true" or config.get("ipv4_mode") == "shared"
    ipv6_enabled = config.get("enable_ipv6") == "true" or config.get("ipv6_mode") == "routed"
    mtu = nm_optional_int(config.get("mtu", ""), 68, 9000)
    route_metric = nm_optional_int(config.get("route_metric", ""), 1, 9999)
    nm_settings = [
        "connection", "modify", "service-lan",
        "connection.autoconnect", nm_bool(config.get("autoconnect", "yes"), "yes"),
        "connection.interface-name", interface,
        "ipv4.method", "shared" if ipv4_enabled else "disabled",
        "ipv4.never-default", nm_bool(config.get("never_default", "yes"), "yes"),
        "ipv4.ignore-auto-routes", nm_bool(config.get("ignore_auto_routes", "yes"), "yes"),
        "ipv6.method", "manual" if ipv6_enabled else "disabled",
        "ipv6.never-default", nm_bool(config.get("never_default", "yes"), "yes"),
        "ipv6.ignore-auto-routes", nm_bool(config.get("ignore_auto_routes", "yes"), "yes"),
    ]
    if mtu:
        nm_settings.extend(["802-3-ethernet.mtu", mtu])
    if route_metric:
        nm_settings.extend(["ipv4.route-metric", route_metric, "ipv6.route-metric", route_metric])
    return [
        shell_preview(nmcli_command(nm_settings)),
        f"{' '.join(f'{key}={shlex.quote(value)}' for key, value in env.items())} /usr/local/bin/service-lan-inet-off.sh",
        f"{' '.join(f'{key}={shlex.quote(value)}' for key, value in env.items())} /usr/local/bin/service-lan-inet-on.sh",
    ]


def build_wifi_preview(payload: dict | None = None) -> list[str]:
    config = dict(WIFI_CONFIG)
    if payload:
        for key, value in payload.items():
            if key in config and isinstance(value, str):
                config[key] = value.strip()
    mode = normalize_wifi_mode(config.get("mode", "client"))
    config["band"] = normalize_wifi_band(config.get("band", "auto"))
    config["channel"] = normalize_wifi_channel(config.get("channel", "auto"), config["band"])
    interface = config.get("interface", "wlan0")
    preview = [
        shell_preview(nmcli_command(["device", "set", interface, "managed", "yes"])),
        shell_preview(["ip", "link", "set", "dev", interface, "up"]),
        shell_preview(nmcli_command(["radio", "wifi", "on"])),
    ]
    if mode == "hotspot":
        if can_set_wifi_regdom():
            preview.append(f"printf %s {shlex.quote(normalize_country_code(config.get('country', 'DE')))} > /host/sys/module/cfg80211/parameters/ieee80211_regdom")
        preview.extend(
            [
                shell_preview(nmcli_command(["connection", "delete", "portal-hotspot"])),
                shell_preview(
                    nmcli_command(
                        [
                            "connection",
                            "add",
                            "type",
                            "wifi",
                            "ifname",
                            interface,
                            "con-name",
                            "portal-hotspot",
                            "autoconnect",
                            "yes",
                            "ssid",
                            config.get("hotspot_ssid", ""),
                        ]
                    )
                ),
                shell_preview(
                    nmcli_command(
                        [
                            "connection",
                            "modify",
                            "portal-hotspot",
                            "802-11-wireless.mode",
                            "ap",
                            "802-11-wireless.band",
                            wifi_band_to_nm(config.get("band", "auto")),
                            "802-11-wireless.channel",
                            wifi_channel_value(config.get("channel", "auto"), config.get("band", "auto")),
                            "802-11-wireless.powersave",
                            "2",
                            "ipv4.method",
                            config.get("ipv4_method", "shared"),
                            "ipv4.addresses",
                            config.get("ipv4_address", "10.42.0.1/24") if config.get("ipv4_method") == "manual" else "",
                            "ipv4.never-default",
                            "yes",
                            "ipv4.ignore-auto-routes",
                            "yes",
                            "ipv6.method",
                            config.get("ipv6_method", "disabled"),
                            "ipv6.addresses",
                            config.get("ipv6_address", "fd42:42::1/64") if config.get("ipv6_method") == "manual" else "",
                            "ipv6.never-default",
                            "yes",
                            "ipv6.ignore-auto-routes",
                            "yes",
                        ]
                    )
                ),
                shell_preview(nmcli_command(["connection", "up", "portal-hotspot"])),
            ]
        )
        if config.get("hotspot_security") != "open":
            preview.insert(
                -1,
                shell_preview(
                    nmcli_command(
                        [
                            "connection",
                            "modify",
                            "portal-hotspot",
                            "802-11-wireless-security.key-mgmt",
                            "sae" if config.get("hotspot_security") == "wpa3-personal" else "wpa-psk",
                            "802-11-wireless-security.proto",
                            "rsn",
                            "802-11-wireless-security.pairwise",
                            "ccmp",
                            "802-11-wireless-security.group",
                            "ccmp",
                            "802-11-wireless-security.pmf",
                            "3" if config.get("hotspot_security") == "wpa3-personal" else "2",
                            "802-11-wireless-security.psk",
                            "<redacted-or-existing>",
                        ]
                    )
                ),
            )
        preview.insert(-1, f"{shell_preview(nmcli_command(['connection', 'down', 'portal-hotspot']))} || true")
    else:
        preview.append(
            shell_preview(
                nmcli_command(
                    [
                        "device",
                        "wifi",
                        "connect",
                        config.get("ssid", ""),
                        "ifname",
                        interface,
                    ]
                )
            )
        )
    return preview


@app.get("/api/pihole/status")
def pihole_status():
    return get_pihole_status()


@app.get("/api/pihole/networks")
def pihole_networks():
    prefs = pihole_network_preferences()
    return {
        "main_lan": prefs["main_lan"],
        "service_lan": prefs["service_lan"],
        "wifi": prefs["wifi"],
        "forwarding_enabled": pihole_forwarding_enabled(),
    }


@app.post("/api/pihole/networks")
def pihole_networks_update(payload: dict = Body(...)):
    create_prewrite_backup("pihole-networks-update")
    for key, target in (
        ("main_lan", MAIN_LAN_CONFIG),
        ("service_lan", SERVICE_LAN_CONFIG),
        ("wifi", WIFI_CONFIG),
    ):
        if key in payload:
            enabled = cfg_flag(payload.get(key, False))
            target["use_pihole_dns"] = "true" if enabled else "false"
    code, stdout, stderr = apply_pihole_preferences()
    if code != 0:
        raise HTTPException(status_code=500, detail={"code": code, "stdout": stdout, "stderr": stderr})
    save_runtime_config()
    return {"ok": True, "preferences": pihole_network_preferences(), "stdout": stdout, "stderr": stderr}


@app.get("/api/netalert/status")
def netalert_status():
    return get_netalert_status()


@app.post("/api/netalert/install")
def netalert_install():
    if not docker_available():
        raise HTTPException(status_code=500, detail="Docker is not available on the host")
    create_prewrite_backup("netalert-install")
    command = docker_cli_command(["compose", "-f", NETALERTX_COMPOSE_FILE, "up", "-d", "netalertx"])
    code, stdout, stderr = run_command_full(command)
    if code != 0:
        raise HTTPException(status_code=500, detail={"code": code, "stdout": stdout, "stderr": stderr})
    return {"ok": True, "stdout": stdout, "stderr": stderr}


@app.post("/api/netalert/sync")
def netalert_sync():
    create_prewrite_backup("netalert-sync")
    result = sync_netalertx_topology(restart=True)
    if not result.get("ok"):
        raise HTTPException(status_code=500, detail=result)
    return result


@app.get("/api/service-lan/clients")
def service_lan_clients():
    def load() -> list[dict[str, str]]:
        clients = get_all_lan_clients()
        clients = [client for client in clients if client.get("state", "").upper() != "FAILED"]
        return summarize_wifi_clients(clients)
    names = ",".join(sorted(iface.get("name", "") for iface in get_lan_interfaces()))
    return cached_read(f"local_lan_clients:{names}", 5, load)


@app.get("/api/local-lan/clients")
def local_lan_clients():
    return service_lan_clients()


@app.get("/api/wifi/clients")
def wifi_clients():
    return get_wifi_clients()


@app.get("/api/service-lan/status")
def service_lan_status():
    ruleset = run_command(["nft", "list", "ruleset"])
    interface = get_service_lan_interface(ruleset)
    target = get_interface_data(interface)
    target.update(get_nmcli_device_status(interface))
    filter_enabled = has_nft_table(ruleset, "inet", "service_lan")
    ipv4_enabled = has_nft_table(ruleset, "ip", "service_lan_nat_v4")
    ipv6_enabled = has_nft_table(ruleset, "ip6", "service_lan_nat_v6")
    legacy_ipv4_enabled = has_nft_table(ruleset, "ip", "service_lan_nat")
    block_enabled = has_nft_table(ruleset, "inet", "service_lan_block")
    ipv4_active = ipv4_enabled or legacy_ipv4_enabled
    connection_mode = get_service_lan_connection_mode()
    dhcp_active = dhcp_listener_active()
    ra_active = ipv6_ra_active()
    forwarding_v4 = forwarding_active(4)
    forwarding_v6 = forwarding_active(6)
    default_v4 = has_default_route(4)
    default_v6 = has_default_route(6)
    interface_v6_disabled = interface_ipv6_disabled(interface)
    interface_conflict = same_physical_lan_interface(get_main_lan_interface(), interface)
    ipv4_path_ready = (
        service_lan_cfg("enable_ipv4") == "true"
        and forwarding_v4
        and default_v4
        and (filter_enabled or ipv4_active or connection_mode == "shared")
    )
    ipv6_path_ready = (
        service_lan_cfg("enable_ipv6") == "true"
        and filter_enabled
        and ipv6_enabled
        and forwarding_v6
        and default_v6
        and ra_active
        and not interface_v6_disabled
    )
    internet_enabled = not block_enabled and (ipv4_path_ready or ipv6_path_ready)

    return {
        "name": service_lan_cfg("name") or "Device LAN",
        "role": service_lan_cfg("role"),
        "interface": interface,
        "target_interface": interface,
        "target_interface_status": target,
        "available_interfaces": [iface["name"] for iface in ethernet_candidates()],
        "role_description": role_description(service_lan_cfg("role")),
        "connection_mode_ipv4": connection_mode,
        "ipv4_mode": "shared" if service_lan_cfg("enable_ipv4") == "true" else "disabled",
        "ipv4_enabled": service_lan_cfg("enable_ipv4") == "true",
        "ipv6_enabled": service_lan_cfg("enable_ipv6") == "true",
        "gateway_ipv4": service_lan_cfg("ipv4_gateway") if service_lan_cfg("enable_ipv4") == "true" else "",
        "ipv4_subnet": service_lan_cfg("ipv4_subnet") if service_lan_cfg("enable_ipv4") == "true" else "",
        "dhcp_range_ipv4": service_lan_cfg("dhcp_range") if service_lan_cfg("enable_ipv4") == "true" else "",
        "dhcp_listener_active": dhcp_active,
        "ipv6_mode": "routed" if service_lan_cfg("enable_ipv6") == "true" else "disabled",
        "gateway_ipv6": service_lan_cfg("ipv6_gateway") if service_lan_cfg("enable_ipv6") == "true" else "",
        "prefix_ipv6": service_lan_cfg("ipv6_prefix") if service_lan_cfg("enable_ipv6") == "true" else "",
        "dns_servers": [item.strip() for item in service_lan_cfg("dns_servers").split(",") if item.strip()],
        "dns_search": service_lan_cfg("dns_search"),
        "use_pihole_dns": cfg_flag(service_lan_cfg("use_pihole_dns")),
        "mtu": service_lan_cfg("mtu"),
        "autoconnect": service_lan_cfg("autoconnect"),
        "route_metric": service_lan_cfg("route_metric"),
        "never_default": service_lan_cfg("never_default"),
        "ignore_auto_routes": service_lan_cfg("ignore_auto_routes"),
        "interface_ipv6_disabled": interface_v6_disabled,
        "forwarding_ipv4_active": forwarding_v4,
        "forwarding_ipv6_active": forwarding_v6,
        "upstream_ipv4_default_route": default_v4,
        "upstream_ipv6_default_route": default_v6,
        "router_advertisements_active": ra_active,
        "firewall_ipv4_active": ipv4_active,
        "firewall_ipv6_active": ipv6_enabled,
        "firewall_filter_active": filter_enabled,
        "firewall_block_active": block_enabled,
        "ipv4_path_ready": ipv4_path_ready,
        "ipv6_path_ready": ipv6_path_ready,
        "internet_enabled": internet_enabled,
        "interface_conflict": interface_conflict,
        "notes": [
            role_description(service_lan_cfg("role")),
            "shared = DHCP + NAT for IPv4 clients on this port",
            "routed = IPv6 forwarding and router advertisements for clients",
            "plugging in a USB Ethernet adapter gives LocalPlane another port it can discover",
        ] + (["choose a different physical interface from Main LAN to keep Device LAN isolated"] if interface_conflict else []),
    }


@app.get("/api/main-lan/status")
@app.get("/api/lan/profile")
def lan_profile():
    target_interface = get_main_lan_interface()
    target = get_interface_data(target_interface)
    target.update(get_nmcli_device_status(target_interface))
    ruleset = run_command(["nft", "list", "ruleset"])
    blocked = interface_block_active(ruleset, target_interface)
    interface_conflict = same_physical_lan_interface(target_interface, get_service_lan_interface())
    connection = get_nmcli_connection_status("main-lan")

    return {
        "name": lan_cfg("name") or "Main LAN",
        "role": normalize_lan_role(lan_cfg("role")),
        "target_interface": target_interface,
        "target_interface_status": target,
        "available_interfaces": [iface["name"] for iface in ethernet_candidates()],
        "role_description": role_description(lan_cfg("role")),
        "internet_enabled": not blocked,
        "blocked_by_portal": blocked,
        "interface_conflict": interface_conflict,
        "ipv4_mode": lan_cfg("ipv4_mode"),
        "ipv4_address": lan_cfg("ipv4_address"),
        "ipv4_subnet": lan_cfg("ipv4_subnet"),
        "dhcp_range": lan_cfg("dhcp_range"),
        "ipv6_mode": lan_cfg("ipv6_mode"),
        "ipv6_address": lan_cfg("ipv6_address"),
        "ipv6_prefix": lan_cfg("ipv6_prefix"),
        "dns_servers": [item.strip() for item in lan_cfg("dns_servers").split(",") if item.strip()],
        "dns_search": lan_cfg("dns_search"),
        "use_pihole_dns": cfg_flag(lan_cfg("use_pihole_dns")),
        "mtu": lan_cfg("mtu"),
        "autoconnect": lan_cfg("autoconnect"),
        "route_metric": lan_cfg("route_metric"),
        "never_default": lan_cfg("never_default"),
        "ignore_auto_routes": lan_cfg("ignore_auto_routes"),
        "nmcli_available": nmcli_available(),
        "connection": connection,
        "notes": [
            role_description(lan_cfg("role")),
            "shared = DHCP + NAT for local clients",
            "manual = static LAN without DHCP/NAT automation",
            "plugging in a USB Ethernet adapter gives the portal another port it can auto-assign",
        ] + (["choose a different physical interface from Device LAN to keep Main LAN separate"] if interface_conflict else []),
    }


@app.post("/api/main-lan/apply")
def main_lan_apply():
    create_prewrite_backup("main-lan-apply")
    code, stdout, stderr = configure_main_lan()
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": stdout, "stderr": stderr or "Main LAN apply failed"},
        )
    role_code, role_stdout, role_stderr = apply_interface_role_policy(get_main_lan_interface(), lan_cfg("role"))
    if role_code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": role_code, "stdout": "\n".join([stdout, role_stdout]).strip(), "stderr": "\n".join([stderr, role_stderr]).strip() or "Main LAN role policy apply failed"},
        )
    sync_netalertx_topology_safe()
    return {"ok": True, "code": code, "stdout": "\n".join([stdout, role_stdout]).strip(), "stderr": "\n".join([stderr, role_stderr]).strip()}


@app.post("/api/main-lan/restart")
def main_lan_restart():
    create_prewrite_backup("main-lan-restart")
    nmcli_cmd = host_nmcli_command if host_nmcli_available() else (lambda args: ["nmcli"] + args)
    if not host_nmcli_available() and not command_exists("nmcli"):
        raise HTTPException(status_code=500, detail="nmcli is not available")
    code, stdout, stderr = run_command_full(nmcli_cmd(["connection", "down", "main-lan"]))
    code2, stdout2, stderr2 = run_command_full(nmcli_cmd(["connection", "up", "main-lan"]))
    if code2 != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code2, "stdout": "\n".join([stdout, stdout2]).strip(), "stderr": "\n".join([stderr, stderr2]).strip()},
        )
    return {"ok": True, "stdout": "\n".join([stdout, stdout2]).strip(), "stderr": "\n".join([stderr, stderr2]).strip()}


def service_lan_command_env() -> dict[str, str]:
    return {
        "SERVICE_LAN_INTERFACE": get_service_lan_interface(),
        "SERVICE_LAN_IPV4_GATEWAY": service_lan_cfg("ipv4_gateway"),
        "SERVICE_LAN_IPV4_SUBNET": service_lan_cfg("ipv4_subnet"),
        "SERVICE_LAN_DHCP_RANGE": service_lan_cfg("dhcp_range"),
        "SERVICE_LAN_IPV6_GATEWAY": service_lan_cfg("ipv6_gateway"),
        "SERVICE_LAN_IPV6_PREFIX": service_lan_cfg("ipv6_prefix"),
        "SERVICE_LAN_ENABLE_IPV4": service_lan_cfg("enable_ipv4"),
        "SERVICE_LAN_ENABLE_IPV6": service_lan_cfg("enable_ipv6"),
    }


def service_lan_ipv4_address() -> str:
    gateway = service_lan_cfg("ipv4_gateway")
    subnet = service_lan_cfg("ipv4_subnet")
    if not gateway or not subnet or "/" not in subnet:
        return ""
    return f"{gateway}/{subnet.split('/', 1)[1]}"


def service_lan_ipv6_address() -> str:
    gateway = service_lan_cfg("ipv6_gateway")
    prefix = service_lan_cfg("ipv6_prefix")
    if not gateway or not prefix or "/" not in prefix:
        return ""
    return f"{gateway}/{prefix.split('/', 1)[1]}"


def sync_service_lan_connection() -> tuple[int, str, str]:
    if not nmcli_available():
        return 0, "", ""
    interface = get_service_lan_interface()
    connection_name = "service-lan"
    nmcli_cmd = host_nmcli_command if host_nmcli_available() else (lambda args: ["nmcli"] + args)

    run_command_full(nmcli_cmd(["device", "set", interface, "managed", "yes"]))
    existing = run_command(nmcli_cmd(["-g", "connection.id", "connection", "show", connection_name]))
    base_cmd = nmcli_cmd(["connection", "modify" if existing else "add"])
    if existing:
        cmd = base_cmd + [connection_name]
    else:
        cmd = base_cmd + ["type", "ethernet", "ifname", interface, "con-name", connection_name]

    ipv4_enabled = service_lan_cfg("enable_ipv4") == "true"
    ipv6_enabled = service_lan_cfg("enable_ipv6") == "true"
    settings = [
        "connection.autoconnect", nm_bool(service_lan_cfg("autoconnect"), "yes"),
        "connection.interface-name", interface,
        "ipv4.method", "shared" if ipv4_enabled else "disabled",
        "ipv4.addresses", service_lan_ipv4_address() if ipv4_enabled else "",
        "ipv4.never-default", nm_bool(service_lan_cfg("never_default"), "yes"),
        "ipv4.ignore-auto-routes", nm_bool(service_lan_cfg("ignore_auto_routes"), "yes"),
        "ipv6.method", "manual" if ipv6_enabled else "disabled",
        "ipv6.addresses", service_lan_ipv6_address() if ipv6_enabled else "",
        "ipv6.never-default", nm_bool(service_lan_cfg("never_default"), "yes"),
        "ipv6.ignore-auto-routes", nm_bool(service_lan_cfg("ignore_auto_routes"), "yes"),
    ]
    mtu = nm_optional_int(service_lan_cfg("mtu"), 68, 9000)
    route_metric = nm_optional_int(service_lan_cfg("route_metric"), 1, 9999)
    if mtu:
        settings.extend(["802-3-ethernet.mtu", mtu])
    if route_metric:
        settings.extend(["ipv4.route-metric", route_metric, "ipv6.route-metric", route_metric])
    code, stdout, stderr = run_command_full(cmd + settings)
    if code != 0:
        return code, stdout, stderr
    down_code, down_stdout, down_stderr = run_command_full(nmcli_cmd(["connection", "down", connection_name]))
    up_code, up_stdout, up_stderr = run_command_full(nmcli_cmd(["connection", "up", connection_name]))
    final_code = up_code
    return (
        final_code,
        "\n".join(part for part in [stdout, down_stdout, up_stdout] if part).strip(),
        "\n".join(part for part in [stderr, down_stderr, up_stderr] if part).strip(),
    )


@app.post("/api/service-lan/apply")
def service_lan_apply():
    create_prewrite_backup("service-lan-apply")
    env = service_lan_command_env()
    stdout_parts = []
    stderr_parts = []
    sync_code, sync_stdout, sync_stderr = sync_service_lan_connection()
    if sync_stdout:
        stdout_parts.append(sync_stdout)
    if sync_stderr:
        stderr_parts.append(sync_stderr)
    if sync_code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": sync_code, "stdout": "\n".join(stdout_parts).strip(), "stderr": "\n".join(stderr_parts).strip() or "Device LAN connection sync failed"},
        )
    run_command_full(
        ["/usr/local/bin/service-lan-inet-off.sh"],
        env={
            "SERVICE_LAN_INTERFACE": env["SERVICE_LAN_INTERFACE"],
            "SERVICE_LAN_IPV6_GATEWAY": env["SERVICE_LAN_IPV6_GATEWAY"],
            "SERVICE_LAN_IPV6_PREFIX": env["SERVICE_LAN_IPV6_PREFIX"],
        },
    )
    if service_lan_cfg("enable_ipv4") != "true" and service_lan_cfg("enable_ipv6") != "true":
        role_code, role_stdout, role_stderr = apply_interface_role_policy(get_service_lan_interface(), service_lan_cfg("role"))
        if role_stdout:
            stdout_parts.append(role_stdout)
        if role_stderr:
            stderr_parts.append(role_stderr)
        if role_code != 0:
            raise HTTPException(
                status_code=500,
                detail={"code": role_code, "stdout": "\n".join(stdout_parts).strip(), "stderr": "\n".join(stderr_parts).strip() or "Device LAN role policy apply failed"},
            )
        sync_netalertx_topology_safe()
        return {"ok": True, "stdout": "\n".join(stdout_parts).strip(), "stderr": "\n".join(stderr_parts).strip()}
    code, stdout, stderr = run_command_full(["/usr/local/bin/service-lan-inet-on.sh"], env=env)
    if stdout:
        stdout_parts.append(stdout)
    if stderr:
        stderr_parts.append(stderr)
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": "\n".join(stdout_parts).strip(), "stderr": "\n".join(stderr_parts).strip() or "Device LAN apply failed"},
        )
    role_code, role_stdout, role_stderr = apply_interface_role_policy(get_service_lan_interface(), service_lan_cfg("role"))
    if role_stdout:
        stdout_parts.append(role_stdout)
    if role_stderr:
        stderr_parts.append(role_stderr)
    if role_code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": role_code, "stdout": "\n".join(stdout_parts).strip(), "stderr": "\n".join(stderr_parts).strip() or "Device LAN role policy apply failed"},
        )
    sync_netalertx_topology_safe()
    return {"ok": True, "stdout": "\n".join(stdout_parts).strip(), "stderr": "\n".join(stderr_parts).strip()}


@app.post("/api/service-lan/restart")
def service_lan_restart():
    create_prewrite_backup("service-lan-restart")
    interface = get_service_lan_interface()
    stdout_parts = []
    stderr_parts = []
    for cmd in (["ip", "link", "set", "dev", interface, "down"], ["ip", "link", "set", "dev", interface, "up"]):
        code, stdout, stderr = run_command_full(cmd)
        if stdout:
            stdout_parts.append(stdout)
        if stderr:
            stderr_parts.append(stderr)
        if code != 0:
            raise HTTPException(status_code=500, detail={"code": code, "stdout": "\n".join(stdout_parts).strip(), "stderr": "\n".join(stderr_parts).strip()})
    return {"ok": True, "stdout": "\n".join(stdout_parts).strip(), "stderr": "\n".join(stderr_parts).strip()}


@app.post("/api/main-lan/internet/on")
def main_lan_internet_on():
    create_prewrite_backup("main-lan-internet-on")
    code, stdout, stderr = set_interface_block(get_main_lan_interface(), False)
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": stdout, "stderr": stderr or "Main LAN internet enable failed"},
        )
    return {"ok": True, "code": code, "stdout": stdout, "stderr": stderr}


@app.post("/api/main-lan/internet/off")
def main_lan_internet_off():
    create_prewrite_backup("main-lan-internet-off")
    code, stdout, stderr = set_interface_block(get_main_lan_interface(), True)
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": stdout, "stderr": stderr or "Main LAN internet disable failed"},
        )
    return {"ok": True, "code": code, "stdout": stdout, "stderr": stderr}


@app.post("/api/interfaces/{interface}/link/up")
def interface_link_up(interface: str):
    create_prewrite_backup(f"interface-{interface}-link-up")
    code, stdout, stderr = run_command_full(["ip", "link", "set", "dev", interface, "up"])
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": stdout, "stderr": stderr or f"Failed to bring {interface} up"},
        )
    return {"ok": True, "code": code, "stdout": stdout, "stderr": stderr}


@app.post("/api/interfaces/{interface}/link/down")
def interface_link_down(interface: str):
    if interface_has_default_route(interface):
        raise HTTPException(status_code=400, detail=f"{interface} has the active default route and will not be brought down")
    create_prewrite_backup(f"interface-{interface}-link-down")
    code, stdout, stderr = run_command_full(["ip", "link", "set", "dev", interface, "down"])
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": stdout, "stderr": stderr or f"Failed to bring {interface} down"},
        )
    return {"ok": True, "code": code, "stdout": stdout, "stderr": stderr}


@app.post("/api/main-lan/config")
def update_main_lan_config(payload: dict = Body(...)):
    proposed_target = str(payload.get("target_interface", get_main_lan_interface())).strip()
    if proposed_target and same_physical_lan_interface(proposed_target, get_service_lan_interface()):
        raise HTTPException(status_code=400, detail="Main LAN and Device LAN cannot use the same interface")
    create_prewrite_backup("main-lan-config")
    allowed = {
        "name",
        "target_interface",
        "role",
        "ipv4_mode",
        "ipv4_address",
        "ipv4_subnet",
        "dhcp_range",
        "ipv6_mode",
        "ipv6_address",
        "ipv6_prefix",
        "dns_servers",
        "dns_search",
        "use_pihole_dns",
        "mtu",
        "autoconnect",
        "route_metric",
        "never_default",
        "ignore_auto_routes",
    }
    for key, value in payload.items():
        if key in allowed and isinstance(value, str):
            MAIN_LAN_CONFIG[key] = normalize_lan_role(value) if key == "role" else value.strip()
    MAIN_LAN_CONFIG["target_interface"] = proposed_target or get_main_lan_interface()
    save_runtime_config()
    sync_netalertx_topology_safe(restart=False)
    return {"ok": True, "config": MAIN_LAN_CONFIG}



@app.post("/api/service-lan/config")
def update_service_lan_config(payload: dict = Body(...)):
    proposed_interface = str(payload.get("interface", get_service_lan_interface())).strip()
    if proposed_interface and same_physical_lan_interface(get_main_lan_interface(), proposed_interface):
        raise HTTPException(status_code=400, detail="Device LAN and Main LAN cannot use the same interface")
    create_prewrite_backup("service-lan-config")
    allowed = {
        "name",
        "interface",
        "role",
        "ipv4_mode",
        "ipv4_gateway",
        "ipv4_subnet",
        "dhcp_range",
        "ipv6_mode",
        "ipv6_gateway",
        "ipv6_prefix",
        "enable_ipv4",
        "enable_ipv6",
        "dns_servers",
        "dns_search",
        "use_pihole_dns",
        "mtu",
        "autoconnect",
        "route_metric",
        "never_default",
        "ignore_auto_routes",
    }
    for key, value in payload.items():
        if key in allowed and isinstance(value, str):
            SERVICE_LAN_CONFIG[key] = normalize_lan_role(value) if key == "role" else value.strip()
    SERVICE_LAN_CONFIG["interface"] = proposed_interface or get_service_lan_interface()
    if "ipv4_mode" in payload and isinstance(payload.get("ipv4_mode"), str):
        SERVICE_LAN_CONFIG["enable_ipv4"] = "true" if payload["ipv4_mode"].strip() != "disabled" else "false"
    if "ipv6_mode" in payload and isinstance(payload.get("ipv6_mode"), str):
        SERVICE_LAN_CONFIG["enable_ipv6"] = "true" if payload["ipv6_mode"].strip() != "disabled" else "false"
    save_runtime_config()
    sync_netalertx_topology_safe(restart=False)
    return {"ok": True, "config": SERVICE_LAN_CONFIG}


@app.get("/api/wifi/status")
def wifi_status():
    return get_wifi_status()


@app.post("/api/wifi/config")
def update_wifi_config(payload: dict = Body(...)):
    create_prewrite_backup("wifi-config")
    allowed = {
        "interface",
        "mode",
        "client_trust_mode",
        "uplink_preference",
        "ssid",
        "password",
        "hotspot_ssid",
        "hotspot_password",
        "hotspot_security",
        "country",
        "band",
        "channel",
        "ipv4_method",
        "ipv4_address",
        "ipv6_method",
        "ipv6_address",
        "use_pihole_dns",
    }
    for key, value in payload.items():
        if key in allowed and isinstance(value, str):
            WIFI_CONFIG[key] = value.strip()
    normalize_wifi_config()
    save_runtime_config()
    route_code, route_stdout, route_stderr = (0, "", "")
    if "uplink_preference" in payload:
        route_code, route_stdout, route_stderr = apply_wifi_route_policy_to_active_client()
        if route_code == 0:
            set_wifi_autoconnect_for_mode()
    sync_netalertx_topology_safe(restart=False)
    public_wifi_config = dict(WIFI_CONFIG)
    for key in WIFI_SECRET_KEYS:
        public_wifi_config[key] = ""
    return {"ok": True, "config": public_wifi_config, "stdout": route_stdout, "stderr": route_stderr}


@app.post("/api/wifi/scan")
def wifi_scan():
    interface = wifi_cfg("interface")
    return {"ok": True, "interface": interface, "scan": get_wifi_scan(interface, force_rescan=True)}


@app.post("/api/wifi/power/{state}")
def wifi_power(state: str):
    if state not in {"on", "off"}:
        raise HTTPException(status_code=400, detail="invalid power state")
    create_prewrite_backup(f"wifi-power-{state}")
    code, stdout, stderr = set_wifi_power(state)
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": stdout, "stderr": stderr or f"Wi-Fi power {state} failed"},
        )
    return {"ok": True, "state": state, "stdout": stdout, "stderr": stderr}


@app.post("/api/wifi/apply")
def wifi_apply():
    plan = wifi_plan()
    if plan.get("errors"):
        raise HTTPException(status_code=400, detail={"errors": plan.get("errors"), "warnings": plan.get("warnings")})
    create_prewrite_backup("wifi-apply")
    code, stdout, stderr = apply_wifi_mode()
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": stdout, "stderr": stderr or "Wi-Fi apply failed"},
        )
    trust_code, trust_stdout, trust_stderr = apply_wifi_client_trust_policy()
    if trust_code != 0:
        raise HTTPException(
            status_code=500,
            detail={
                "code": trust_code,
                "stdout": "\n".join(part for part in [stdout, trust_stdout] if part).strip(),
                "stderr": trust_stderr or "Wi-Fi client trust policy apply failed",
            },
        )
    sync_netalertx_topology_safe()
    return {
        "ok": True,
        "code": code,
        "stdout": "\n".join(part for part in [stdout, trust_stdout] if part).strip(),
        "stderr": "\n".join(part for part in [stderr, trust_stderr] if part).strip(),
    }



@app.post("/api/service-lan/internet/on")
def service_lan_internet_on():
    create_prewrite_backup("service-lan-internet-on")
    env = service_lan_command_env()
    code, stdout, stderr = run_command_full(["/usr/local/bin/service-lan-inet-on.sh"], env=env)
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": stdout, "stderr": stderr or "Device LAN enable failed"},
        )
    return {"ok": True, "code": code, "stdout": stdout, "stderr": stderr}


@app.post("/api/service-lan/internet/off")
def service_lan_internet_off():
    create_prewrite_backup("service-lan-internet-off")
    code, stdout, stderr = run_command_full(
        ["/usr/local/bin/service-lan-inet-off.sh"],
        env={
            "SERVICE_LAN_INTERFACE": get_service_lan_interface(),
            "SERVICE_LAN_IPV6_GATEWAY": service_lan_cfg("ipv6_gateway"),
            "SERVICE_LAN_IPV6_PREFIX": service_lan_cfg("ipv6_prefix"),
        },
    )
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": stdout, "stderr": stderr or "Device LAN disable failed"},
        )
    return {"ok": True, "code": code, "stdout": stdout, "stderr": stderr}
