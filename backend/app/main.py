from fastapi import FastAPI, HTTPException, Body, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
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
import secrets
import hashlib
import threading
import urllib.request
import urllib.error


app = FastAPI(title="R1000 Network Panel")
FRONTEND_DIST_CANDIDATES = [
    Path(os.getenv("FRONTEND_DIST_PATH", "")) if os.getenv("FRONTEND_DIST_PATH") else None,
    Path(__file__).resolve().parent.parent / "frontend-dist",
    Path(__file__).resolve().parent.parent.parent / "frontend" / "dist",
]
FRONTEND_DIST_PATH = next(
    (path for path in FRONTEND_DIST_CANDIDATES if path and (path / "index.html").exists()),
    Path(__file__).resolve().parent.parent / "frontend-dist",
)
PANEL_AUTH_COOKIE = "network_panel_session"
PANEL_SESSION_TTL_SECONDS = int(os.getenv("PANEL_SESSION_TTL_SECONDS", "86400") or "86400")
PANEL_USERNAME = os.getenv("PANEL_USERNAME", "admin")
PANEL_PASSWORD = os.getenv("PANEL_PASSWORD", "")
PANEL_SESSIONS: dict[str, float] = {}
AUTH_OPEN_PATHS = {"/", "/favicon.ico", "/api/health", "/api/auth/status", "/api/auth/login", "/api/auth/logout"}
PANEL_SESSION_PATH = "/app/data/panel-sessions.json"
PANEL_SESSION_LOCK = threading.Lock()
SERVICE_LAN_DNSMASQ_IPV6_CONF = "/etc/NetworkManager/dnsmasq-shared.d/99-service-lan-ipv6.conf"
PIHOLE_DNSMASQ_FORWARD_CONF = "/etc/NetworkManager/dnsmasq-shared.d/98-pihole-upstream.conf"
WIFI_DNSMASQ_IPV6_CONF = "/etc/NetworkManager/dnsmasq-shared.d/99-wifi-hotspot-ipv6.conf"
WIFI_RA_PID = "/run/wifi-hotspot-ra.pid"
WIFI_RA_LOG = "/tmp/wifi-hotspot-ra.log"
NETALERTX_COMPOSE_FILE = "/home/evil/netalertx-stack/docker-compose.yml"
HOST_SAMBA_CONFIG_PATHS = [
    "/host/etc/samba/smb.conf",
    "/etc/samba/smb.conf",
]
HOST_SAMBA_MAIN_CONFIG = "/host/etc/samba/smb.conf"
HOST_SAMBA_PORTAL_CONFIG = "/host/etc/samba/portal-shares.conf"
HOST_SAMBA_INCLUDE_LINE = "include = /etc/samba/portal-shares.conf"
RUNTIME_CONFIG_PATH = "/app/data/runtime-config.json"
NETALERTX_SYNC_STATE_PATH = "/app/data/netalertx-sync-state.json"
PANEL_AUTH_CONFIG_PATH = "/app/data/panel-auth.json"

if (FRONTEND_DIST_PATH / "assets").exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST_PATH / "assets"), name="frontend-assets")


def load_panel_sessions() -> dict[str, float]:
    path = Path(PANEL_SESSION_PATH)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    now = time.time()
    sessions: dict[str, float] = {}
    for token, expires_at in data.items():
        try:
            expires = float(expires_at)
        except (TypeError, ValueError):
            continue
        if isinstance(token, str) and token and expires > now:
            sessions[token] = expires
    return sessions


def save_panel_sessions() -> None:
    now = time.time()
    active_sessions = {
        token: expires_at
        for token, expires_at in PANEL_SESSIONS.items()
        if token and expires_at > now
    }
    PANEL_SESSIONS.clear()
    PANEL_SESSIONS.update(active_sessions)
    path = Path(PANEL_SESSION_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(active_sessions, indent=2))


def password_hash(password: str, salt: str | None = None) -> dict[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000)
    return {"salt": salt, "hash": digest.hex()}


def load_panel_auth_config() -> dict[str, str]:
    path = Path(PANEL_AUTH_CONFIG_PATH)
    if path.exists():
        try:
            data = json.loads(path.read_text())
            if isinstance(data, dict) and data.get("username") and data.get("password_hash") and data.get("password_salt"):
                return {
                    "username": str(data["username"]),
                    "password_hash": str(data["password_hash"]),
                    "password_salt": str(data["password_salt"]),
                }
        except Exception:
            pass
    if not PANEL_PASSWORD:
        raise RuntimeError("PANEL_PASSWORD must be set before first startup")
    hashed = password_hash(PANEL_PASSWORD)
    return {"username": PANEL_USERNAME, "password_hash": hashed["hash"], "password_salt": hashed["salt"]}


def save_panel_auth_config(username: str, password: str) -> dict[str, str]:
    username = username.strip()
    hashed = password_hash(password)
    data = {"username": username, "password_hash": hashed["hash"], "password_salt": hashed["salt"]}
    path = Path(PANEL_AUTH_CONFIG_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
    return data


def verify_panel_password(password: str, config: dict[str, str]) -> bool:
    expected = config.get("password_hash", "")
    salt = config.get("password_salt", "")
    if not expected or not salt:
        return False
    candidate = password_hash(password, salt)["hash"]
    return secrets.compare_digest(candidate, expected)


def authenticated_username(request: Request) -> str:
    token = request.cookies.get(PANEL_AUTH_COOKIE, "")
    with PANEL_SESSION_LOCK:
        if not PANEL_SESSIONS:
            PANEL_SESSIONS.update(load_panel_sessions())
        expires_at = PANEL_SESSIONS.get(token, 0.0)
        if token and expires_at > time.time():
            return load_panel_auth_config()["username"]
        if token:
            PANEL_SESSIONS.pop(token, None)
            save_panel_sessions()
    return ""


@app.middleware("http")
async def require_panel_auth(request: Request, call_next):
    path = request.url.path
    if path in AUTH_OPEN_PATHS or path.startswith("/assets/"):
        return await call_next(request)
    if authenticated_username(request):
        return await call_next(request)
    return JSONResponse({"detail": "Authentication required"}, status_code=401)


@app.get("/api/auth/status")
def auth_status(request: Request):
    username = authenticated_username(request)
    return {"authenticated": bool(username), "username": username}


@app.post("/api/auth/login")
def auth_login(response: Response, payload: dict = Body(...)):
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()
    config = load_panel_auth_config()
    if not (
        secrets.compare_digest(username, config["username"])
        and verify_panel_password(password, config)
    ):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = secrets.token_urlsafe(32)
    with PANEL_SESSION_LOCK:
        if not PANEL_SESSIONS:
            PANEL_SESSIONS.update(load_panel_sessions())
        PANEL_SESSIONS[token] = time.time() + PANEL_SESSION_TTL_SECONDS
        save_panel_sessions()
    response.set_cookie(
        PANEL_AUTH_COOKIE,
        token,
        max_age=PANEL_SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
    )
    return {"ok": True, "username": config["username"]}


@app.post("/api/auth/logout")
def auth_logout(request: Request, response: Response):
    token = request.cookies.get(PANEL_AUTH_COOKIE, "")
    if token:
        with PANEL_SESSION_LOCK:
            if not PANEL_SESSIONS:
                PANEL_SESSIONS.update(load_panel_sessions())
            PANEL_SESSIONS.pop(token, None)
            save_panel_sessions()
    response.delete_cookie(PANEL_AUTH_COOKIE)
    return {"ok": True}


@app.post("/api/auth/credentials")
def auth_credentials(request: Request, payload: dict = Body(...)):
    current_username = authenticated_username(request)
    if not current_username:
        raise HTTPException(status_code=401, detail="Authentication required")

    config = load_panel_auth_config()
    current_password = str(payload.get("current_password", ""))
    if not verify_panel_password(current_password, config):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    username = str(payload.get("username", config["username"])).strip()
    new_password = str(payload.get("new_password", ""))
    if not username:
        raise HTTPException(status_code=400, detail="Username cannot be empty")
    password = new_password or current_password
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    save_panel_auth_config(username, password)
    token = request.cookies.get(PANEL_AUTH_COOKIE, "")
    with PANEL_SESSION_LOCK:
        if not PANEL_SESSIONS:
            PANEL_SESSIONS.update(load_panel_sessions())
        expires_at = PANEL_SESSIONS.get(token, time.time() + PANEL_SESSION_TTL_SECONDS)
        PANEL_SESSIONS.clear()
        if token:
            PANEL_SESSIONS[token] = expires_at
        save_panel_sessions()
    return {"ok": True, "username": username}


LTE_APN_PROFILES = [
    {
        "id": "de-telekom-dual",
        "country": "Germany",
        "provider": "Telekom",
        "apn": "internet.telekom",
        "ipv4_method": "auto",
        "ipv6_method": "auto",
        "mccmnc": ["26201"],
    },
    {
        "id": "de-telekom-v6",
        "country": "Germany",
        "provider": "Telekom (IPv6)",
        "apn": "internet.v6.telekom",
        "ipv4_method": "disabled",
        "ipv6_method": "auto",
        "mccmnc": ["26201"],
    },
    {
        "id": "de-vodafone",
        "country": "Germany",
        "provider": "Vodafone DE",
        "apn": "web.vodafone.de",
        "ipv4_method": "auto",
        "ipv6_method": "auto",
        "mccmnc": ["26202"],
    },
    {
        "id": "de-o2",
        "country": "Germany",
        "provider": "O2 / Telefonica DE",
        "apn": "internet",
        "ipv4_method": "auto",
        "ipv6_method": "auto",
        "mccmnc": ["26207", "26203"],
    },
    {
        "id": "tr-turkcell",
        "country": "Turkey",
        "provider": "Turkcell",
        "apn": "internet",
        "ipv4_method": "auto",
        "ipv6_method": "auto",
        "mccmnc": ["28601"],
    },
    {
        "id": "tr-vodafone",
        "country": "Turkey",
        "provider": "Vodafone",
        "apn": "internet",
        "ipv4_method": "auto",
        "ipv6_method": "auto",
        "mccmnc": ["28602"],
    },
    {
        "id": "tr-turk-telekom",
        "country": "Turkey",
        "provider": "Turk Telekom",
        "apn": "internet",
        "ipv4_method": "auto",
        "ipv6_method": "auto",
        "mccmnc": ["28603"],
    },
]
LTE_AUTO_APN = {
    "enabled": True,
    "last_key": "",
    "last_applied": 0.0,
}
LTE_SIM_OVERRIDES: dict[str, dict[str, str]] = {}


def env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


SERVICE_LAN_INTERFACE = os.getenv("SERVICE_LAN_INTERFACE", "")
SERVICE_LAN_IPV4_GATEWAY = os.getenv("SERVICE_LAN_IPV4_GATEWAY", "192.168.10.1")
SERVICE_LAN_IPV4_SUBNET = os.getenv("SERVICE_LAN_IPV4_SUBNET", "192.168.10.0/24")
SERVICE_LAN_DHCP_RANGE = os.getenv("SERVICE_LAN_DHCP_RANGE", "192.168.10.100-192.168.10.199")
SERVICE_LAN_IPV6_GATEWAY = os.getenv("SERVICE_LAN_IPV6_GATEWAY", "fd42:10::1")
SERVICE_LAN_IPV6_PREFIX = os.getenv("SERVICE_LAN_IPV6_PREFIX", "fd42:10::/64")
SERVICE_LAN_ENABLE_IPV4 = env_flag("SERVICE_LAN_ENABLE_IPV4", True)
SERVICE_LAN_ENABLE_IPV6 = env_flag("SERVICE_LAN_ENABLE_IPV6", True)
SERVICE_LAN_ROLE = os.getenv("SERVICE_LAN_ROLE", "isolated")
SERVICE_LAN_DNS_SERVERS = os.getenv("SERVICE_LAN_DNS_SERVERS", LAN_DNS_SERVERS if "LAN_DNS_SERVERS" in globals() else "1.1.1.1,8.8.8.8")
SERVICE_LAN_DNS_SEARCH = os.getenv("SERVICE_LAN_DNS_SEARCH", LAN_DNS_SEARCH if "LAN_DNS_SEARCH" in globals() else "home.lab")
FALLBACK_SERVICE_LAN_INTERFACE = "enx2cf7f1232c1a"
LAN_PROFILE_NAME = os.getenv("LAN_PROFILE_NAME", "Home Lab LAN")
LAN_TARGET_INTERFACE = os.getenv("LAN_TARGET_INTERFACE", "eth0")
LAN_ROLE = os.getenv("LAN_ROLE", "multi-purpose")
LAN_IPV4_MODE = os.getenv("LAN_IPV4_MODE", "shared")
LAN_IPV4_ADDRESS = os.getenv("LAN_IPV4_ADDRESS", "10.0.0.1/24")
LAN_IPV4_SUBNET = os.getenv("LAN_IPV4_SUBNET", "10.0.0.0/24")
LAN_DHCP_RANGE = os.getenv("LAN_DHCP_RANGE", "10.0.0.100-10.0.0.199")
LAN_IPV6_MODE = os.getenv("LAN_IPV6_MODE", "routed")
LAN_IPV6_ADDRESS = os.getenv("LAN_IPV6_ADDRESS", "fd42:100::1/64")
LAN_IPV6_PREFIX = os.getenv("LAN_IPV6_PREFIX", "fd42:100::/64")
LAN_DNS_SERVERS = os.getenv("LAN_DNS_SERVERS", "1.1.1.1,8.8.8.8")
LAN_DNS_SEARCH = os.getenv("LAN_DNS_SEARCH", "home.lab")
LAN_ROLE_OPTIONS = ["isolated", "internal", "external"]
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
}
SERVICE_LAN_CONFIG = {
    "name": "Service LAN",
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
}
WIFI_CONFIG = {
    "interface": os.getenv("WIFI_INTERFACE", "wlan0"),
    "mode": os.getenv("WIFI_MODE", "client"),
    "client_trust_mode": os.getenv("WIFI_CLIENT_TRUST_MODE", "normal"),
    "uplink_preference": os.getenv("WIFI_UPLINK_PREFERENCE", "prefer-lte"),
    "ssid": os.getenv("WIFI_SSID", ""),
    "password": os.getenv("WIFI_PASSWORD", ""),
    "hotspot_ssid": os.getenv("WIFI_HOTSPOT_SSID", "R1000-Hotspot"),
    "hotspot_password": os.getenv("WIFI_HOTSPOT_PASSWORD", "changeme123"),
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
WIFI_SECRET_KEYS = {"password", "hotspot_password"}
WIFI_SCAN_CACHE = {"interface": "", "timestamp": 0.0, "scan": []}
DEVICE_IO_LED_POLICY = {
    "last_blue_blink": 0.0,
    "last_user_state": "",
    "last_act_trigger": "",
    "manual_override_until": 0.0,
    "manual_user_override_until": 0.0,
    "manual_act_override_until": 0.0,
    "last_disk_activity_total": 0,
    "last_act_pulse": 0.0,
    "online": False,
    "internet_success_count": 0,
    "internet_failure_count": 0,
}
DEVICE_IO_LED_POLICY_ENABLED = env_flag("DEVICE_IO_LED_POLICY_ENABLED", True)
DEVICE_IO_ACT_SOFTWARE_DISK_LED = env_flag("DEVICE_IO_ACT_SOFTWARE_DISK_LED", True)
DEVICE_IO_INTERNET_DOWN_FAILURES = int(os.getenv("DEVICE_IO_INTERNET_DOWN_FAILURES", "4") or "4")
DEVICE_IO_ACT_DISK_NAMES = tuple(
    name.strip()
    for name in os.getenv("DEVICE_IO_ACT_DISK_NAMES", "nvme0n1,mmcblk0,sda,sdb").split(",")
    if name.strip()
)
DEVICE_IO_LED_ROLE_ALIASES = {
    "act": ("act", "activity", "disk-activity", "storage", "mmc0"),
    "red": ("led-red", "usrred", "userred", "user-red", "usr-r", "red-led"),
    "green": ("led-green", "usrgreen", "usergreen", "user-green", "usr-g", "green-led"),
    "blue": ("led-blue", "usrblue", "userblue", "user-blue", "usr-b", "blue-led"),
}
DEVICE_IO_ACT_TRIGGERS = ("disk-activity", "mmc0", "activity")
DEVICE_IO_ACTIVE_LOW_LED_ROLES = {
    role.strip().lower()
    for role in os.getenv("DEVICE_IO_ACTIVE_LOW_LED_ROLES", "").split(",")
    if role.strip()
}


def runtime_config_snapshot() -> dict[str, object]:
    wifi_persisted = {
        key: value
        for key, value in WIFI_CONFIG.items()
        if key not in WIFI_SECRET_KEYS
    }
    return {
        "main_lan": dict(MAIN_LAN_CONFIG),
        "service_lan": dict(SERVICE_LAN_CONFIG),
        "wifi": wifi_persisted,
        "lte": {
            "auto_apn_enabled": LTE_AUTO_APN["enabled"],
            "sim_overrides": dict(LTE_SIM_OVERRIDES),
        },
    }


def save_runtime_config() -> None:
    path = Path(RUNTIME_CONFIG_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(runtime_config_snapshot(), indent=2))


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


def read_text(path: str, default: str = "") -> str:
    try:
        return Path(path).read_text().strip()
    except Exception:
        return default


def run_command(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except Exception:
        return ""


def run_command_full(cmd: list[str], env: dict[str, str] | None = None) -> tuple[int, str, str]:
    try:
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        result = subprocess.run(cmd, capture_output=True, text=True, env=merged_env)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def run_command_input(cmd: list[str], input_text: str) -> tuple[int, str, str]:
    try:
        result = subprocess.run(cmd, input=input_text, capture_output=True, text=True)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def host_nmcli_command(args: list[str]) -> list[str]:
    return ["chroot", "/host", "/usr/bin/nmcli"] + args


def host_nmcli_available() -> bool:
    return Path("/host/usr/bin/nmcli").exists()


def nmcli_command(args: list[str]) -> list[str]:
    return host_nmcli_command(args) if host_nmcli_available() else ["nmcli"] + args


def nmcli_available() -> bool:
    return host_nmcli_available() or command_exists("nmcli")


def run_nmcli(args: list[str]) -> str:
    return run_command(nmcli_command(args))


def run_nmcli_full(args: list[str]) -> tuple[int, str, str]:
    return run_command_full(nmcli_command(args))


def host_command_available(path: str) -> bool:
    return Path("/host").joinpath(path.lstrip("/")).exists()


def host_binary_command(path: str, args: list[str]) -> list[str]:
    return ["chroot", "/host", path] + args


def command_exists(name: str) -> bool:
    result = subprocess.run(["which", name], capture_output=True, text=True)
    return result.returncode == 0


def slugify(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]+", "_", value).strip("_").lower()


def lan_cfg(key: str) -> str:
    return str(MAIN_LAN_CONFIG.get(key, ""))


def service_lan_cfg(key: str) -> str:
    return str(SERVICE_LAN_CONFIG.get(key, ""))


def wifi_cfg(key: str) -> str:
    return str(WIFI_CONFIG.get(key, ""))


def cfg_flag(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def same_physical_lan_interface(main_interface: str, service_interface: str) -> bool:
    return bool(main_interface and service_interface and main_interface == service_interface)


def normalize_lan_role(value: str) -> str:
    role = (value or "").strip().lower()
    mapping = {
        "multi-purpose": "internal",
        "home-lab": "internal",
        "service": "external",
        "isolated": "isolated",
        "internal": "internal",
        "external": "external",
    }
    return mapping.get(role, "internal")


def normalize_wifi_mode(value: str) -> str:
    mode = (value or "").strip().lower()
    return mode if mode in {"client", "hotspot"} else "client"


def normalize_wifi_client_trust_mode(value: str) -> str:
    mode = (value or "").strip().lower()
    return mode if mode in {"normal", "isolated"} else "normal"


def normalize_wifi_uplink_preference(value: str) -> str:
    mode = (value or "").strip().lower()
    mapping = {
        "": "prefer-lte",
        "prefer-lte": "prefer-lte",
        "lte": "prefer-lte",
        "cellular": "prefer-lte",
        "prefer-wifi": "prefer-wifi",
        "wifi": "prefer-wifi",
        "failover-only": "failover-only",
        "failover": "failover-only",
    }
    return mapping.get(mode, "prefer-lte")


def normalize_wifi_security(value: str) -> str:
    security = (value or "").strip().lower()
    return security if security in {"open", "wpa2-personal", "wpa3-personal"} else "wpa2-personal"


def normalize_wifi_band(value: str) -> str:
    band = (value or "").strip().lower()
    mapping = {
        "": "2.4ghz",
        "auto": "2.4ghz",
        "dual": "2.4ghz",
        "both": "2.4ghz",
        "2.4": "2.4ghz",
        "2.4ghz": "2.4ghz",
        "bg": "2.4ghz",
        "5": "5ghz",
        "5ghz": "5ghz",
        "a": "5ghz",
    }
    return mapping.get(band, "2.4ghz")


def normalize_wifi_channel(value: str, band: str) -> str:
    channel = (value or "").strip().lower()
    if channel in {"", "0", "auto"}:
        return "auto"
    if not channel.isdigit():
        return "auto"
    channel_int = int(channel)
    channels_24 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
    channels_5 = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165}
    if band == "2.4ghz" and channel_int not in channels_24:
        return "auto"
    if band == "5ghz" and channel_int not in channels_5:
        return "auto"
    return str(channel_int)


def normalize_country_code(value: str) -> str:
    code = (value or "").strip().upper()
    if re.fullmatch(r"[A-Z]{2}", code):
        return code
    return "DE"


def normalize_wifi_ipv4_method(mode: str, value: str) -> str:
    method = (value or "").strip().lower()
    allowed = {"client": {"auto", "manual", "disabled"}, "hotspot": {"shared", "manual", "disabled"}}
    return method if method in allowed[mode] else ("auto" if mode == "client" else "shared")


def normalize_wifi_ipv6_method(mode: str, value: str) -> str:
    method = (value or "").strip().lower()
    allowed = {"client": {"auto", "manual", "disabled"}, "hotspot": {"shared", "manual", "disabled"}}
    default = "auto" if mode == "client" else "disabled"
    return method if method in allowed[mode] else default


def normalize_wifi_config() -> None:
    WIFI_CONFIG["mode"] = normalize_wifi_mode(WIFI_CONFIG.get("mode", "client"))
    WIFI_CONFIG["client_trust_mode"] = normalize_wifi_client_trust_mode(WIFI_CONFIG.get("client_trust_mode", "normal"))
    WIFI_CONFIG["uplink_preference"] = normalize_wifi_uplink_preference(WIFI_CONFIG.get("uplink_preference", "prefer-lte"))
    WIFI_CONFIG["hotspot_security"] = normalize_wifi_security(WIFI_CONFIG.get("hotspot_security", "wpa2-personal"))
    WIFI_CONFIG["country"] = normalize_country_code(WIFI_CONFIG.get("country", "DE"))
    WIFI_CONFIG["band"] = normalize_wifi_band(WIFI_CONFIG.get("band", "auto"))
    WIFI_CONFIG["channel"] = normalize_wifi_channel(WIFI_CONFIG.get("channel", "auto"), WIFI_CONFIG["band"])
    WIFI_CONFIG["ipv4_method"] = normalize_wifi_ipv4_method(WIFI_CONFIG["mode"], WIFI_CONFIG.get("ipv4_method", "auto"))
    WIFI_CONFIG["ipv6_method"] = normalize_wifi_ipv6_method(WIFI_CONFIG["mode"], WIFI_CONFIG.get("ipv6_method", "disabled"))
    if WIFI_CONFIG["mode"] == "hotspot" and WIFI_CONFIG["hotspot_security"] != "open" and not WIFI_CONFIG.get("hotspot_password", "").strip():
        WIFI_CONFIG["hotspot_password"] = ""
    if WIFI_CONFIG["mode"] == "hotspot" and WIFI_CONFIG["ipv6_method"] == "auto":
        WIFI_CONFIG["ipv6_method"] = "disabled"


def role_description(role: str) -> str:
    normalized = normalize_lan_role(role)
    if normalized == "isolated":
        return "clients get internet, but cannot reach internal LAN, Wi-Fi, Tailscale, or most device services"
    if normalized == "external":
        return "clients get internet and stay away from internal LAN, while Tailscale devices can still reach the router and this external segment"
    return "trusted internal LAN with access to local services and management"


def read_millicelsius(path: str) -> float | None:
    raw = read_text(path, "")
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return round(value / 1000.0, 1)


def fetch_node_exporter_metrics() -> str:
    try:
        with urllib.request.urlopen("http://127.0.0.1:9100/metrics", timeout=1.5) as response:
            return response.read().decode("utf-8", errors="ignore")
    except Exception:
        return ""


def metric_value(metrics_text: str, pattern: str) -> float | None:
    match = re.search(pattern, metrics_text, re.MULTILINE)
    if not match:
        return None
    try:
        return round(float(match.group(1)), 1)
    except ValueError:
        return None


def get_cpu_temperature_c() -> float | None:
    metrics = fetch_node_exporter_metrics()
    value = metric_value(
        metrics,
        r'^node_hwmon_temp_celsius\{[^}]*chip="thermal_thermal_zone0"[^}]*\}\s+([0-9.]+)$',
    )
    if value is not None:
        return value
    base = Path("/sys/class/thermal")
    if not base.exists():
        return None
    for zone in sorted(base.glob("thermal_zone*")):
        zone_type = read_text(str(zone / "type"), "").lower()
        if "cpu" in zone_type:
            value = read_millicelsius(str(zone / "temp"))
            if value is not None:
                return value
    for zone in sorted(base.glob("thermal_zone*")):
        value = read_millicelsius(str(zone / "temp"))
        if value is not None:
            return value
    return None


def get_nvme_temperature_c() -> float | None:
    metrics = fetch_node_exporter_metrics()
    value = metric_value(
        metrics,
        r'^node_hwmon_temp_celsius\{[^}]*chip="nvme_nvme0"[^}]*\}\s+([0-9.]+)$',
    )
    if value is not None:
        return value
    value = metric_value(metrics, r'^edge_nvme_temp_c\s+([0-9.]+)$')
    if value is not None:
        return value
    candidates = list(Path("/sys/class/nvme").glob("nvme*/device/hwmon/hwmon*/temp1_input"))
    for candidate in candidates:
        value = read_millicelsius(str(candidate))
        if value is not None:
            return value
    return None


def get_input_voltage_v() -> float | None:
    for candidate in Path("/sys/class/power_supply").glob("*/voltage_now"):
        raw = read_text(str(candidate), "")
        if not raw:
            continue
        try:
            return round(int(raw) / 1_000_000.0, 2)
        except ValueError:
            continue
    return None


def get_memory_stats() -> dict[str, float | int | None]:
    meminfo = read_text("/host/proc/meminfo", "")
    if not meminfo:
        return {"total_mb": None, "available_mb": None, "used_mb": None, "used_percent": None}
    values: dict[str, int] = {}
    for line in meminfo.splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        number = rest.strip().split()[0]
        try:
            values[key] = int(number)
        except ValueError:
            continue
    total = values.get("MemTotal")
    available = values.get("MemAvailable")
    if not total or available is None:
        return {"total_mb": None, "available_mb": None, "used_mb": None, "used_percent": None}
    used = max(total - available, 0)
    return {
        "total_mb": round(total / 1024.0, 1),
        "available_mb": round(available / 1024.0, 1),
        "used_mb": round(used / 1024.0, 1),
        "used_percent": round((used / total) * 100.0, 1) if total else None,
    }


def get_load_averages() -> dict[str, str]:
    raw = read_text("/host/proc/loadavg", "")
    parts = raw.split()
    return {
        "load_1": parts[0] if len(parts) > 0 else "",
        "load_5": parts[1] if len(parts) > 1 else "",
        "load_15": parts[2] if len(parts) > 2 else "",
    }


def docker_cli_command(args: list[str]) -> list[str]:
    if host_command_available("/usr/bin/docker"):
        return host_binary_command("/usr/bin/docker", args)
    return ["docker"] + args


def docker_available() -> bool:
    return host_command_available("/usr/bin/docker") or command_exists("docker")


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
            "LTE Uplink",
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
        core_nodes.append((service_mac, "Service LAN", "Switch", "", "r1000-core", "R1000"))

    parent_targets: list[tuple[ipaddress.IPv4Network, str, str]] = []
    if lan_cfg("ipv4_subnet") and main_mac:
        try:
            parent_targets.append((ipaddress.ip_network(lan_cfg("ipv4_subnet"), strict=False), main_mac, "Main LAN"))
        except ValueError:
            pass
    if service_lan_cfg("ipv4_subnet") and service_mac and str(service_data.get("state", "")).upper() == "UP":
        try:
            parent_targets.append((ipaddress.ip_network(service_lan_cfg("ipv4_subnet"), strict=False), service_mac, "Service LAN"))
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


def get_docker_brief_status() -> dict[str, object]:
    if not docker_available():
        return {"available": False, "running": 0, "containers": []}
    code, stdout, stderr = run_command_full(
        docker_cli_command(["ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"])
    )
    if code != 0:
        return {"available": False, "running": 0, "containers": [], "error": stderr}
    containers = []
    for line in stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        containers.append({"name": parts[0], "image": parts[1], "status": parts[2]})
    return {"available": True, "running": len(containers), "containers": containers}


def get_filesystem_status() -> dict[str, object]:
    disks_code, disks_out, _ = run_command_full(["lsblk", "-J", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,LABEL,MODEL,TRAN,HOTPLUG,RM"])
    mounts_code, mounts_out, _ = run_command_full(["df", "-hP"])
    disks = []
    if disks_code == 0 and disks_out:
        try:
            disks = json.loads(disks_out).get("blockdevices", [])
        except Exception:
            disks = []

    mounts = []
    if mounts_code == 0 and mounts_out:
        for line in mounts_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue
            mounts.append(
                {
                    "filesystem": parts[0],
                    "size": parts[1],
                    "used": parts[2],
                    "available": parts[3],
                    "use_percent": parts[4],
                    "mountpoint": parts[5],
                }
            )
    external = []
    def walk_disk(entries: list[dict[str, object]]) -> None:
        for entry in entries:
            if str(entry.get("tran", "")).lower() == "usb" or bool(entry.get("hotplug")) or bool(entry.get("rm")):
                external.append(entry)
            children = entry.get("children", [])
            if isinstance(children, list):
                walk_disk(children)
    walk_disk(disks)
    return {"disks": disks, "mounts": mounts, "external": external}


def read_text_raw(path: Path, default: str = "") -> str:
    try:
        return path.read_text().strip()
    except Exception:
        return default


def led_sysfs_roots() -> list[Path]:
    roots = [Path("/host-sys/class/leds"), Path("/sys/class/leds"), Path("/host/sys/class/leds")]
    return [root for root in roots if root.exists()]


def parse_led_trigger(raw: str) -> tuple[str, list[str]]:
    current = ""
    available = []
    for token in raw.split():
        if token.startswith("[") and token.endswith("]"):
            current = token[1:-1]
            available.append(current)
        else:
            available.append(token)
    return current, available


def get_led_status() -> list[dict[str, object]]:
    leds: dict[str, dict[str, object]] = {}
    for root in led_sysfs_roots():
        for entry in sorted(root.iterdir(), key=lambda item: item.name):
            if not entry.exists():
                continue
            name = entry.name
            trigger_raw = read_text_raw(entry / "trigger")
            current_trigger, triggers = parse_led_trigger(trigger_raw)
            brightness_path = entry / "brightness"
            trigger_path = entry / "trigger"
            role = led_role_name(name)
            leds.setdefault(name, {
                "name": name,
                "role": role,
                "source": str(root),
                "brightness": read_text_raw(brightness_path, "unknown"),
                "max_brightness": read_text_raw(entry / "max_brightness", "unknown"),
                "trigger": current_trigger or read_text_raw(trigger_path, "unknown"),
                "triggers": triggers,
                "active_low": led_is_active_low(name),
                "logical_on_brightness": led_logical_on_value(name),
                "logical_off_brightness": led_logical_off_value(name),
                "can_set_brightness": os.access(brightness_path, os.W_OK) and not protected_led_name(name),
                "can_set_trigger": os.access(trigger_path, os.W_OK) and not protected_led_name(name),
                "protected": protected_led_name(name),
            })
    return list(leds.values())


def get_serial_status() -> list[dict[str, str]]:
    ports: dict[str, dict[str, str]] = {}
    patterns = [
        "/dev/ttyS*",
        "/dev/ttyAMA*",
        "/dev/ttyUSB*",
        "/host/dev/ttyS*",
        "/host/dev/ttyAMA*",
        "/host/dev/ttyUSB*",
    ]
    for pattern in patterns:
        for path in sorted(Path(pattern).parent.glob(Path(pattern).name)):
            display_path = str(path).replace("/host", "", 1)
            if display_path in ports:
                continue
            ports[display_path] = {
                "path": display_path,
                "source": str(path),
                "kind": "usb-modem" if "ttyUSB" in path.name else ("uart" if "ttyAMA" in path.name else "serial"),
                "readable": "yes" if os.access(path, os.R_OK) else "no",
                "writable": "yes" if os.access(path, os.W_OK) else "no",
                "link": "",
            }

    for symlink_root in (Path("/dev/serial"), Path("/host/dev/serial")):
        if not symlink_root.exists():
            continue
        for link in sorted(symlink_root.rglob("*")):
            if not link.is_symlink():
                continue
            try:
                target = str(link.resolve()).replace("/host", "", 1)
            except Exception:
                target = ""
            if target in ports:
                ports[target]["link"] = str(link).replace("/host", "", 1)
    return sorted(ports.values(), key=lambda item: item["path"])


def get_gpio_status() -> list[dict[str, str]]:
    chips = []
    for root in (Path("/sys/class/gpio"), Path("/host/sys/class/gpio")):
        if not root.exists():
            continue
        for chip in sorted(root.glob("gpiochip*"), key=lambda item: item.name):
            chips.append(
                {
                    "name": chip.name,
                    "source": str(chip),
                    "label": read_text_raw(chip / "label", ""),
                    "base": read_text_raw(chip / "base", ""),
                    "ngpio": read_text_raw(chip / "ngpio", ""),
                }
            )
    unique = {}
    for chip in chips:
        unique.setdefault(chip["name"], chip)
    return list(unique.values())


def writable_led_path(name: str) -> Path | None:
    if not re.fullmatch(r"[A-Za-z0-9_.:+-]+", name or ""):
        return None
    for root in (Path("/host-sys/class/leds"), Path("/sys/class/leds")):
        led = root / name
        if led.exists():
            return led
    return None


def led_name_matches(name: str, aliases: tuple[str, ...]) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "", name.lower())
    return any(re.sub(r"[^a-z0-9]+", "", alias.lower()) in normalized for alias in aliases)


def led_role_name(name: str) -> str:
    if led_name_matches(name, DEVICE_IO_LED_ROLE_ALIASES["act"]):
        return "act"
    if led_name_matches(name, DEVICE_IO_LED_ROLE_ALIASES["red"]):
        return "red"
    if led_name_matches(name, DEVICE_IO_LED_ROLE_ALIASES["green"]):
        return "green"
    if led_name_matches(name, DEVICE_IO_LED_ROLE_ALIASES["blue"]):
        return "blue"
    return ""


def protected_led_name(name: str) -> bool:
    return name.upper() == "PWR"


def find_led_name(aliases: tuple[str, ...]) -> str:
    for led in get_led_status():
        name = str(led.get("name", ""))
        if led_name_matches(name, aliases):
            return name
    return ""


def user_rgb_led_names() -> dict[str, str]:
    leds = {str(led.get("name", "")): led for led in get_led_status()}
    expected = {"red": "led-red", "green": "led-green", "blue": "led-blue"}
    if all(name in leds for name in expected.values()):
        return expected
    return {
        "red": find_led_name(("led-red", "userred", "usrred", "userr", "usr:r", "usr-r", "user-red")),
        "green": find_led_name(("led-green", "usergreen", "usrgreen", "userg", "usr:g", "usr-g", "user-green")),
        "blue": find_led_name(("led-blue", "userblue", "usrblue", "userb", "usr:b", "usr-b", "user-blue")),
    }


def act_led_name() -> str:
    return find_led_name(DEVICE_IO_LED_ROLE_ALIASES["act"])


def set_led_trigger(name: str, preferred_triggers: tuple[str, ...]) -> str:
    led = writable_led_path(name)
    if not led:
        return ""
    trigger_path = led / "trigger"
    current, available = parse_led_trigger(read_text_raw(trigger_path))
    for trigger in preferred_triggers:
        if trigger in available:
            if current != trigger:
                try:
                    trigger_path.write_text(trigger)
                except Exception:
                    pass
            return trigger
    return current


def configure_timer_led(name: str, delay_on_ms: int = 125, delay_off_ms: int = 875) -> bool:
    led = writable_led_path(name)
    if not led:
        return False
    trigger = set_led_trigger(name, ("timer",))
    if trigger != "timer":
        return False
    for field, value in (("delay_on", str(delay_on_ms)), ("delay_off", str(delay_off_ms))):
        path = led / field
        if path.exists():
            try:
                path.write_text(value)
            except Exception:
                pass
    return True


def write_led_value(name: str, field: str, value: str) -> bool:
    led = writable_led_path(name)
    if not led:
        return False
    try:
        (led / field).write_text(value)
        return True
    except Exception:
        return False


def led_is_active_low(name: str) -> bool:
    return led_role_name(name) in DEVICE_IO_ACTIVE_LOW_LED_ROLES


def led_max_write_value(name: str) -> str:
    led = writable_led_path(name)
    if not led:
        return "1"
    max_value = read_text_raw(led / "max_brightness", "1")
    return max_value if max_value.isdigit() else "1"


def led_logical_on_value(name: str) -> str:
    return "0" if led_is_active_low(name) else led_max_write_value(name)


def led_logical_off_value(name: str) -> str:
    return led_max_write_value(name) if led_is_active_low(name) else "0"


def set_led_off(name: str) -> bool:
    if not name:
        return False
    write_led_value(name, "trigger", "none")
    return write_led_value(name, "brightness", led_logical_off_value(name))


def set_led_on(name: str) -> bool:
    if not name:
        return False
    write_led_value(name, "trigger", "none")
    return write_led_value(name, "brightness", led_logical_on_value(name))


def set_user_rgb(red: bool, green: bool, blue: bool) -> dict[str, str]:
    channels = user_rgb_led_names()
    desired = {"red": red, "green": green, "blue": blue}
    for color, led_name in channels.items():
        if not led_name:
            continue
        if desired[color]:
            set_led_on(led_name)
        else:
            set_led_off(led_name)
    return channels


def device_io_manual_override_active() -> bool:
    return device_io_user_override_active() or device_io_act_override_active()


def device_io_user_override_active() -> bool:
    return time.time() < float(DEVICE_IO_LED_POLICY.get("manual_user_override_until", 0.0) or 0.0)


def device_io_act_override_active() -> bool:
    return time.time() < float(DEVICE_IO_LED_POLICY.get("manual_act_override_until", 0.0) or 0.0)


def internet_reachable() -> bool:
    if command_exists("ping"):
        probes = [
            ["ping", "-4", "-c", "1", "-W", "1", "1.1.1.1"],
            ["ping", "-4", "-c", "1", "-W", "1", "8.8.8.8"],
            ["ping", "-6", "-c", "1", "-W", "1", "2606:4700:4700::1111"],
        ]
        for probe in probes:
            code, _, _ = run_command_full(probe)
            if code == 0:
                return True
    tcp_probes = [
        (socket.AF_INET, ("1.1.1.1", 443)),
        (socket.AF_INET, ("8.8.8.8", 443)),
        (socket.AF_INET6, ("2606:4700:4700::1111", 443, 0, 0)),
    ]
    for family, address in tcp_probes:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.5)
                sock.connect(address)
                return True
        except OSError:
            continue
    return False


def stable_internet_reachable() -> bool:
    reachable = internet_reachable()
    if reachable:
        DEVICE_IO_LED_POLICY["internet_success_count"] = int(DEVICE_IO_LED_POLICY.get("internet_success_count", 0) or 0) + 1
        DEVICE_IO_LED_POLICY["internet_failure_count"] = 0
        DEVICE_IO_LED_POLICY["online"] = True
        return True

    DEVICE_IO_LED_POLICY["internet_success_count"] = 0
    failures = int(DEVICE_IO_LED_POLICY.get("internet_failure_count", 0) or 0) + 1
    DEVICE_IO_LED_POLICY["internet_failure_count"] = failures
    if failures >= max(1, DEVICE_IO_INTERNET_DOWN_FAILURES):
        DEVICE_IO_LED_POLICY["online"] = False
    return bool(DEVICE_IO_LED_POLICY.get("online", False))


def has_external_active_session() -> bool:
    return bool(get_active_sessions())


def disk_activity_total() -> int:
    raw = read_text("/proc/diskstats", "")
    total = 0
    wanted = set(DEVICE_IO_ACT_DISK_NAMES)
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 14:
            continue
        name = parts[2]
        if wanted and name not in wanted:
            continue
        try:
            reads_completed = int(parts[3])
            sectors_read = int(parts[5])
            writes_completed = int(parts[7])
            sectors_written = int(parts[9])
            discards_completed = int(parts[14]) if len(parts) > 14 else 0
            sectors_discarded = int(parts[16]) if len(parts) > 16 else 0
        except ValueError:
            continue
        total += reads_completed + sectors_read + writes_completed + sectors_written + discards_completed + sectors_discarded
    return total


def device_act_disk_activity_loop() -> None:
    time.sleep(3)
    act_name = act_led_name()
    if not act_name:
        return
    last_total = disk_activity_total()
    DEVICE_IO_LED_POLICY["last_disk_activity_total"] = last_total
    while True:
        try:
            if DEVICE_IO_ACT_SOFTWARE_DISK_LED and not device_io_act_override_active():
                current_total = disk_activity_total()
                if current_total and current_total != last_total:
                    write_led_value(act_name, "trigger", "none")
                    write_led_value(act_name, "brightness", led_max_write_value(act_name))
                    DEVICE_IO_LED_POLICY["last_act_trigger"] = "software-disk-activity"
                    DEVICE_IO_LED_POLICY["last_act_pulse"] = time.time()
                    time.sleep(0.08)
                    write_led_value(act_name, "brightness", "0")
                last_total = current_total
                DEVICE_IO_LED_POLICY["last_disk_activity_total"] = last_total
            time.sleep(0.15)
        except Exception:
            time.sleep(1)


def apply_device_led_policy_once() -> dict[str, object]:
    act_name = act_led_name()
    act_trigger = ""
    if act_name and DEVICE_IO_ACT_SOFTWARE_DISK_LED and not device_io_act_override_active():
        act_trigger = "software-disk-activity"
        DEVICE_IO_LED_POLICY["last_act_trigger"] = act_trigger
    elif act_name and not device_io_act_override_active():
        act_trigger = set_led_trigger(act_name, DEVICE_IO_ACT_TRIGGERS)
    else:
        DEVICE_IO_LED_POLICY["last_act_trigger"] = ""
    if act_trigger:
        DEVICE_IO_LED_POLICY["last_act_trigger"] = act_trigger

    channels = user_rgb_led_names()
    if not all(channels.values()):
        DEVICE_IO_LED_POLICY["last_user_state"] = "waiting-for-led-red-green-blue"
        return {
            "online": False,
            "external_session": False,
            "state": DEVICE_IO_LED_POLICY["last_user_state"],
            "act": DEVICE_IO_LED_POLICY["last_act_trigger"],
            "user_channels": channels,
            "device_policy_enabled": DEVICE_IO_LED_POLICY_ENABLED,
            "manual_override_active": device_io_manual_override_active(),
        }

    if not DEVICE_IO_LED_POLICY_ENABLED:
        DEVICE_IO_LED_POLICY["last_user_state"] = "policy-disabled"
        return {
            "online": stable_internet_reachable(),
            "external_session": has_external_active_session(),
            "state": DEVICE_IO_LED_POLICY["last_user_state"],
            "act": DEVICE_IO_LED_POLICY["last_act_trigger"],
            "user_channels": channels,
            "device_policy_enabled": False,
            "manual_override_active": device_io_manual_override_active(),
        }

    online = stable_internet_reachable()
    external_session = has_external_active_session()
    state = "green-online" if online else "red-offline"
    manual_override = device_io_user_override_active()
    if not manual_override:
        set_user_rgb(not online, online, False)

        if external_session:
            blue_name = channels.get("blue", "")
            state = f"{state}+blue"
            if blue_name and configure_timer_led(blue_name, 125, 875):
                DEVICE_IO_LED_POLICY["last_blue_blink"] = time.time()
            else:
                now = time.time()
                if now - DEVICE_IO_LED_POLICY["last_blue_blink"] >= 3:
                    DEVICE_IO_LED_POLICY["last_blue_blink"] = now
                    set_user_rgb(not online, online, True)
                    time.sleep(0.25)
                    set_user_rgb(not online, online, False)
    else:
        state = f"{state}+manual"

    DEVICE_IO_LED_POLICY["last_user_state"] = state
    return {
        "online": online,
        "external_session": external_session,
        "state": state,
        "act": DEVICE_IO_LED_POLICY["last_act_trigger"],
        "user_channels": channels,
        "device_policy_enabled": True,
        "manual_override_active": device_io_manual_override_active(),
        "manual_user_override_active": device_io_user_override_active(),
        "manual_act_override_active": device_io_act_override_active(),
        "device_policy_note": "ACT uses disk-activity trigger when exposed; USER LEDs map to red/green/blue roles.",
    }


def device_led_policy_loop() -> None:
    time.sleep(12)
    while True:
        try:
            apply_device_led_policy_once()
        except Exception:
            pass
        time.sleep(2 if DEVICE_IO_LED_POLICY_ENABLED else 30)


def get_device_io_status() -> dict[str, object]:
    leds = get_led_status()
    serial = get_serial_status()
    gpio = get_gpio_status()
    expected_rs485 = ["/dev/ttyAMA2", "/dev/ttyAMA3", "/dev/ttyAMA5"]
    present_paths = {port["path"] for port in serial}
    notes = []
    missing_rs485 = [path for path in expected_rs485 if path not in present_paths]
    if missing_rs485:
        notes.append("Expected R1000 RS485 UARTs are not visible yet: " + ", ".join(missing_rs485))
    if not any(led.get("role") in {"red", "green", "blue"} for led in leds):
        notes.append("R1000 USER RGB LEDs are not exposed. Expected /sys/class/leds/led-red, led-green and led-blue.")
    if not any(led.get("role") == "act" for led in leds):
        notes.append("ACT LED is not exposed. It should be the storage-activity LED.")
    return {
        "leds": leds,
        "serial_ports": serial,
        "gpio_chips": gpio,
        "expected_rs485": expected_rs485,
        "led_policy": dict(DEVICE_IO_LED_POLICY),
        "device_policy_enabled": DEVICE_IO_LED_POLICY_ENABLED,
        "manual_override_active": device_io_manual_override_active(),
        "notes": notes,
    }


def resolve_writable_led(name: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.:+-]+", name or ""):
        raise HTTPException(status_code=400, detail="Invalid LED name")
    if protected_led_name(name):
        raise HTTPException(status_code=400, detail="PWR LED is reserved for power state")
    led = writable_led_path(name)
    if not led:
        raise HTTPException(status_code=404, detail="LED is not available through writable sysfs")
    return led


@app.post("/api/device-io/led")
def update_led(payload: dict = Body(...)):
    name = str(payload.get("name", "")).strip()
    led = resolve_writable_led(name)
    stdout_parts = []
    trigger = str(payload.get("trigger", "")).strip()
    brightness = str(payload.get("brightness", "")).strip()
    state = str(payload.get("state", "")).strip().lower()
    role = led_role_name(name)

    if trigger:
        trigger_path = led / "trigger"
        current, available = parse_led_trigger(read_text_raw(trigger_path))
        if available and trigger not in available:
            raise HTTPException(status_code=400, detail="Unsupported LED trigger")
        try:
            trigger_path.write_text(trigger)
            stdout_parts.append(f"{name} trigger set to {trigger}")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    if state:
        if state not in {"on", "off"}:
            raise HTTPException(status_code=400, detail="State must be on or off")
        brightness = led_logical_on_value(name) if state == "on" else led_logical_off_value(name)

    if brightness:
        if not brightness.isdigit():
            raise HTTPException(status_code=400, detail="Brightness must be numeric")
        max_value = read_text_raw(led / "max_brightness", "1")
        try:
            value = int(brightness)
            max_int = int(max_value)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid brightness range")
        if value < 0 or value > max_int:
            raise HTTPException(status_code=400, detail=f"Brightness must be between 0 and {max_int}")
        try:
            if not trigger:
                trigger_path = led / "trigger"
                current, available = parse_led_trigger(read_text_raw(trigger_path))
                if "none" in available and current != "none":
                    trigger_path.write_text("none")
                    stdout_parts.append(f"{name} trigger set to none")
            (led / "brightness").write_text(str(value))
            stdout_parts.append(f"{name} brightness set to {value}")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    if role and (brightness or trigger):
        until = time.time() + 600
        if role == "act":
            DEVICE_IO_LED_POLICY["manual_act_override_until"] = until
        if role in {"red", "green", "blue"}:
            DEVICE_IO_LED_POLICY["manual_user_override_until"] = until
            DEVICE_IO_LED_POLICY["last_user_state"] = "manual-override"
        DEVICE_IO_LED_POLICY["manual_override_until"] = max(
            float(DEVICE_IO_LED_POLICY.get("manual_user_override_until", 0.0) or 0.0),
            float(DEVICE_IO_LED_POLICY.get("manual_act_override_until", 0.0) or 0.0),
        )

    return {"ok": True, "stdout": "\n".join(stdout_parts), "status": get_device_io_status()}


normalize_wifi_config()
load_runtime_config()
save_runtime_config()


def is_process_running(name: str) -> bool:
    result = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True)
    return result.returncode == 0


def clean_ansi(text: str) -> str:
    return re.sub(r"\x1B\[[0-9;]*[A-Za-z]", "", text).strip()


def parse_mmcli_value(text: str, label: str) -> str:
    pattern = rf"{re.escape(label)}\s*:\s*(.+)"
    match = re.search(pattern, text)
    return match.group(1).strip() if match else ""


def get_modem_id() -> str:
    output = run_command(["mmcli", "-L"])
    match = re.search(r"/Modem/(\d+)", output)
    return match.group(1) if match else ""


def get_operator_info(modem_id: str) -> dict[str, str]:
    info = {"mcc": "", "mnc": "", "operator_name": ""}
    if not modem_id:
        return info
    data = run_command(["mmcli", "-m", modem_id, "--3gpp"])
    if not data:
        return info
    info["operator_name"] = clean_ansi(parse_mmcli_value(data, "operator name"))
    info["mcc"] = clean_ansi(parse_mmcli_value(data, "operator mcc"))
    info["mnc"] = clean_ansi(parse_mmcli_value(data, "operator mnc"))
    return info


def get_sim_imsi(modem_id: str) -> str:
    if not modem_id:
        return ""
    modem = run_command(["mmcli", "-m", modem_id])
    sim_path = clean_ansi(parse_mmcli_value(modem, "primary sim path"))
    match = re.search(r"/SIM/(\d+)", sim_path)
    if not match:
        return ""
    sim_id = match.group(1)
    sim_info = run_command(["mmcli", "-i", sim_id])
    return clean_ansi(parse_mmcli_value(sim_info, "imsi"))


def get_active_cellular_connection() -> str:
    output = run_nmcli(["-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active"])
    if not output:
        return ""
    for line in output.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] == "gsm":
            return parts[0]
    return ""


def get_cellular_connection(interface: str = "") -> str:
    target = interface.strip()
    active = get_active_cellular_connection()
    if active:
        if not target:
            return active
        active_device = run_nmcli(["-g", "GENERAL.DEVICES", "connection", "show", active]).strip()
        if active_device == target:
            return active

    output = run_nmcli(["-t", "-f", "NAME,TYPE,DEVICE", "connection", "show"])
    if not output:
        return ""
    for line in output.splitlines():
        parts = line.split(":")
        if len(parts) < 2 or parts[1] != "gsm":
            continue
        device = parts[2] if len(parts) >= 3 else ""
        if not target or device == target or device in {"", "--"}:
            return parts[0]
    return ""


def wifi_client_route_policy() -> tuple[str, str]:
    preference = normalize_wifi_uplink_preference(wifi_cfg("uplink_preference"))
    if preference == "prefer-wifi":
        return "600", "no"
    if preference == "failover-only":
        return "900", "yes" if get_active_cellular_connection() else "no"
    return "900", "no"


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


def suggest_apn_profile(operator: dict[str, str]) -> dict[str, str] | None:
    key = f"{operator.get('mcc', '')}{operator.get('mnc', '')}".strip()
    if key:
        for item in LTE_APN_PROFILES:
            if key in item.get("mccmnc", []):
                return item
    name = operator.get("operator_name", "").lower()
    if name:
        for item in LTE_APN_PROFILES:
            if item["provider"].lower() in name:
                return item
    return None


def ensure_auto_apn() -> None:
    if not LTE_AUTO_APN["enabled"]:
        return
    modem_id = get_modem_id()
    operator = get_operator_info(modem_id)
    sim_imsi = get_sim_imsi(modem_id)
    sim_key = sim_imsi or f"{operator.get('mcc', '')}{operator.get('mnc', '')}".strip()
    override = LTE_SIM_OVERRIDES.get(sim_key, {})
    if override.get("apn"):
        profile = override
    else:
        profile = suggest_apn_profile(operator)
    if not profile:
        return
    key = profile.get("id", profile.get("apn", ""))
    now = time.time()
    if LTE_AUTO_APN["last_key"] == key and (now - LTE_AUTO_APN["last_applied"]) < 20:
        return
    conn = get_active_cellular_connection()
    if not conn:
        return
    current_apn = run_nmcli(["-g", "gsm.apn", "connection", "show", conn])
    current_v4 = run_nmcli(["-g", "ipv4.method", "connection", "show", conn])
    current_v6 = run_nmcli(["-g", "ipv6.method", "connection", "show", conn])
    if current_apn == profile["apn"] and current_v4 == profile["ipv4_method"] and current_v6 == profile["ipv6_method"]:
        return
    run_nmcli_full(["connection", "modify", conn, "gsm.apn", profile["apn"], "ipv4.method", profile["ipv4_method"], "ipv6.method", profile["ipv6_method"]])
    run_nmcli_full(["connection", "down", conn])
    run_nmcli_full(["connection", "up", conn])
    LTE_AUTO_APN["last_key"] = key
    LTE_AUTO_APN["last_applied"] = now


def parse_samba_shares(conf_text: str, source: str) -> list[dict[str, str]]:
    shares: list[dict[str, str]] = []
    current_name = ""
    current_share: dict[str, str] | None = None
    for raw_line in conf_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            if current_share and current_name and current_name.lower() != "global":
                shares.append(current_share)
            current_name = line[1:-1].strip()
            current_share = {
                "name": current_name,
                "path": "",
                "read_only": "",
                "guest_ok": "",
                "valid_users": "",
                "source": source,
            }
            continue
        if "=" not in line or not current_share:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        key = key.lower()
        if key == "path":
            current_share["path"] = value
        elif key == "read only":
            current_share["read_only"] = value
        elif key == "guest ok":
            current_share["guest_ok"] = value
        elif key == "valid users":
            current_share["valid_users"] = value

    if current_share and current_name and current_name.lower() != "global":
        shares.append(current_share)
    return shares


def ensure_samba_portal_include() -> None:
    main_path = Path(HOST_SAMBA_MAIN_CONFIG)
    if not main_path.exists():
        raise HTTPException(status_code=500, detail="Host Samba config not found")
    text = main_path.read_text()
    if HOST_SAMBA_INCLUDE_LINE in text:
        return
    lines = text.splitlines()
    inserted = False
    for index, line in enumerate(lines):
        if line.strip().lower() == "[global]":
            insert_at = index + 1
            while insert_at < len(lines) and lines[insert_at].startswith(("\t", " ")):
                insert_at += 1
            lines.insert(insert_at, f"\t{HOST_SAMBA_INCLUDE_LINE}")
            inserted = True
            break
    if not inserted:
        lines.extend(["", "[global]", f"\t{HOST_SAMBA_INCLUDE_LINE}"])
    main_path.write_text("\n".join(lines).rstrip() + "\n")


def read_portal_samba_shares() -> list[dict[str, str]]:
    return parse_samba_shares(read_text(HOST_SAMBA_PORTAL_CONFIG, ""), "portal")


def write_portal_samba_shares(shares: list[dict[str, str]]) -> None:
    lines = ["# Managed by Network Panel", ""]
    for share in shares:
        lines.append(f"[{share['name']}]")
        lines.append(f"\tpath = {share['path']}")
        lines.append(f"\tread only = {share['read_only'] or 'No'}")
        lines.append(f"\tguest ok = {share['guest_ok'] or 'No'}")
        if share.get("valid_users"):
            lines.append(f"\tvalid users = {share['valid_users']}")
        lines.append("")
    Path(HOST_SAMBA_PORTAL_CONFIG).write_text("\n".join(lines).rstrip() + "\n")


def test_samba_config() -> None:
    code, stdout, stderr = run_command_full(["testparm", "-s", HOST_SAMBA_MAIN_CONFIG])
    if code != 0:
        raise HTTPException(status_code=500, detail={"code": code, "stdout": stdout, "stderr": stderr or "Samba config validation failed"})


def get_samba_users() -> list[dict[str, str]]:
    if not host_command_available("/usr/bin/pdbedit"):
        return []
    code, stdout, _ = run_command_full(host_binary_command("/usr/bin/pdbedit", ["-L"]))
    if code != 0:
        return []
    users: list[dict[str, str]] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        username, _, description = line.partition(":")
        users.append(
            {
                "username": username.strip(),
                "description": description.strip(),
            }
        )
    return users


def get_printing_status() -> dict[str, object]:
    listeners = parse_service_listeners()
    cups_listener = any("631" in (svc.get("ports") or []) for svc in listeners)
    samba = get_samba_status()
    printer_shares = [share for share in samba.get("shares", []) if share.get("name", "").lower() in {"printers", "print$"}]
    cups_installed = host_command_available("/usr/bin/systemctl")
    cups_enabled = False
    cups_active = is_process_running("cupsd")
    if cups_installed:
        _, enabled_out, enabled_err = run_command_full(host_binary_command("/usr/bin/systemctl", ["is-enabled", "cups"]))
        _, active_out, active_err = run_command_full(host_binary_command("/usr/bin/systemctl", ["is-active", "cups"]))
        if "not-found" in (enabled_out + enabled_err + active_out + active_err):
            cups_installed = False
        else:
            cups_enabled = enabled_out.strip() == "enabled"
            cups_active = active_out.strip() == "active" or cups_active
    return {
        "cups_installed": cups_installed,
        "cups_enabled": cups_enabled,
        "cups_active": cups_active,
        "cups_listener": cups_listener,
        "printer_shares": printer_shares,
    }


def get_samba_status() -> dict[str, object]:
    smbd = is_process_running("smbd")
    nmbd = is_process_running("nmbd")
    conf_path = ""
    conf_text = ""
    for candidate in HOST_SAMBA_CONFIG_PATHS:
        conf_text = read_text(candidate, "")
        if conf_text:
            conf_path = candidate
            break

    shares = parse_samba_shares(conf_text, "main")
    portal_shares = read_portal_samba_shares()
    combined_shares = shares + [
        share for share in portal_shares
        if all(existing["name"].lower() != share["name"].lower() for existing in shares)
    ]

    return {
        "running": smbd,
        "nmbd_running": nmbd,
        "config_path": conf_path or "not found",
        "shares": combined_shares,
        "portal_shares": portal_shares,
        "users": get_samba_users(),
        "host_config_writable": Path("/host/etc/samba").exists() and os.access("/host/etc/samba", os.W_OK),
        "smbpasswd_available": command_exists("smbpasswd"),
    }


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


def parse_service_listeners() -> list[dict[str, object]]:
    output = run_command(["ss", "-H", "-ltnup"])
    if not output:
        return []

    port_names = {
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
        "8080": "Network Panel",
        "8081": "Pi-hole",
        "9000": "Portainer",
        "9090": "Cockpit",
        "9091": "Prometheus",
        "9100": "Node Exporter",
        "9443": "Portainer HTTPS",
        "41641": "Tailscale",
    }

    services: dict[tuple[str, str], dict[str, object]] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue

        proto = parts[0]
        local = parts[4]
        if local.startswith("["):
            host_part, _, port = local.rpartition(":")
            host = host_part.strip("[]")
        else:
            host, _, port = local.rpartition(":")

        if not port:
            continue

        name = port_names.get(port, f"Port {port}")
        key = (name, proto)
        service = services.setdefault(
            key,
            {"name": name, "type": "listener", "active": True, "ports": set(), "binds": set()},
        )
        service["ports"].add(f"{proto}/{port}")
        service["binds"].add(host or "*")

    result = []
    for service in sorted(services.values(), key=lambda item: item["name"]):
        result.append(
            {
                "name": service["name"],
                "type": service["type"],
                "active": service["active"],
                "ports": sorted(service["ports"]),
                "binds": sorted(service["binds"]),
            }
        )

    return result


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
        "network-panel-backend": "Network Panel",
    }
    for line in stdout.splitlines():
        name = line.split("\t", 1)[0].strip().lower()
        if name in known:
            service_names.add(known[name])
    return service_names


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
        "8080": "Network Panel",
        "8081": "Pi-hole",
        "9000": "Portainer",
        "9090": "Cockpit",
        "9091": "Prometheus",
        "9100": "Node Exporter",
        "9443": "Portainer HTTPS",
        "20211": "NetAlertX",
        "41641": "Tailscale",
    }


def local_http_probe(url: str, timeout: float = 3.0) -> dict[str, object]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return {"ok": True, "code": getattr(response, "status", 200), "url": url}
    except urllib.error.HTTPError as exc:
        return {"ok": True, "code": exc.code, "url": url}
    except Exception as exc:
        return {"ok": False, "code": 0, "url": url, "error": str(exc)}


def get_pihole_container_ip() -> str:
    docker_cmd = None
    if host_command_available("/usr/bin/docker"):
        docker_cmd = host_binary_command(
            "/usr/bin/docker",
            [
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                "pihole",
            ],
        )
    elif command_exists("docker"):
        docker_cmd = [
            "docker",
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            "pihole",
        ]
    if not docker_cmd:
        return ""
    code, stdout, stderr = run_command_full(docker_cmd)
    if code != 0:
        return ""
    candidate = stdout.strip()
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", candidate):
        return candidate
    return ""


def pihole_forwarding_enabled() -> bool:
    config = read_text(PIHOLE_DNSMASQ_FORWARD_CONF, "")
    ip = get_pihole_container_ip()
    if not config or not ip:
        return False
    return f"server={ip}" in config


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
        "# Managed by network-panel\n"
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
        active_networks.append("Service LAN")
    if wifi_bind and wifi_bind in dns_binds:
        active_networks.append("Wi-Fi Hotspot")
    pihole_ip = get_pihole_container_ip()
    forwarding_enabled = pihole_forwarding_enabled()
    prefs = pihole_network_preferences()
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
            active_segments.append("Main LAN" if item.startswith(lan_cfg("ipv4_subnet")) else "Service LAN")
        elif "--interface=wl" in item:
            active_segments.append("Wi-Fi Hotspot")
        elif "--interface=wwan" in item:
            active_segments.append("LTE")
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

        result.append(
            {
                "name": name,
                "state": state,
                "mac": iface.get("address"),
                "ipv4": ipv4,
                "ipv6": ipv6,
                "mtu": iface.get("mtu"),
                "role": guess_interface_role(name),
                "flags": iface.get("flags", []),
                "physical": guess_interface_role(name) in {"ethernet", "wifi", "cellular"},
            }
        )

    return result


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


def humanize_wifi_security(key_mgmt: str, proto: str = "") -> str:
    key = (key_mgmt or "").strip().lower()
    proto_value = (proto or "").strip().upper()
    if not key:
        return "open"
    if key == "wpa-psk":
        return "WPA2-Personal" if "RSN" in proto_value or not proto_value else f"WPA-PSK ({proto_value})"
    if key == "sae":
        return "WPA3-Personal"
    return key_mgmt or "unknown"


def wifi_band_to_nm(value: str) -> str:
    return {"2.4ghz": "bg", "5ghz": "a"}.get(normalize_wifi_band(value), "")


def wifi_band_from_nm(value: str) -> str:
    return {"bg": "2.4 GHz", "a": "5 GHz", "": "Auto", "--": "Auto"}.get((value or "").strip().lower(), value or "Auto")


def wifi_channel_value(value: str, band: str) -> str:
    return "" if normalize_wifi_channel(value, normalize_wifi_band(band)) == "auto" else normalize_wifi_channel(value, normalize_wifi_band(band))


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
    return run_nmcli(["--show-secrets", "-g", key, "connection", "show", connection]).strip()


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


def parse_default_route(raw: str) -> dict[str, str]:
    route = {"raw": raw, "via": "", "dev": "", "src": ""}
    if not raw:
        return route

    via = re.search(r"\bvia\s+([^\s]+)", raw)
    dev = re.search(r"\bdev\s+([^\s]+)", raw)
    src = re.search(r"\bsrc\s+([^\s]+)", raw)
    if via:
        route["via"] = via.group(1)
    if dev:
        route["dev"] = dev.group(1)
    if src:
        route["src"] = src.group(1)
    return route


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
            0 if iface["name"].startswith("eth") else 1,
            0 if iface["state"] == "UP" else 1,
            0 if iface["name"].startswith("enx") else 1,
            iface["name"],
        ),
    )


def choose_interface(preferred: str, exclude: set[str], purpose: str) -> str:
    candidates = ethernet_candidates()
    candidate_names = {iface["name"] for iface in candidates}
    if preferred and preferred in candidate_names and preferred not in exclude:
        return preferred

    if purpose == "service":
        sorted_candidates = sorted(
            candidates,
            key=lambda iface: (
                0 if iface["name"].startswith("enx") else 1,
                0 if iface["state"] == "UP" else 1,
                iface["name"],
            ),
        )
    else:
        sorted_candidates = sorted(
            candidates,
            key=lambda iface: (
                0 if iface["name"].startswith("eth") else 1,
                0 if iface["state"] == "UP" else 1,
                iface["name"],
            ),
        )

    for iface in sorted_candidates:
        if iface["name"] not in exclude:
            return iface["name"]
    return preferred or (sorted_candidates[0]["name"] if sorted_candidates else "")


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
    for iface in interfaces:
        neighbors = {}
        neighbors.update(parse_ip_neighbors(iface["name"], "ipv4"))
        neighbors.update(parse_ip_neighbors(iface["name"], "ipv6"))
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


def get_active_sessions() -> list[dict[str, str]]:
    output = run_command(["ss", "-H", "-tnp", "state", "established"])
    if not output:
        return []

    interfaces = get_interfaces_data()
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
        elif preference == "failover-only":
            notes.append("uplink preference is failover only, so Wi-Fi stays off the default route while LTE is active")
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
        "802-11-wireless.mode",
        "ap",
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
        "ipv6.method",
        wifi_cfg("ipv6_method") or "disabled",
        "ipv6.addresses",
        wifi_ipv6_addresses_for_mode("hotspot", wifi_cfg("ipv6_method")),
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
        "connection.autoconnect", "yes",
        "connection.interface-name", interface,
        "ipv4.method", lan_cfg("ipv4_mode"),
        "ipv4.addresses", lan_cfg("ipv4_address"),
        "ipv6.method", "manual" if lan_cfg("ipv6_mode") != "disabled" else "disabled",
        "ipv6.addresses", lan_cfg("ipv6_address") if lan_cfg("ipv6_mode") != "disabled" else "",
    ]
    if lan_cfg("ipv4_mode") != "shared":
        settings.extend(["ipv4.dns", dns_servers, "ipv4.dns-search", dns_search])
    code, stdout, stderr = run_command_full(cmd + settings)
    if code != 0:
        return apply_static_fallback(stderr or "NetworkManager profile apply failed")

    code, stdout, stderr = run_command_full(nmcli_cmd(["connection", "up", connection_name]))
    if code != 0:
        return apply_static_fallback(stderr or "Failed to bring main-lan up")
    return code, stdout, stderr



@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/overview")
def overview():
    hostname = read_text("/host/etc/hostname", "unknown")

    uptime_raw = read_text("/host/proc/uptime", "0 0").split()
    uptime_seconds = int(float(uptime_raw[0])) if uptime_raw else 0

    default_v4 = run_command(["ip", "route", "show", "default"])
    default_v6 = run_command(["ip", "-6", "route", "show", "default"])

    interfaces_data = get_interfaces_data()
    uplinks = [
        iface for iface in interfaces_data
        if iface["role"] in {"cellular", "wifi", "overlay"} and (iface["ipv4"] or iface["ipv6"] or iface["state"] == "UP")
    ]
    local_lans = [
        iface for iface in interfaces_data
        if iface["role"] == "ethernet"
    ]
    hardware = {
        "cpu_temp_c": get_cpu_temperature_c(),
        "nvme_temp_c": get_nvme_temperature_c(),
        "input_voltage_v": get_input_voltage_v(),
    }
    memory = get_memory_stats()
    load = get_load_averages()
    docker = get_docker_brief_status()

    return {
        "hostname": hostname,
        "uptime_seconds": uptime_seconds,
        "default_route_v4": default_v4,
        "default_route_v6": default_v6,
        "uplink_ipv4": parse_default_route(default_v4),
        "uplink_ipv6": parse_default_route(default_v6),
        "uplinks": uplinks,
        "local_lans": local_lans,
        "hardware": hardware,
        "memory": memory,
        "load": load,
        "docker": docker,
    }


@app.get("/api/interfaces")
def interfaces():
    return get_interfaces_data()


@app.get("/api/lte")
def lte():
    modem_id = get_modem_id()
    if not modem_id:
        return {"available": False}

    run_command(["mmcli", "-m", modem_id, "--signal-setup=5"])

    modem = run_command(["mmcli", "-m", modem_id])
    signal = run_command(["mmcli", "-m", modem_id, "--signal-get"])
    operator = get_operator_info(modem_id)

    if not modem:
        return {"available": False}

    ensure_auto_apn()

    return {
        "available": True,
        "state": clean_ansi(parse_mmcli_value(modem, "state")),
        "power_state": clean_ansi(parse_mmcli_value(modem, "power state")),
        "access_tech": clean_ansi(parse_mmcli_value(modem, "access tech")),
        "signal_quality": clean_ansi(parse_mmcli_value(modem, "signal quality")),
        "operator_name": operator.get("operator_name") or clean_ansi(parse_mmcli_value(modem, "operator name")),
        "operator_mcc": operator.get("mcc", ""),
        "operator_mnc": operator.get("mnc", ""),
        "registration": clean_ansi(parse_mmcli_value(modem, "registration")),
        "packet_service_state": clean_ansi(parse_mmcli_value(modem, "packet service state")),
        "rssi": clean_ansi(parse_mmcli_value(signal, "rssi")),
        "rsrq": clean_ansi(parse_mmcli_value(signal, "rsrq")),
        "rsrp": clean_ansi(parse_mmcli_value(signal, "rsrp")),
        "snr": clean_ansi(parse_mmcli_value(signal, "s/n")),
    }


@app.get("/api/lte/profile")
def lte_profile():
    conn = get_active_cellular_connection()
    if not conn:
        return {"available": False, "connection": ""}

    apn = run_nmcli(["-g", "gsm.apn", "connection", "show", conn])
    ipv4_method = run_nmcli(["-g", "ipv4.method", "connection", "show", conn])
    ipv6_method = run_nmcli(["-g", "ipv6.method", "connection", "show", conn])
    raw_profile = run_nmcli(["connection", "show", conn])
    return {
        "available": True,
        "connection": conn,
        "apn": apn,
        "ipv4_method": ipv4_method,
        "ipv6_method": ipv6_method,
        "raw_profile": raw_profile,
    }


@app.get("/api/lte/apn/options")
def lte_apn_options():
    return {"options": LTE_APN_PROFILES}


@app.get("/api/lte/apn/suggest")
def lte_apn_suggest():
    modem_id = get_modem_id()
    operator = get_operator_info(modem_id)
    sim_imsi = get_sim_imsi(modem_id)
    sim_key = sim_imsi or f"{operator.get('mcc', '')}{operator.get('mnc', '')}".strip()
    profile = suggest_apn_profile(operator)
    return {
        "operator": operator,
        "suggested": profile or {},
        "sim_key": sim_key,
        "override": LTE_SIM_OVERRIDES.get(sim_key, {}),
    }


@app.get("/api/lte/apn/auto")
def lte_apn_auto_status():
    return {"enabled": LTE_AUTO_APN["enabled"]}


@app.post("/api/lte/apn/auto")
def lte_apn_auto_update(payload: dict = Body(...)):
    enabled = str(payload.get("enabled", "")).strip().lower()
    LTE_AUTO_APN["enabled"] = enabled in {"1", "true", "yes", "on"}
    save_runtime_config()
    return {"ok": True, "enabled": LTE_AUTO_APN["enabled"]}


@app.post("/api/lte/apn/apply")
def lte_apn_apply(payload: dict = Body(...)):
    conn = get_active_cellular_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="No active cellular connection found")

    profile_id = str(payload.get("profile_id", "")).strip()
    custom_apn = str(payload.get("apn", "")).strip()
    ipv4_method = str(payload.get("ipv4_method", "auto")).strip() or "auto"
    ipv6_method = str(payload.get("ipv6_method", "auto")).strip() or "auto"
    remember = str(payload.get("remember", "true")).strip().lower() in {"1", "true", "yes", "on"}

    selected = None
    if profile_id:
        for item in LTE_APN_PROFILES:
            if item["id"] == profile_id:
                selected = item
                break

    if selected:
        apn = selected["apn"]
        ipv4_method = selected["ipv4_method"]
        ipv6_method = selected["ipv6_method"]
    else:
        apn = custom_apn

    if not apn:
        raise HTTPException(status_code=400, detail="APN is required")

    code, stdout, stderr = run_nmcli_full(["connection", "modify", conn, "gsm.apn", apn, "ipv4.method", ipv4_method, "ipv6.method", ipv6_method])
    if code != 0:
        raise HTTPException(status_code=500, detail={"code": code, "stdout": stdout, "stderr": stderr})

    modem_id = get_modem_id()
    operator = get_operator_info(modem_id)
    sim_imsi = get_sim_imsi(modem_id)
    sim_key = sim_imsi or f"{operator.get('mcc', '')}{operator.get('mnc', '')}".strip()
    if remember and sim_key:
        LTE_SIM_OVERRIDES[sim_key] = {
            "id": profile_id or "custom",
            "apn": apn,
            "ipv4_method": ipv4_method,
            "ipv6_method": ipv6_method,
        }
        save_runtime_config()
    elif sim_key and sim_key in LTE_SIM_OVERRIDES and not remember:
        del LTE_SIM_OVERRIDES[sim_key]
        save_runtime_config()

    run_nmcli_full(["connection", "down", conn])
    code, stdout, stderr = run_nmcli_full(["connection", "up", conn])
    if code != 0:
        raise HTTPException(status_code=500, detail={"code": code, "stdout": stdout, "stderr": stderr})

    return {
        "ok": True,
        "connection": conn,
        "apn": apn,
        "ipv4_method": ipv4_method,
        "ipv6_method": ipv6_method,
        "remembered": bool(remember and sim_key),
    }


@app.post("/api/main-lan/preview")
def main_lan_preview(payload: dict = Body(default={})):
    return {"ok": True, "commands": build_main_lan_preview(payload)}


@app.post("/api/service-lan/preview")
def service_lan_preview(payload: dict = Body(default={})):
    return {"ok": True, "commands": build_service_lan_preview(payload)}


@app.post("/api/wifi/preview")
def wifi_preview(payload: dict = Body(default={})):
    return {"ok": True, "commands": build_wifi_preview(payload)}


@app.post("/api/lte/apn/preview")
def lte_apn_preview(payload: dict = Body(default={})):
    return {"ok": True, "commands": build_lte_apn_preview(payload)}


@app.get("/api/lte/at/examples")
def lte_at_examples():
    return {
        "disclaimer": "AT commands can drop the modem connection or change persistent modem state. Use carefully.",
        "commands": [
            "ATI",
            "AT+CSQ",
            'AT+QENG="servingcell"',
            "AT+COPS?",
            "AT+CGDCONT?",
        ],
    }


@app.post("/api/lte/at")
def lte_at_command(payload: dict = Body(...)):
    modem_id = get_modem_id()
    command = str(payload.get("command", "")).strip()
    if not modem_id:
        raise HTTPException(status_code=500, detail="No modem detected")
    if not command:
        raise HTTPException(status_code=400, detail="AT command is required")
    code, stdout, stderr = run_command_full(["mmcli", "-m", modem_id, f"--command={command}"])
    if code != 0:
        error_text = stderr or stdout
        if "debug mode" in error_text.lower() or "unauthorized" in error_text.lower():
            raise HTTPException(
                status_code=403,
                detail={
                    "code": code,
                    "stdout": stdout,
                    "stderr": stderr,
                    "message": "AT commands are blocked by ModemManager until modem debug mode is enabled on the host.",
                },
            )
        raise HTTPException(status_code=500, detail={"code": code, "stdout": stdout, "stderr": stderr})
    return {"ok": True, "command": command, "stdout": stdout, "stderr": stderr}


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
                    "yes",
                    "connection.interface-name",
                    interface,
                    "ipv4.method",
                    config.get("ipv4_mode", ""),
                    "ipv4.addresses",
                    config.get("ipv4_address", ""),
                    "ipv6.method",
                    "manual" if config.get("ipv6_mode") != "disabled" else "disabled",
                    "ipv6.addresses",
                    config.get("ipv6_address", "") if config.get("ipv6_mode") != "disabled" else "",
                ]
            )
        ),
        shell_preview(nmcli_command(["connection", "up", "main-lan"])),
    ]


def build_service_lan_preview(payload: dict | None = None) -> list[str]:
    env = service_lan_command_env()
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
    return [
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
                            "ipv6.method",
                            config.get("ipv6_method", "disabled"),
                            "ipv6.addresses",
                            config.get("ipv6_address", "fd42:42::1/64") if config.get("ipv6_method") == "manual" else "",
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


def build_lte_apn_preview(payload: dict | None = None) -> list[str]:
    payload = payload or {}
    conn = get_active_cellular_connection() or "<active-cellular-connection>"
    apn = str(payload.get("apn", "")).strip() or "<apn>"
    ipv4_method = str(payload.get("ipv4_method", "auto")).strip() or "auto"
    ipv6_method = str(payload.get("ipv6_method", "auto")).strip() or "auto"
    return [
        shell_preview(["nmcli", "connection", "modify", conn, "gsm.apn", apn, "ipv4.method", ipv4_method, "ipv6.method", ipv6_method]),
        shell_preview(["nmcli", "connection", "down", conn]),
        shell_preview(["nmcli", "connection", "up", conn]),
    ]

@app.get("/api/services")
def services():
    docker_names = get_docker_service_names()
    process_services = [
        {"name": "NetworkManager", "type": "host", "active": is_process_running("NetworkManager"), "source": "system"},
        {"name": "ModemManager", "type": "host", "active": is_process_running("ModemManager"), "source": "system"},
        {"name": "tailscaled", "type": "host", "active": is_process_running("tailscaled"), "source": "system"},
        {"name": "smbd", "type": "host", "active": is_process_running("smbd"), "source": "system"},
    ]

    discovered = parse_service_listeners()
    combined: dict[str, dict[str, object]] = {
        service["name"]: service for service in process_services if service["active"]
    }
    for service in discovered:
        service["source"] = "docker" if service["name"] in docker_names else "system"
        combined[service["name"]] = service

    return sorted(combined.values(), key=lambda item: item["name"])


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
    command = docker_cli_command(["compose", "-f", NETALERTX_COMPOSE_FILE, "up", "-d", "netalertx"])
    code, stdout, stderr = run_command_full(command)
    if code != 0:
        raise HTTPException(status_code=500, detail={"code": code, "stdout": stdout, "stderr": stderr})
    return {"ok": True, "stdout": stdout, "stderr": stderr}


@app.post("/api/netalert/sync")
def netalert_sync():
    result = sync_netalertx_topology(restart=True)
    if not result.get("ok"):
        raise HTTPException(status_code=500, detail=result)
    return result


@app.get("/api/samba/status")
def samba_status():
    return get_samba_status()


@app.get("/api/filesystem")
def filesystem_status():
    return get_filesystem_status()


@app.get("/api/device-io")
def device_io_status():
    return get_device_io_status()


@app.get("/api/system/stats")
def system_stats():
    return {
        "memory": get_memory_stats(),
        "load": get_load_averages(),
        "docker": get_docker_brief_status(),
        "hardware": {
            "cpu_temp_c": get_cpu_temperature_c(),
            "nvme_temp_c": get_nvme_temperature_c(),
            "input_voltage_v": get_input_voltage_v(),
        },
    }


@app.post("/api/samba/control")
def samba_control(payload: dict = Body(...)):
    action = str(payload.get("action", "")).strip().lower()
    if action not in {"start", "stop", "restart"}:
        raise HTTPException(status_code=400, detail="Invalid action")
    if command_exists("systemctl"):
        code, stdout, stderr = run_command_full(["systemctl", action, "smbd"])
    elif command_exists("service"):
        code, stdout, stderr = run_command_full(["service", "smbd", action])
    else:
        raise HTTPException(status_code=500, detail="No service manager available")
    if code != 0:
        raise HTTPException(status_code=500, detail={"code": code, "stdout": stdout, "stderr": stderr})
    return {"ok": True}


@app.post("/api/samba/user/password")
def samba_user_password(payload: dict = Body(...)):
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    if not host_command_available("/usr/bin/smbpasswd"):
        raise HTTPException(status_code=500, detail="Host smbpasswd not available")
    code, stdout, stderr = run_command_input(host_binary_command("/usr/bin/smbpasswd", ["-L", "-a", "-s", username]), f"{password}\n{password}\n")
    if code != 0:
        raise HTTPException(status_code=500, detail={"code": code, "stdout": stdout, "stderr": stderr})
    return {"ok": True}


@app.post("/api/samba/user/delete")
def samba_user_delete(payload: dict = Body(...)):
    username = str(payload.get("username", "")).strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username required")
    if not host_command_available("/usr/bin/smbpasswd"):
        raise HTTPException(status_code=500, detail="Host smbpasswd not available")
    code, stdout, stderr = run_command_full(host_binary_command("/usr/bin/smbpasswd", ["-L", "-x", username]))
    if code != 0:
        raise HTTPException(status_code=500, detail={"code": code, "stdout": stdout, "stderr": stderr})
    return {"ok": True, "username": username}


@app.post("/api/samba/user/state")
def samba_user_state(payload: dict = Body(...)):
    username = str(payload.get("username", "")).strip()
    action = str(payload.get("action", "")).strip().lower()
    if not username or action not in {"enable", "disable"}:
        raise HTTPException(status_code=400, detail="Username and valid action required")
    if not host_command_available("/usr/bin/smbpasswd"):
        raise HTTPException(status_code=500, detail="Host smbpasswd not available")
    flag = "-e" if action == "enable" else "-d"
    code, stdout, stderr = run_command_full(host_binary_command("/usr/bin/smbpasswd", ["-L", flag, username]))
    if code != 0:
        raise HTTPException(status_code=500, detail={"code": code, "stdout": stdout, "stderr": stderr})
    return {"ok": True, "username": username, "action": action}


@app.post("/api/samba/share")
def samba_share_save(payload: dict = Body(...)):
    name = str(payload.get("name", "")).strip()
    path = str(payload.get("path", "")).strip()
    read_only = str(payload.get("read_only", "No")).strip() or "No"
    guest_ok = str(payload.get("guest_ok", "No")).strip() or "No"
    valid_users = str(payload.get("valid_users", "")).strip()
    if not name or not path:
        raise HTTPException(status_code=400, detail="Share name and path are required")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise HTTPException(status_code=400, detail="Share name may only contain letters, numbers, dot, dash, and underscore")

    ensure_samba_portal_include()
    shares = read_portal_samba_shares()
    updated = False
    for share in shares:
        if share["name"].lower() == name.lower():
            share.update({"name": name, "path": path, "read_only": read_only, "guest_ok": guest_ok, "valid_users": valid_users, "source": "portal"})
            updated = True
            break
    if not updated:
        shares.append({"name": name, "path": path, "read_only": read_only, "guest_ok": guest_ok, "valid_users": valid_users, "source": "portal"})
    write_portal_samba_shares(shares)
    test_samba_config()
    return {"ok": True, "share": name}


@app.post("/api/samba/share/delete")
def samba_share_delete(payload: dict = Body(...)):
    name = str(payload.get("name", "")).strip()
    if not name:
        raise HTTPException(status_code=400, detail="Share name is required")
    shares = [share for share in read_portal_samba_shares() if share["name"].lower() != name.lower()]
    write_portal_samba_shares(shares)
    test_samba_config()
    return {"ok": True, "share": name}


@app.get("/api/printing/status")
def printing_status():
    return get_printing_status()


@app.post("/api/printing/control")
def printing_control(payload: dict = Body(...)):
    action = str(payload.get("action", "")).strip().lower()
    if action not in {"start", "stop", "restart"}:
        raise HTTPException(status_code=400, detail="Invalid action")
    if not host_command_available("/usr/bin/systemctl"):
        raise HTTPException(status_code=500, detail="Host systemctl not available")
    status = get_printing_status()
    if not status.get("cups_installed"):
        raise HTTPException(status_code=500, detail="CUPS is not installed on the device")
    code, stdout, stderr = run_command_full(host_binary_command("/usr/bin/systemctl", [action, "cups"]))
    if code != 0:
        raise HTTPException(status_code=500, detail={"code": code, "stdout": stdout, "stderr": stderr})
    return {"ok": True, "action": action}


@app.get("/api/service-lan/clients")
def service_lan_clients():
    interface = get_service_lan_interface()
    iface = get_interface_data(interface)
    if not iface.get("name"):
        return []
    clients = collect_clients_for_interfaces([iface], interface)
    clients = [client for client in clients if client.get("state", "").upper() != "FAILED"]
    return summarize_wifi_clients(clients)


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
        "name": service_lan_cfg("name") or "Service LAN",
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
            "shared = DHCP + NAT for IPv4 clients on the service port",
            "routed = IPv6 forwarding and router advertisements for service clients",
            "plugging in a USB Ethernet adapter gives the portal another port it can auto-assign",
        ] + (["choose a different physical interface from Main LAN to keep Service LAN isolated"] if interface_conflict else []),
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
        "name": "Main LAN",
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
        "nmcli_available": nmcli_available(),
        "connection": connection,
        "notes": [
            role_description(lan_cfg("role")),
            "shared = DHCP + NAT for local clients",
            "manual = static LAN without DHCP/NAT automation",
            "plugging in a USB Ethernet adapter gives the portal another port it can auto-assign",
        ] + (["choose a different physical interface from Service LAN to keep Main LAN separate"] if interface_conflict else []),
    }


@app.post("/api/main-lan/apply")
def main_lan_apply():
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
        "connection.autoconnect", "yes",
        "connection.interface-name", interface,
        "ipv4.method", "shared" if ipv4_enabled else "disabled",
        "ipv4.addresses", service_lan_ipv4_address() if ipv4_enabled else "",
        "ipv6.method", "manual" if ipv6_enabled else "disabled",
        "ipv6.addresses", service_lan_ipv6_address() if ipv6_enabled else "",
    ]
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
            detail={"code": sync_code, "stdout": "\n".join(stdout_parts).strip(), "stderr": "\n".join(stderr_parts).strip() or "Service LAN connection sync failed"},
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
                detail={"code": role_code, "stdout": "\n".join(stdout_parts).strip(), "stderr": "\n".join(stderr_parts).strip() or "Service LAN role policy apply failed"},
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
            detail={"code": code, "stdout": "\n".join(stdout_parts).strip(), "stderr": "\n".join(stderr_parts).strip() or "Service LAN apply failed"},
        )
    role_code, role_stdout, role_stderr = apply_interface_role_policy(get_service_lan_interface(), service_lan_cfg("role"))
    if role_stdout:
        stdout_parts.append(role_stdout)
    if role_stderr:
        stderr_parts.append(role_stderr)
    if role_code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": role_code, "stdout": "\n".join(stdout_parts).strip(), "stderr": "\n".join(stderr_parts).strip() or "Service LAN role policy apply failed"},
        )
    sync_netalertx_topology_safe()
    return {"ok": True, "stdout": "\n".join(stdout_parts).strip(), "stderr": "\n".join(stderr_parts).strip()}


@app.post("/api/service-lan/restart")
def service_lan_restart():
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
    code, stdout, stderr = set_interface_block(get_main_lan_interface(), False)
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": stdout, "stderr": stderr or "Main LAN internet enable failed"},
        )
    return {"ok": True, "code": code, "stdout": stdout, "stderr": stderr}


@app.post("/api/main-lan/internet/off")
def main_lan_internet_off():
    code, stdout, stderr = set_interface_block(get_main_lan_interface(), True)
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": stdout, "stderr": stderr or "Main LAN internet disable failed"},
        )
    return {"ok": True, "code": code, "stdout": stdout, "stderr": stderr}


@app.post("/api/interfaces/{interface}/link/up")
def interface_link_up(interface: str):
    code, stdout, stderr = run_command_full(["ip", "link", "set", "dev", interface, "up"])
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": stdout, "stderr": stderr or f"Failed to bring {interface} up"},
        )
    return {"ok": True, "code": code, "stdout": stdout, "stderr": stderr}


@app.post("/api/interfaces/{interface}/link/down")
def interface_link_down(interface: str):
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
        raise HTTPException(status_code=400, detail="Main LAN and Service LAN cannot use the same interface")
    allowed = {
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
    }
    for key, value in payload.items():
        if key in allowed and isinstance(value, str):
            MAIN_LAN_CONFIG[key] = normalize_lan_role(value) if key == "role" else value.strip()
    MAIN_LAN_CONFIG["target_interface"] = proposed_target or get_main_lan_interface()
    save_runtime_config()
    sync_netalertx_topology_safe(restart=False)
    return {"ok": True, "config": MAIN_LAN_CONFIG}


@app.get("/api/active-sessions")
def active_sessions():
    return get_active_sessions()


@app.post("/api/service-lan/config")
def update_service_lan_config(payload: dict = Body(...)):
    proposed_interface = str(payload.get("interface", get_service_lan_interface())).strip()
    if proposed_interface and same_physical_lan_interface(get_main_lan_interface(), proposed_interface):
        raise HTTPException(status_code=400, detail="Service LAN and Main LAN cannot use the same interface")
    allowed = {
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
    code, stdout, stderr = set_wifi_power(state)
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": stdout, "stderr": stderr or f"Wi-Fi power {state} failed"},
        )
    return {"ok": True, "state": state, "stdout": stdout, "stderr": stderr}


@app.post("/api/wifi/apply")
def wifi_apply():
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
    env = service_lan_command_env()
    code, stdout, stderr = run_command_full(["/usr/local/bin/service-lan-inet-on.sh"], env=env)
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": stdout, "stderr": stderr or "Service LAN enable failed"},
        )
    return {"ok": True, "code": code, "stdout": stdout, "stderr": stderr}


@app.post("/api/service-lan/internet/off")
def service_lan_internet_off():
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
            detail={"code": code, "stdout": stdout, "stderr": stderr or "Service LAN disable failed"},
        )
    return {"ok": True, "code": code, "stdout": stdout, "stderr": stderr}


@app.post("/api/system/restart")
def system_restart():
    if host_command_available("/usr/sbin/shutdown"):
        cmd = ["chroot", "/host", "/usr/sbin/shutdown", "-r", "now"]
    elif host_command_available("/usr/sbin/reboot"):
        cmd = ["chroot", "/host", "/usr/sbin/reboot"]
    else:
        raise HTTPException(status_code=500, detail="Host restart command not available")
    code, stdout, stderr = run_command_full(cmd)
    if code != 0:
        raise HTTPException(status_code=500, detail={"code": code, "stdout": stdout, "stderr": stderr or "Restart command failed"})
    return {"ok": True, "stdout": stdout, "stderr": stderr}


@app.post("/api/system/poweroff")
def system_poweroff():
    if host_command_available("/usr/sbin/shutdown"):
        cmd = ["chroot", "/host", "/usr/sbin/shutdown", "-P", "now"]
    elif host_command_available("/usr/sbin/poweroff"):
        cmd = ["chroot", "/host", "/usr/sbin/poweroff"]
    else:
        raise HTTPException(status_code=500, detail="Host poweroff command not available")
    code, stdout, stderr = run_command_full(cmd)
    if code != 0:
        raise HTTPException(status_code=500, detail={"code": code, "stdout": stdout, "stderr": stderr or "Power off command failed"})
    return {"ok": True, "stdout": stdout, "stderr": stderr}


@app.get("/", response_class=HTMLResponse)
def home():
    frontend_index = FRONTEND_DIST_PATH / "index.html"
    if frontend_index.exists():
        return FileResponse(frontend_index)
    return HTMLResponse(Path(__file__).with_name("portal.html").read_text())
