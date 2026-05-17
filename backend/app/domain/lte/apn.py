import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable

from fastapi import HTTPException

from app.core.host import run_command, run_nmcli, run_nmcli_full


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
SERVICE_PROVIDER_DB_PATHS = [
    "/usr/share/mobile-broadband-provider-info/serviceproviders.xml",
    "/host/usr/share/mobile-broadband-provider-info/serviceproviders.xml",
    "/usr/local/share/mobile-broadband-provider-info/serviceproviders.xml",
    "/host/usr/local/share/mobile-broadband-provider-info/serviceproviders.xml",
]
SERVICE_PROVIDER_DB_CACHE = {"path": "", "mtime": 0.0, "profiles": []}


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


def get_lte_connection_profile(connection: str) -> dict[str, str]:
    if not connection:
        return {"apn": "", "ipv4_method": "", "ipv6_method": ""}
    return {
        "apn": run_nmcli(["-g", "gsm.apn", "connection", "show", connection]).strip(),
        "ipv4_method": run_nmcli(["-g", "ipv4.method", "connection", "show", connection]).strip(),
        "ipv6_method": run_nmcli(["-g", "ipv6.method", "connection", "show", connection]).strip(),
    }


def modify_lte_connection_profile(connection: str, profile: dict[str, str]) -> tuple[int, str, str]:
    return run_nmcli_full(
        [
            "connection",
            "modify",
            connection,
            "gsm.apn",
            profile.get("apn", ""),
            "ipv4.method",
            profile.get("ipv4_method", "auto") or "auto",
            "ipv6.method",
            profile.get("ipv6_method", "auto") or "auto",
        ]
    )


def reconnect_lte_connection(connection: str) -> tuple[int, str, str]:
    down_code, down_stdout, down_stderr = run_nmcli_full(["connection", "down", connection])
    up_code, up_stdout, up_stderr = run_nmcli_full(["connection", "up", connection])
    stdout = "\n".join(part for part in (down_stdout, up_stdout) if part)
    stderr = "\n".join(part for part in (down_stderr, up_stderr) if part)
    if up_code != 0:
        return up_code, stdout, stderr
    return down_code if down_code != 0 else 0, stdout, stderr


def service_provider_db_path() -> str:
    for path in SERVICE_PROVIDER_DB_PATHS:
        if Path(path).exists():
            return path
    return ""


def parse_service_provider_database(path: str) -> list[dict[str, object]]:
    try:
        root = ET.parse(path).getroot()
    except Exception:
        return []
    profiles: list[dict[str, object]] = []
    for country in root.findall("country"):
        country_code = str(country.attrib.get("code", "")).strip().upper()
        for provider in country.findall("provider"):
            provider_name = (provider.findtext("name") or "").strip()
            gsm = provider.find("gsm")
            if gsm is None or not provider_name:
                continue
            mccmnc = []
            for network_id in gsm.findall("network-id"):
                mcc = str(network_id.attrib.get("mcc", "")).strip()
                mnc = str(network_id.attrib.get("mnc", "")).strip()
                if mcc and mnc:
                    mccmnc.append(f"{mcc}{mnc}")
            for index, apn in enumerate(gsm.findall("apn")):
                apn_value = str(apn.attrib.get("value", "")).strip()
                if not apn_value:
                    continue
                apn_name = (apn.findtext("name") or "").strip()
                profile_id = f"{country_code.lower()}-{provider_name.lower()}-{apn_value.lower()}-{index}"
                profile_id = re.sub(r"[^a-z0-9]+", "-", profile_id).strip("-")
                profiles.append(
                    {
                        "id": profile_id,
                        "country": country_code,
                        "provider": provider_name,
                        "name": apn_name,
                        "apn": apn_value,
                        "username": (apn.findtext("username") or "").strip(),
                        "password": (apn.findtext("password") or "").strip(),
                        "ipv4_method": "auto",
                        "ipv6_method": "auto",
                        "mccmnc": sorted(set(mccmnc)),
                        "source": "mobile-broadband-provider-info",
                    }
                )
    profiles.sort(key=lambda item: (str(item["country"]), str(item["provider"]).lower(), str(item["apn"]).lower()))
    return profiles


def service_provider_profiles() -> list[dict[str, object]]:
    path = service_provider_db_path()
    if not path:
        return []
    try:
        mtime = Path(path).stat().st_mtime
    except Exception:
        return []
    if SERVICE_PROVIDER_DB_CACHE["path"] == path and SERVICE_PROVIDER_DB_CACHE["mtime"] == mtime:
        return list(SERVICE_PROVIDER_DB_CACHE["profiles"])
    profiles = parse_service_provider_database(path)
    SERVICE_PROVIDER_DB_CACHE.update({"path": path, "mtime": mtime, "profiles": profiles})
    return list(profiles)


def apn_options() -> list[dict[str, object]]:
    profiles = service_provider_profiles()
    return profiles if profiles else list(LTE_APN_PROFILES)


def apn_catalog() -> dict[str, object]:
    profiles = apn_options()
    countries: dict[str, dict[str, object]] = {}
    for profile in profiles:
        country = str(profile.get("country", "")).strip() or "Unknown"
        provider = str(profile.get("provider", "")).strip() or "Unknown"
        entry = countries.setdefault(country, {"code": country, "providers": {}})
        providers = entry["providers"]
        if isinstance(providers, dict):
            providers.setdefault(provider, []).append(profile)
    db_profiles = service_provider_profiles()
    return {
        "source": "mobile-broadband-provider-info" if db_profiles else "built-in-fallback",
        "database_path": service_provider_db_path(),
        "countries": [
            {
                "code": code,
                "providers": [
                    {"name": name, "options": options}
                    for name, options in sorted(data["providers"].items(), key=lambda item: item[0].lower())
                ],
            }
            for code, data in sorted(countries.items(), key=lambda item: item[0])
        ],
        "options": profiles,
    }


def suggest_apn_profile(operator: dict[str, str]) -> dict[str, str] | None:
    key = f"{operator.get('mcc', '')}{operator.get('mnc', '')}".strip()
    if key:
        for item in apn_options():
            if key in item.get("mccmnc", []):
                return item
    name = operator.get("operator_name", "").lower()
    if name:
        for item in apn_options():
            if str(item["provider"]).lower() in name:
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
    profile = override if override.get("apn") else suggest_apn_profile(operator)
    if not profile:
        return
    key = profile.get("id", profile.get("apn", ""))
    now = time.time()
    if LTE_AUTO_APN["last_key"] == key and (now - LTE_AUTO_APN["last_applied"]) < 20:
        return
    conn = get_active_cellular_connection()
    if not conn:
        return
    current = get_lte_connection_profile(conn)
    if (
        current["apn"] == profile["apn"]
        and current["ipv4_method"] == profile["ipv4_method"]
        and current["ipv6_method"] == profile["ipv6_method"]
    ):
        return
    modify_lte_connection_profile(conn, profile)
    reconnect_lte_connection(conn)
    LTE_AUTO_APN["last_key"] = key
    LTE_AUTO_APN["last_applied"] = now


def lte_status() -> dict[str, object]:
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


def lte_profile_status() -> dict[str, object]:
    conn = get_active_cellular_connection()
    if not conn:
        return {"available": False, "connection": ""}

    profile = get_lte_connection_profile(conn)
    raw_profile = run_nmcli(["connection", "show", conn])
    return {
        "available": True,
        "connection": conn,
        "apn": profile["apn"],
        "ipv4_method": profile["ipv4_method"],
        "ipv6_method": profile["ipv6_method"],
        "raw_profile": raw_profile,
    }


def lte_apn_suggestion() -> dict[str, object]:
    modem_id = get_modem_id()
    operator = get_operator_info(modem_id)
    sim_imsi = get_sim_imsi(modem_id)
    sim_key = sim_imsi or f"{operator.get('mcc', '')}{operator.get('mnc', '')}".strip()
    profile = suggest_apn_profile(operator)
    override = LTE_SIM_OVERRIDES.get(sim_key, {})
    return {
        "operator": operator,
        "suggested": profile or {},
        "sim_key": sim_key,
        "override": override,
        "source": "sim_override" if override.get("apn") else ("mcc_mnc_database" if profile else "manual"),
    }


def apply_lte_apn(payload: dict, save_config: Callable[[], None]) -> dict[str, object]:
    conn = get_active_cellular_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="No active cellular connection found")
    previous_profile = get_lte_connection_profile(conn)

    profile_id = str(payload.get("profile_id", "")).strip()
    custom_apn = str(payload.get("apn", "")).strip()
    ipv4_method = str(payload.get("ipv4_method", "auto")).strip() or "auto"
    ipv6_method = str(payload.get("ipv6_method", "auto")).strip() or "auto"
    remember = str(payload.get("remember", "true")).strip().lower() in {"1", "true", "yes", "on"}

    selected = next((item for item in apn_options() if item["id"] == profile_id), None) if profile_id else None
    if selected:
        apn = selected["apn"]
        ipv4_method = selected["ipv4_method"]
        ipv6_method = selected["ipv6_method"]
    else:
        apn = custom_apn

    if not apn:
        raise HTTPException(status_code=400, detail="APN is required")

    next_profile = {"apn": apn, "ipv4_method": ipv4_method, "ipv6_method": ipv6_method}
    code, stdout, stderr = modify_lte_connection_profile(conn, next_profile)
    if code != 0:
        raise HTTPException(status_code=500, detail={"code": code, "stdout": stdout, "stderr": stderr})

    modem_id = get_modem_id()
    operator = get_operator_info(modem_id)
    sim_imsi = get_sim_imsi(modem_id)
    sim_key = sim_imsi or f"{operator.get('mcc', '')}{operator.get('mnc', '')}".strip()
    previous_override = dict(LTE_SIM_OVERRIDES.get(sim_key, {})) if sim_key else {}
    if remember and sim_key:
        LTE_SIM_OVERRIDES[sim_key] = {
            "id": profile_id or "custom",
            "apn": apn,
            "ipv4_method": ipv4_method,
            "ipv6_method": ipv6_method,
        }
        save_config()
    elif sim_key and sim_key in LTE_SIM_OVERRIDES and not remember:
        del LTE_SIM_OVERRIDES[sim_key]
        save_config()

    code, stdout, stderr = reconnect_lte_connection(conn)
    if code != 0:
        rollback_code, rollback_stdout, rollback_stderr = modify_lte_connection_profile(conn, previous_profile)
        reconnect_code, reconnect_stdout, reconnect_stderr = reconnect_lte_connection(conn)
        if sim_key:
            if previous_override:
                LTE_SIM_OVERRIDES[sim_key] = previous_override
            else:
                LTE_SIM_OVERRIDES.pop(sim_key, None)
            save_config()
        raise HTTPException(
            status_code=500,
            detail={
                "code": code,
                "stdout": stdout,
                "stderr": stderr,
                "rollback": {
                    "attempted": True,
                    "profile": previous_profile,
                    "modify_code": rollback_code,
                    "modify_stdout": rollback_stdout,
                    "modify_stderr": rollback_stderr,
                    "reconnect_code": reconnect_code,
                    "reconnect_stdout": reconnect_stdout,
                    "reconnect_stderr": reconnect_stderr,
                    "ok": rollback_code == 0 and reconnect_code == 0,
                },
            },
        )

    return {
        "ok": True,
        "connection": conn,
        "apn": apn,
        "ipv4_method": ipv4_method,
        "ipv6_method": ipv6_method,
        "previous_profile": previous_profile,
        "remembered": bool(remember and sim_key),
    }


def shell_preview(cmd: list[str]) -> str:
    import shlex

    return " ".join(shlex.quote(part) for part in cmd)


def build_apn_preview(payload: dict | None = None) -> list[str]:
    payload = payload or {}
    conn = get_active_cellular_connection() or "<active-cellular-connection>"
    apn = str(payload.get("apn", "")).strip() or "<apn>"
    ipv4_method = str(payload.get("ipv4_method", "auto")).strip() or "auto"
    ipv6_method = str(payload.get("ipv6_method", "auto")).strip() or "auto"
    return [
        "# backup current gsm.apn, ipv4.method and ipv6.method before modify",
        shell_preview(["nmcli", "connection", "modify", conn, "gsm.apn", apn, "ipv4.method", ipv4_method, "ipv6.method", ipv6_method]),
        shell_preview(["nmcli", "connection", "down", conn]),
        shell_preview(["nmcli", "connection", "up", conn]),
        "# if connection up fails, restore the backed-up profile and reconnect",
    ]


def run_at_command(command: str) -> dict[str, str | bool]:
    modem_id = get_modem_id()
    if not modem_id:
        raise HTTPException(status_code=500, detail="No modem detected")
    command = command.strip()
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
