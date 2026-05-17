import re

from app.core.host import read_text, run_command
from app.domain.network.state import normalize_interfaces
from app.domain.system.status import (
    get_cpu_temperature_c,
    get_docker_brief_status,
    get_input_voltage_v,
    get_load_averages,
    get_memory_stats,
    get_nvme_temperature_c,
)
from app.providers import iproute2


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


def system_stats() -> dict[str, object]:
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


def overview() -> dict[str, object]:
    hostname = read_text("/host/etc/hostname", "unknown")

    uptime_raw = read_text("/host/proc/uptime", "0 0").split()
    uptime_seconds = int(float(uptime_raw[0])) if uptime_raw else 0

    default_v4 = run_command(["ip", "route", "show", "default"])
    default_v6 = run_command(["ip", "-6", "route", "show", "default"])

    interfaces_data = normalize_interfaces(iproute2.addresses(), iproute2.links())
    default_devices = {
        item for item in [parse_default_route(default_v4).get("dev"), parse_default_route(default_v6).get("dev")]
        if item
    }
    uplinks = [
        iface for iface in interfaces_data
        if (
            iface["role"] in {"cellular", "wifi", "overlay"}
            or (iface["role"] == "ethernet" and iface["name"] in default_devices)
        )
        and (iface["ipv4"] or iface["ipv6"] or iface["state"] == "UP")
    ]
    local_lans = [
        iface for iface in interfaces_data
        if iface["role"] == "ethernet" and iface["name"] not in default_devices
    ]
    return {
        "hostname": hostname,
        "uptime_seconds": uptime_seconds,
        "default_route_v4": default_v4,
        "default_route_v6": default_v6,
        "uplink_ipv4": parse_default_route(default_v4),
        "uplink_ipv6": parse_default_route(default_v6),
        "uplinks": uplinks,
        "local_lans": local_lans,
        "hardware": {
            "cpu_temp_c": get_cpu_temperature_c(),
            "nvme_temp_c": get_nvme_temperature_c(),
            "input_voltage_v": get_input_voltage_v(),
        },
        "memory": get_memory_stats(),
        "load": get_load_averages(),
        "docker": get_docker_brief_status(),
    }
