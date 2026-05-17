import re
from pathlib import Path
import urllib.request

from app.core.cache import cached_read
from app.core.host import command_exists, host_binary_command, host_command_available, read_text, run_command_full


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
    def load() -> str:
        try:
            with urllib.request.urlopen("http://127.0.0.1:9100/metrics", timeout=1.5) as response:
                return response.read().decode("utf-8", errors="ignore")
        except Exception:
            return ""
    return cached_read("node_exporter_metrics", 10, load)


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


def get_docker_brief_status() -> dict[str, object]:
    def load() -> dict[str, object]:
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
    return cached_read("docker_brief_status", 10, load)
