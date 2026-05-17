import json
from pathlib import Path


RUNTIME_CONFIG_PATH = "/app/data/runtime-config.json"


def runtime_config() -> dict[str, object]:
    path = Path(RUNTIME_CONFIG_PATH)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def section(name: str) -> dict[str, str]:
    data = runtime_config().get(name, {})
    if not isinstance(data, dict):
        return {}
    return {str(key): str(value).strip() for key, value in data.items() if isinstance(value, str)}


def write_runtime_config(data: dict[str, object]) -> None:
    path = Path(RUNTIME_CONFIG_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def update_lte_config(auto_apn_enabled: bool, sim_overrides: dict[str, dict[str, str]]) -> None:
    data = runtime_config()
    data["lte"] = {
        "auto_apn_enabled": auto_apn_enabled,
        "sim_overrides": dict(sim_overrides),
    }
    write_runtime_config(data)
