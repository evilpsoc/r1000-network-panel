from copy import deepcopy

from app.core.runtime_config import runtime_config, write_runtime_config


CORE_TABS = ("dashboard", "network", "logs", "services", "runtime")
OPTIONAL_TABS = (
    "interfaces",
    "wireless",
    "cellular",
    "diagnostics",
    "routefirewall",
    "monitoring",
    "terminal",
    "filesharing",
    "users",
    "filesystem",
    "deviceio",
    "actions",
    "lorawan",
)
KNOWN_TABS = CORE_TABS + OPTIONAL_TABS

DEFAULT_SETTINGS = {
    "ui": {
        "visible_tabs": {
            "dashboard": True,
            "network": True,
            "logs": True,
            "services": True,
            "runtime": True,
            "interfaces": True,
            "wireless": True,
            "cellular": True,
            "diagnostics": True,
            "routefirewall": True,
            "monitoring": True,
            "terminal": True,
            "filesharing": True,
            "users": True,
            "filesystem": True,
            "deviceio": True,
            "actions": True,
            "lorawan": False,
        },
        "compact_mode": True,
        "show_demo_mode_hint": True,
    },
    "network_safety": {
        "require_preview_for_apply": True,
        "protect_default_route_interfaces": True,
        "backup_before_host_writes": True,
        "allow_route_firewall_apply": False,
    },
    "security": {
        "cookie_secure": False,
        "csrf_protection_target": True,
        "login_rate_limit_target": True,
        "api_keys_target": True,
    },
}


def deep_merge(defaults: dict[str, object], current: dict[str, object]) -> dict[str, object]:
    merged = deepcopy(defaults)
    for key, value in current.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)  # type: ignore[arg-type]
        else:
            merged[key] = value
    return merged


def normalize_visible_tabs(value: object) -> dict[str, bool]:
    raw = value if isinstance(value, dict) else {}
    defaults = DEFAULT_SETTINGS["ui"]["visible_tabs"]
    tabs = {
        tab: bool(raw.get(tab, defaults.get(tab, False)))  # type: ignore[union-attr]
        for tab in KNOWN_TABS
    }
    for tab in CORE_TABS:
        tabs[tab] = True
    return tabs


def panel_settings() -> dict[str, object]:
    data = runtime_config()
    settings = data.get("settings", {})
    if not isinstance(settings, dict):
        settings = {}
    merged = deep_merge(DEFAULT_SETTINGS, settings)
    ui = merged.setdefault("ui", {})
    if isinstance(ui, dict):
        ui["visible_tabs"] = normalize_visible_tabs(ui.get("visible_tabs"))
    return merged


def update_panel_settings(payload: dict[str, object]) -> dict[str, object]:
    allowed_top = {"ui", "network_safety", "security"}
    data = runtime_config()
    existing = panel_settings()
    updates = {key: value for key, value in payload.items() if key in allowed_top and isinstance(value, dict)}
    merged = deep_merge(existing, updates)
    ui = merged.setdefault("ui", {})
    if isinstance(ui, dict):
        ui["visible_tabs"] = normalize_visible_tabs(ui.get("visible_tabs"))
    data["settings"] = merged
    write_runtime_config(data)
    return merged
