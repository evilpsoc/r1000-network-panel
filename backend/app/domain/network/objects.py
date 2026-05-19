from __future__ import annotations

from typing import Any

from .interface_configs import interface_configs, readiness_for_config, rules_from_config


OBJECT_GROUP_LABELS = {
    "ethernet": "Ethernet devices",
    "wifi": "Wi-Fi radios",
    "cellular": "Cellular modems",
    "overlay": "Remote access tunnels",
    "container": "Container networks",
    "loopback": "System interfaces",
    "other": "Other interfaces",
}

KIND_PROVIDER_SURFACES = {
    "ethernet": {
        "provider": "NetworkManager",
        "surfaces": [
            {"id": "identity", "label": "Identity", "state": "active"},
            {"id": "addressing", "label": "Addressing", "state": "planned"},
            {"id": "routing", "label": "Routing", "state": "planned"},
            {"id": "firewall", "label": "Firewall", "state": "planned"},
            {"id": "traffic", "label": "Traffic", "state": "read_only"},
        ],
        "safe_apply": "preview_required",
    },
    "wifi": {
        "provider": "NetworkManager",
        "surfaces": [
            {"id": "radio", "label": "Radio", "state": "read_only"},
            {"id": "client", "label": "Client", "state": "legacy_apply"},
            {"id": "hotspot", "label": "Hotspot", "state": "legacy_apply"},
            {"id": "scan", "label": "Scan", "state": "read_only"},
            {"id": "routing", "label": "Routing", "state": "planned"},
            {"id": "traffic", "label": "Traffic", "state": "read_only"},
        ],
        "safe_apply": "legacy_preview_then_apply",
    },
    "cellular": {
        "provider": "ModemManager",
        "surfaces": [
            {"id": "modem", "label": "Modem", "state": "read_only"},
            {"id": "sim", "label": "SIM / Operator", "state": "read_only"},
            {"id": "apn", "label": "APN", "state": "legacy_apply"},
            {"id": "routing", "label": "Routing", "state": "planned"},
            {"id": "traffic", "label": "Traffic", "state": "read_only"},
        ],
        "safe_apply": "legacy_preview_then_apply",
    },
    "overlay": {
        "provider": "Tunnel provider",
        "surfaces": [
            {"id": "identity", "label": "Identity", "state": "read_only"},
            {"id": "routes", "label": "Advertised Routes", "state": "future"},
            {"id": "policy", "label": "Access Policy", "state": "future"},
        ],
        "safe_apply": "observe_only",
    },
    "container": {
        "provider": "Docker",
        "surfaces": [
            {"id": "identity", "label": "Identity", "state": "read_only"},
            {"id": "service_map", "label": "Service Map", "state": "future"},
        ],
        "safe_apply": "observe_only",
    },
    "loopback": {
        "provider": "Kernel",
        "surfaces": [{"id": "identity", "label": "Identity", "state": "read_only"}],
        "safe_apply": "observe_only",
    },
    "other": {
        "provider": "Unknown",
        "surfaces": [{"id": "identity", "label": "Identity", "state": "read_only"}],
        "safe_apply": "observe_only",
    },
}


def _string(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    return str(value).strip()


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _object_status(config_item: dict[str, Any], readiness: dict[str, Any]) -> str:
    live = _dict(config_item.get("live"))
    capabilities = _dict(config_item.get("capabilities"))
    if readiness.get("status") == "blocked":
        return "blocked"
    if readiness.get("status") == "warning":
        return "warning"
    if capabilities.get("observe_only"):
        return "observe_only"
    state = _string(live.get("state")).upper()
    if state in {"UP", "CONNECTED", "ACTIVATED"}:
        return "ready"
    if state in {"DOWN", "DISCONNECTED", "UNAVAILABLE"}:
        return "down"
    return "unknown"


def _network_object(config_item: dict[str, Any]) -> dict[str, Any]:
    readiness = readiness_for_config(config_item)
    rules = rules_from_config(config_item)
    capabilities = _dict(config_item.get("capabilities"))
    config = _dict(config_item.get("config"))
    identity = _dict(config_item.get("identity"))
    live = _dict(config_item.get("live"))
    kind = _string(config_item.get("kind"), "other")
    provider_model = KIND_PROVIDER_SURFACES.get(kind, KIND_PROVIDER_SURFACES["other"])
    display_name = _string(config.get("display_name"), _string(config_item.get("interface")))

    return {
        "id": _string(config_item.get("id")),
        "interface": _string(config_item.get("interface")),
        "display_name": display_name,
        "kind": kind,
        "kind_label": _string(config_item.get("kind_label"), OBJECT_GROUP_LABELS.get(kind, kind)),
        "status": _object_status(config_item, readiness),
        "source": _string(config_item.get("source"), "observed"),
        "provider": capabilities.get("owner", "unknown"),
        "provider_model": provider_model,
        "capabilities": capabilities,
        "identity": identity,
        "live": {
            "state": live.get("state", ""),
            "mac": live.get("mac", ""),
            "mtu": live.get("mtu"),
            "ipv4": live.get("ipv4", []),
            "ipv6": live.get("ipv6", []),
            "default_route": live.get("default_route", False),
            "counters": live.get("counters", {}),
        },
        "desired": config,
        "rules_preview": rules,
        "readiness": readiness,
        "editable": bool(config_item.get("editable")),
    }


def network_objects() -> dict[str, Any]:
    configs_payload = interface_configs()
    objects = [
        _network_object(config_item)
        for config_item in configs_payload.get("configs", [])
        if isinstance(config_item, dict)
    ]

    groups: dict[str, list[dict[str, Any]]] = {}
    for item in objects:
        groups.setdefault(_string(item.get("kind"), "other"), []).append(item)

    group_payload = [
        {
            "kind": kind,
            "label": OBJECT_GROUP_LABELS.get(kind, kind),
            "count": len(items),
            "items": sorted(items, key=lambda item: (_string(item.get("display_name")), _string(item.get("interface")))),
        }
        for kind, items in sorted(groups.items(), key=lambda pair: OBJECT_GROUP_LABELS.get(pair[0], pair[0]))
    ]

    return {
        "generated_at": configs_payload.get("generated_at"),
        "summary": {
            "objects": len(objects),
            "editable": sum(1 for item in objects if item.get("editable")),
            "observe_only": sum(1 for item in objects if _dict(item.get("capabilities")).get("observe_only")),
            "blocked": sum(1 for item in objects if item.get("status") == "blocked"),
            "warnings": sum(1 for item in objects if item.get("status") == "warning"),
        },
        "groups": group_payload,
        "objects": objects,
        "model": {
            **_dict(configs_payload.get("model")),
            "read_only": True,
            "purpose": "Generic LocalPlane network object inventory. This does not apply host settings.",
            "layers": [
                "discovered interface/device",
                "stable identity",
                "provider/capability ownership",
                "desired config",
                "readiness findings",
                "rules preview",
            ],
            "next": [
                "Use this as the primary UI source for network inventory.",
                "Keep Wi-Fi, Cellular, Firewall/DNS/DHCP and Routing as dedicated provider surfaces.",
                "Only enable apply after backup, verify and rollback are wired per provider.",
            ],
        },
    }


def network_objects_by_kind(kind: str) -> dict[str, Any]:
    kind = _string(kind, "other")
    payload = network_objects()
    items = [item for item in payload.get("objects", []) if _string(item.get("kind")) == kind]
    return {
        "generated_at": payload.get("generated_at"),
        "kind": kind,
        "label": OBJECT_GROUP_LABELS.get(kind, kind),
        "count": len(items),
        "items": items,
        "objects": items,
        "summary": {
            "objects": len(items),
            "editable": sum(1 for item in items if item.get("editable")),
            "observe_only": sum(1 for item in items if _dict(item.get("capabilities")).get("observe_only")),
            "blocked": sum(1 for item in items if item.get("status") == "blocked"),
            "warnings": sum(1 for item in items if item.get("status") == "warning"),
        },
        "model": {
            **_dict(payload.get("model")),
            "scope": kind,
            "purpose": f"Read-only LocalPlane {OBJECT_GROUP_LABELS.get(kind, kind).lower()} inventory.",
            "provider_surface": KIND_PROVIDER_SURFACES.get(kind, KIND_PROVIDER_SURFACES["other"]),
        },
    }
