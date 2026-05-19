from __future__ import annotations

import time
from copy import deepcopy
from typing import Any

from app.core.runtime_config import runtime_config, write_runtime_config
from app.providers.common import available

from .profiles import interface_identity, nmcli_device_map
from .state import current_interfaces, network_snapshot


CONFIG_VERSION = 1

KIND_LABELS = {
    "ethernet": "Ethernet",
    "wifi": "Wi-Fi",
    "cellular": "Cellular",
    "overlay": "Tunnel",
    "container": "Container",
    "loopback": "Loopback",
    "other": "Other",
}

CONFIGURABLE_KINDS = {"ethernet", "wifi", "cellular"}


def _interface_capabilities(interface: str, kind: str, identity: dict[str, Any]) -> dict[str, Any]:
    kind = _string(kind, "other")
    interface = _string(interface)
    owner = "kernel"
    controls: list[str] = ["observe"]
    warnings: list[str] = []
    planned: list[str] = []

    if kind == "ethernet":
        owner = "networkmanager"
        controls.extend(["display_name", "addressing", "dns", "traffic", "link_routing", "client_egress"])
    elif kind == "wifi":
        owner = "networkmanager"
        controls.extend(["display_name", "wireless", "dns", "traffic", "link_routing"])
        planned.append("wifi_secret_apply")
    elif kind == "cellular":
        owner = "modemmanager"
        controls.extend(["display_name", "cellular", "traffic", "link_routing"])
        planned.append("carrier_profile_apply")
    elif kind == "overlay":
        owner = "tunnel_provider"
        controls.extend(["remote_access_observe"])
        planned.append("tunnel_policy")
        warnings.append("Tunnel interfaces are observe-only in the generic interface config surface.")
    elif kind == "container":
        owner = "docker"
        controls.extend(["container_network_observe"])
        warnings.append("Container and bridge interfaces should be managed through the container provider.")
    elif kind == "loopback":
        owner = "kernel"
        warnings.append("Loopback is system-owned and cannot be configured from LocalPlane.")
    else:
        owner = "unknown"
        planned.append("provider_detection")
        warnings.append("LocalPlane does not know a safe provider for this interface yet.")

    if identity.get("hotplug_candidate"):
        controls.append("hotplug_identity")

    configurable = bool({"addressing", "wireless", "cellular", "traffic", "link_routing"} & set(controls))
    return {
        "owner": owner,
        "controls": sorted(set(controls)),
        "configurable": configurable,
        "observe_only": not configurable,
        "warnings": warnings,
        "planned": planned,
    }


def _string(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    return str(value).strip()


def _bool(value: Any, fallback: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.strip().lower() in {"1", "true", "yes", "on", "enabled"}:
            return True
        if value.strip().lower() in {"0", "false", "no", "off", "disabled"}:
            return False
    return fallback


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _runtime_interface_configs() -> dict[str, dict[str, Any]]:
    configs = runtime_config().get("interface_configs", {})
    if not isinstance(configs, dict):
        return {}
    return {str(key): _dict(value) for key, value in configs.items()}


def _discovered_interface_ids() -> set[str]:
    inventory = interface_inventory()
    ids: set[str] = set()
    for item in inventory.get("interfaces", []):
        if not isinstance(item, dict):
            continue
        identity = _dict(item.get("identity"))
        stable_key = _string(identity.get("stable_key"), _string(item.get("interface")))
        if stable_key:
            ids.add(stable_key)
    return ids


def stale_interface_configs() -> dict[str, Any]:
    stored = _runtime_interface_configs()
    discovered = _discovered_interface_ids()
    stale = []
    for config_id, config in stored.items():
        if config_id not in discovered:
            meta = _dict(config.get("_meta"))
            stale.append({
                "id": config_id,
                "display_name": _string(config.get("display_name"), config_id),
                "last_kernel_name": _string(meta.get("last_kernel_name")),
                "kind": _string(meta.get("kind")),
                "updated_at": meta.get("updated_at"),
            })
    return {
        "ok": True,
        "count": len(stale),
        "stale": stale,
        "message": "Stale desired configs are saved LocalPlane records for interfaces that are not currently discovered.",
    }


def prune_stale_interface_configs() -> dict[str, Any]:
    data = runtime_config()
    stored = data.get("interface_configs", {})
    if not isinstance(stored, dict):
        stored = {}
    discovered = _discovered_interface_ids()
    removed = []
    kept: dict[str, Any] = {}
    for config_id, config in stored.items():
        if str(config_id) in discovered:
            kept[str(config_id)] = config
        else:
            removed.append({"id": str(config_id), "display_name": _string(_dict(config).get("display_name"), str(config_id))})
    data["interface_configs"] = kept
    write_runtime_config(data)
    return {
        "ok": True,
        "removed": removed,
        "removed_count": len(removed),
        "remaining_count": len(kept),
        "applied_to_host": False,
        "message": "Removed stale LocalPlane desired configs only. No host interfaces, routes, firewall rules or services were changed.",
    }


def _legacy_config_for_interface(interface: str, kind: str) -> dict[str, Any]:
    config = runtime_config()
    main_lan = _dict(config.get("main_lan"))
    device_lan = _dict(config.get("service_lan"))
    wifi = _dict(config.get("wifi"))
    lte = _dict(config.get("lte"))

    if interface and interface == _string(main_lan.get("target_interface")):
        return {
            "source": "legacy.main_lan",
            "display_name": _string(main_lan.get("name"), interface),
            "addressing": {
                "ipv4_mode": _string(main_lan.get("ipv4_mode"), "preserve_existing"),
                "ipv4_address": _string(main_lan.get("ipv4_address")),
                "ipv4_subnet": _string(main_lan.get("ipv4_subnet")),
                "dhcp_range": _string(main_lan.get("dhcp_range")),
                "ipv6_mode": _string(main_lan.get("ipv6_mode"), "preserve_existing"),
                "ipv6_address": _string(main_lan.get("ipv6_address")),
                "ipv6_prefix": _string(main_lan.get("ipv6_prefix")),
            },
            "dns": {
                "mode": "pihole" if _string(main_lan.get("use_pihole_dns")) == "true" else "custom",
                "servers": _string(main_lan.get("dns_servers")),
                "search": _string(main_lan.get("dns_search")),
            },
            "internet": {
                "use_as_uplink": False,
                "share_to_clients": _string(main_lan.get("ipv4_mode")) == "shared",
                "priority": None,
            },
            "link": {
                "mtu": "",
                "autoconnect": "yes",
            },
            "routing": {
                "route_metric": "",
                "never_default": "yes",
                "ignore_auto_routes": "yes",
            },
            "firewall": {
                "isolation": "off" if _string(main_lan.get("role")) == "internal" else "limited",
                "exposed_services": [],
            },
        }

    if interface and interface == _string(device_lan.get("interface")):
        return {
            "source": "legacy.service_lan",
            "display_name": _string(device_lan.get("name"), interface),
            "addressing": {
                "ipv4_mode": "shared" if _string(device_lan.get("enable_ipv4")) == "true" else "disabled",
                "ipv4_address": _string(device_lan.get("ipv4_gateway")),
                "ipv4_subnet": _string(device_lan.get("ipv4_subnet")),
                "dhcp_range": _string(device_lan.get("dhcp_range")),
                "ipv6_mode": "routed" if _string(device_lan.get("enable_ipv6")) == "true" else "disabled",
                "ipv6_address": _string(device_lan.get("ipv6_gateway")),
                "ipv6_prefix": _string(device_lan.get("ipv6_prefix")),
            },
            "dns": {
                "mode": "pihole" if _string(device_lan.get("use_pihole_dns")) == "true" else "custom",
                "servers": _string(device_lan.get("dns_servers")),
                "search": _string(device_lan.get("dns_search")),
            },
            "internet": {
                "use_as_uplink": False,
                "share_to_clients": _string(device_lan.get("role")) in {"external", "isolated"},
                "priority": None,
            },
            "link": {
                "mtu": "",
                "autoconnect": "yes",
            },
            "routing": {
                "route_metric": "",
                "never_default": "yes",
                "ignore_auto_routes": "yes",
            },
            "firewall": {
                "isolation": "on" if _string(device_lan.get("role")) == "isolated" else "limited",
                "exposed_services": [],
            },
        }

    if interface and interface == _string(wifi.get("interface")):
        mode = _string(wifi.get("mode"), "client")
        return {
            "source": "legacy.wifi",
            "display_name": _string(wifi.get("hotspot_ssid" if mode == "hotspot" else "ssid"), interface),
            "wireless": {
                "mode": mode,
                "ssid": _string(wifi.get("hotspot_ssid" if mode == "hotspot" else "ssid")),
                "country": _string(wifi.get("country")),
                "band": _string(wifi.get("band")),
                "channel": _string(wifi.get("channel")),
                "security": _string(wifi.get("hotspot_security")),
            },
            "addressing": {
                "ipv4_mode": _string(wifi.get("ipv4_method"), "preserve_existing"),
                "ipv4_address": _string(wifi.get("ipv4_address")),
                "ipv6_mode": _string(wifi.get("ipv6_method"), "preserve_existing"),
                "ipv6_address": _string(wifi.get("ipv6_address")),
            },
            "internet": {
                "use_as_uplink": mode == "client",
                "share_to_clients": mode == "hotspot",
                "priority": None,
            },
            "link": {
                "mtu": "",
                "autoconnect": "yes",
            },
            "routing": {
                "route_metric": "",
                "never_default": "no" if mode == "client" else "yes",
                "ignore_auto_routes": "no" if mode == "client" else "yes",
            },
            "firewall": {
                "isolation": "on" if _string(wifi.get("client_trust_mode")) == "isolated" else "preserve_existing",
                "exposed_services": [],
            },
        }

    if kind == "cellular":
        return {
            "source": "legacy.lte",
            "display_name": "Cellular",
            "cellular": {
                "apn": "",
                "auto_apn": _bool(lte.get("auto_apn_enabled"), True),
            },
            "internet": {
                "use_as_uplink": True,
                "share_to_clients": False,
                "priority": None,
            },
            "link": {
                "mtu": "",
                "autoconnect": "preserve_existing",
            },
            "routing": {
                "route_metric": "",
                "never_default": "preserve_existing",
                "ignore_auto_routes": "preserve_existing",
            },
            "firewall": {
                "isolation": "preserve_existing",
                "exposed_services": [],
            },
        }

    return {}


def _observed_config(interface: dict[str, Any], default_devices: set[str]) -> dict[str, Any]:
    name = _string(interface.get("name"))
    kind = _string(interface.get("role"), "other")
    ipv4 = [_string(item) for item in _list(interface.get("ipv4")) if _string(item)]
    ipv6 = [_string(item) for item in _list(interface.get("ipv6")) if _string(item)]
    return {
        "source": "observed",
        "display_name": name,
        "admin_state": "enabled" if _string(interface.get("state")).upper() == "UP" else "observed",
        "addressing": {
            "mode": "preserve_existing",
            "ipv4_mode": "preserve_existing" if ipv4 else "disabled",
            "ipv4_addresses": ipv4,
            "ipv6_mode": "preserve_existing" if ipv6 else "disabled",
            "ipv6_addresses": ipv6,
        },
        "dns": {
            "mode": "preserve_existing",
            "servers": "",
            "search": "",
        },
        "internet": {
            "use_as_uplink": name in default_devices and kind in {"ethernet", "wifi", "cellular"},
            "share_to_clients": False,
            "priority": None,
        },
        "link": {
            "mtu": "",
            "autoconnect": "preserve_existing",
        },
        "routing": {
            "route_metric": "",
            "never_default": "preserve_existing",
            "ignore_auto_routes": "preserve_existing",
        },
        "firewall": {
            "isolation": "preserve_existing",
            "exposed_services": [],
        },
        "wireless": {},
        "cellular": {},
    }


def _merge_config(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge_config(result[key], value)
        else:
            result[key] = value
    return result


def _default_route_devices() -> set[str]:
    routes = network_snapshot().get("routes", {})
    devices: set[str] = set()
    for key in ("default_ipv4", "default_ipv6"):
        route = routes.get(key, {})
        if isinstance(route, dict) and route.get("dev"):
            devices.add(str(route.get("dev")))
    return devices


def interface_inventory() -> dict[str, Any]:
    nmcli_map = nmcli_device_map()
    interfaces = []
    for item in current_interfaces():
        name = _string(item.get("name"))
        kind = _string(item.get("role"), "other")
        identity = interface_identity(item, nmcli_map.get(name, {}))
        capabilities = _interface_capabilities(name, kind, identity)
        interfaces.append({
            "interface": name,
            "kind": kind,
            "kind_label": KIND_LABELS.get(kind, kind),
            "state": item.get("state", ""),
            "mac": item.get("mac", ""),
            "mtu": item.get("mtu"),
            "ipv4": item.get("ipv4", []),
            "ipv6": item.get("ipv6", []),
            "default_route": item.get("default_route", False),
            "physical": item.get("physical", False),
            "counters": item.get("counters", {}),
            "identity": identity,
            "nmcli": nmcli_map.get(name, {}),
            "capabilities": capabilities,
            "configurable": bool(capabilities.get("configurable")),
            "hotplug_candidate": bool(identity.get("hotplug_candidate")),
        })
    return {
        "generated_at": time.time(),
        "interfaces": interfaces,
        "model": {
            "source_of_truth": "interface_configs",
            "identity_key": "stable_key",
            "legacy_compatibility": ["main_lan", "service_lan", "wifi", "lte"],
            "hard_apply_requires_preview": True,
        },
    }


def interface_configs() -> dict[str, Any]:
    inventory = interface_inventory()
    stored = _runtime_interface_configs()
    default_devices = _default_route_devices()
    configs = []
    for item in inventory.get("interfaces", []):
        identity = _dict(item.get("identity"))
        stable_key = _string(identity.get("stable_key"), _string(item.get("interface")))
        observed = _observed_config(
            {
                "name": item.get("interface"),
                "role": item.get("kind"),
                "state": item.get("state"),
                "ipv4": item.get("ipv4", []),
                "ipv6": item.get("ipv6", []),
            },
            default_devices,
        )
        legacy = _legacy_config_for_interface(_string(item.get("interface")), _string(item.get("kind")))
        saved = stored.get(stable_key, {})
        effective = _merge_config(_merge_config(observed, legacy), saved)
        configs.append({
            "id": stable_key,
            "interface": item.get("interface"),
            "kind": item.get("kind"),
            "kind_label": item.get("kind_label"),
            "identity": identity,
            "live": item,
            "capabilities": item.get("capabilities", {}),
            "config": effective,
            "source": "stored" if saved else (legacy.get("source") or "observed"),
            "editable": bool(item.get("configurable")),
        })
    return {
        "generated_at": time.time(),
        "configs": configs,
        "model": {
            "version": CONFIG_VERSION,
            "stored_configs": [
                {
                    "id": key,
                    "display_name": _string(value.get("display_name"), key),
                    "last_kernel_name": _string(_dict(value.get("_meta")).get("last_kernel_name")),
                    "kind": _string(_dict(value.get("_meta")).get("kind")),
                }
                for key, value in stored.items()
            ],
            "terms": {
                "interface": "discovered hardware/software network device",
                "config": "user-named desired behavior for that interface",
                "rules": "routing/firewall/DNS/NAT intent derived from config",
                "preset": "optional starter template, not a fixed role",
            },
        },
    }


def _config_item_for_payload(payload: dict[str, Any], configs: list[dict[str, Any]]) -> dict[str, Any]:
    config_id = _string(payload.get("id") or payload.get("stable_key"))
    interface = _string(payload.get("interface"))
    if config_id:
        matched = next((item for item in configs if _string(item.get("id")) == config_id), None)
        if matched:
            return matched
    if interface:
        matched = next((item for item in configs if _string(item.get("interface")) == interface), None)
        if matched:
            return matched
    raise ValueError("Known interface id or interface name is required")


def save_interface_config(payload: dict[str, Any]) -> dict[str, Any]:
    configs_payload = interface_configs()
    configs = [item for item in configs_payload.get("configs", []) if isinstance(item, dict)]
    item = _config_item_for_payload(payload, configs)
    if not item.get("editable"):
        raise ValueError(f"{item.get('interface') or item.get('id')} is inventory-only and cannot be configured yet")

    config_id = _string(item.get("id"))
    overlay = _dict(payload.get("config"))
    if not overlay and any(key in payload for key in ("display_name", "addressing", "dns", "internet", "link", "routing", "firewall", "wireless", "cellular")):
        overlay = {
            key: payload[key]
            for key in ("display_name", "addressing", "dns", "internet", "link", "routing", "firewall", "wireless", "cellular")
            if key in payload
        }
    if not overlay:
        raise ValueError("Config payload is empty")

    data = runtime_config()
    stored = data.get("interface_configs", {})
    if not isinstance(stored, dict):
        stored = {}
    existing = stored.get(config_id, {})
    if not isinstance(existing, dict):
        existing = {}
    next_config = _merge_config(existing, overlay)
    next_config["_meta"] = {
        "last_kernel_name": _string(item.get("interface")),
        "kind": _string(item.get("kind")),
        "updated_at": int(time.time()),
        "source": "runtime_config.interface_configs",
    }
    stored[config_id] = next_config
    data["interface_configs"] = stored
    write_runtime_config(data)

    updated = interface_configs()
    preview_item = next((config for config in updated.get("configs", []) if _string(config.get("id")) == config_id), None)
    return {
        "ok": True,
        "id": config_id,
        "interface": item.get("interface"),
        "saved": next_config,
        "config": preview_item,
        "readiness": interface_config_readiness({"configs": [preview_item]} if preview_item else {}),
        "rules_preview": interface_rules_preview({"configs": [preview_item]} if preview_item else {}),
        "applied_to_host": False,
        "message": "Interface config saved as desired state only. No host networking changes were applied.",
    }


def reset_interface_config(payload: dict[str, Any]) -> dict[str, Any]:
    configs_payload = interface_configs()
    configs = [item for item in configs_payload.get("configs", []) if isinstance(item, dict)]
    item = _config_item_for_payload(payload, configs)
    config_id = _string(item.get("id"))

    data = runtime_config()
    stored = data.get("interface_configs", {})
    if not isinstance(stored, dict):
        stored = {}
    existed = config_id in stored
    stored.pop(config_id, None)
    data["interface_configs"] = stored
    write_runtime_config(data)

    return {
        "ok": True,
        "id": config_id,
        "interface": item.get("interface"),
        "removed": existed,
        "configs": interface_configs(),
        "applied_to_host": False,
        "message": "Saved interface desired state was reset. No host networking changes were applied.",
    }


def rules_from_config(config_item: dict[str, Any]) -> list[dict[str, Any]]:
    config = _dict(config_item.get("config"))
    interface = _string(config_item.get("interface"))
    kind = _string(config_item.get("kind"), "other")
    addressing = _dict(config.get("addressing"))
    dns = _dict(config.get("dns"))
    internet = _dict(config.get("internet"))
    link = _dict(config.get("link"))
    routing = _dict(config.get("routing"))
    firewall = _dict(config.get("firewall"))
    wireless = _dict(config.get("wireless"))
    cellular = _dict(config.get("cellular"))
    rules: list[dict[str, Any]] = []

    if _string(link.get("mtu")):
        rules.append({
            "type": "link.mtu",
            "interface": interface,
            "mtu": _string(link.get("mtu")),
        })
    if _string(link.get("autoconnect"), "preserve_existing") != "preserve_existing":
        rules.append({
            "type": "connection.autoconnect",
            "interface": interface,
            "enabled": _string(link.get("autoconnect")),
        })

    if _string(addressing.get("ipv4_mode"), "preserve_existing") != "preserve_existing":
        rules.append({
            "type": "addressing.ipv4",
            "interface": interface,
            "mode": _string(addressing.get("ipv4_mode")),
            "address": _string(addressing.get("ipv4_address")),
            "subnet": _string(addressing.get("ipv4_subnet")),
            "dhcp_range": _string(addressing.get("dhcp_range")),
        })
    if _string(addressing.get("ipv6_mode"), "preserve_existing") != "preserve_existing":
        rules.append({
            "type": "addressing.ipv6",
            "interface": interface,
            "mode": _string(addressing.get("ipv6_mode")),
            "address": _string(addressing.get("ipv6_address")),
            "prefix": _string(addressing.get("ipv6_prefix")),
        })
    if _string(dns.get("mode"), "preserve_existing") != "preserve_existing":
        rules.append({
            "type": "dns",
            "interface": interface,
            "mode": _string(dns.get("mode")),
            "servers": _string(dns.get("servers")),
            "search": _string(dns.get("search")),
        })
    if _bool(internet.get("use_as_uplink")):
        rules.append({
            "type": "routing.uplink_candidate",
            "interface": interface,
            "kind": kind,
            "priority": internet.get("priority"),
        })
    if _string(routing.get("route_metric")):
        rules.append({
            "type": "routing.route_metric",
            "interface": interface,
            "metric": _string(routing.get("route_metric")),
        })
    if _string(routing.get("never_default"), "preserve_existing") != "preserve_existing":
        rules.append({
            "type": "routing.never_default",
            "interface": interface,
            "enabled": _string(routing.get("never_default")),
            "ignore_auto_routes": _string(routing.get("ignore_auto_routes"), "preserve_existing"),
        })
    if _bool(internet.get("share_to_clients")):
        rules.append({
            "type": "routing.client_egress",
            "interface": interface,
            "requires": ["ipv4_forwarding", "nat", "firewall_forward_policy"],
        })
    if _string(firewall.get("isolation"), "preserve_existing") not in {"", "off", "preserve_existing"}:
        rules.append({
            "type": "firewall.isolation",
            "interface": interface,
            "mode": _string(firewall.get("isolation")),
            "exposed_services": _list(firewall.get("exposed_services")),
        })
    if kind == "wifi" and any(_string(wireless.get(key)) for key in ("mode", "ssid", "country", "band", "channel", "security")):
        rules.append({
            "type": "wireless.profile",
            "interface": interface,
            "mode": _string(wireless.get("mode"), "preserve_existing"),
            "ssid": _string(wireless.get("ssid")),
            "country": _string(wireless.get("country")),
            "band": _string(wireless.get("band")),
            "channel": _string(wireless.get("channel")),
            "security": _string(wireless.get("security")),
        })
    if kind == "cellular" and ("auto_apn" in cellular or _string(cellular.get("apn"))):
        rules.append({
            "type": "cellular.apn",
            "interface": interface,
            "auto_apn": _bool(cellular.get("auto_apn"), True),
            "apn": _string(cellular.get("apn")),
        })
    return rules


def _finding(severity: str, code: str, title: str, detail: str, suggestion: str = "") -> dict[str, Any]:
    return {
        "severity": severity,
        "code": code,
        "title": title,
        "detail": detail,
        "suggestion": suggestion,
    }


def readiness_for_config(config_item: dict[str, Any]) -> dict[str, Any]:
    interface = _string(config_item.get("interface"))
    kind = _string(config_item.get("kind"), "other")
    live = _dict(config_item.get("live"))
    config = _dict(config_item.get("config"))
    addressing = _dict(config.get("addressing"))
    internet = _dict(config.get("internet"))
    link = _dict(config.get("link"))
    routing = _dict(config.get("routing"))
    firewall = _dict(config.get("firewall"))
    wireless = _dict(config.get("wireless"))
    cellular = _dict(config.get("cellular"))
    findings: list[dict[str, Any]] = []

    nmcli_ok = available("nmcli")
    nft_ok = available("nft")
    sysctl_ok = available("sysctl")
    mmcli_ok = available("mmcli")

    if not interface:
        findings.append(_finding("blocker", "missing_interface", "Interface is missing", "The config item has no interface name."))
    if kind not in CONFIGURABLE_KINDS:
        findings.append(_finding(
            "info",
            "observe_only_kind",
            "Observe-only interface",
            f"{kind or 'unknown'} interfaces are visible for inventory, but are not managed by interface configs yet.",
        ))

    mtu = _string(link.get("mtu"))
    if mtu:
        try:
            mtu_value = int(mtu)
            if mtu_value < 68 or mtu_value > 9000:
                findings.append(_finding(
                    "warning",
                    "mtu_unusual",
                    "MTU looks unusual",
                    f"{mtu_value} is outside the normal Ethernet/Linux range LocalPlane expects.",
                    "Use the live interface MTU or a value supported by the adapter and upstream network.",
                ))
        except ValueError:
            findings.append(_finding("blocker", "mtu_invalid", "MTU is not numeric", f"{mtu} must be a number."))

    metric = _string(routing.get("route_metric"))
    if metric:
        try:
            metric_value = int(metric)
            if metric_value < 1 or metric_value > 9999:
                findings.append(_finding(
                    "warning",
                    "route_metric_unusual",
                    "Route metric looks unusual",
                    f"{metric_value} is outside the expected 1-9999 range.",
                    "Lower metrics win. Keep failover priorities easy to reason about.",
                ))
        except ValueError:
            findings.append(_finding("blocker", "route_metric_invalid", "Route metric is not numeric", f"{metric} must be a number."))

    if _bool(internet.get("use_as_uplink")) and kind not in {"ethernet", "wifi", "cellular"}:
        findings.append(_finding(
            "blocker",
            "invalid_uplink_kind",
            "Cannot use this interface as an uplink",
            f"{kind or 'unknown'} is not a supported internet uplink kind.",
            "Choose an Ethernet, Wi-Fi or Cellular interface for uplink behavior.",
        ))

    if _bool(internet.get("share_to_clients")) and kind not in {"ethernet", "wifi"}:
        findings.append(_finding(
            "blocker",
            "invalid_client_share_kind",
            "Cannot share client egress from this interface",
            f"{kind or 'unknown'} is not a supported client-facing network kind.",
            "Use an Ethernet or Wi-Fi interface for client-facing networks.",
        ))

    if _string(addressing.get("ipv4_mode")) in {"shared", "manual"} and not nmcli_ok:
        findings.append(_finding(
            "blocker",
            "networkmanager_missing",
            "NetworkManager provider is missing",
            "Addressing changes need nmcli/NetworkManager so LocalPlane can preview and later apply profile changes safely.",
            "Install or expose NetworkManager/nmcli to the container.",
        ))

    if _bool(internet.get("share_to_clients")):
        if not nft_ok:
            findings.append(_finding(
                "blocker",
                "nftables_missing",
                "nftables provider is missing",
                "Client internet sharing needs a managed firewall/NAT backend.",
                "Install nftables or expose nft from the host.",
            ))
        if not sysctl_ok:
            findings.append(_finding(
                "blocker",
                "sysctl_missing",
                "sysctl provider is missing",
                "Client internet sharing needs forwarding visibility before apply.",
                "Install or expose sysctl from the host.",
            ))

    isolation = _string(firewall.get("isolation"), "preserve_existing")
    if isolation not in {"", "off", "preserve_existing"} and not nft_ok:
        findings.append(_finding(
            "blocker",
            "firewall_provider_missing",
            "Firewall provider is missing",
            "Isolation policy needs nftables visibility and a managed table before apply.",
            "Install nftables or expose nft from the host.",
        ))

    if kind == "wifi":
        mode = _string(wireless.get("mode"), "client")
        country = _string(wireless.get("country"))
        channel = _string(wireless.get("channel"))
        security = _string(wireless.get("security"))
        if not nmcli_ok:
            findings.append(_finding(
                "blocker",
                "wifi_networkmanager_missing",
                "Wi-Fi provider is missing",
                "Wi-Fi client/hotspot changes need NetworkManager/nmcli.",
                "Install or expose NetworkManager/nmcli to the container.",
            ))
        if mode == "hotspot" and not _string(wireless.get("ssid")):
            findings.append(_finding(
                "warning",
                "wifi_hotspot_ssid_missing",
                "Hotspot SSID is empty",
                "A hotspot config needs an SSID before it can be applied.",
            ))
        if mode not in {"client", "hotspot", "disabled", "preserve_existing", ""}:
            findings.append(_finding("blocker", "wifi_mode_unknown", "Unknown Wi-Fi mode", f"{mode} is not a supported Wi-Fi mode."))
        if country and not (len(country) == 2 and country.isalpha()):
            findings.append(_finding("warning", "wifi_country_invalid", "Wi-Fi country looks invalid", f"{country} should be a two-letter regulatory domain such as DE or US."))
        if channel and channel.lower() != "auto" and not channel.isdigit():
            findings.append(_finding("warning", "wifi_channel_invalid", "Wi-Fi channel is not numeric", f"{channel} must be a channel number or auto."))
        if security and security not in {"preserve_existing", "open", "wpa2-personal", "wpa3-personal"}:
            findings.append(_finding("blocker", "wifi_security_unknown", "Unknown Wi-Fi security mode", f"{security} is not supported yet."))

    if kind == "cellular":
        if not mmcli_ok:
            findings.append(_finding(
                "warning",
                "modemmanager_missing",
                "ModemManager provider is missing",
                "Cellular inventory can still show the interface, but SIM/operator/APN readiness needs mmcli.",
                "Install or expose ModemManager/mmcli for full cellular diagnostics.",
            ))
        if not _bool(cellular.get("auto_apn"), True) and not _string(cellular.get("apn")):
            findings.append(_finding("warning", "cellular_apn_missing", "Manual APN is empty", "Manual cellular mode needs an APN before apply."))

    if _string(live.get("state")).upper() != "UP" and (_bool(internet.get("use_as_uplink")) or _bool(internet.get("share_to_clients"))):
        findings.append(_finding(
            "warning",
            "interface_down",
            "Interface is currently down",
            "The desired behavior may be valid, but live link state is down right now.",
            "Check cable, radio state, modem registration or NetworkManager device state.",
        ))

    severity_rank = {"blocker": 3, "warning": 2, "info": 1}
    max_severity = max((severity_rank.get(str(item.get("severity")), 0) for item in findings), default=0)
    status = "blocked" if max_severity >= 3 else ("warning" if max_severity == 2 else "ready")
    return {
        "interface": interface,
        "kind": kind,
        "status": status,
        "findings": findings,
        "providers": {
            "networkmanager": nmcli_ok,
            "nftables": nft_ok,
            "sysctl": sysctl_ok,
            "modemmanager": mmcli_ok,
        },
    }


def interface_config_readiness(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    if isinstance(payload.get("configs"), list):
        configs = [item for item in payload.get("configs", []) if isinstance(item, dict)]
    elif isinstance(payload.get("config"), dict):
        configs = [payload.get("config", {})]
    else:
        configs = interface_configs().get("configs", [])

    items = [readiness_for_config(item) for item in configs]
    blocked = sum(1 for item in items if item.get("status") == "blocked")
    warnings = sum(1 for item in items if item.get("status") == "warning")
    return {
        "ok": blocked == 0,
        "summary": {
            "total": len(items),
            "ready": sum(1 for item in items if item.get("status") == "ready"),
            "warning": warnings,
            "blocked": blocked,
        },
        "items": items,
    }


def interface_rules_preview(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    if isinstance(payload.get("configs"), list):
        configs = [item for item in payload.get("configs", []) if isinstance(item, dict)]
    elif isinstance(payload.get("config"), dict):
        configs = [payload.get("config", {})]
    else:
        configs = interface_configs().get("configs", [])

    rules = []
    for item in configs:
        rules.extend(rules_from_config(item))
    readiness = interface_config_readiness({"configs": configs})

    return {
        "ok": bool(readiness.get("ok")),
        "mode": "preview",
        "rules": rules,
        "readiness": readiness,
        "warnings": [
            "This endpoint is read-only. It does not apply NetworkManager, nftables, DNS, DHCP, route or modem changes.",
            "Legacy main_lan/service_lan/wifi/lte settings are imported only as compatibility context.",
        ],
        "next": [
            "Add validation for interface-specific capabilities.",
            "Review /api/network/interface-plan/preview for the read-only provider step plan.",
        ],
    }
