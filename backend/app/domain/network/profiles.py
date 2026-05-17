from pathlib import Path
import time

from app.core.cache import cached_read, clear_read_cache
from app.core.runtime_config import runtime_config, write_runtime_config
from app.providers import networkmanager
from app.providers.common import available, command_spec, run

from .state import current_interfaces, network_snapshot


PROFILE_SETTINGS = {
    "management_lan": ["addressing", "dns", "pihole", "internet_access"],
    "device_lan": ["addressing", "dhcp", "dns", "pihole", "internet_access", "isolation"],
    "uplink_ethernet": ["dhcp_or_static", "route_metric", "failover", "trust_policy"],
    "uplink_wifi": ["client_profile", "country", "route_metric", "trust_policy"],
    "hotspot_wifi": ["ssid", "security", "channel", "addressing", "dns"],
    "uplink_cellular": ["apn", "route_metric", "failover"],
    "management_tunnel": ["routes", "access_policy"],
    "container": ["read_only_visibility"],
    "unassigned": ["role_assignment"],
}

PROFILE_OPTIONS_BY_ROLE = {
    "ethernet": ["management_lan", "device_lan", "uplink_ethernet", "unassigned"],
    "wifi": ["hotspot_wifi", "uplink_wifi", "unassigned"],
    "cellular": ["uplink_cellular", "unassigned"],
    "overlay": ["management_tunnel", "unassigned"],
    "container": ["container"],
}

KNOWN_PROFILES = set(PROFILE_SETTINGS)

PROFILE_LABELS = {
    "management_lan": "Management LAN",
    "device_lan": "Device LAN",
    "uplink_ethernet": "Ethernet Uplink",
    "uplink_wifi": "Wi-Fi uplink",
    "hotspot_wifi": "Wi-Fi hotspot",
    "uplink_cellular": "Cellular Uplink",
    "management_tunnel": "Management Tunnel",
    "container": "container",
    "unassigned": "unassigned",
}

BEHAVIOR_LABELS = {
    "management_lan": "Trusted local network",
    "device_lan": "Isolated client network",
    "uplink_ethernet": "Wired uplink",
    "uplink_wifi": "Wi-Fi uplink",
    "hotspot_wifi": "Wi-Fi hotspot",
    "uplink_cellular": "Cellular uplink",
    "management_tunnel": "Remote management tunnel",
    "container": "Container interface",
    "unassigned": "Observe only",
}


def sysfs_interface_path(interface: str) -> Path:
    host_path = Path("/host/sys/class/net") / interface
    if host_path.exists():
        return host_path
    return Path("/sys/class/net") / interface


def symlink_name(path: Path) -> str:
    try:
        if path.exists() or path.is_symlink():
            return path.resolve().name
    except Exception:
        return ""
    return ""


def interface_identity(iface: dict[str, object], nmcli: dict[str, str]) -> dict[str, object]:
    name = str(iface.get("name", ""))
    role = str(iface.get("role", ""))
    mac = str(iface.get("mac", "") or "")
    sys_path = sysfs_interface_path(name)
    device_path = sys_path / "device"
    driver = symlink_name(device_path / "driver")
    bus_path = ""
    bus = ""
    try:
        if device_path.exists() or device_path.is_symlink():
            resolved = device_path.resolve()
            bus_path = str(resolved).replace("/host", "")
            parts = resolved.parts
            if any(part == "usb" or part.startswith("usb") or ".usb" in part for part in parts):
                bus = "usb"
            elif "pci" in parts:
                bus = "pci"
            elif "platform" in parts:
                bus = "platform"
    except Exception:
        pass

    stable_key = ""
    if mac and mac != "00:00:00:00:00:00":
        stable_key = f"mac:{mac.lower()}"
    elif driver and bus_path:
        stable_key = f"path:{bus_path}"
    else:
        stable_key = f"name:{name}"

    bus_label = bus or ("virtual" if not bool(iface.get("physical")) else "unknown")
    return {
        "stable_key": stable_key,
        "kernel_name": name,
        "mac": mac,
        "driver": driver,
        "bus": bus_label,
        "bus_path": bus_path,
        "nm_type": nmcli.get("type", ""),
        "nm_connection": nmcli.get("connection", ""),
        "hotplug_candidate": bus == "usb" or name.startswith(("enx", "wlx", "ww", "usb")),
        "flexible_behavior_options": PROFILE_OPTIONS_BY_ROLE.get(role, ["unassigned"]),
        "flexible_role_options": PROFILE_OPTIONS_BY_ROLE.get(role, ["unassigned"]),
    }


def nmcli_device_map() -> dict[str, dict[str, str]]:
    result = networkmanager.device_status()
    devices: dict[str, dict[str, str]] = {}
    if not result.get("ok"):
        return devices
    for line in str(result.get("stdout", "")).splitlines():
        parts = line.split(":")
        if len(parts) < 4:
            continue
        device, dev_type, state, connection = parts[0], parts[1], parts[2], ":".join(parts[3:])
        devices[device] = {
            "type": dev_type,
            "state": state,
            "connection": connection,
        }
    return devices


def default_route_devices(snapshot: dict[str, object]) -> set[str]:
    routes = snapshot.get("routes", {})
    devices = set()
    for key in ("default_ipv4", "default_ipv6"):
        route = routes.get(key, {})
        dev = route.get("dev") if isinstance(route, dict) else ""
        if dev:
            devices.add(str(dev))
    return devices


def suggested_profile(iface: dict[str, object], defaults: set[str], ethernet_index: int) -> str:
    name = str(iface.get("name", ""))
    role = str(iface.get("role", ""))
    if name in defaults and role == "wifi":
        return "uplink_wifi"
    if name in defaults and role == "cellular":
        return "uplink_cellular"
    if role == "cellular":
        return "uplink_cellular"
    if role == "wifi":
        return "uplink_wifi"
    if role == "overlay":
        return "management_tunnel"
    if role == "container":
        return "container"
    if role == "ethernet":
        if name in defaults:
            return "uplink_ethernet"
        if iface.get("ipv4") or iface.get("ipv6"):
            return "uplink_ethernet" if str(iface.get("state", "")).upper() == "UP" else "management_lan"
        if ethernet_index == 0:
            return "management_lan"
        if ethernet_index == 1:
            return "device_lan"
        return "unassigned"
    return "unassigned"


def profile_capabilities(iface: dict[str, object], nmcli: dict[str, str]) -> dict[str, object]:
    role = str(iface.get("role", ""))
    capabilities = {
        "can_assign_role": role in {"ethernet", "wifi", "cellular", "overlay"},
        "can_set_link_state": bool(iface.get("physical")),
        "can_manage_nm_profile": bool(nmcli.get("connection")) and nmcli.get("connection") != "--",
        "can_configure_addressing": role in {"ethernet", "wifi"},
        "can_be_uplink": role in {"ethernet", "wifi", "cellular"},
        "can_be_lan": role in {"ethernet", "wifi"},
    }
    if role == "wifi":
        capabilities.update({
            "can_scan": True,
            "can_hotspot": True,
            "driver_note": "brcmfmac channel errors usually mean the requested AP/channel/regdom is not accepted by the firmware; prefer country-correct 2.4 GHz channels 1/6/11 first.",
        })
    return capabilities


def configured_profile(interface: str, config: dict[str, object], stable_key: str = "") -> tuple[str, dict[str, object]]:
    interface_registry = config.get("interface_registry", {})
    if stable_key and isinstance(interface_registry, dict):
        assignment = interface_registry.get(stable_key, {})
        if isinstance(assignment, dict):
            profile = str(assignment.get("profile", "")).strip()
            if profile in KNOWN_PROFILES:
                return profile, {
                    "source": "runtime_config.interface_registry",
                    "stable_key": stable_key,
                    "last_kernel_name": str(assignment.get("last_kernel_name", "")).strip(),
                    "assigned": "true",
                }

    interface_profiles = config.get("interface_profiles", {})
    if isinstance(interface_profiles, dict):
        assignment = interface_profiles.get(interface, {})
        if isinstance(assignment, dict):
            profile = str(assignment.get("profile", "")).strip()
            if profile in KNOWN_PROFILES:
                return profile, {
                    "source": "runtime_config.interface_profiles",
                    "profile": profile,
                    "assigned": "true",
                }

    main_lan = config.get("main_lan", {}) if isinstance(config.get("main_lan", {}), dict) else {}
    service_lan = config.get("service_lan", {}) if isinstance(config.get("service_lan", {}), dict) else {}
    wifi = config.get("wifi", {}) if isinstance(config.get("wifi", {}), dict) else {}
    if interface and interface == str(main_lan.get("target_interface", "")).strip():
        return "management_lan", {
            "source": "runtime_config.main_lan",
            "lan_role": str(main_lan.get("role", "")).strip() or "internal",
            "addressing": str(main_lan.get("ipv4_mode", "")).strip(),
            "dns": str(main_lan.get("dns_servers", "")).strip(),
            "pihole": str(main_lan.get("use_pihole_dns", "")).strip(),
        }
    if interface and interface == str(service_lan.get("interface", "")).strip():
        return "device_lan", {
            "source": "runtime_config.service_lan",
            "lan_role": str(service_lan.get("role", "")).strip() or "isolated",
            "ipv4": str(service_lan.get("enable_ipv4", "")).strip(),
            "ipv6": str(service_lan.get("enable_ipv6", "")).strip(),
            "dns": str(service_lan.get("dns_servers", "")).strip(),
            "pihole": str(service_lan.get("use_pihole_dns", "")).strip(),
        }
    if interface and interface == str(wifi.get("interface", "")).strip():
        mode = str(wifi.get("mode", "")).strip()
        return ("hotspot_wifi" if mode == "hotspot" else "uplink_wifi"), {
            "source": "runtime_config.wifi",
            "mode": mode,
            "ssid": str(wifi.get("hotspot_ssid" if mode == "hotspot" else "ssid", "")).strip(),
            "band": str(wifi.get("band", "")).strip(),
            "channel": str(wifi.get("channel", "")).strip(),
            "client_trust_mode": str(wifi.get("client_trust_mode", "")).strip(),
            "uplink_preference": str(wifi.get("uplink_preference", "")).strip(),
        }
    return "", {}


def interface_behavior_options(interface: str) -> list[str]:
    for iface in current_interfaces():
        if str(iface.get("name", "")) == interface:
            role = str(iface.get("role", ""))
            return PROFILE_OPTIONS_BY_ROLE.get(role, ["unassigned"])
    return ["unassigned"]


def interface_profile_options(interface: str) -> list[str]:
    return interface_behavior_options(interface)


def save_interface_behavior_assignment(interface: str, behavior: str) -> dict[str, object]:
    interface = str(interface or "").strip()
    behavior = str(behavior or "unassigned").strip()
    if not interface:
        raise ValueError("Interface is required")

    options = interface_behavior_options(interface)
    if options == ["unassigned"]:
        known_interfaces = {str(iface.get("name", "")) for iface in current_interfaces()}
        if interface not in known_interfaces:
            raise ValueError(f"Unknown interface: {interface}")
    if behavior not in options:
        raise ValueError(f"{behavior} is not valid for {interface}. Allowed: {', '.join(options)}")

    interfaces = current_interfaces()
    nmcli_map = nmcli_device_map()
    matched = next((iface for iface in interfaces if str(iface.get("name", "")) == interface), None)
    identity = interface_identity(matched or {"name": interface, "role": "unassigned"}, nmcli_map.get(interface, {}))
    stable_key = str(identity.get("stable_key", "")).strip()

    data = runtime_config()
    registry = data.get("interface_registry", {})
    if not isinstance(registry, dict):
        registry = {}
    assignments = data.get("interface_profiles", {})
    if not isinstance(assignments, dict):
        assignments = {}
    if behavior == "unassigned":
        if stable_key:
            registry.pop(stable_key, None)
        assignments.pop(interface, None)
    else:
        if stable_key:
            registry[stable_key] = {
                "profile": behavior,
                "behavior": behavior,
                "last_kernel_name": interface,
                "driver": str(identity.get("driver", "")).strip(),
                "bus": str(identity.get("bus", "")).strip(),
                "mac": str(identity.get("mac", "")).strip(),
                "updated_at": int(time.time()),
            }
        # Keep the legacy name-keyed assignment during migration so older
        # endpoints and UI builds continue to resolve the same role.
        assignments[interface] = {"profile": behavior, "behavior": behavior}
    data["interface_registry"] = registry
    data["interface_profiles"] = assignments
    write_runtime_config(data)
    clear_read_cache("network_interface_profiles")
    return {
        "interface": interface,
        "profile": behavior,
        "behavior": behavior,
        "behavior_label": BEHAVIOR_LABELS.get(behavior, behavior),
        "options": options,
        "behavior_options": options,
        "identity": identity,
        "assignment_source": "interface_registry" if stable_key else "interface_profiles",
    }


def save_interface_profile_assignment(interface: str, profile: str) -> dict[str, object]:
    return save_interface_behavior_assignment(interface, profile)


def behavior_bindings() -> dict[str, object]:
    profiles_payload = interface_behaviors()
    bindings = []
    for item in profiles_payload.get("interfaces", []) or []:
        identity = item.get("identity", {}) if isinstance(item.get("identity", {}), dict) else {}
        bindings.append({
            "interface": item.get("interface", ""),
            "stable_key": identity.get("stable_key", ""),
            "detected_role": item.get("detected_role", ""),
            "detected_kind": item.get("detected_kind", item.get("detected_role", "")),
            "suggested_behavior": item.get("suggested_profile", ""),
            "suggested_profile": item.get("suggested_profile", ""),
            "configured_behavior": item.get("configured_profile", ""),
            "configured_profile": item.get("configured_profile", ""),
            "effective_behavior": item.get("effective_profile", ""),
            "effective_profile": item.get("effective_profile", ""),
            "effective_behavior_label": item.get("effective_behavior_label", item.get("effective_label", "")),
            "effective_label": item.get("effective_label", ""),
            "state": item.get("state", ""),
            "default_route": item.get("default_route", False),
            "behavior_options": item.get("profile_options", []),
            "profile_options": item.get("profile_options", []),
            "assignment_source": (item.get("configured_policy", {}) or {}).get("source", "suggested")
            if isinstance(item.get("configured_policy", {}), dict)
            else "suggested",
        })
    return {
        "bindings": bindings,
        "behavior_bindings": bindings,
        "model": profiles_payload.get("model", {}),
        "default_route_devices": profiles_payload.get("default_route_devices", []),
    }


def role_bindings() -> dict[str, object]:
    return behavior_bindings()


def profile_warnings(effective_profile: str, policy: dict[str, object], driver_errors: list[str]) -> list[str]:
    warnings: list[str] = []
    if effective_profile == "hotspot_wifi":
        band = str(policy.get("band", "")).lower()
        channel = str(policy.get("channel", "")).lower()
        if driver_errors and band == "5ghz" and channel in {"", "auto"}:
            warnings.append("brcmfmac errors are present while hotspot uses 5 GHz auto channel; prefer 2.4 GHz channel 1/6/11 for the next apply.")
        if str(policy.get("ssid", "")).strip() == "":
            warnings.append("Hotspot profile has no SSID in runtime config.")
    if effective_profile == "uplink_wifi" and str(policy.get("uplink_preference", "")) == "prefer-wifi":
        warnings.append("Wi-Fi is configured to prefer default route when connected; verify this is intended while LTE is primary.")
    if effective_profile == "uplink_ethernet":
        warnings.append("Ethernet is available as a wired uplink/failover candidate; route metrics should decide priority before apply.")
    return warnings


def provider_health() -> list[dict[str, object]]:
    providers = [
        ("iproute2", "ip", "Required for interface, route and address snapshots."),
        ("NetworkManager", "nmcli", "Required for profile-based Ethernet/Wi-Fi/cellular apply flows."),
        ("nftables", "nft", "Required for managed firewall/NAT chains."),
        ("systemd-resolved", "resolvectl", "Required for DNS explanation on systemd-resolved systems."),
        ("ModemManager", "mmcli", "Required for detailed LTE/5G modem state."),
        ("iptables legacy snapshot", "iptables-save", "Optional fallback visibility for legacy firewall rules."),
        ("sysctl", "sysctl", "Required for forwarding state visibility."),
    ]
    return [
        {
            "name": name,
            "binary": binary,
            "available": available(binary),
            "candidate_paths": command_spec(binary).get("host_paths", []),
            "purpose": purpose,
        }
        for name, binary, purpose in providers
    ]


def brcmfmac_recent_errors() -> list[str]:
    def load() -> list[str]:
        commands = [
            ["journalctl", "-k", "-n", "200", "-g", "brcmfmac", "--no-pager"],
            ["dmesg", "-T"],
        ]
        errors: list[str] = []
        for command in commands:
            result = run(command)
            if not result.get("ok"):
                continue
            for line in str(result.get("stdout", "")).splitlines()[-200:]:
                if "brcmfmac" in line and ("fail" in line.lower() or "error" in line.lower()):
                    errors.append(line.strip())
            if errors:
                break
        return errors[-8:]

    return cached_read("brcmfmac_recent_errors", 300, load)


def interface_behaviors() -> dict[str, object]:
    return cached_read("network_interface_profiles", 15, _interface_profiles_uncached)


def interface_profiles() -> dict[str, object]:
    return interface_behaviors()


def _interface_profiles_uncached() -> dict[str, object]:
    snapshot = network_snapshot()
    interfaces = current_interfaces()
    defaults = default_route_devices(snapshot)
    nmcli_map = nmcli_device_map()
    config = runtime_config()
    driver_errors = brcmfmac_recent_errors()
    ethernet_seen = 0
    profiles = []
    for iface in interfaces:
        role = str(iface.get("role", ""))
        ethernet_index = ethernet_seen
        if role == "ethernet":
            ethernet_seen += 1
        nmcli = nmcli_map.get(str(iface.get("name", "")), {})
        identity = interface_identity(iface, nmcli)
        profile = suggested_profile(iface, defaults, ethernet_index)
        configured, configured_policy = configured_profile(
            str(iface.get("name", "")),
            config,
            str(identity.get("stable_key", "")),
        )
        effective_profile = configured or profile
        profiles.append({
            "interface": iface.get("name"),
            "identity": identity,
            "detected_kind": role,
            "detected_role": role,
            "suggested_behavior": profile,
            "suggested_profile": profile,
            "suggested_behavior_label": BEHAVIOR_LABELS.get(profile, profile),
            "suggested_label": PROFILE_LABELS.get(profile, profile),
            "configured_behavior": configured,
            "configured_profile": configured,
            "effective_behavior": effective_profile,
            "effective_profile": effective_profile,
            "effective_behavior_label": BEHAVIOR_LABELS.get(effective_profile, effective_profile),
            "effective_label": PROFILE_LABELS.get(effective_profile, effective_profile),
            "behavior_labels": BEHAVIOR_LABELS,
            "profile_labels": PROFILE_LABELS,
            "configured_policy": configured_policy,
            "warnings": profile_warnings(effective_profile, configured_policy, driver_errors),
            "state": iface.get("state"),
            "mac": iface.get("mac"),
            "mtu": iface.get("mtu"),
            "ipv4": iface.get("ipv4", []),
            "ipv6": iface.get("ipv6", []),
            "default_route": iface.get("name") in defaults,
            "nmcli": nmcli,
            "capabilities": profile_capabilities(iface, nmcli),
            "behavior_options": PROFILE_OPTIONS_BY_ROLE.get(role, ["unassigned"]),
            "profile_options": PROFILE_OPTIONS_BY_ROLE.get(role, ["unassigned"]),
            "settings": PROFILE_SETTINGS.get(effective_profile, PROFILE_SETTINGS["unassigned"]),
        })
    return {
        "interfaces": profiles,
        "default_route_devices": sorted(defaults),
        "providers": provider_health(),
        "wifi_driver_errors": driver_errors,
        "runtime_config_present": bool(config),
        "model": {
            "behaviors": [
                "management_lan",
                "device_lan",
                "uplink_ethernet",
                "uplink_wifi",
                "hotspot_wifi",
                "uplink_cellular",
                "management_tunnel",
                "container",
                "unassigned",
            ],
            "roles": [
                "management_lan",
                "device_lan",
                "uplink_ethernet",
                "uplink_wifi",
                "hotspot_wifi",
                "uplink_cellular",
                "management_tunnel",
                "container",
                "unassigned",
            ],
            "behavior_labels": BEHAVIOR_LABELS,
            "role_labels": PROFILE_LABELS,
            "assignment_key": "interface_registry.stable_key",
            "apply_model": "observe -> preview -> apply -> verify",
            "hard_apply_requires_confirmation": True,
        },
    }
