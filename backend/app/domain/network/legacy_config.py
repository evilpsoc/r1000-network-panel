import re


def slugify(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]+", "_", value).strip("_").lower()


def cfg_flag(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def nm_bool(value: object, default: str = "yes") -> str:
    normalized = str(value or default).strip().lower()
    if normalized in {"1", "true", "yes", "on", "enabled"}:
        return "yes"
    if normalized in {"0", "false", "no", "off", "disabled"}:
        return "no"
    return default


def nm_optional_int(value: object, min_value: int, max_value: int) -> str:
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


def nm_route_policy_settings(config: dict[str, object], default_never: str = "yes") -> list[str]:
    never_default = nm_bool(config.get("never_default", default_never), default_never)
    ignore_auto_routes = nm_bool(config.get("ignore_auto_routes", "yes"), "yes")
    return [
        "ipv4.never-default", never_default,
        "ipv4.ignore-auto-routes", ignore_auto_routes,
        "ipv6.never-default", never_default,
        "ipv6.ignore-auto-routes", ignore_auto_routes,
    ]


def nm_link_route_settings(config: dict[str, object]) -> list[str]:
    settings: list[str] = []
    mtu = nm_optional_int(config.get("mtu", ""), 68, 9000)
    route_metric = nm_optional_int(config.get("route_metric", ""), 1, 9999)
    if mtu:
        settings.extend(["802-3-ethernet.mtu", mtu])
    if route_metric:
        settings.extend(["ipv4.route-metric", route_metric, "ipv6.route-metric", route_metric])
    return settings


def nm_ethernet_profile_settings(
    config: dict[str, object],
    interface: str,
    ipv4_method: str,
    ipv6_method: str,
    ipv4_address: str = "",
    ipv6_address: str = "",
) -> list[str]:
    settings = [
        "connection.autoconnect", nm_bool(config.get("autoconnect", "yes"), "yes"),
        "connection.interface-name", interface,
        "ipv4.method", ipv4_method,
        "ipv4.addresses", ipv4_address,
        "ipv6.method", ipv6_method,
        "ipv6.addresses", ipv6_address,
    ]
    settings.extend(nm_route_policy_settings(config))
    settings.extend(nm_link_route_settings(config))
    return settings


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
        "prefer-cellular": "prefer-lte",
        "lte": "prefer-lte",
        "cellular": "prefer-lte",
        "prefer-wifi": "prefer-wifi",
        "wifi": "prefer-wifi",
        "prefer-wired": "prefer-wired",
        "prefer-ethernet": "prefer-wired",
        "ethernet": "prefer-wired",
        "wired": "prefer-wired",
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


def normalize_wifi_config_values(config: dict[str, str]) -> None:
    config["mode"] = normalize_wifi_mode(config.get("mode", "client"))
    config["client_trust_mode"] = normalize_wifi_client_trust_mode(config.get("client_trust_mode", "normal"))
    config["uplink_preference"] = normalize_wifi_uplink_preference(config.get("uplink_preference", "prefer-lte"))
    config["hotspot_security"] = normalize_wifi_security(config.get("hotspot_security", "wpa2-personal"))
    config["country"] = normalize_country_code(config.get("country", "DE"))
    config["band"] = normalize_wifi_band(config.get("band", "auto"))
    config["channel"] = normalize_wifi_channel(config.get("channel", "auto"), config["band"])
    config["ipv4_method"] = normalize_wifi_ipv4_method(config["mode"], config.get("ipv4_method", "auto"))
    config["ipv6_method"] = normalize_wifi_ipv6_method(config["mode"], config.get("ipv6_method", "disabled"))
    if config["mode"] == "hotspot" and config["hotspot_security"] != "open" and not config.get("hotspot_password", "").strip():
        config["hotspot_password"] = ""
    if config["mode"] == "hotspot" and config["ipv6_method"] == "auto":
        config["ipv6_method"] = "disabled"


def role_description(role: str) -> str:
    normalized = normalize_lan_role(role)
    if normalized == "isolated":
        return "clients get internet, but cannot reach internal LAN, Wi-Fi, Tailscale, or most device services"
    if normalized == "external":
        return "clients get internet and stay away from internal LAN, while Tailscale devices can still reach the router and this external segment"
    return "trusted internal LAN with access to local services and management"
