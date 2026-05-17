from app.providers.common import available, provider_command


def is_available() -> bool:
    return available("nmcli")


def nmcli(args: list[str]) -> dict[str, object]:
    return provider_command("nmcli", args, "nmcli not available")


def device_status() -> dict[str, object]:
    return nmcli(["-t", "device", "status"])


def active_connections() -> dict[str, object]:
    return nmcli(["-t", "connection", "show", "--active"])
