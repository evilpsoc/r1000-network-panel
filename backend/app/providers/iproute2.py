from app.providers.common import provider_command, provider_json_command


def links() -> list[dict[str, object]]:
    return provider_json_command("ip", ["-j", "link"])


def addresses() -> list[dict[str, object]]:
    return provider_json_command("ip", ["-j", "addr"])


def routes(family: int = 4) -> list[dict[str, object]]:
    if family == 6:
        return provider_json_command("ip", ["-j", "-6", "route"])
    return provider_json_command("ip", ["-j", "route"])


def rules() -> dict[str, object]:
    return provider_command("ip", ["rule"], "iproute2 ip not available")
