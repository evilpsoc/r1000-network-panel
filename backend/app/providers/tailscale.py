from app.providers.common import provider_command


def status() -> dict[str, object]:
    return provider_command("tailscale", ["status", "--json"], "tailscale not available")
