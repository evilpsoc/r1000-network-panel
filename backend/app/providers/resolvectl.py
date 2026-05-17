from app.providers.common import available, provider_command


def is_available() -> bool:
    return available("resolvectl")


def status() -> dict[str, object]:
    return provider_command("resolvectl", ["status"], "resolvectl/systemd-resolve not available")
