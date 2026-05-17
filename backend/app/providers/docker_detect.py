from app.providers.common import provider_command


def networks() -> dict[str, object]:
    return provider_command("docker", ["network", "ls", "--format", "{{json .}}"], "docker not available")
