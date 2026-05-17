from app.providers.common import provider_command


def nft_ruleset() -> dict[str, object]:
    return provider_command("nft", ["list", "ruleset"], "nft not available")


def iptables_save() -> dict[str, object]:
    return provider_command("iptables-save", [], "iptables-save not available")
