from pathlib import Path
import subprocess


COMMAND_CANDIDATES: dict[str, dict[str, list[str]]] = {
    "docker": {"local_names": ["docker"], "host_paths": ["/usr/bin/docker", "/bin/docker", "/usr/local/bin/docker"]},
    "ip": {"local_names": ["ip"], "host_paths": ["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"]},
    "iptables-save": {"local_names": ["iptables-save"], "host_paths": ["/usr/sbin/iptables-save", "/usr/bin/iptables-save", "/sbin/iptables-save"]},
    "mmcli": {"local_names": ["mmcli"], "host_paths": ["/usr/bin/mmcli", "/bin/mmcli"]},
    "nft": {"local_names": ["nft"], "host_paths": ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft", "/bin/nft"]},
    "nmcli": {"local_names": ["nmcli"], "host_paths": ["/usr/bin/nmcli", "/bin/nmcli"]},
    "ping": {"local_names": ["ping"], "host_paths": ["/usr/bin/ping", "/bin/ping"]},
    "resolvectl": {
        "local_names": ["resolvectl", "systemd-resolve"],
        "host_paths": ["/usr/bin/resolvectl", "/bin/resolvectl", "/usr/bin/systemd-resolve", "/bin/systemd-resolve"],
    },
    "sysctl": {"local_names": ["sysctl"], "host_paths": ["/usr/sbin/sysctl", "/usr/bin/sysctl", "/sbin/sysctl", "/bin/sysctl"]},
    "tailscale": {"local_names": ["tailscale"], "host_paths": ["/usr/bin/tailscale", "/usr/local/bin/tailscale", "/bin/tailscale"]},
    "wg": {"local_names": ["wg"], "host_paths": ["/usr/bin/wg", "/usr/sbin/wg", "/bin/wg", "/sbin/wg"]},
}


def read_text(path: str, default: str = "") -> str:
    try:
        return Path(path).read_text().strip()
    except Exception:
        return default


def run_command(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except Exception:
        return ""


def command_exists(name: str) -> bool:
    try:
        result = subprocess.run(["which", name], capture_output=True, text=True)
    except Exception:
        return False
    return result.returncode == 0


def host_command_available(path: str) -> bool:
    return Path("/host").joinpath(path.lstrip("/")).exists()


def command_spec(name: str) -> dict[str, list[str]]:
    spec = COMMAND_CANDIDATES.get(name, {})
    return {
        "local_names": list(spec.get("local_names", [name])),
        "host_paths": list(spec.get("host_paths", [])),
    }


def host_or_container_command_exists(
    name: str,
    host_path: str = "",
    *,
    host_paths: list[str] | None = None,
    local_names: list[str] | None = None,
) -> bool:
    spec = command_spec(name)
    paths = list(host_paths if host_paths is not None else spec["host_paths"])
    if host_path:
        paths.append(host_path)
    names = local_names if local_names is not None else spec["local_names"]
    return any(command_exists(local_name) for local_name in names) or any(host_command_available(path) for path in paths)


def resolved_command(name: str, args: list[str] | None = None) -> list[str]:
    spec = command_spec(name)
    command_args = args or []
    for local_name in spec["local_names"]:
        if command_exists(local_name):
            if name == "resolvectl" and local_name == "systemd-resolve" and command_args == ["status"]:
                return [local_name, "--status"]
            return [local_name] + command_args
    for path in spec["host_paths"]:
        if host_command_available(path):
            if name == "resolvectl" and path.endswith("systemd-resolve") and command_args == ["status"]:
                return ["chroot", "/host", path, "--status"]
            return ["chroot", "/host", path] + command_args
    return []


def is_process_running(name: str) -> bool:
    try:
        result = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True)
    except Exception:
        return False
    return result.returncode == 0


def docker_available() -> bool:
    return host_or_container_command_exists("docker")


def docker_service_names() -> list[str]:
    if not docker_available():
        return []
    cmd = resolved_command("docker", ["ps", "--format", "{{.Names}}"])
    if not cmd:
        return []
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except Exception:
        return []
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def detected_package_manager() -> dict[str, str]:
    managers = [
        ("apt", "/usr/bin/apt-get", "apt-get update && apt-get install -y"),
        ("dnf", "/usr/bin/dnf", "dnf install -y"),
        ("yum", "/usr/bin/yum", "yum install -y"),
        ("apk", "/sbin/apk", "apk add"),
        ("pacman", "/usr/bin/pacman", "pacman -Sy --noconfirm"),
    ]
    for manager_id, path, install_prefix in managers:
        if host_command_available(path):
            return {
                "id": manager_id,
                "scope": "host",
                "path": path,
                "install_prefix": f"chroot /host {install_prefix}",
            }
    for manager_id, path, install_prefix in managers:
        name = Path(path).name
        if command_exists(name):
            return {
                "id": manager_id,
                "scope": "container",
                "path": path,
                "install_prefix": install_prefix,
            }
    return {"id": "", "scope": "", "path": "", "install_prefix": ""}


def provider_install_hint(packages: list[str], services: list[str] | None = None) -> dict[str, object]:
    package_manager = detected_package_manager()
    commands: list[str] = []
    if package_manager.get("install_prefix") and packages:
        commands.append(f"{package_manager['install_prefix']} {' '.join(packages)}")
    for service in services or []:
        if package_manager.get("scope") == "host":
            commands.append(f"chroot /host systemctl enable --now {service}")
        elif command_exists("systemctl"):
            commands.append(f"systemctl enable --now {service}")
    return {
        "package_manager": package_manager,
        "packages": packages,
        "services": services or [],
        "commands": commands,
        "note": "Installation is guidance only for now. A future installer must use preview, confirmation and audit logging.",
    }


def manual_install_hint(commands: list[str], note: str) -> dict[str, object]:
    return {
        "package_manager": {"id": "manual", "scope": "host", "path": "", "install_prefix": ""},
        "packages": [],
        "services": [],
        "commands": commands,
        "note": note,
    }


def provider_status(
    provider_id: str,
    name: str,
    available: bool,
    *,
    active: bool | None = None,
    install_packages: list[str] | None = None,
    install_services: list[str] | None = None,
    required_commands: list[str] | None = None,
    features: list[str] | None = None,
    reason: str = "",
    fallback: str = "",
    recommended: bool = False,
    experimental: bool = False,
    unsupported: bool = False,
) -> dict[str, object]:
    installable = bool(install_packages) and not available and bool(detected_package_manager().get("id"))
    if unsupported:
        state = "unsupported"
    elif available:
        state = "available"
    elif installable:
        state = "installable"
    else:
        state = "missing"
    return {
        "id": provider_id,
        "name": name,
        "state": state,
        "available": available,
        "active": active if active is not None else available,
        "installable": installable,
        "recommended": recommended,
        "experimental": experimental,
        "reason": reason or ("Provider is available" if available else "Required host dependency is missing"),
        "fallback": fallback,
        "required_commands": required_commands or [],
        "features": features or [],
        "install_hint": provider_install_hint(install_packages or [], install_services or []) if install_packages else {},
    }


def nmcli_available() -> bool:
    return host_or_container_command_exists("nmcli")


def get_provider_statuses() -> list[dict[str, object]]:
    nmcli_ok = nmcli_available()
    iproute2_ok = host_or_container_command_exists("ip")
    resolved_ok = host_or_container_command_exists("resolvectl")
    mmcli_ok = host_or_container_command_exists("mmcli")
    docker_ok = docker_available()
    nft_ok = host_or_container_command_exists("nft")
    tailscale_ok = host_or_container_command_exists("tailscale") or is_process_running("tailscaled")
    wireguard_ok = host_or_container_command_exists("wg")
    samba_ok = host_command_available("/usr/sbin/smbd") or host_command_available("/usr/bin/smbpasswd") or command_exists("smbd")
    cups_ok = host_command_available("/usr/sbin/cupsd") or host_command_available("/usr/bin/lpstat") or command_exists("lpstat")
    led_ok = Path("/sys/class/leds").exists() or Path("/host/sys/class/leds").exists()
    gpio_ok = Path("/sys/class/gpio").exists() or Path("/host/sys/class/gpio").exists()
    k3s_ok = host_or_container_command_exists("k3s", "/usr/local/bin/k3s") or host_or_container_command_exists("kubectl", "/usr/local/bin/kubectl")
    kubernetes_provider = provider_status(
        "kubernetes",
        "Kubernetes / K3s",
        k3s_ok,
        required_commands=["k3s", "kubectl"],
        features=["future optional runtime provider", "pods", "ingress", "storage class"],
        fallback="Kubernetes is optional; Docker Compose remains the recommended default runtime.",
        experimental=True,
    )
    if not k3s_ok:
        kubernetes_provider["state"] = "installable"
        kubernetes_provider["installable"] = True
        kubernetes_provider["install_hint"] = manual_install_hint(
            ["curl -sfL https://get.k3s.io | sh -"],
            "K3s uses its own installer. Keep this as a manual/experimental provider until preview and rollback are implemented.",
        )

    return [
        provider_status(
            "core",
            "Core Panel",
            True,
            required_commands=["python", "fastapi"],
            features=["auth", "dashboard-shell", "configuration"],
            reason="Core web panel is running.",
            recommended=True,
        ),
        provider_status(
            "iproute2",
            "iproute2",
            iproute2_ok,
            install_packages=["iproute2"],
            required_commands=["ip"],
            features=["interfaces", "addresses", "routes", "policy rules"],
            fallback="Network inventory and diagnostics are degraded without iproute2.",
            recommended=True,
        ),
        provider_status(
            "networkmanager",
            "NetworkManager",
            nmcli_ok,
            active=is_process_running("NetworkManager"),
            install_packages=["network-manager"],
            install_services=["NetworkManager"],
            required_commands=["nmcli"],
            features=["LAN roles", "Wi-Fi client/hotspot", "connection profiles"],
            fallback="Read-only iproute2/system inspection can still be used later when NetworkManager is missing.",
            recommended=True,
        ),
        provider_status(
            "systemd-resolved",
            "systemd-resolved",
            resolved_ok,
            active=is_process_running("systemd-resolved"),
            install_packages=["systemd-resolved"],
            install_services=["systemd-resolved"],
            required_commands=["resolvectl", "systemd-resolve"],
            features=["DNS state", "per-link DNS visibility", "split DNS explanation"],
            fallback="DNS pages can still show configured values, but live resolver explanation is degraded.",
            recommended=True,
        ),
        provider_status(
            "modemmanager",
            "ModemManager",
            mmcli_ok,
            active=is_process_running("ModemManager"),
            install_packages=["modemmanager"],
            install_services=["ModemManager"],
            required_commands=["mmcli"],
            features=["LTE state", "APN profiles", "guarded AT commands"],
            fallback="Cellular page should show unavailable if no modem provider exists.",
        ),
        provider_status(
            "docker-compose",
            "Docker Compose",
            docker_ok,
            active=is_process_running("dockerd") or bool(docker_service_names()),
            install_packages=["docker.io", "docker-compose-plugin"],
            install_services=["docker"],
            required_commands=["docker"],
            features=["container inventory", "local provider apps", "NetAlertX install"],
            fallback="Apps can stay disabled while services/listeners remain visible.",
            recommended=True,
        ),
        provider_status(
            "nftables",
            "nftables",
            nft_ok,
            active=bool(run_command(resolved_command("nft", ["list", "ruleset"]))) if nft_ok else False,
            install_packages=["nftables"],
            install_services=["nftables"],
            required_commands=["nft"],
            features=["managed firewall tables", "NAT visibility", "future rollback-safe fixes"],
            fallback="Firewall pages can remain read-only or degraded without nft.",
            recommended=True,
        ),
        provider_status(
            "tailscale",
            "Tailscale",
            tailscale_ok,
            active=is_process_running("tailscaled"),
            install_packages=["tailscale"],
            install_services=["tailscaled"],
            required_commands=["tailscale"],
            features=["management tunnel", "overlay IP", "future subnet route checks"],
            fallback="Remote Access can show no overlay path.",
        ),
        provider_status(
            "wireguard",
            "WireGuard",
            wireguard_ok,
            install_packages=["wireguard-tools"],
            required_commands=["wg"],
            features=["future site-to-site tunnels", "peer status"],
            fallback="WireGuard tunnel controls stay unavailable.",
            experimental=True,
        ),
        provider_status(
            "samba",
            "Samba",
            samba_ok,
            active=is_process_running("smbd"),
            install_packages=["samba"],
            install_services=["smbd"],
            required_commands=["smbd", "smbpasswd"],
            features=["shares", "SMB users", "file sharing"],
            fallback="File sharing page can show install prompt and keep storage visibility.",
        ),
        provider_status(
            "cups",
            "CUPS Printing",
            cups_ok,
            active=is_process_running("cupsd"),
            install_packages=["cups"],
            install_services=["cups"],
            required_commands=["lpstat", "systemctl"],
            features=["printer daemon status", "printer share visibility"],
            fallback="Printing controls stay unavailable.",
        ),
        provider_status(
            "device-io",
            "Device I/O",
            led_ok or gpio_ok,
            required_commands=[],
            features=["LEDs", "GPIO", "serial/RS-485 inventory"],
            reason="Kernel sysfs/device paths are visible." if (led_ok or gpio_ok) else "No LED/GPIO sysfs paths are visible.",
            fallback="Device page should show unavailable hardware sections instead of failing.",
        ),
        kubernetes_provider,
    ]


def get_capabilities() -> dict[str, object]:
    providers = get_provider_statuses()
    by_id = {provider["id"]: provider for provider in providers}

    def capability(provider_id: str, name: str, *, reason: str = "") -> dict[str, object]:
        provider = by_id.get(provider_id, {})
        return {
            "id": name,
            "provider": provider_id,
            "state": provider.get("state", "missing"),
            "available": bool(provider.get("available")),
            "installable": bool(provider.get("installable")),
            "reason": reason or str(provider.get("reason", "")),
        }

    return {
        "device_profile": detect_device_profile(),
        "providers": providers,
        "capabilities": [
            capability("networkmanager", "network-control"),
            capability("networkmanager", "wifi-control"),
            capability("iproute2", "network-inventory"),
            capability("systemd-resolved", "dns-inspection"),
            capability("modemmanager", "cellular-control"),
            capability("docker-compose", "container-runtime"),
            capability("docker-compose", "local-provider"),
            capability("nftables", "firewall-control"),
            capability("tailscale", "remote-access-tailscale"),
            capability("wireguard", "remote-access-wireguard"),
            capability("samba", "file-sharing"),
            capability("cups", "printing"),
            capability("device-io", "device-io"),
            capability("kubernetes", "kubernetes-runtime"),
        ],
    }


def detect_device_profile() -> dict[str, object]:
    model = read_text("/host/proc/device-tree/model") or read_text("/proc/device-tree/model")
    machine = run_command(["uname", "-m"]) or ""
    profile_id = "generic_linux"
    name = "Generic Linux"
    if "Raspberry Pi" in model:
        profile_id = "raspberry_pi"
        name = "Raspberry Pi"
    if "reComputer" in model or "R1000" in model or "R1035" in model:
        profile_id = "seeed_r1000"
        name = "Seeed reComputer R1000"
    elif machine in {"x86_64", "amd64"}:
        profile_id = "x86_linux"
        name = "x86 Linux"
    return {
        "id": profile_id,
        "name": name,
        "model": model or "Unknown Linux device",
        "architecture": machine,
    }
