import os
from pathlib import Path
import subprocess


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


def run_command_full(cmd: list[str], env: dict[str, str] | None = None) -> tuple[int, str, str]:
    try:
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        result = subprocess.run(cmd, capture_output=True, text=True, env=merged_env)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def run_command_input(cmd: list[str], input_text: str) -> tuple[int, str, str]:
    try:
        result = subprocess.run(cmd, input=input_text, capture_output=True, text=True)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def host_nmcli_command(args: list[str]) -> list[str]:
    return ["chroot", "/host", "/usr/bin/nmcli"] + args


def host_nmcli_available() -> bool:
    return Path("/host/usr/bin/nmcli").exists()


def nmcli_command(args: list[str]) -> list[str]:
    return host_nmcli_command(args) if host_nmcli_available() else ["nmcli"] + args


def nmcli_available() -> bool:
    return host_nmcli_available() or command_exists("nmcli")


def run_nmcli(args: list[str]) -> str:
    return run_command(nmcli_command(args))


def run_nmcli_full(args: list[str]) -> tuple[int, str, str]:
    return run_command_full(nmcli_command(args))


def host_command_available(path: str) -> bool:
    return Path("/host").joinpath(path.lstrip("/")).exists()


def host_binary_command(path: str, args: list[str]) -> list[str]:
    return ["chroot", "/host", path] + args


def command_exists(name: str) -> bool:
    result = subprocess.run(["which", name], capture_output=True, text=True)
    return result.returncode == 0
