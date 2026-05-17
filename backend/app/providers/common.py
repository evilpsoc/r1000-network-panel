import json

from app.core.command_runner import CommandRunner
from app.core.providers import command_exists, command_spec, host_command_available, resolved_command


runner = CommandRunner(timeout_seconds=8)


def run(command: list[str]) -> dict[str, object]:
    result = runner.run(command)
    return {
        "command": result.command,
        "ok": result.ok,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "timed_out": result.timed_out,
        "duration_ms": result.duration_ms,
    }


def json_command(command: list[str]) -> list[dict[str, object]]:
    result = runner.run(command)
    if not result.ok or not result.stdout:
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def candidate_command(
    name: str,
    args: list[str],
    *,
    host_paths: list[str] | None = None,
    local_names: list[str] | None = None,
) -> list[str]:
    if host_paths is None and local_names is None:
        return resolved_command(name, args)
    spec = command_spec(name)
    names = local_names if local_names is not None else spec["local_names"]
    paths = host_paths if host_paths is not None else spec["host_paths"]
    for local_name in names:
        if command_exists(local_name):
            command_args = ["--status"] if name == "resolvectl" and local_name == "systemd-resolve" and args == ["status"] else args
            return [local_name] + command_args
    for path in paths:
        if host_command_available(path):
            command_args = ["--status"] if name == "resolvectl" and path.endswith("systemd-resolve") and args == ["status"] else args
            return ["chroot", "/host", path] + command_args
    return []


def host_or_local_command(path: str, name: str, args: list[str]) -> list[str]:
    command = candidate_command(name, args, host_paths=[path])
    return command or [name] + args


def available(name: str, host_path: str = "", host_paths: list[str] | None = None, local_names: list[str] | None = None) -> bool:
    spec = command_spec(name)
    paths = list(host_paths if host_paths is not None else spec["host_paths"])
    if host_path:
        paths.append(host_path)
    return bool(candidate_command(name, [], host_paths=paths, local_names=local_names))


def provider_command(name: str, args: list[str], unavailable_message: str = "") -> dict[str, object]:
    command = candidate_command(name, args)
    if not command:
        return {"ok": False, "stdout": "", "stderr": unavailable_message or f"{name} not available", "command": []}
    return run(command)


def provider_json_command(name: str, args: list[str]) -> list[dict[str, object]]:
    command = candidate_command(name, args)
    if not command:
        return []
    return json_command(command)
