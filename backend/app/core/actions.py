from dataclasses import asdict, dataclass
import shlex
from typing import Any

from app.core.command_runner import CommandRunner
from app.core.events import EventLog
from app.core.providers import get_provider_statuses, resolved_command
from app.core.backups import create_backup
from app.domain.network.analyzer import network_diagnostics


event_log = EventLog()
terminal_runner = CommandRunner(timeout_seconds=15)


@dataclass(frozen=True)
class ActionSpec:
    id: str
    title: str
    description: str
    risk: str
    execute_mode: str
    requires_confirmation: bool


ACTION_SPECS = {
    "network.diagnostics.collect": ActionSpec(
        id="network.diagnostics.collect",
        title="Collect Network Diagnostics",
        description="Collect a read-only network snapshot, normalized state and findings.",
        risk="low",
        execute_mode="read_only",
        requires_confirmation=False,
    ),
    "providers.rescan": ActionSpec(
        id="providers.rescan",
        title="Rescan Providers",
        description="Refresh host provider/capability state without changing the host.",
        risk="low",
        execute_mode="read_only",
        requires_confirmation=False,
    ),
    "providers.install.guidance": ActionSpec(
        id="providers.install.guidance",
        title="Show Provider Install Guidance",
        description="Return install commands for a missing provider. This does not run them.",
        risk="medium",
        execute_mode="preview_only",
        requires_confirmation=True,
    ),
    "terminal.command": ActionSpec(
        id="terminal.command",
        title="Run Guarded Terminal Command",
        description="Run an allowlisted read-only host inspection command.",
        risk="medium",
        execute_mode="read_only",
        requires_confirmation=True,
    ),
    "system.backup.create": ActionSpec(
        id="system.backup.create",
        title="Create Safety Backup",
        description="Copy panel runtime files and capture read-only host network snapshots.",
        risk="low",
        execute_mode="state_write",
        requires_confirmation=True,
    ),
}


TERMINAL_ALLOWED = {
    "ip": [(), ("addr",), ("link",), ("route",), ("-6", "route"), ("rule",)],
    "nmcli": [("device", "status"), ("connection", "show"), ("radio",), ("general", "status")],
    "resolvectl": [("status",)],
    "nft": [("list", "ruleset"), ("list", "tables")],
    "docker": [("ps",), ("network", "ls")],
    "mmcli": [("-L",)],
    "tailscale": [("status",)],
}


def _terminal_parts(command: str) -> list[str]:
    if any(token in command for token in ("|", ">", "<", ";", "&&", "||", "$(", "`")):
        raise ValueError("Shell operators are not allowed in the guarded terminal")
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        raise ValueError(f"Invalid command: {exc}") from exc
    if not parts:
        raise ValueError("Command is required")
    return parts


def _terminal_allowed(parts: list[str]) -> bool:
    binary = parts[0]
    args = tuple(parts[1:])
    allowed = TERMINAL_ALLOWED.get(binary, [])
    if not allowed:
        return False
    return any(args[: len(prefix)] == prefix for prefix in allowed)


def terminal_plan(command: str) -> dict[str, Any]:
    parts = _terminal_parts(command)
    if not _terminal_allowed(parts):
        raise PermissionError("Command is not in the read-only terminal allowlist")
    resolved = resolved_command(parts[0], parts[1:])
    if not resolved:
        raise ValueError(f"{parts[0]} is not available")
    return {
        "input": command,
        "resolved": resolved,
        "commands": [shlex.join(resolved)],
        "notes": [
            "Guarded terminal only runs allowlisted read-only commands.",
            "Shell operators, pipes and redirects are blocked.",
        ],
    }


def list_actions() -> list[dict[str, Any]]:
    return [asdict(action) for action in ACTION_SPECS.values()]


def _provider_by_id(provider_id: str) -> dict[str, Any]:
    for provider in get_provider_statuses():
        if provider.get("id") == provider_id:
            return provider
    raise ValueError(f"Unknown provider: {provider_id}")


def preview_action(action_id: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    spec = ACTION_SPECS.get(action_id)
    if not spec:
        raise ValueError(f"Unknown action: {action_id}")

    commands: list[str] = []
    notes: list[str] = []
    target = str(payload.get("target", "")).strip()

    if action_id == "network.diagnostics.collect":
        commands.append("GET /api/network/diagnostics")
        notes.append("Read-only collection. No routes, firewall rules or services are changed.")
    elif action_id == "providers.rescan":
        commands.append("GET /api/providers")
        notes.append("Read-only provider detection. No packages or services are installed.")
    elif action_id == "providers.install.guidance":
        if not target:
            raise ValueError("target provider id is required")
        provider = _provider_by_id(target)
        commands.extend((provider.get("install_hint") or {}).get("commands") or [])
        if not commands:
            notes.append("No install guidance is available for this provider on the current host.")
        notes.append("Preview only. The panel will not run host install commands from this action.")
    elif action_id == "terminal.command":
        command = str(payload.get("command", "")).strip()
        plan = terminal_plan(command)
        commands.extend(plan["commands"])
        notes.extend(plan["notes"])
    elif action_id == "system.backup.create":
        label = str(payload.get("label", "manual")).strip() or "manual"
        commands.extend([
            f"copy /app/data/runtime-config.json -> /app/data/backups/<timestamp>-{label}/runtime/",
            "nft list ruleset > /app/data/backups/<timestamp>/network/nft-ruleset.txt",
            "nmcli connection show > /app/data/backups/<timestamp>/network/nmcli-connections.txt",
        ])
        notes.extend([
            "This creates local backup files under /app/data/backups.",
            "NetworkManager profile export is documented as a manual plan; restore is not automated yet.",
        ])

    preview = {
        "action": asdict(spec),
        "target": target,
        "commands": commands,
        "notes": notes,
    }
    event_log.append(
        source="actions",
        action="preview",
        message=f"Action preview requested: {action_id}",
        details={"action_id": action_id, "target": target, "risk": spec.risk},
    )
    return preview


def execute_action(action_id: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    spec = ACTION_SPECS.get(action_id)
    if not spec:
        raise ValueError(f"Unknown action: {action_id}")
    if spec.execute_mode == "preview_only":
        raise PermissionError("This action is preview-only and cannot be executed")

    target = str(payload.get("target", "")).strip()
    if action_id == "network.diagnostics.collect":
        result: Any = network_diagnostics()
    elif action_id == "providers.rescan":
        result = {"providers": get_provider_statuses()}
    elif action_id == "terminal.command":
        command = str(payload.get("command", "")).strip()
        plan = terminal_plan(command)
        run = terminal_runner.run(plan["resolved"])
        result = {
            "command": run.command,
            "ok": run.ok,
            "returncode": run.returncode,
            "stdout": run.stdout,
            "stderr": run.stderr,
            "timed_out": run.timed_out,
            "duration_ms": run.duration_ms,
        }
    elif action_id == "system.backup.create":
        label = str(payload.get("label", "manual")).strip() or "manual"
        result = create_backup(label, bool(payload.get("include_host_snapshots", True)))
    else:
        raise PermissionError("No executor is registered for this action")

    event_log.append(
        source="actions",
        action="execute",
        message=f"Action executed: {action_id}",
        details={"action_id": action_id, "target": target, "risk": spec.risk},
    )
    return {"ok": True, "action": asdict(spec), "target": target, "result": result}


def action_history(limit: int = 100) -> list[dict[str, Any]]:
    return [
        event
        for event in event_log.tail(limit)
        if event.get("source") == "actions"
    ]
