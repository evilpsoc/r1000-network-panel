from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any

from app.core.command_runner import CommandRunner
from app.core.runtime_config import RUNTIME_CONFIG_PATH
from app.core.host import nmcli_command


BACKUP_ROOT = Path(os.getenv("PANEL_BACKUP_ROOT", "/app/data/backups"))
RUNNER = CommandRunner(timeout_seconds=15)


@dataclass(frozen=True)
class BackupItem:
    kind: str
    source: str
    target: str
    ok: bool
    note: str = ""


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _safe_label(label: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", label.strip())
    return cleaned.strip("-") or "manual"


def backup_dir(label: str) -> Path:
    return BACKUP_ROOT / f"{_timestamp()}-{_safe_label(label)}"


def copy_file_if_exists(path: str | Path, destination: Path) -> BackupItem:
    source = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not source.exists():
        return BackupItem("file", str(source), str(destination), False, "source missing")
    try:
        shutil.copy2(source, destination)
    except Exception as exc:
        return BackupItem("file", str(source), str(destination), False, str(exc))
    return BackupItem("file", str(source), str(destination), True)


def write_text_backup(name: str, content: str, destination_dir: Path, note: str = "") -> BackupItem:
    target = destination_dir / name
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        target.write_text(content)
    except Exception as exc:
        return BackupItem("snapshot", name, str(target), False, str(exc))
    return BackupItem("snapshot", name, str(target), True, note)


def backup_runtime_files(destination_dir: Path) -> list[BackupItem]:
    files = [
        RUNTIME_CONFIG_PATH,
        "/app/data/panel-auth.json",
        "/app/data/panel-sessions.json",
        "/app/data/netalertx-sync-state.json",
    ]
    return [
        copy_file_if_exists(path, destination_dir / "runtime" / Path(path).name)
        for path in files
    ]


def backup_nftables_snapshot(destination_dir: Path) -> BackupItem:
    result = RUNNER.run(["nft", "list", "ruleset"], timeout_seconds=10)
    content = result.stdout if result.ok else result.stderr
    note = "nft list ruleset" if result.ok else f"nft snapshot failed: {result.returncode}"
    return write_text_backup("nft-ruleset.txt", content, destination_dir / "network", note)


def backup_nmcli_snapshot(destination_dir: Path) -> BackupItem:
    command = nmcli_command(["-f", "NAME,UUID,TYPE,DEVICE", "connection", "show"])
    result = RUNNER.run(command, timeout_seconds=10)
    content = result.stdout if result.ok else result.stderr
    note = "nmcli connection show" if result.ok else f"nmcli snapshot failed: {result.returncode}"
    return write_text_backup("nmcli-connections.txt", content, destination_dir / "network", note)


def network_profile_export_plan() -> list[str]:
    return [
        "# Review exported profile paths before using them for restore.",
        "nmcli -f NAME,UUID,TYPE,DEVICE connection show",
        "nmcli connection export <connection-name> > <backup-dir>/network/<connection-name>.nmconnection",
    ]


def create_backup(label: str = "manual", include_host_snapshots: bool = True) -> dict[str, Any]:
    destination = backup_dir(label)
    items = backup_runtime_files(destination)
    if include_host_snapshots:
        items.append(backup_nftables_snapshot(destination))
        items.append(backup_nmcli_snapshot(destination))

    manifest = {
        "created_at": _timestamp(),
        "label": label,
        "path": str(destination),
        "items": [asdict(item) for item in items],
        "network_profile_export_plan": network_profile_export_plan(),
        "restore_note": "Restore is intentionally manual until apply/rollback flows are implemented.",
    }
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def list_backups(limit: int = 50) -> list[dict[str, Any]]:
    if not BACKUP_ROOT.exists():
        return []
    backups = []
    for path in sorted(BACKUP_ROOT.iterdir(), reverse=True):
        if not path.is_dir():
            continue
        manifest_path = path / "manifest.json"
        if manifest_path.exists():
            try:
                data = json.loads(manifest_path.read_text())
            except Exception:
                data = {"path": str(path), "created_at": path.name, "items": []}
        else:
            data = {"path": str(path), "created_at": path.name, "items": []}
        backups.append(data)
        if len(backups) >= limit:
            break
    return backups
