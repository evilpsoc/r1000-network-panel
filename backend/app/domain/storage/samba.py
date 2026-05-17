import os
import re
from pathlib import Path

from app.core.host import (
    command_exists,
    host_binary_command,
    host_command_available,
    read_text,
    run_command_full,
    run_command_input,
)
from app.domain.system.services import is_process_running, parse_service_listeners


HOST_SAMBA_CONFIG_PATHS = [
    "/host/etc/samba/smb.conf",
    "/etc/samba/smb.conf",
]
HOST_SAMBA_MAIN_CONFIG = "/host/etc/samba/smb.conf"
HOST_SAMBA_PORTAL_CONFIG = "/host/etc/samba/portal-shares.conf"
HOST_SAMBA_INCLUDE_LINE = "include = /etc/samba/portal-shares.conf"


class StorageServiceError(Exception):
    def __init__(self, status_code: int, detail):
        super().__init__(str(detail))
        self.status_code = status_code
        self.detail = detail


def parse_samba_shares(conf_text: str, source: str) -> list[dict[str, str]]:
    shares: list[dict[str, str]] = []
    current_name = ""
    current_share: dict[str, str] | None = None
    for raw_line in conf_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            if current_share and current_name and current_name.lower() != "global":
                shares.append(current_share)
            current_name = line[1:-1].strip()
            current_share = {
                "name": current_name,
                "path": "",
                "read_only": "",
                "guest_ok": "",
                "valid_users": "",
                "source": source,
            }
            continue
        if "=" not in line or not current_share:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        key = key.lower()
        if key == "path":
            current_share["path"] = value
        elif key == "read only":
            current_share["read_only"] = value
        elif key == "guest ok":
            current_share["guest_ok"] = value
        elif key == "valid users":
            current_share["valid_users"] = value

    if current_share and current_name and current_name.lower() != "global":
        shares.append(current_share)
    return shares


def ensure_samba_portal_include() -> None:
    main_path = Path(HOST_SAMBA_MAIN_CONFIG)
    if not main_path.exists():
        raise StorageServiceError(500, "Host Samba config not found")
    text = main_path.read_text()
    if HOST_SAMBA_INCLUDE_LINE in text:
        return
    lines = text.splitlines()
    inserted = False
    for index, line in enumerate(lines):
        if line.strip().lower() == "[global]":
            insert_at = index + 1
            while insert_at < len(lines) and lines[insert_at].startswith(("\t", " ")):
                insert_at += 1
            lines.insert(insert_at, f"\t{HOST_SAMBA_INCLUDE_LINE}")
            inserted = True
            break
    if not inserted:
        lines.extend(["", "[global]", f"\t{HOST_SAMBA_INCLUDE_LINE}"])
    main_path.write_text("\n".join(lines).rstrip() + "\n")


def read_portal_samba_shares() -> list[dict[str, str]]:
    return parse_samba_shares(read_text(HOST_SAMBA_PORTAL_CONFIG, ""), "portal")


def write_portal_samba_shares(shares: list[dict[str, str]]) -> None:
    lines = ["# Managed by LocalPlane", ""]
    for share in shares:
        lines.append(f"[{share['name']}]")
        lines.append(f"\tpath = {share['path']}")
        lines.append(f"\tread only = {share['read_only'] or 'No'}")
        lines.append(f"\tguest ok = {share['guest_ok'] or 'No'}")
        if share.get("valid_users"):
            lines.append(f"\tvalid users = {share['valid_users']}")
        lines.append("")
    Path(HOST_SAMBA_PORTAL_CONFIG).write_text("\n".join(lines).rstrip() + "\n")


def test_samba_config() -> None:
    code, stdout, stderr = run_command_full(["testparm", "-s", HOST_SAMBA_MAIN_CONFIG])
    if code != 0:
        raise StorageServiceError(
            500,
            {"code": code, "stdout": stdout, "stderr": stderr or "Samba config validation failed"},
        )


def get_samba_users() -> list[dict[str, str]]:
    if not host_command_available("/usr/bin/pdbedit"):
        return []
    code, stdout, _ = run_command_full(host_binary_command("/usr/bin/pdbedit", ["-L"]))
    if code != 0:
        return []
    users: list[dict[str, str]] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        username, _, description = line.partition(":")
        users.append(
            {
                "username": username.strip(),
                "description": description.strip(),
            }
        )
    return users


def get_samba_status() -> dict[str, object]:
    smbd = is_process_running("smbd")
    nmbd = is_process_running("nmbd")
    conf_path = ""
    conf_text = ""
    for candidate in HOST_SAMBA_CONFIG_PATHS:
        conf_text = read_text(candidate, "")
        if conf_text:
            conf_path = candidate
            break

    shares = parse_samba_shares(conf_text, "main")
    portal_shares = read_portal_samba_shares()
    combined_shares = shares + [
        share for share in portal_shares
        if all(existing["name"].lower() != share["name"].lower() for existing in shares)
    ]

    return {
        "running": smbd,
        "nmbd_running": nmbd,
        "config_path": conf_path or "not found",
        "shares": combined_shares,
        "portal_shares": portal_shares,
        "users": get_samba_users(),
        "host_config_writable": Path("/host/etc/samba").exists() and os.access("/host/etc/samba", os.W_OK),
        "smbpasswd_available": command_exists("smbpasswd"),
    }


def control_samba(action: str) -> dict[str, object]:
    if action not in {"start", "stop", "restart"}:
        raise StorageServiceError(400, "Invalid action")
    if command_exists("systemctl"):
        code, stdout, stderr = run_command_full(["systemctl", action, "smbd"])
    elif command_exists("service"):
        code, stdout, stderr = run_command_full(["service", "smbd", action])
    else:
        raise StorageServiceError(500, "No service manager available")
    if code != 0:
        raise StorageServiceError(500, {"code": code, "stdout": stdout, "stderr": stderr})
    return {"ok": True}


def set_samba_user_password(username: str, password: str) -> dict[str, object]:
    if not username or not password:
        raise StorageServiceError(400, "Username and password required")
    if not host_command_available("/usr/bin/smbpasswd"):
        raise StorageServiceError(500, "Host smbpasswd not available")
    code, stdout, stderr = run_command_input(host_binary_command("/usr/bin/smbpasswd", ["-L", "-a", "-s", username]), f"{password}\n{password}\n")
    if code != 0:
        raise StorageServiceError(500, {"code": code, "stdout": stdout, "stderr": stderr})
    return {"ok": True}


def delete_samba_user(username: str) -> dict[str, object]:
    if not username:
        raise StorageServiceError(400, "Username required")
    if not host_command_available("/usr/bin/smbpasswd"):
        raise StorageServiceError(500, "Host smbpasswd not available")
    code, stdout, stderr = run_command_full(host_binary_command("/usr/bin/smbpasswd", ["-L", "-x", username]))
    if code != 0:
        raise StorageServiceError(500, {"code": code, "stdout": stdout, "stderr": stderr})
    return {"ok": True, "username": username}


def set_samba_user_state(username: str, action: str) -> dict[str, object]:
    if not username or action not in {"enable", "disable"}:
        raise StorageServiceError(400, "Username and valid action required")
    if not host_command_available("/usr/bin/smbpasswd"):
        raise StorageServiceError(500, "Host smbpasswd not available")
    flag = "-e" if action == "enable" else "-d"
    code, stdout, stderr = run_command_full(host_binary_command("/usr/bin/smbpasswd", ["-L", flag, username]))
    if code != 0:
        raise StorageServiceError(500, {"code": code, "stdout": stdout, "stderr": stderr})
    return {"ok": True, "username": username, "action": action}


def save_samba_share(payload: dict) -> dict[str, object]:
    name = str(payload.get("name", "")).strip()
    path = str(payload.get("path", "")).strip()
    read_only = str(payload.get("read_only", "No")).strip() or "No"
    guest_ok = str(payload.get("guest_ok", "No")).strip() or "No"
    valid_users = str(payload.get("valid_users", "")).strip()
    if not name or not path:
        raise StorageServiceError(400, "Share name and path are required")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise StorageServiceError(400, "Share name may only contain letters, numbers, dot, dash, and underscore")

    ensure_samba_portal_include()
    shares = read_portal_samba_shares()
    updated = False
    for share in shares:
        if share["name"].lower() == name.lower():
            share.update({"name": name, "path": path, "read_only": read_only, "guest_ok": guest_ok, "valid_users": valid_users, "source": "portal"})
            updated = True
            break
    if not updated:
        shares.append({"name": name, "path": path, "read_only": read_only, "guest_ok": guest_ok, "valid_users": valid_users, "source": "portal"})
    write_portal_samba_shares(shares)
    test_samba_config()
    return {"ok": True, "share": name}


def delete_samba_share(name: str) -> dict[str, object]:
    if not name:
        raise StorageServiceError(400, "Share name is required")
    shares = [share for share in read_portal_samba_shares() if share["name"].lower() != name.lower()]
    write_portal_samba_shares(shares)
    test_samba_config()
    return {"ok": True, "share": name}


def get_printing_status() -> dict[str, object]:
    listeners = parse_service_listeners()
    cups_listener = any("631" in (svc.get("ports") or []) for svc in listeners)
    samba = get_samba_status()
    printer_shares = [share for share in samba.get("shares", []) if share.get("name", "").lower() in {"printers", "print$"}]
    cups_installed = host_command_available("/usr/bin/systemctl")
    cups_enabled = False
    cups_active = is_process_running("cupsd")
    if cups_installed:
        _, enabled_out, enabled_err = run_command_full(host_binary_command("/usr/bin/systemctl", ["is-enabled", "cups"]))
        _, active_out, active_err = run_command_full(host_binary_command("/usr/bin/systemctl", ["is-active", "cups"]))
        if "not-found" in (enabled_out + enabled_err + active_out + active_err):
            cups_installed = False
        else:
            cups_enabled = enabled_out.strip() == "enabled"
            cups_active = active_out.strip() == "active" or cups_active
    return {
        "cups_installed": cups_installed,
        "cups_enabled": cups_enabled,
        "cups_active": cups_active,
        "cups_listener": cups_listener,
        "printer_shares": printer_shares,
    }


def control_printing(action: str) -> dict[str, object]:
    if action not in {"start", "stop", "restart"}:
        raise StorageServiceError(400, "Invalid action")
    if not host_command_available("/usr/bin/systemctl"):
        raise StorageServiceError(500, "Host systemctl not available")
    status = get_printing_status()
    if not status.get("cups_installed"):
        raise StorageServiceError(500, "CUPS is not installed on the device")
    code, stdout, stderr = run_command_full(host_binary_command("/usr/bin/systemctl", [action, "cups"]))
    if code != 0:
        raise StorageServiceError(500, {"code": code, "stdout": stdout, "stderr": stderr})
    return {"ok": True, "action": action}
