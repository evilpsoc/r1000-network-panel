import hashlib
import json
import os
from pathlib import Path
import secrets
import threading
import time

from fastapi import Request
from fastapi.responses import JSONResponse


PANEL_AUTH_COOKIE = "network_panel_session"
PANEL_SESSION_TTL_SECONDS = int(os.getenv("PANEL_SESSION_TTL_SECONDS", "86400") or "86400")
PANEL_USERNAME = os.getenv("PANEL_USERNAME", "admin")
PANEL_PASSWORD = os.getenv("PANEL_PASSWORD", "")
PANEL_SESSIONS: dict[str, float] = {}
AUTH_OPEN_PATHS = {"/", "/favicon.ico", "/api/health", "/api/auth/status", "/api/auth/login", "/api/auth/logout"}
PANEL_SESSION_PATH = "/app/data/panel-sessions.json"
PANEL_AUTH_CONFIG_PATH = "/app/data/panel-auth.json"
PANEL_SESSION_LOCK = threading.Lock()


def load_panel_sessions() -> dict[str, float]:
    path = Path(PANEL_SESSION_PATH)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    now = time.time()
    sessions: dict[str, float] = {}
    for token, expires_at in data.items():
        try:
            expires = float(expires_at)
        except (TypeError, ValueError):
            continue
        if isinstance(token, str) and token and expires > now:
            sessions[token] = expires
    return sessions


def save_panel_sessions() -> None:
    now = time.time()
    active_sessions = {
        token: expires_at
        for token, expires_at in PANEL_SESSIONS.items()
        if token and expires_at > now
    }
    PANEL_SESSIONS.clear()
    PANEL_SESSIONS.update(active_sessions)
    path = Path(PANEL_SESSION_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(active_sessions, indent=2))


def password_hash(password: str, salt: str | None = None) -> dict[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000)
    return {"salt": salt, "hash": digest.hex()}


def load_panel_auth_config() -> dict[str, str]:
    path = Path(PANEL_AUTH_CONFIG_PATH)
    if path.exists():
        try:
            data = json.loads(path.read_text())
            if isinstance(data, dict) and data.get("username") and data.get("password_hash") and data.get("password_salt"):
                return {
                    "username": str(data["username"]),
                    "password_hash": str(data["password_hash"]),
                    "password_salt": str(data["password_salt"]),
                }
        except Exception:
            pass
    if not PANEL_PASSWORD:
        raise RuntimeError("PANEL_PASSWORD must be set before first startup")
    hashed = password_hash(PANEL_PASSWORD)
    return {"username": PANEL_USERNAME, "password_hash": hashed["hash"], "password_salt": hashed["salt"]}


def save_panel_auth_config(username: str, password: str) -> dict[str, str]:
    username = username.strip()
    hashed = password_hash(password)
    data = {"username": username, "password_hash": hashed["hash"], "password_salt": hashed["salt"]}
    path = Path(PANEL_AUTH_CONFIG_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
    return data


def verify_panel_password(password: str, config: dict[str, str]) -> bool:
    expected = config.get("password_hash", "")
    salt = config.get("password_salt", "")
    if not expected or not salt:
        return False
    candidate = password_hash(password, salt)["hash"]
    return secrets.compare_digest(candidate, expected)


def authenticated_username(request: Request) -> str:
    token = request.cookies.get(PANEL_AUTH_COOKIE, "")
    with PANEL_SESSION_LOCK:
        if not PANEL_SESSIONS:
            PANEL_SESSIONS.update(load_panel_sessions())
        expires_at = PANEL_SESSIONS.get(token, 0.0)
        if token and expires_at > time.time():
            return load_panel_auth_config()["username"]
        if token:
            PANEL_SESSIONS.pop(token, None)
            save_panel_sessions()
    return ""


async def require_panel_auth(request: Request, call_next):
    path = request.url.path
    if path in AUTH_OPEN_PATHS or path.startswith("/assets/"):
        return await call_next(request)
    if authenticated_username(request):
        return await call_next(request)
    return JSONResponse({"detail": "Authentication required"}, status_code=401)
