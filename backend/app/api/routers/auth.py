import secrets
import time

from fastapi import APIRouter, Body, HTTPException, Request, Response

from app.core.auth import (
    PANEL_AUTH_COOKIE,
    PANEL_SESSION_LOCK,
    PANEL_SESSION_TTL_SECONDS,
    PANEL_SESSIONS,
    authenticated_username,
    load_panel_auth_config,
    load_panel_sessions,
    save_panel_auth_config,
    save_panel_sessions,
    verify_panel_password,
)
from app.core.events import EventLog


router = APIRouter(prefix="/api/auth", tags=["auth"])
event_log = EventLog()


@router.get("/status")
def auth_status(request: Request):
    username = authenticated_username(request)
    return {"authenticated": bool(username), "username": username}


@router.post("/login")
def auth_login(response: Response, payload: dict = Body(...)):
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()
    config = load_panel_auth_config()
    if not (
        secrets.compare_digest(username, config["username"])
        and verify_panel_password(password, config)
    ):
        event_log.append(
            source="auth",
            action="login_failed",
            level="warn",
            message="Panel login failed",
            details={"username": username or "unknown"},
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = secrets.token_urlsafe(32)
    with PANEL_SESSION_LOCK:
        if not PANEL_SESSIONS:
            PANEL_SESSIONS.update(load_panel_sessions())
        PANEL_SESSIONS[token] = time.time() + PANEL_SESSION_TTL_SECONDS
        save_panel_sessions()
    response.set_cookie(
        PANEL_AUTH_COOKIE,
        token,
        max_age=PANEL_SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
    )
    event_log.append(
        source="auth",
        action="login",
        message="Panel login succeeded",
        details={"username": config["username"]},
    )
    return {"ok": True, "username": config["username"]}


@router.post("/logout")
def auth_logout(request: Request, response: Response):
    token = request.cookies.get(PANEL_AUTH_COOKIE, "")
    if token:
        with PANEL_SESSION_LOCK:
            if not PANEL_SESSIONS:
                PANEL_SESSIONS.update(load_panel_sessions())
            PANEL_SESSIONS.pop(token, None)
            save_panel_sessions()
    response.delete_cookie(PANEL_AUTH_COOKIE)
    event_log.append(source="auth", action="logout", message="Panel session ended")
    return {"ok": True}


@router.post("/credentials")
def auth_credentials(request: Request, payload: dict = Body(...)):
    current_username = authenticated_username(request)
    if not current_username:
        raise HTTPException(status_code=401, detail="Authentication required")

    config = load_panel_auth_config()
    current_password = str(payload.get("current_password", ""))
    if not verify_panel_password(current_password, config):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    username = str(payload.get("username", config["username"])).strip()
    new_password = str(payload.get("new_password", ""))
    if not username:
        raise HTTPException(status_code=400, detail="Username cannot be empty")
    password = new_password or current_password
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    save_panel_auth_config(username, password)
    token = request.cookies.get(PANEL_AUTH_COOKIE, "")
    with PANEL_SESSION_LOCK:
        if not PANEL_SESSIONS:
            PANEL_SESSIONS.update(load_panel_sessions())
        expires_at = PANEL_SESSIONS.get(token, time.time() + PANEL_SESSION_TTL_SECONDS)
        PANEL_SESSIONS.clear()
        if token:
            PANEL_SESSIONS[token] = expires_at
        save_panel_sessions()
    event_log.append(
        source="auth",
        action="credentials_update",
        message="Panel credentials updated",
        details={"username": username},
    )
    return {"ok": True, "username": username}
