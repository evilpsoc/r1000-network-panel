from fastapi import APIRouter

from app.domain.system.sessions import get_active_sessions

router = APIRouter(tags=["system"])


@router.get("/api/active-sessions")
def active_sessions():
    return get_active_sessions()
