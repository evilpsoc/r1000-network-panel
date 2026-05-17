from fastapi import APIRouter, Query

from app.core.events import EventLog


router = APIRouter(prefix="/api", tags=["events"])
event_log = EventLog()


@router.get("/events")
def events(
    limit: int = Query(100, ge=1, le=500),
    level: str = "",
    source: str = "",
):
    return {"events": event_log.filter(limit=limit, level=level, source=source)}


@router.delete("/events")
def delete_events(level: str = "", source: str = ""):
    deleted = event_log.delete(level=level, source=source)
    event_log.append(
        source="events",
        action="delete",
        level="warn",
        message="Event log entries deleted",
        details={"deleted": deleted, "filter_level": level, "filter_source": source},
    )
    return {"ok": True, "deleted": deleted}
