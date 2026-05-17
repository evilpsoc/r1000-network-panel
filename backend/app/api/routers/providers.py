from fastapi import APIRouter, HTTPException

from app.core.events import EventLog
from app.core.providers import detect_device_profile, get_capabilities, get_provider_statuses


router = APIRouter(prefix="/api", tags=["providers"])
event_log = EventLog()


@router.get("/providers")
def providers():
    return {
        "device_profile": detect_device_profile(),
        "providers": get_provider_statuses(),
    }


@router.get("/capabilities")
def capabilities():
    return get_capabilities()


@router.get("/providers/{provider_id}/requirements")
def provider_requirements(provider_id: str):
    for provider in get_provider_statuses():
        if provider["id"] == provider_id:
            return provider
    raise HTTPException(status_code=404, detail="Provider not found")


@router.post("/providers/{provider_id}/rescan")
def provider_rescan(provider_id: str):
    provider = provider_requirements(provider_id)
    event_log.append(
        source="providers",
        action="rescan",
        message=f"Provider rescan requested for {provider_id}",
        details={"provider_id": provider_id, "state": provider.get("state", "unknown")},
    )
    return provider
