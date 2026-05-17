from fastapi import APIRouter

from app.core.events import EventLog
from app.domain.system.overview import overview as system_overview
from app.domain.system.overview import system_stats as system_status
from app.domain.system.power import poweroff_host, restart_host
from app.domain.system.services import prune_missing_service_registry, service_inventory, service_inventory_model


router = APIRouter(tags=["system"])
event_log = EventLog()


@router.get("/api/overview")
def overview():
    return system_overview()


@router.get("/api/system/stats")
def stats():
    return system_status()


@router.get("/api/services")
def services():
    return service_inventory()


@router.get("/api/services/inventory")
def services_inventory():
    return service_inventory_model()


@router.delete("/api/services/registry/missing")
def services_registry_missing_delete():
    result = prune_missing_service_registry()
    event_log.append(
        source="services",
        action="prune-missing-registry",
        level="info" if result.get("ok") else "error",
        message="Missing service registry entries pruned",
        details={"deleted": result.get("deleted", 0), "ok": result.get("ok", False)},
    )
    return result


@router.post("/api/system/restart")
def restart():
    return restart_host()


@router.post("/api/system/poweroff")
def poweroff():
    return poweroff_host()
