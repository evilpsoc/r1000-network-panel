from fastapi import APIRouter, Body, Query

from app.core.backups import create_backup, list_backups, network_profile_export_plan


router = APIRouter(prefix="/api/backups", tags=["backups"])


@router.get("")
def backups(limit: int = Query(50, ge=1, le=200)):
    return {"backups": list_backups(limit)}


@router.post("")
def create(payload: dict = Body(default={})):
    label = str(payload.get("label", "manual")).strip() or "manual"
    include_host_snapshots = payload.get("include_host_snapshots", True)
    return {"ok": True, "backup": create_backup(label, bool(include_host_snapshots))}


@router.get("/network-profile-export-plan")
def profile_export_plan():
    return {"commands": network_profile_export_plan()}
