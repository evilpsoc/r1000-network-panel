from fastapi import APIRouter

from app.domain.storage.status import get_filesystem_status


router = APIRouter(tags=["storage"])


@router.get("/api/filesystem")
def filesystem_status():
    return get_filesystem_status()
