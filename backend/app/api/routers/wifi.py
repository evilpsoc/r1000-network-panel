from fastapi import APIRouter

from app.domain.network.objects import network_objects_by_kind


router = APIRouter(tags=["wifi"])


@router.get("/api/wifi/radios")
def radios():
    return network_objects_by_kind("wifi")
