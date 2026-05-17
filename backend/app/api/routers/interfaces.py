from fastapi import APIRouter

from app.domain.network.state import current_interfaces


router = APIRouter(tags=["network"])


@router.get("/api/interfaces")
def interfaces():
    return current_interfaces()
