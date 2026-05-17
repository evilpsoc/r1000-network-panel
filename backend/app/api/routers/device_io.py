from fastapi import APIRouter, Body, HTTPException

from app.domain.device_io.status import DeviceIoError, get_device_io_status, update_led

router = APIRouter(tags=["device-io"])


@router.get("/api/device-io")
def device_io_status():
    return get_device_io_status()


@router.post("/api/device-io/led")
def update_device_led(payload: dict = Body(...)):
    try:
        return update_led(payload)
    except DeviceIoError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
