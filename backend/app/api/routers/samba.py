from fastapi import APIRouter, Body, HTTPException

from app.domain.storage.samba import (
    StorageServiceError,
    control_printing,
    control_samba,
    delete_samba_share,
    delete_samba_user,
    get_printing_status,
    get_samba_status,
    save_samba_share,
    set_samba_user_password,
    set_samba_user_state,
)

router = APIRouter(tags=["storage"])


def raise_storage_error(exc: StorageServiceError):
    raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@router.get("/api/samba/status")
def samba_status():
    return get_samba_status()


@router.post("/api/samba/control")
def samba_control(payload: dict = Body(...)):
    try:
        return control_samba(str(payload.get("action", "")).strip().lower())
    except StorageServiceError as exc:
        raise_storage_error(exc)


@router.post("/api/samba/user/password")
def samba_user_password(payload: dict = Body(...)):
    try:
        return set_samba_user_password(
            str(payload.get("username", "")).strip(),
            str(payload.get("password", "")).strip(),
        )
    except StorageServiceError as exc:
        raise_storage_error(exc)


@router.post("/api/samba/user/delete")
def samba_user_delete(payload: dict = Body(...)):
    try:
        return delete_samba_user(str(payload.get("username", "")).strip())
    except StorageServiceError as exc:
        raise_storage_error(exc)


@router.post("/api/samba/user/state")
def samba_user_state(payload: dict = Body(...)):
    try:
        return set_samba_user_state(
            str(payload.get("username", "")).strip(),
            str(payload.get("action", "")).strip().lower(),
        )
    except StorageServiceError as exc:
        raise_storage_error(exc)


@router.post("/api/samba/share")
def samba_share_save(payload: dict = Body(...)):
    try:
        return save_samba_share(payload)
    except StorageServiceError as exc:
        raise_storage_error(exc)


@router.post("/api/samba/share/delete")
def samba_share_delete(payload: dict = Body(...)):
    try:
        return delete_samba_share(str(payload.get("name", "")).strip())
    except StorageServiceError as exc:
        raise_storage_error(exc)


@router.get("/api/printing/status")
def printing_status():
    return get_printing_status()


@router.post("/api/printing/control")
def printing_control(payload: dict = Body(...)):
    try:
        return control_printing(str(payload.get("action", "")).strip().lower())
    except StorageServiceError as exc:
        raise_storage_error(exc)
