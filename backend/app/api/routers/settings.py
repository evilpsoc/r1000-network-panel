from fastapi import APIRouter, Body

from app.core.settings import CORE_TABS, KNOWN_TABS, OPTIONAL_TABS, panel_settings, update_panel_settings


router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
def get_settings():
    return {
        "settings": panel_settings(),
        "tabs": {
            "core": list(CORE_TABS),
            "optional": list(OPTIONAL_TABS),
            "known": list(KNOWN_TABS),
        },
    }


@router.post("")
def save_settings(payload: dict = Body(default={})):
    return {
        "ok": True,
        "settings": update_panel_settings(payload),
    }
