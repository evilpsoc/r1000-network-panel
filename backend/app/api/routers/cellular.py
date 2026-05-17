from fastapi import APIRouter, Body

from app.core.runtime_config import update_lte_config
from app.domain.lte.apn import (
    LTE_AUTO_APN,
    LTE_SIM_OVERRIDES,
    apn_catalog,
    apply_lte_apn,
    build_apn_preview,
    lte_apn_suggestion,
    lte_profile_status,
    lte_status,
    run_at_command,
)


router = APIRouter(tags=["cellular"])


def _set_auto_apn(enabled: bool, save_config):
    LTE_AUTO_APN["enabled"] = enabled
    save_config()
    return {"ok": True, "enabled": LTE_AUTO_APN["enabled"]}


def save_cellular_runtime_config() -> None:
    update_lte_config(bool(LTE_AUTO_APN["enabled"]), LTE_SIM_OVERRIDES)


@router.get("/api/cellular")
@router.get("/api/lte")
def status():
    return lte_status()


@router.get("/api/cellular/profile")
@router.get("/api/lte/profile")
def profile():
    return lte_profile_status()


@router.get("/api/cellular/apn/options")
@router.get("/api/lte/apn/options")
def apn_options():
    return apn_catalog()


@router.get("/api/cellular/apn/catalog")
@router.get("/api/lte/apn/catalog")
def catalog():
    return apn_catalog()


@router.get("/api/cellular/apn/suggest")
@router.get("/api/lte/apn/suggest")
def apn_suggest():
    return lte_apn_suggestion()


@router.get("/api/cellular/apn/auto")
@router.get("/api/lte/apn/auto")
def apn_auto_status():
    return {"enabled": LTE_AUTO_APN["enabled"]}


@router.post("/api/cellular/apn/auto")
@router.post("/api/lte/apn/auto")
def apn_auto_update(payload: dict = Body(...)):
    enabled = str(payload.get("enabled", "")).strip().lower() in {"1", "true", "yes", "on"}
    return _set_auto_apn(enabled, save_cellular_runtime_config)


@router.post("/api/cellular/apn/apply")
@router.post("/api/lte/apn/apply")
def apn_apply(payload: dict = Body(...)):
    return apply_lte_apn(payload, save_cellular_runtime_config)


@router.post("/api/cellular/apn/preview")
@router.post("/api/lte/apn/preview")
def apn_preview(payload: dict = Body(default={})):
    return {"ok": True, "commands": build_apn_preview(payload)}


@router.get("/api/cellular/at/examples")
@router.get("/api/lte/at/examples")
def at_examples():
    return {
        "disclaimer": "AT commands can drop the modem connection or change persistent modem state. Use carefully.",
        "commands": [
            "ATI",
            "AT+CSQ",
            'AT+QENG="servingcell"',
            "AT+COPS?",
            "AT+CGDCONT?",
        ],
    }


@router.post("/api/cellular/at")
@router.post("/api/lte/at")
def at_command(payload: dict = Body(...)):
    return run_at_command(str(payload.get("command", "")))
