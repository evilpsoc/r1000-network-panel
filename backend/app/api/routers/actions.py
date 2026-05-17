from fastapi import APIRouter, Body, HTTPException, Query

from app.core.actions import action_history, execute_action, list_actions, preview_action


router = APIRouter(prefix="/api/actions", tags=["actions"])


@router.get("")
def actions():
    return {"actions": list_actions()}


@router.post("/preview")
def preview(payload: dict = Body(...)):
    action_id = str(payload.get("action", "")).strip()
    try:
        return preview_action(action_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/execute")
def execute(payload: dict = Body(...)):
    action_id = str(payload.get("action", "")).strip()
    try:
        return execute_action(action_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/history")
def history(limit: int = Query(100, ge=1, le=500)):
    return {"events": action_history(limit)}
