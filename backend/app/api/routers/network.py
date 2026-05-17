from fastapi import APIRouter, Body, HTTPException

from app.domain.network.analyzer import network_diagnostics, network_findings
from app.domain.network.interface_configs import (
    interface_config_readiness,
    interface_configs,
    interface_inventory,
    interface_rules_preview,
    reset_interface_config,
    save_interface_config,
)
from app.domain.network.interface_planner import interface_plan_preview
from app.domain.network.policy import preview_route_firewall_reconcile, route_firewall_policy
from app.domain.network.profiles import (
    behavior_bindings,
    interface_behaviors,
    interface_profiles,
    role_bindings,
    save_interface_behavior_assignment,
    save_interface_profile_assignment,
)
from app.domain.network.reconciler import cached_network_reconcile_plan, network_reconcile_plan
from app.domain.network.state import connectivity_test, network_snapshot, network_state


router = APIRouter(prefix="/api/network", tags=["network"])


@router.get("/snapshot")
def snapshot():
    return network_snapshot()


@router.get("/state")
def state():
    return network_state()


@router.post("/connectivity-test")
def connectivity(payload: dict = Body(default={})):
    return connectivity_test(payload)


@router.get("/findings")
def findings():
    return {"findings": network_findings()}


@router.get("/diagnostics")
def diagnostics():
    return network_diagnostics()


@router.get("/interface-profiles")
def profiles():
    # Compatibility alias for older frontend builds. Prefer /interface-behaviors.
    return interface_profiles()


@router.get("/interface-behaviors")
def behaviors():
    return interface_behaviors()


@router.get("/inventory")
def inventory():
    return interface_inventory()


@router.get("/interface-configs")
def configs():
    return interface_configs()


@router.post("/interface-configs/preview")
def configs_preview(payload: dict = Body(default={})):
    return interface_rules_preview(payload)


@router.post("/interface-configs/save")
def configs_save(payload: dict = Body(default={})):
    try:
        return save_interface_config(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/interface-configs/reset")
def configs_reset(payload: dict = Body(default={})):
    try:
        return reset_interface_config(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/interface-configs/readiness")
def configs_readiness():
    return interface_config_readiness()


@router.post("/interface-configs/readiness")
def configs_readiness_with_payload(payload: dict = Body(default={})):
    return interface_config_readiness(payload)


@router.get("/interface-rules/preview")
def rules_preview():
    return interface_rules_preview()


@router.post("/interface-rules/preview")
def rules_preview_with_payload(payload: dict = Body(default={})):
    return interface_rules_preview(payload)


@router.get("/interface-plan/preview")
def plan_preview():
    return interface_plan_preview()


@router.post("/interface-plan/preview")
def plan_preview_with_payload(payload: dict = Body(default={})):
    return interface_plan_preview(payload)


@router.post("/interface-profiles/{interface}")
def save_profile(interface: str, payload: dict = Body(default={})):
    # Compatibility alias for older frontend builds. Prefer /interface-behaviors/{interface}.
    try:
        assignment = save_interface_profile_assignment(interface, str(payload.get("profile", "unassigned")))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    profiles_payload = interface_profiles()
    return {"ok": True, "assignment": assignment, "profiles": profiles_payload}


@router.post("/interface-behaviors/{interface}")
def save_behavior(interface: str, payload: dict = Body(default={})):
    behavior = str(payload.get("behavior", payload.get("profile", "unassigned")))
    try:
        assignment = save_interface_behavior_assignment(interface, behavior)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    profiles_payload = interface_behaviors()
    return {"ok": True, "assignment": assignment, "behaviors": profiles_payload}


@router.get("/role-bindings")
def get_role_bindings():
    # Compatibility alias for older frontend builds. Prefer /behavior-bindings.
    return role_bindings()


@router.get("/behavior-bindings")
def get_behavior_bindings():
    return behavior_bindings()


@router.post("/role-bindings")
def save_role_binding(payload: dict = Body(default={})):
    # Compatibility alias for older frontend builds. Prefer /behavior-bindings.
    interface = str(payload.get("interface", "")).strip()
    profile = str(payload.get("profile", "unassigned")).strip()
    if not interface:
        raise HTTPException(status_code=400, detail="Interface is required")
    try:
        assignment = save_interface_profile_assignment(interface, profile)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "assignment": assignment, "role_bindings": role_bindings()}


@router.post("/behavior-bindings")
def save_behavior_binding(payload: dict = Body(default={})):
    interface = str(payload.get("interface", "")).strip()
    behavior = str(payload.get("behavior", payload.get("profile", "unassigned"))).strip()
    if not interface:
        raise HTTPException(status_code=400, detail="Interface is required")
    try:
        assignment = save_interface_behavior_assignment(interface, behavior)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "assignment": assignment, "behavior_bindings": behavior_bindings()}


@router.delete("/role-bindings/{interface}")
def delete_role_binding(interface: str):
    # Compatibility alias for older frontend builds. Prefer /behavior-bindings/{interface}.
    try:
        assignment = save_interface_profile_assignment(interface, "unassigned")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "assignment": assignment, "role_bindings": role_bindings()}


@router.delete("/behavior-bindings/{interface}")
def delete_behavior_binding(interface: str):
    try:
        assignment = save_interface_behavior_assignment(interface, "unassigned")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "assignment": assignment, "behavior_bindings": behavior_bindings()}


@router.get("/route-firewall-policy")
def policy():
    return route_firewall_policy()


@router.post("/route-firewall-policy/preview")
def policy_preview(payload: dict = Body(default={})):
    return preview_route_firewall_reconcile(payload)


@router.get("/reconcile/preview")
def reconcile_preview():
    return cached_network_reconcile_plan()


@router.post("/reconcile/preview")
def reconcile_preview_with_payload(payload: dict = Body(default={})):
    return network_reconcile_plan(payload)
