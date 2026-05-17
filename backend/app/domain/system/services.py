import json
import subprocess
import time
from pathlib import Path

from app.core.host import run_command
from app.core.providers import docker_service_names
from app.domain.system.status import get_docker_brief_status


SERVICE_REGISTRY_PATH = Path("/app/data/service-registry.json")


def is_process_running(name: str) -> bool:
    result = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True)
    return result.returncode == 0


def parse_service_listeners() -> list[dict[str, object]]:
    output = run_command(["ss", "-H", "-ltnup"])
    if not output:
        return []

    port_names = {
        "22": "SSH",
        "53": "DNS",
        "67": "DHCP",
        "80": "HTTP",
        "137": "NetBIOS",
        "138": "NetBIOS Datagram",
        "139": "Samba",
        "445": "Samba",
        "3000": "Grafana",
        "7575": "VirtualHere",
        "8080": "LocalPlane",
        "8081": "Pi-hole",
        "9000": "Portainer",
        "9090": "Cockpit",
        "9091": "Prometheus",
        "9100": "Node Exporter",
        "9443": "Portainer HTTPS",
        "41641": "Tailscale",
    }

    services: dict[tuple[str, str], dict[str, object]] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue

        proto = parts[0]
        local = parts[4]
        if local.startswith("["):
            host_part, _, port = local.rpartition(":")
            host = host_part.strip("[]")
        else:
            host, _, port = local.rpartition(":")

        if not port:
            continue

        name = port_names.get(port, f"Port {port}")
        key = (name, proto)
        service = services.setdefault(
            key,
            {"name": name, "type": "listener", "active": True, "ports": set(), "binds": set()},
        )
        service["ports"].add(f"{proto}/{port}")
        service["binds"].add(host or "*")

    result = []
    for service in sorted(services.values(), key=lambda item: item["name"]):
        result.append(
            {
                "name": service["name"],
                "type": service["type"],
                "active": service["active"],
                "ports": sorted(service["ports"]),
                "binds": sorted(service["binds"]),
            }
        )

    return result


def service_inventory() -> list[dict[str, object]]:
    docker_name_map = {
        "pihole": "Pi-hole",
        "grafana": "Grafana",
        "prometheus": "Prometheus",
        "portainer": "Portainer",
        "node-exporter": "Node Exporter",
        "netalertx": "NetAlertX",
        "network-panel-backend": "LocalPlane",
        "nodus-backend": "LocalPlane",
        "localplane-backend": "LocalPlane",
    }
    docker_services = {docker_name_map.get(name.lower(), name) for name in docker_service_names()}
    process_services = [
        {"name": "NetworkManager", "type": "host", "active": is_process_running("NetworkManager"), "source": "system"},
        {"name": "ModemManager", "type": "host", "active": is_process_running("ModemManager"), "source": "system"},
        {"name": "tailscaled", "type": "host", "active": is_process_running("tailscaled"), "source": "system"},
        {"name": "smbd", "type": "host", "active": is_process_running("smbd"), "source": "system"},
    ]

    combined: dict[str, dict[str, object]] = {
        service["name"]: service for service in process_services if service["active"]
    }
    for service in parse_service_listeners():
        service["source"] = "docker" if service["name"] in docker_services else "system"
        combined[service["name"]] = service

    current = sorted(combined.values(), key=lambda item: str(item["name"]))
    return update_service_registry(current)


def service_category(service: dict[str, object]) -> str:
    if service.get("registry_state") == "missing":
        return "missing"
    if service.get("source") == "docker":
        return "docker_listener"
    if service.get("type") == "host":
        return "host_service"
    return "listener"


def service_capabilities(service: dict[str, object]) -> list[str]:
    ports = {str(port).split("/")[-1] for port in service.get("ports", []) or []}
    capabilities: list[str] = []
    if ports & {"80", "8080", "8081", "9000", "9090", "9091", "3000", "9443", "9100", "7575"}:
        capabilities.append("open_web")
    if service.get("source") == "docker":
        capabilities.append("docker_managed")
    if service.get("source") == "system":
        capabilities.append("host_managed")
    if service.get("registry_state") == "missing":
        capabilities.append("previously_seen")
    return capabilities


def service_actions(service: dict[str, object]) -> list[dict[str, object]]:
    capabilities = set(service_capabilities(service))
    missing = service.get("registry_state") == "missing"
    return [
        {
            "id": "open",
            "label": "Open",
            "enabled": "open_web" in capabilities and not missing,
            "reason": "Known web listener" if "open_web" in capabilities and not missing else "No known web endpoint",
        },
        {
            "id": "inspect",
            "label": "Inspect",
            "enabled": True,
            "reason": "Inventory details are available",
        },
        {
            "id": "logs",
            "label": "Logs",
            "enabled": False,
            "reason": "A safe per-service log provider is not wired yet",
        },
        {
            "id": "restart",
            "label": "Restart",
            "enabled": False,
            "reason": "Restart needs service-specific preview, confirmation and rollback notes first",
        },
    ]


def service_inventory_model() -> dict[str, object]:
    services = service_inventory()
    docker = get_docker_brief_status()
    groups = {
        "listeners": [],
        "docker_listeners": [],
        "host_services": [],
        "missing": [],
        "containers": docker.get("containers", []) if isinstance(docker, dict) else [],
    }

    enriched = []
    for service in services:
        item = {
            **service,
            "category": service_category(service),
            "capabilities": service_capabilities(service),
        }
        item["actions"] = service_actions(item)
        enriched.append(item)
        if item["category"] == "missing":
            groups["missing"].append(item)
        elif item["category"] == "docker_listener":
            groups["docker_listeners"].append(item)
        elif item["category"] == "host_service":
            groups["host_services"].append(item)
        else:
            groups["listeners"].append(item)

    return {
        "summary": {
            "services": len(enriched),
            "present": len([item for item in enriched if item.get("registry_state") != "missing"]),
            "missing": len(groups["missing"]),
            "listeners": len(groups["listeners"]) + len(groups["docker_listeners"]),
            "host_services": len(groups["host_services"]),
            "containers": len(groups["containers"]),
            "docker_available": bool(docker.get("available")) if isinstance(docker, dict) else False,
        },
        "groups": groups,
        "services": enriched,
        "model": {
            "source": "ss + process checks + docker ps + retained registry",
            "read_only": True,
            "notes": [
                "This endpoint is a generic LocalPlane service inventory surface.",
                "It does not start, stop, update or deploy services.",
                "Missing services are retained from the local registry so previous exposure does not disappear silently.",
            ],
        },
    }


def service_registry() -> dict[str, dict[str, object]]:
    if not SERVICE_REGISTRY_PATH.exists():
        return {}
    try:
        data = json.loads(SERVICE_REGISTRY_PATH.read_text())
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def prune_missing_service_registry() -> dict[str, object]:
    registry = service_registry()
    kept: dict[str, dict[str, object]] = {}
    removed: list[dict[str, object]] = []

    for key, service in registry.items():
        if not isinstance(service, dict):
            continue
        if service.get("registry_state") == "missing":
            removed.append(
                {
                    "registry_key": key,
                    "name": service.get("name", ""),
                    "source": service.get("source", ""),
                    "ports": service.get("ports", []),
                    "last_seen_at": service.get("last_seen_at", 0),
                    "last_missing_at": service.get("last_missing_at", 0),
                }
            )
            continue
        kept[key] = service

    try:
        SERVICE_REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
        SERVICE_REGISTRY_PATH.write_text(json.dumps(kept, indent=2))
    except Exception:
        return {"ok": False, "deleted": 0, "removed": [], "error": "failed to write service registry"}

    return {"ok": True, "deleted": len(removed), "removed": removed}


def service_registry_key(service: dict[str, object]) -> str:
    name = str(service.get("name", "") or "unknown")
    source = str(service.get("source", "") or service.get("type", "") or "system")
    ports = ",".join(str(port) for port in service.get("ports", []) or [])
    return f"{source}:{name}:{ports or 'no-port'}"


def update_service_registry(current: list[dict[str, object]]) -> list[dict[str, object]]:
    now = int(time.time())
    registry = service_registry()
    seen_keys = set()

    for service in current:
        key = service_registry_key(service)
        seen_keys.add(key)
        previous = registry.get(key, {}) if isinstance(registry.get(key, {}), dict) else {}
        service["registry_key"] = key
        service["first_seen_at"] = previous.get("first_seen_at", now)
        service["last_seen_at"] = now
        service["registry_state"] = "present"
        registry[key] = {
            **previous,
            **service,
            "first_seen_at": service["first_seen_at"],
            "last_seen_at": now,
            "last_missing_at": previous.get("last_missing_at", 0),
            "active": bool(service.get("active")),
            "registry_state": "present",
        }

    retained: list[dict[str, object]] = []
    for key, service in list(registry.items()):
        if key in seen_keys:
            continue
        if not isinstance(service, dict):
            registry.pop(key, None)
            continue
        service["active"] = False
        service["registry_state"] = "missing"
        service["last_missing_at"] = now
        service.setdefault("last_seen_at", 0)
        registry[key] = service
        retained.append(service)

    try:
        SERVICE_REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
        SERVICE_REGISTRY_PATH.write_text(json.dumps(registry, indent=2))
    except Exception:
        pass

    return sorted(current + retained, key=lambda item: (str(item.get("registry_state", "present")), str(item.get("name", ""))))
