# Network Panel

A self-hosted, containerized network management portal built for the reComputer R1035-10 running Ubuntu Server on NVMe SSD.

This project is designed as a lightweight edge infrastructure node for field-service and homelab use cases, with a focus on LTE-aware connectivity, remote access, service network control, and local infrastructure observability.

## Overview

Network Panel provides centralized management for a small, portable infrastructure environment where network availability, bandwidth efficiency, and remote maintainability are critical.

It is especially useful in scenarios where:
- internet connectivity is provided over LTE
- service ports or isolated LAN segments require controlled internet access
- remote administration must be simple and secure
- observability and local service management are needed on low-power hardware

## Key Capabilities

- LTE-aware network operation for constrained uplinks
- Tailscale-based secure remote access
- Selective internet enable/disable controls for service LAN interfaces
- Containerized service deployment with Docker / Docker Compose
- Integrated monitoring and infrastructure visibility
- Web-based management approach for operational simplicity
- Designed for both field deployment and homelab infrastructure use

## Technology Stack

- Ubuntu Server
- Docker / Docker Compose
- Python backend
- Custom frontend
- Tailscale
- Cockpit
- Grafana
- Prometheus
- Node Exporter
- Pi-hole
- Samba
- VirtualHere

## Architecture Goals

The platform is being developed with the following goals:

- lightweight deployment on compact hardware
- easy recovery and maintainability
- modular self-hosted service integration
- controlled routing and internet access for isolated interfaces
- future-ready IPv6 support
- practical usability for real-world troubleshooting and edge operations

## Current Development

Work in progress includes:

- IPv6 routing support
- extended network control capabilities
- APN and LTE management from the web UI
- hotspot / LAN role switching
- improved service orchestration and automation

## Service LAN Configuration

The backend includes built-in Service LAN internet control scripts and supports configuration through `docker-compose.yml` environment variables:

- `SERVICE_LAN_INTERFACE`
- `SERVICE_LAN_IPV4_GATEWAY`
- `SERVICE_LAN_IPV4_SUBNET`
- `SERVICE_LAN_DHCP_RANGE`
- `SERVICE_LAN_IPV6_GATEWAY`
- `SERVICE_LAN_IPV6_PREFIX`
- `SERVICE_LAN_ENABLE_IPV4`
- `SERVICE_LAN_ENABLE_IPV6`

When IPv6 is enabled, the container applies IPv6 forwarding and an `nftables` `ip6` masquerade rule for the configured Service LAN prefix in addition to the existing IPv4 NAT behavior.

## Planned Improvements

- role-based service control
- better UI/UX for network operations
- logging and alerting improvements
- backup/restore workflow
- deployment profiles for field and homelab modes

## Why This Project Matters

This project reflects practical hands-on work in:

- Linux system administration
- containerized infrastructure
- network segmentation and routing
- remote access design
- observability stack integration
- edge device operational planning

It is also part of my broader transition toward Infrastructure, System Administration, and DevOps-oriented roles.