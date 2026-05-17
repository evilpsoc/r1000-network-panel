# Operator Guide

## First Run

1. Copy the environment template:

   ```sh
   cp .env.example .env
   ```

2. Set a real panel password in `.env`:

   ```txt
   PANEL_PASSWORD=change-this
   ```

3. Start the backend:

   ```sh
   docker compose up -d --build backend
   ```

4. Open the panel and sign in.

## Setup Flow Target

The current app uses environment/runtime files directly. A future setup wizard
should turn first boot into a guided flow:

- confirm hostname and device profile
- choose which tabs are visible
- confirm management access path
- detect NetworkManager, nftables, ModemManager, Docker and Tailscale
- choose primary uplink preference
- set the first panel password
- save a runtime config snapshot

The wizard should not apply risky network changes automatically. It should
produce a proposed configuration and ask for confirmation.

## Day-to-Day Use

- Dashboard: quick health, uplinks, local clients, containers and sessions.
- Network: discovered interfaces, desired behavior previews and policy intent.
- Wireless: Wi-Fi client/hotspot state and safe apply previews.
- Cellular: LTE/5G modem state, APN profile and guarded AT commands.
- Routing / Firewall: read-only exposure and reconcile preview.
- Runtime: host capability/dependency view.
- Logs and Actions: command history and operational trail.

## Manual Health Checks

```sh
docker compose ps
docker compose logs --tail=80 backend
docker stats --no-stream localplane-backend
```

Networking checks:

```sh
ip route show default
ip -6 route show default
nmcli device status
nft list ruleset
resolvectl status
```
