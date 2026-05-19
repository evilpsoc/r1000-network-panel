# Development Backlog

## Setup Wizard

Build a first-run wizard:

- detect host capabilities
- choose visible tabs
- confirm management/tunnel access
- choose primary uplink preference
- set admin credentials
- save runtime config
- show warnings before any network apply

## Settings Model

Add a central settings page/model:

- visible tabs
- refresh intervals
- cookie/security flags
- provider paths
- device profile
- backup settings
- network safety defaults

## Flexible Hardware / Discovered Interfaces

- Treat every discovered NIC/radio/modem as an inventory item, not as a fixed
  hardcoded slot.
- Store interface assignments by stable identity when possible:
  MAC address, sysfs bus path, modem ID/SIM identity or NetworkManager UUID.
- Keep kernel names visible, but do not make them the only source of truth.
- Support attachable hardware without special-casing every device path:
  Ethernet adapters, Wi-Fi radios and LTE/5G modems should appear in inventory
  whether they are onboard, USB, PCIe or exposed through another Linux driver.
- Let compatible discovered devices become client networks, wired uplinks,
  Wi-Fi uplinks, Wi-Fi hotspots, cellular uplinks or observe-only interfaces.
- Give Wi-Fi and Cellular the same pattern as LAN: discovered device first,
  selected behavior second, settings surface third.
- Add readiness diagnostics for every assignable interface so the UI can explain
  why a role cannot be applied yet: unsupported mode, missing provider, blocked
  rfkill, NetworkManager unavailable, ModemManager missing, firmware/channel
  rejection, no SIM, no APN match, no carrier, no default route or DNS failure.
- Show a settings surface only after the operator chooses compatible behavior.
- Never auto-apply behavior to a newly attached device; suggest, preview, then
  apply.

## Actions and Backups

Before hard apply flows:

- standard action model: preview, execute, verify, rollback
- backup helper for config/state files
- action history with status, command, stdout/stderr summary and duration
- "restore backup" flow for runtime config and selected host config files

## Local NOC Assistant

This can become an optional later layer once the deterministic control plane is
solid. The useful version is not a chatbot that runs commands freely. It should
act like a local NOC assistant:

- read inventory, events, findings, action history and provider status
- explain incidents in plain language
- propose preview-only fixes with evidence
- require operator confirmation before any apply path
- keep a full audit trail of prompts, context, proposed plan and executed
  action IDs
- degrade gracefully on 8 GB edge devices by using small/local models only for
  summaries, or remote models only when explicitly configured

The deterministic planner/reconciler remains the authority. Any assistant layer
should reason over plans; it must not bypass preview, backup, verify or rollback.

## UI Ideas

- Optional tabs to reduce clutter.
- Focused floating detail windows for dense panels.
- Route/topology map with hover path highlighting.
- Card/list toggle for services and interfaces.
- Active-filter badges and clear-filter actions.
- Mobile-first bottom navigation later.

## Security Ideas

- Login rate limit.
- CSRF for browser session POST/DELETE.
- API keys for scripts/mobile tools.
- Optional TOTP after core auth stabilizes.
- Exposure analyzer warnings for admin services bound to all interfaces.

## Code Architecture

- Continue moving legacy `main.py` paths into routers/domain/providers.
- Providers read/apply host state.
- Domain code decides and plans.
- API routers stay thin.
- UI only displays and asks.
- Add smoke tests for provider resolution and preview endpoints.
