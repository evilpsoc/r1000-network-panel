# Configuration Reference

## Environment

`.env.example` documents required runtime variables. Real `.env` files must not
be committed.

Important variables:

- `PANEL_USERNAME`
- `PANEL_PASSWORD`
- `PANEL_SESSION_TTL_SECONDS`
- `WIFI_RESTORE_ON_STARTUP`
- Wi-Fi/cellular and legacy LAN defaults used before runtime config exists

## Runtime Config

Runtime state is currently stored under backend data as JSON, including:

- panel auth/session data
- legacy LAN configuration
- Wi-Fi configuration, without saved passwords
- cellular APN auto/override state
- NetAlertX sync state

Target direction:

- keep JSON for the current prototype
- move toward SQLite when actions, audit events, backups and users grow
- keep secrets out of screenshots, logs and committed files

## Capability-Driven UI

The Runtime page should become the source for optional feature availability.

Examples:

- show Cellular only when ModemManager or a modem is present
- show Wi-Fi actions only when NetworkManager and a Wi-Fi interface are present
- show firewall reconcile only when nftables is available
- show Docker/Compose tools only when Docker is available
- degrade to read-only when a provider is missing

## Optional Tabs

Borrowing the product idea, optional tabs should be explicit and persisted:

- core tabs always visible: Dashboard, Network, Logs, Services, Runtime
- optional tabs: Cellular, Wireless, File Sharing, Device I/O, Monitoring,
  Terminal, Actions, LoRaWAN

This avoids a crowded UI on hosts that do not support every feature.
