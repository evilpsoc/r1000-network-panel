# Security Notes

LocalPlane controls a real Linux host. Treat it as an admin surface.

## Authentication

- `PANEL_PASSWORD` must be set before first startup.
- The plaintext password should never be written to docs, logs or commits.
- Session cookies should stay `HttpOnly` and `SameSite=Lax`.
- Add `Secure` cookie support when the panel is served behind HTTPS.

Future hardening:

- login rate limiting
- CSRF token for session-authenticated state-changing endpoints
- per-device API keys for scripts/mobile clients
- optional OIDC/SSO later, after local auth is stable

## Network Exposure

The Routing / Firewall page already reports broad bind scopes and likely
reachable management ports. This should evolve into:

- per-interface exposure checks
- tunnel-only admin recommendations
- warnings when SSH, panel, Grafana, Prometheus, Portainer or Samba bind to all
  interfaces
- suggested fixes that preserve the current admin session

## Backups

Before any feature writes host config, it should create or reference a backup.

Target backup areas:

- runtime config
- NetworkManager connection profiles before modification
- nftables panel-owned tables before replacement
- Samba portal shares before rewrite
- compose draft/source files before update

Restore should create another backup before overwriting current state.

Current backup API:

```http
GET  /api/backups
POST /api/backups
GET  /api/backups/network-profile-export-plan
```

The first implementation creates local backup folders under:

```txt
/app/data/backups/
```

It copies panel runtime files and captures read-only host network snapshots such
as `nft list ruleset` and `nmcli connection show`. Automated restore is not
implemented yet; hard apply flows must not depend on restore until verify and
rollback are real.

## Dangerous Actions

High-impact actions need clear preview and confirmation:

- route metric/default route changes
- firewall/NAT reconcile
- Wi-Fi mode switch
- cellular APN reconnect
- service restart/poweroff
- package/dependency installation
