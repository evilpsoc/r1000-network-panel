# Networking Model

LocalPlane should think in discovered interfaces with user-defined behavior, not
fixed `eth0`/`service_lan`/`management_lan` slots.

Every usable interface should appear with its own identity:

- current kernel name, such as `eth0`, `enx...`, `wlan0`, `wwan0`
- stable key when possible, such as `mac:<address>` or a sysfs path
- driver and bus information
- detected kind: ethernet, Wi-Fi, cellular, tunnel, bridge or virtual
- configurable behavior the operator can assign

Interface configs should be saved against the stable identity first. Kernel
names are only a compatibility fallback because USB adapters and modems can come
back with different names after reconnects.

## Interface Configs

The long-term UI should not show two hardcoded LAN forms or force predefined
roles. It should show discovered interfaces and let the operator name/configure
each one:

```txt
Add interface config
  interface: discovered stable identity
  display name: user chosen
  settings: addressing, DNS, internet sharing, uplink priority, isolation
```

Every interface that appears through hotplug discovery can be configured if the
device supports that behavior. Existing `main_lan`, `service_lan`, `wifi` and
`lte` config keys are migration compatibility, not the final user-facing model.

## Interface Configs / Rules

The long-term source of truth should be neutral interface configs, not fixed
roles. A discovered interface gets a user-defined config:

```txt
interface: eth0 / wlan0 / wwan0 / tailscale0 / ...
display name: user chosen
addressing: preserve existing / static / shared / disabled
DNS: preserve existing / custom / Pi-hole
internet: use as uplink, share to clients, priority
firewall: isolation, allowed/exposed services
type-specific: Wi-Fi SSID/hotspot, Cellular APN/SIM, tunnel routes
```

Routing, firewall, NAT, DHCP and DNS behavior should be derived from those
rules. Presets such as "trusted LAN", "isolated client network" or "cellular
backup" may exist later as shortcuts, but they are not fixed product roles.

Current compatibility endpoints can still import legacy `main_lan`,
`service_lan`, `wifi` and `lte` config as observed context while the new model
stabilizes.

Before any future apply, every interface config should pass readiness checks.
Readiness explains blockers and warnings such as missing NetworkManager,
missing nftables/sysctl, unsupported Wi-Fi mode, empty hotspot SSID, missing
ModemManager, manual APN gaps, down links or invalid client/uplink behavior for
the selected interface kind.

The read-only planner endpoint turns validated rules into provider-specific
preview steps:

```http
GET  /api/network/interface-plan/preview
POST /api/network/interface-plan/preview
```

It returns NetworkManager, DNS, routing, sysctl and nftables planning steps with
risk labels and command previews. It does not execute host changes. Command
previews are intentionally incomplete until backup, verify and rollback are
implemented.

Neutral desired-state overlays can be saved without touching the host:

```http
POST /api/network/interface-configs/save
POST /api/network/interface-configs/reset
```

These endpoints only update LocalPlane runtime config. They do not restart links,
modify routes, apply NetworkManager profiles, write firewall rules or change
modem state. The returned payload includes readiness and rules preview so the UI
can show what would happen before any future apply flow exists.

All Ethernet/LAN-style interfaces should share the same base settings model:

- assigned interface
- IPv4 mode/address/block/DHCP range where supported
- IPv6 mode/address/prefix/RA where supported
- DNS servers and Pi-hole policy
- internet sharing policy
- live state, desired state and drift/warning explanation

Differences should come from selected behavior and device capability, not from
hardcoded forms. For example, one Ethernet interface may share internet to local
clients while another may be only an uplink candidate. Speed, driver capability,
hardware offload and supported modes should come from the selected interface.

## Hotplug / Flexible Interfaces

The device must not assume that the original `eth0`, `wlan0` or `wwan0` are the
only useful ports. Operators may attach:

- USB Ethernet adapters
- USB Wi-Fi adapters
- USB LTE/5G modems
- internal mini-PCIe/M.2 modems
- extra tunnel interfaces

Discovery should produce an inventory item for every usable interface with:

- kernel name
- stable key when possible, such as MAC address or sysfs bus path
- detected kind: ethernet, Wi-Fi, cellular, tunnel, bridge or virtual
- driver and bus information
- NetworkManager connection when available
- compatible behavior options
- whether the interface looks hotpluggable

The UI should then allow configuring any compatible interface. The selected
kind and behavior open the correct settings surface:

- Ethernet adapter -> LAN, device LAN or wired uplink settings
- Wi-Fi adapter -> hotspot or client-uplink settings
- Cellular modem -> APN, SIM/operator and failover settings
- Tunnel -> management or route advertisement settings

The long-term target is an interface registry keyed by stable identity, not only
by kernel name. If a USB adapter changes from `enx...` to another name but keeps
the same MAC/sysfs identity, the panel should be able to reconnect the saved
config.

## Control Loop

```txt
Observe -> Analyze -> Plan -> Apply -> Verify -> Explain
```

The current direction is:

- providers collect host facts
- domain code normalizes state and creates findings
- API routers expose data and action previews
- UI displays state and asks before applying

## Reconciler Preview

The first reconciler API is intentionally preview-only:

```http
GET  /api/network/reconcile/preview
POST /api/network/reconcile/preview
```

It reads the observed network state and effective interface roles, then returns:

- current active uplink, forwarding state and panel-owned nftables visibility
- desired role policy
- proposed commands
- verification commands
- rollback commands
- warnings

It does not execute host changes. This is the migration path away from
`service-lan-inet-on.sh`, `service-lan-inet-off.sh` and the custom RA helper.
Future apply support must add backup, idempotent nftables batch writes,
NetworkManager profile backups, verification and rollback before it is enabled.

## Safe Apply Rules

- Do not change the active default-route interface without explicit staged
  confirmation.
- Do not bring down an interface that owns a default route.
- Do not append firewall/NAT rules blindly.
- Use panel-owned nftables tables/chains.
- Keep rollback commands for any hard route/firewall apply.
- Verify default route, forwarding, DNS, NAT and client reachability after
  apply.

## Route Map Target

The dashboard flow map should evolve into a topology view:

```txt
Uplinks -> Device -> LAN / Wi-Fi / Services / Tunnels
```

Useful behavior:

- show active and candidate uplinks
- show live RX/TX rates per interface
- highlight the path for selected LAN/client/service
- open a focused detail window for a selected node
- keep the map read-only; action buttons belong in preview/apply panels

## Failover Target

Start simple:

```txt
active default route
candidate uplinks
route metrics
connectivity probes
```

Then add controlled failover:

```json
{
  "priority": ["uplink_ethernet", "uplink_wifi", "uplink_cellular"],
  "failure_threshold": 3,
  "recovery_threshold": 5,
  "failback_delay_sec": 60
}
```
