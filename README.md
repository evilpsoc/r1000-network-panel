# LocalPlane

Host-aware local control plane for self-hosted Linux infrastructure.

LocalPlane is a self-hosted web UI for Linux hosts that need clear visibility
into networking, local services, containers, storage and device state. It is
for homelab nodes, small edge gateways and field-service boxes where the host
itself matters. The project started on a Seeed reComputer R1000/R1035-class
device, but the direction is broader: generic Linux hosts with capability-aware
controls.

## Screenshots

<p>
  <a href="assets/images/dashboard.png"><img src="assets/images/dashboard.png" width="220" alt="Dashboard"></a>
  <a href="assets/images/network.png"><img src="assets/images/network.png" width="220" alt="Network"></a>
  <a href="assets/images/wireless.png"><img src="assets/images/wireless.png" width="220" alt="Wireless"></a>
  <a href="assets/images/cellular.png"><img src="assets/images/cellular.png" width="220" alt="Cellular"></a>
  <a href="assets/images/services.png"><img src="assets/images/services.png" width="220" alt="Services"></a>
  <a href="assets/images/logs.png"><img src="assets/images/logs.png" width="220" alt="Logs"></a>
</p>

More:
[login](assets/images/login-page.png),
[monitoring](assets/images/monitoring.png),
[file sharing](assets/images/file-sharing.png),
[file system](assets/images/file-system.png),
[device I/O](assets/images/deviceio.png),
[review and run](assets/images/reviewandrun.png).

## What It Does

- Host and system overview
- Discovered network interfaces with live state
- Wi-Fi, cellular and uplink visibility
- Docker/container and local service visibility
- Pi-hole, Samba, NetAlertX and monitoring integrations
- Logs, actions, sessions and activity views
- Session-cookie login
- Diagnostics/findings direction for safer operations
- Capability-aware UI direction for different Linux hosts

## Quick Start

```sh
git clone https://github.com/ergunozgur/LocalPlane.git
cd LocalPlane
cp .env.example .env
nano .env
docker compose up -d --build backend
```

Set this in `.env` before first start:

```txt
PANEL_PASSWORD=change-me-before-first-run
```

Open:

```txt
http://<device-ip>:8080
```

Default username: `admin`

Password: the value you set in `PANEL_PASSWORD`.

Docker builds the frontend automatically. `npm install` is only needed for
frontend development.

## Current Status

LocalPlane is in active development.

- R1000/R1035-class reComputer hardware is the reference target.
- Generic Linux compatibility is being improved.
- Some device I/O and hardware assumptions are still R1000-oriented.
- Network changes are moving toward preview, audit, verify and rollback.
- The current app is usable for experimentation, but still changing quickly.

## Roadmap Summary

Near term:

- Backend foundation cleanup
- Generic service inventory
- Network diagnostics and findings
- Provider/capability model
- Safer preview and audit actions

Later:

- Local app/stack deployment
- Podman and systemd providers
- Multi-host/fleet views
- Traffic path explainer

## Documentation

- [Guide](docs/guide.md)
- [Networking](docs/networking.md)
- [Configuration](docs/configuration.md)
- [Security](docs/security.md)
- [Development backlog](docs/development-backlog.md)

<details>
<summary><strong>Architecture overview</strong></summary>

LocalPlane is built from a FastAPI backend, a Vite frontend and Docker Compose.
In production, the frontend is built into static files and served by the backend
container.

```txt
backend/app/
  api/        HTTP routers
  core/       auth, events, cache, host command wrappers
  domain/     network, system, storage, LTE and device logic
  providers/  host/tool-specific collectors

frontend/src/
  app.js
  styles.css
```

Design direction:

```txt
providers read/apply host state
domain code decides and plans
api routers expose data
frontend displays state and asks
```

</details>

<details>
<summary><strong>Supported and planned host types</strong></summary>

Current:

- Seeed reComputer R1000/R1035 reference target
- Generic Linux testing ongoing

The long-term goal is broader Linux host support, but host capabilities will
decide what the UI can safely show or change.

</details>

<details>
<summary><strong>R1000 / hardware-specific notes</strong></summary>

The original reference device is a Seeed reComputer R1000/R1035-class gateway
with Raspberry Pi CM4, Ubuntu Server, Ethernet, Wi-Fi, LTE-oriented workflows,
RS-485 ports and sysfs-visible LEDs.

For the reComputer R1035-10, the Seeed overlay should be loaded as:

```txt
dtoverlay=reComputer-R100x
```

in:

```txt
/boot/firmware/config.txt
```

Expected LED paths:

```txt
/sys/class/leds/led-red
/sys/class/leds/led-green
/sys/class/leds/led-blue
/sys/class/leds/ACT
```

Expected RS-485 ports:

```txt
/dev/ttyAMA2
/dev/ttyAMA3
/dev/ttyAMA5
```

On generic Linux hosts, these hardware-specific features may be unavailable or
shown as missing capabilities.

</details>

<details>
<summary><strong>Security and repository hygiene</strong></summary>

`.env` is local configuration. Do not commit real passwords, tokens or host
secrets.

Set a strong password before first start:

```txt
PANEL_PASSWORD=change-me-before-first-run
```

Runtime files such as auth state, sessions, events, service registry snapshots
and backups are generated on the device and should stay out of commits.

High-impact actions should continue moving toward:

```txt
preview -> confirm -> apply -> verify -> audit event -> rollback plan
```

Demo mode is frontend-only:

```txt
http://<device-ip>:8080/?demo=1
```

It masks sensitive values in the browser for screenshots. It does not change
backend data or API behavior.

</details>

<details>
<summary><strong>Development notes</strong></summary>

Backend: FastAPI inside Docker.

Frontend: Vite, plain JavaScript and CSS.

Production rebuild:

```sh
docker compose up -d --build backend
```

Backend validation:

```sh
python3 -m compileall -q backend/app
```

Frontend development:

```sh
cd frontend
npm install
npm run dev
```

Frontend build:

```sh
cd frontend
npm run build
```

The Vite dev server proxies API requests to `127.0.0.1:8080`.

</details>

<details>
<summary><strong>Troubleshooting</strong></summary>

Check the container:

```sh
docker compose ps
docker compose logs --tail=120 backend
```

If login fails, confirm `.env` contains `PANEL_PASSWORD` and restart the backend.

If port `8080` is unavailable, check what is already listening:

```sh
ss -ltnp | grep :8080
```

If a generic Linux host is missing features, check installed providers and host
tools such as NetworkManager, nftables, ModemManager, Docker and resolvectl.

If R1000-specific pages show missing data on non-R1000 hardware, that is
expected unless equivalent LED, serial, GPIO or modem paths exist.

For network debugging:

```sh
nmcli device status
nmcli connection show
ip addr
ip route
resolvectl status
```

</details>

## License

This project is licensed under the [Apache License 2.0](LICENSE).
