from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pathlib import Path
import subprocess
import json
import re


app = FastAPI(title="R1000 Network Panel")


def read_text(path: str, default: str = "") -> str:
    try:
        return Path(path).read_text().strip()
    except Exception:
        return default


def run_command(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except Exception:
        return ""


def run_command_full(cmd: list[str]) -> tuple[int, str, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def is_process_running(name: str) -> bool:
    result = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True)
    return result.returncode == 0


def clean_ansi(text: str) -> str:
    return re.sub(r"\x1B\[[0-9;]*[A-Za-z]", "", text).strip()


def parse_mmcli_value(text: str, label: str) -> str:
    pattern = rf"{re.escape(label)}\s*:\s*(.+)"
    match = re.search(pattern, text)
    return match.group(1).strip() if match else ""
    
def get_modem_id() -> str:
    output = run_command(["mmcli", "-L"])
    match = re.search(r"/Modem/(\d+)", output)
    return match.group(1) if match else ""



@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/overview")
def overview():
    hostname = read_text("/host/etc/hostname", "unknown")

    uptime_raw = read_text("/host/proc/uptime", "0 0").split()
    uptime_seconds = int(float(uptime_raw[0])) if uptime_raw else 0

    default_v4 = run_command(["ip", "route", "show", "default"])
    default_v6 = run_command(["ip", "-6", "route", "show", "default"])

    return {
        "hostname": hostname,
        "uptime_seconds": uptime_seconds,
        "default_route_v4": default_v4,
        "default_route_v6": default_v6,
    }


@app.get("/api/interfaces")
def interfaces():
    output = run_command(["ip", "-j", "addr"])
    if not output:
        return []

    try:
        data = json.loads(output)
    except Exception:
        return []

    result = []
    for iface in data:
        name = iface.get("ifname", "")
        if name.startswith("veth") or name.startswith("br-") or name == "docker0":
            continue

        ipv4 = []
        ipv6 = []

        for addr in iface.get("addr_info", []):
            if addr.get("family") == "inet":
                ipv4.append(addr.get("local"))
            elif addr.get("family") == "inet6":
                ipv6.append(addr.get("local"))

        state = iface.get("operstate")
        if state == "UNKNOWN" and (ipv4 or ipv6):
            state = "UP"

        result.append(
            {
                "name": name,
                "state": state,
                "mac": iface.get("address"),
                "ipv4": ipv4,
                "ipv6": ipv6,
                "mtu": iface.get("mtu"),
            }
        )

    return result


@app.get("/api/lte")
def lte():
    modem_id = get_modem_id()
    if not modem_id:
        return {"available": False}

    run_command(["mmcli", "-m", modem_id, "--signal-setup=5"])

    modem = run_command(["mmcli", "-m", modem_id])
    signal = run_command(["mmcli", "-m", modem_id, "--signal-get"])

    if not modem:
        return {"available": False}

    return {
        "available": True,
        "state": clean_ansi(parse_mmcli_value(modem, "state")),
        "power_state": clean_ansi(parse_mmcli_value(modem, "power state")),
        "access_tech": clean_ansi(parse_mmcli_value(modem, "access tech")),
        "signal_quality": clean_ansi(parse_mmcli_value(modem, "signal quality")),
        "operator_name": clean_ansi(parse_mmcli_value(modem, "operator name")),
        "registration": clean_ansi(parse_mmcli_value(modem, "registration")),
        "packet_service_state": clean_ansi(parse_mmcli_value(modem, "packet service state")),
        "rssi": clean_ansi(parse_mmcli_value(signal, "rssi")),
        "rsrq": clean_ansi(parse_mmcli_value(signal, "rsrq")),
        "rsrp": clean_ansi(parse_mmcli_value(signal, "rsrp")),
        "snr": clean_ansi(parse_mmcli_value(signal, "s/n")),
    }

@app.get("/api/services")
def services():
    return [
        {"name": "NetworkManager", "type": "host", "active": is_process_running("NetworkManager")},
        {"name": "ModemManager", "type": "host", "active": is_process_running("ModemManager")},
        {"name": "tailscaled", "type": "host", "active": is_process_running("tailscaled")},
        {"name": "smbd", "type": "host", "active": is_process_running("smbd")},
    ]


@app.get("/api/service-lan/clients")
def service_lan_clients():
    leases = []
    leases_raw = read_text("/host/var/lib/misc/dnsmasq.leases", "")
    for line in leases_raw.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            leases.append(
                {
                    "expires": parts[0],
                    "mac": parts[1],
                    "ip": parts[2],
                    "hostname": parts[3] if parts[3] != "*" else "",
                }
            )

    neigh_raw = run_command(["ip", "neigh", "show", "dev", "enx2cf7f1232c1a"])
    neigh_map = {}
    for line in neigh_raw.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            ip = parts[0]
            mac = parts[4] if parts[3] == "lladdr" else ""
            state = parts[-1]
            neigh_map[ip] = {"mac": mac, "state": state}

    result = []
    for lease in leases:
        neigh = neigh_map.get(lease["ip"], {})
        result.append(
            {
                "ip": lease["ip"],
                "mac": lease["mac"] or neigh.get("mac", ""),
                "hostname": lease["hostname"],
                "state": neigh.get("state", "unknown"),
            }
        )

    return result


@app.get("/api/service-lan/status")
def service_lan_status():
    ruleset = run_command(["nft", "list", "ruleset"])
    internet_enabled = "table inet service_lan" in ruleset and "table ip service_lan_nat" in ruleset

    return {
        "interface": "enx2cf7f1232c1a",
        "gateway_ip": "192.168.10.1",
        "dhcp_range": "192.168.10.100-192.168.10.199",
        "internet_enabled": internet_enabled,
    }



@app.post("/api/service-lan/internet/on")
def service_lan_internet_on():
    code, stdout, stderr = run_command_full(["/usr/local/bin/service-lan-inet-on.sh"])
    return {"ok": code == 0, "code": code, "stdout": stdout, "stderr": stderr}


@app.post("/api/service-lan/internet/off")
def service_lan_internet_off():
    code, stdout, stderr = run_command_full(["/usr/local/bin/service-lan-inet-off.sh"])
    return {"ok": code == 0, "code": code, "stdout": stdout, "stderr": stderr}


@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>R1000 Network Panel</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          background: #0f172a;
          color: #e5e7eb;
          margin: 0;
          padding: 24px;
        }
        h1, h2 { margin-top: 0; }
        .topbar {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 16px;
        }
        .grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
          gap: 16px;
        }
        .card {
          background: #111827;
          border: 1px solid #1f2937;
          border-radius: 16px;
          padding: 16px;
          box-shadow: 0 10px 30px rgba(0,0,0,0.25);
          overflow-wrap: anywhere;
          word-break: break-word;
        }
        .label {
          color: #9ca3af;
          font-size: 14px;
        }
        .value {
          font-size: 20px;
          font-weight: 700;
          margin-top: 6px;
        }
        ul { padding-left: 18px; }
        .route {
          background: #0b1220;
          border: 1px solid #1f2937;
          border-radius: 12px;
          padding: 10px;
          margin-top: 10px;
          font-family: monospace;
          font-size: 13px;
          line-height: 1.5;
          white-space: pre-wrap;
          word-break: break-word;
          overflow-wrap: anywhere;
        }
        button {
          background: #2563eb;
          color: white;
          border: none;
          border-radius: 10px;
          padding: 10px 14px;
          font-weight: 700;
          cursor: pointer;
        }
        button:hover {
          background: #1d4ed8;
        }
      </style>
    </head>
    <body>
      <div class="topbar">
        <h1>R1000 Network Panel</h1>
        <button onclick="render()">Refresh</button>
      </div>

      <div class="grid">
        <div class="card">
          <h2>Overview</h2>
          <div id="overview">Loading...</div>
        </div>
        <div class="card">
          <h2>LTE</h2>
          <div id="lte">Loading...</div>
        </div>
        <div class="card">
          <h2>Services</h2>
          <div id="services">Loading...</div>
        </div>
        <div class="card">
          <h2>Service LAN</h2>
          <div id="service-lan">Loading...</div>
        </div>
      </div>

      <div class="card" style="margin-top:16px;">
        <h2>Interfaces</h2>
        <div id="interfaces">Loading...</div>
      </div>

      <div class="card" style="margin-top:16px;">
        <h2>Connected Clients</h2>
        <div id="service-lan-clients">Loading...</div>
      </div>

      <script>
        async function loadJSON(url) {
          const res = await fetch(url);
          return await res.json();
        }

        async function toggleServiceLanInternet(mode) {
          const endpoint = mode === 'on'
            ? '/api/service-lan/internet/on'
            : '/api/service-lan/internet/off';

          const res = await fetch(endpoint, { method: 'POST' });
          if (!res.ok) {
            alert('Failed to change Service LAN internet state');
            return;
          }

          await render();
        }

        async function render() {
          const overview = await loadJSON('/api/overview');
          const lte = await loadJSON('/api/lte');
          const services = await loadJSON('/api/services');
          const interfaces = await loadJSON('/api/interfaces');
          const serviceLan = await loadJSON('/api/service-lan/status');
          const serviceLanClients = await loadJSON('/api/service-lan/clients');

          document.getElementById('overview').innerHTML = `
            <div><span class="label">Hostname:</span> <span class="value">${overview.hostname}</span></div>
            <div><span class="label">Uptime (sec):</span> <span class="value">${overview.uptime_seconds}</span></div>

            <div class="route">
              <div class="label">Default IPv4</div>
              <div>${overview.default_route_v4 || '-'}</div>
            </div>

            <div class="route">
              <div class="label">Default IPv6</div>
              <div>${overview.default_route_v6 || '-'}</div>
            </div>
          `;

          document.getElementById('lte').innerHTML = `
            <div><span class="label">Available:</span> <span class="value">${lte.available}</span></div>
            <div><span class="label">State:</span> <span class="value">${lte.state || '-'}</span></div>
            <div><span class="label">Operator:</span> <span class="value">${lte.operator_name || '-'}</span></div>
            <div><span class="label">Signal:</span> <span class="value">${lte.signal_quality || '-'}</span></div>
            <div><span class="label">Tech:</span> <span class="value">${lte.access_tech || '-'}</span></div>
            <div><span class="label">RSSI:</span> <span class="value">${lte.rssi || '-'}</span></div>
            <div><span class="label">RSRP:</span> <span class="value">${lte.rsrp || '-'}</span></div>
            <div><span class="label">RSRQ:</span> <span class="value">${lte.rsrq || '-'}</span></div>
            <div><span class="label">SNR:</span> <span class="value">${lte.snr || '-'}</span></div>
          `;

          document.getElementById('services').innerHTML = `
            <ul>
              ${services.map(s => `<li><strong>${s.name}</strong>: ${s.active ? 'UP' : 'DOWN'}</li>`).join('')}
            </ul>
          `;

          document.getElementById('service-lan').innerHTML = `
            <div><span class="label">Interface:</span> <span class="value">${serviceLan.interface}</span></div>
            <div><span class="label">Gateway:</span> <span class="value">${serviceLan.gateway_ip}</span></div>
            <div><span class="label">DHCP Range:</span> <span class="value">${serviceLan.dhcp_range}</span></div>
            <div><span class="label">Internet:</span> <span class="value">${serviceLan.internet_enabled ? 'ON' : 'OFF'}</span></div>
            <div style="margin-top: 12px; display:flex; gap:10px; flex-wrap:wrap;">
              <button onclick="toggleServiceLanInternet('on')">Enable Internet</button>
              <button onclick="toggleServiceLanInternet('off')">Disable Internet</button>
            </div>
          `;

          document.getElementById('interfaces').innerHTML = `
            <div class="grid">
              ${interfaces.map(i => `
                <div class="card">
                  <div class="label">${i.name}</div>
                  <div class="value">${i.state}</div>
                  <div><span class="label">MAC:</span> ${i.mac || '-'}</div>
                  <div><span class="label">IPv4:</span> ${(i.ipv4 || []).join(', ') || '-'}</div>
                  <div><span class="label">IPv6:</span> ${(i.ipv6 || []).join(', ') || '-'}</div>
                  <div><span class="label">MTU:</span> ${i.mtu}</div>
                </div>
              `).join('')}
            </div>
          `;

          document.getElementById('service-lan-clients').innerHTML = serviceLanClients.length
            ? `
              <div class="grid">
                ${serviceLanClients.map(c => `
                  <div class="card">
                    <div><span class="label">IP:</span> <span class="value">${c.ip}</span></div>
                    <div><span class="label">MAC:</span> ${c.mac || '-'}</div>
                    <div><span class="label">Hostname:</span> ${c.hostname || '-'}</div>
                    <div><span class="label">State:</span> ${c.state || '-'}</div>
                  </div>
                `).join('')}
              </div>
            `
            : '<div class="label">No clients detected</div>';
        }

        render();
        setInterval(render, 10000);
      </script>
    </body>
    </html>
    """
