import './styles.css';

    const appState = {
      drafts: {},
      activeView: sessionStorage.getItem('portal.activeView') || 'dashboard',
      lastSyncAt: null,
      authUsername: '',
      serviceDetails: {},
      commandContext: null,
      rawProfile: '',
      pendingToggles: {},
    };
    window.appState = appState;
    const VIEW_META = {
      dashboard: { title: 'Dashboard', subtitle: 'Device overview, usage and quick health.' },
      network: { title: 'Network', subtitle: 'LAN roles, clients, DNS policy and interface control.' },
      wireless: { title: 'Wireless', subtitle: 'Wi-Fi scan, hotspot, radio power and wireless DNS policy.' },
      cellular: { title: 'Cellular', subtitle: 'Modem signal, APN editor, raw profile and AT command tools.' },
      monitoring: { title: 'Monitoring', subtitle: 'Pi-hole, NetAlertX and network visibility tools.' },
      logs: { title: 'Logs', subtitle: 'Recent panel, network and service activity.' },
      services: { title: 'Services', subtitle: 'Compact service discovery with docker/system source tags.' },
      filesharing: { title: 'File Sharing', subtitle: 'Samba shares, printing and future NFS style expansion.' },
      users: { title: 'Users', subtitle: 'Samba account and access management.' },
      filesystem: { title: 'File System', subtitle: 'Storage topology, mounts and removable device visibility.' },
      deviceio: { title: 'Device I/O', subtitle: 'LEDs, serial ports, GPIO chips and expansion readiness.' },
      lorawan: { title: 'LoRaWAN', subtitle: 'Placeholder for future LoRa, Meshtastic and radio workflows.' },
    };
    const REACTIVE_DRAFT_KEYS = new Set([
      'main_lan.ipv4_mode',
      'main_lan.ipv6_mode',
      'service_lan.ipv4_mode',
      'service_lan.ipv6_mode',
      'wifi.mode',
      'wifi.client_trust_mode',
      'wifi.band',
      'wifi.ipv4_method',
      'wifi.ipv6_method',
    ]);
    const AUTO_REFRESH_MS = 30000;
    const DEMO_MODE = new URLSearchParams(window.location.search).get('demo') === '1';
    const DEMO_PLACEHOLDERS = {
      hostname: 'recomputer-r1000',
      ipv4: '10.0.0.100',
      gateway: '10.0.0.1',
      tailscale: '100.x.x.x',
      ipv6: 'fe80::demo',
      mac: '00:00:00:00:00:00',
      ssid: 'example-wifi',
      username: 'demo-user',
      port: '443',
    };

    function draftValue(key, fallback) {
      return Object.prototype.hasOwnProperty.call(appState.drafts, key) ? appState.drafts[key] : (fallback ?? '');
    }
    function bindDraft(id, key) {
      const el = document.getElementById(id);
      if (!el) return;
      const capture = () => {
        appState.drafts[key] = el.type === 'checkbox' ? el.checked : el.value;
        if ((key === 'main_lan.ipv4_mode' || key === 'service_lan.ipv4_mode') && el.value === 'disabled') {
          appState.drafts[key.replace('ipv4_mode', 'ipv6_mode')] = 'disabled';
        }
        updateRefreshState();
        if (REACTIVE_DRAFT_KEYS.has(key)) {
          setTimeout(() => render(), 0);
        }
      };
      el.oninput = capture;
      el.onchange = capture;
    }
    function clearDraft(prefix) {
      Object.keys(appState.drafts).filter(key => key.startsWith(prefix)).forEach(key => delete appState.drafts[key]);
      updateRefreshState();
    }
    function isTogglePending(key) {
      return Boolean(appState.pendingToggles[key]);
    }
    function setTogglePending(key, pending) {
      if (pending) appState.pendingToggles[key] = true;
      else delete appState.pendingToggles[key];
    }
    function escapeHtml(value) {
      return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    }
    function demoMaskText(value) {
      if (!DEMO_MODE) return String(value ?? '');
      return String(value ?? '')
        .replace(/\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/gi, DEMO_PLACEHOLDERS.mac)
        .replace(/\b100\.(?:\d{1,3}\.){2}\d{1,3}(?:\/\d{1,2})?\b/g, DEMO_PLACEHOLDERS.tailscale)
        .replace(/\b(?:via|gateway|gw)\s+((?:\d{1,3}\.){3}\d{1,3})(?:\/\d{1,2})?\b/gi, match => match.replace(/(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?/, DEMO_PLACEHOLDERS.gateway))
        .replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g, DEMO_PLACEHOLDERS.ipv4)
        .replace(/\b(?=[0-9a-f:]*[a-f][0-9a-f:]*\b|[0-9a-f:]*::)(?:[0-9a-f]{1,4}:){2,}[0-9a-f:]{0,39}(?:\/\d{1,3})?\b/gi, DEMO_PLACEHOLDERS.ipv6)
        .replace(/\/home\/[A-Za-z0-9._-]+/g, `/home/${DEMO_PLACEHOLDERS.username}`)
        .replace(/\b(user|username|users)\s*[:=]\s*[A-Za-z0-9._-]+/gi, `$1: ${DEMO_PLACEHOLDERS.username}`);
    }
    function demoMaskValue(value, key = '') {
      if (!DEMO_MODE) return value;
      if (value === null || value === undefined || typeof value === 'boolean' || typeof value === 'number') return value;
      const raw = String(value);
      const normalizedKey = String(key || '').toLowerCase();
      if (normalizedKey.includes('hostname')) return DEMO_PLACEHOLDERS.hostname;
      if (normalizedKey.includes('ssid')) return DEMO_PLACEHOLDERS.ssid;
      if (normalizedKey === 'username' || normalizedKey.includes('valid_users')) return DEMO_PLACEHOLDERS.username;
      if (normalizedKey.includes('mac')) return DEMO_PLACEHOLDERS.mac;
      if (normalizedKey === 'peer_port' || normalizedKey === 'local_port') return DEMO_PLACEHOLDERS.port;
      if (normalizedKey.includes('tailscale') || raw.startsWith('100.')) return DEMO_PLACEHOLDERS.tailscale;
      if (normalizedKey.includes('ipv6') || raw.includes(':')) return demoMaskText(raw);
      if (normalizedKey.includes('gateway') || normalizedKey === 'via') return DEMO_PLACEHOLDERS.gateway;
      if (/(ipv4|address|subnet|prefix|src|ip|bind|dns|route|target)/.test(normalizedKey)) return demoMaskText(raw);
      if (/(message|stdout|stderr|raw|profile|path|description|notes)/.test(normalizedKey)) return demoMaskText(raw);
      return demoMaskText(raw);
    }
    function demoMaskData(value, key = '') {
      if (!DEMO_MODE) return value;
      if (Array.isArray(value)) return value.map(item => demoMaskData(item, key));
      if (value && typeof value === 'object') {
        return Object.fromEntries(Object.entries(value).map(([childKey, childValue]) => [childKey, demoMaskData(childValue, childKey)]));
      }
      return demoMaskValue(value, key);
    }
    function demoMaskPayload(payload) {
      return JSON.stringify(demoMaskData(payload || {}), null, 2);
    }
    function applyDemoMaskToDom() {
      if (!DEMO_MODE) return;
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      const nodes = [];
      while (walker.nextNode()) nodes.push(walker.currentNode);
      nodes.forEach(node => {
        node.nodeValue = demoMaskText(node.nodeValue);
      });
      document.querySelectorAll('input, textarea').forEach(input => {
        const id = input.id || '';
        if (input.type === 'password') {
          input.value = input.value ? 'demo-password' : '';
        } else if (/username|user/i.test(id)) {
          input.value = input.value ? DEMO_PLACEHOLDERS.username : input.value;
        } else if (/ssid/i.test(id)) {
          input.value = input.value ? DEMO_PLACEHOLDERS.ssid : input.value;
        } else if (/ipv4|gateway|subnet|dns|ip|address|payload|preview/i.test(id)) {
          input.value = demoMaskText(input.value);
        }
      });
    }
    function safeText(value, key = '') {
      return escapeHtml(demoMaskValue(value, key));
    }
    function setAuthState(authenticated) {
      document.body.dataset.auth = authenticated ? 'unlocked' : 'locked';
      const accountUsername = document.getElementById('account-username');
      if (accountUsername && appState.authUsername) accountUsername.value = demoMaskValue(appState.authUsername, 'username');
      if (!authenticated) {
        const password = document.getElementById('login-password');
        if (password) password.value = '';
      }
    }
    async function checkAuth() {
      try {
        const res = await fetch('/api/auth/status');
        const payload = await res.json();
        appState.authUsername = payload.username || '';
        setAuthState(Boolean(payload.authenticated));
        return Boolean(payload.authenticated);
      } catch (err) {
        setAuthState(false);
        return false;
      }
    }
    async function login(event) {
      event.preventDefault();
      const error = document.getElementById('login-error');
      if (error) error.textContent = '';
      try {
        await fetchJSON('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: document.getElementById('login-username').value,
            password: document.getElementById('login-password').value,
          }),
        });
        appState.authUsername = document.getElementById('login-username').value;
        setAuthState(true);
        await render();
      } catch (err) {
        if (error) error.textContent = err.message || 'Sign in failed';
        setAuthState(false);
      }
    }
    async function logout() {
      await fetch('/api/auth/logout', { method: 'POST' });
      appState.authUsername = '';
      setAuthState(false);
    }
    async function updateCredentials() {
      const message = document.getElementById('account-message');
      if (message) message.textContent = '';
      const username = document.getElementById('account-username').value;
      const currentPassword = document.getElementById('account-current-password').value;
      const newPassword = document.getElementById('account-new-password').value;
      try {
        const result = await fetchJSON('/api/auth/credentials', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username,
            current_password: currentPassword,
            new_password: newPassword,
          }),
        });
        appState.authUsername = result.username || username;
        document.getElementById('login-username').value = appState.authUsername;
        document.getElementById('account-current-password').value = '';
        document.getElementById('account-new-password').value = '';
        if (message) message.textContent = 'Account updated.';
      } catch (err) {
        if (message) message.textContent = err.message || 'Account update failed';
      }
    }
    async function loadJSON(url) {
      const res = await fetch(url);
      if (res.status === 401) {
        setAuthState(false);
        throw new Error('Authentication required');
      }
      return await res.json();
    }
    async function fetchJSON(url, options) {
      const res = await fetch(url, options);
      let payload = {};
      try { payload = await res.json(); } catch (err) {}
      if (res.status === 401) {
        setAuthState(false);
      }
      if (!res.ok) {
        const detail = payload.detail || payload || {};
        if (typeof detail === 'string') throw new Error(detail);
        throw new Error(detail.stderr || detail.stdout || 'Request failed');
      }
      return payload;
    }
    async function postAction(endpoint, fallbackMessage, payload = null) {
      try {
        const response = await fetchJSON(endpoint, {
          method: 'POST',
          headers: payload ? { 'Content-Type': 'application/json' } : undefined,
          body: payload ? JSON.stringify(payload) : undefined,
        });
        if (response.ok === false) throw new Error(response.stderr || fallbackMessage);
        return response;
      } catch (err) {
        alert(err.message || fallbackMessage);
        return null;
      }
    }
    function hasActiveEditing() {
      const active = document.activeElement;
      const focusedEdit = active && ['INPUT', 'SELECT', 'TEXTAREA'].includes(active.tagName);
      return focusedEdit
        || Object.keys(appState.drafts).length > 0
        || document.getElementById('command-overlay').classList.contains('open')
        || document.getElementById('service-overlay').classList.contains('open')
        || document.getElementById('text-overlay').classList.contains('open');
    }
    function updateRefreshState() {
      const editing = hasActiveEditing();
      const dot = document.getElementById('refresh-dot');
      const label = document.getElementById('refresh-state');
      const detail = document.getElementById('refresh-detail');
      if (dot) dot.className = `dot ${editing ? 'pause' : 'live'}`;
      if (label) label.textContent = editing ? 'Auto refresh paused while editing' : 'Auto refresh live';
      if (detail) detail.textContent = editing ? 'Draft values stay local until you save or run them.' : 'The page refreshes in the background every 30 seconds.';
      if (appState.lastSyncAt) document.getElementById('last-sync').textContent = `Last sync ${new Date(appState.lastSyncAt).toLocaleTimeString()}`;
    }
    function setView(view) {
      appState.activeView = view;
      sessionStorage.setItem('portal.activeView', view);
      closeNavMenus();
      Object.entries(VIEW_META).forEach(([key, meta]) => {
        const page = document.getElementById(`page-${key}`);
        const buttons = document.querySelectorAll(`[data-view="${key}"]`);
        if (page) page.classList.toggle('active', key === view);
        buttons.forEach(button => button.classList.toggle('active', key === view));
        if (key === view) {
          document.getElementById('page-title').textContent = meta.title;
          document.getElementById('page-subtitle').textContent = meta.subtitle;
          const navContext = document.getElementById('nav-context');
          if (navContext) navContext.textContent = meta.title.toLowerCase().replace(/\s+/g, '-');
        }
      });
    }
    function closeNavMenus() {
      document.querySelectorAll('.nav-menu.open').forEach(menu => menu.classList.remove('open'));
    }
    function bindNavMenus() {
      document.querySelectorAll('.nav-menu > .nav-trigger').forEach(trigger => {
        const menu = trigger.closest('.nav-menu');
        if (!menu || !menu.querySelector('.mega-menu')) return;
        trigger.addEventListener('click', event => {
          event.stopPropagation();
          const wasOpen = menu.classList.contains('open');
          closeNavMenus();
          menu.classList.toggle('open', !wasOpen);
        });
      });
      document.querySelectorAll('.mega-menu').forEach(menu => {
        menu.addEventListener('click', event => event.stopPropagation());
      });
      document.addEventListener('click', closeNavMenus);
      document.addEventListener('keydown', event => {
        if (event.key === 'Escape') closeNavMenus();
      });
    }
    function loadTheme() {
      document.body.dataset.theme = 'dark';
      localStorage.setItem('portal.theme', 'dark');
      updateRefreshState();
    }
    function toggleTheme() {
      document.body.dataset.theme = 'dark';
      localStorage.setItem('portal.theme', 'dark');
      updateRefreshState();
    }
    function getUptimeMode() {
      return sessionStorage.getItem('portal.uptimeMode') || 'dhm';
    }
    function cycleUptimeMode() {
      const order = ['seconds', 'clock', 'dhm'];
      const current = getUptimeMode();
      const next = order[(order.indexOf(current) + 1) % order.length];
      sessionStorage.setItem('portal.uptimeMode', next);
      render();
    }
    function fmtUptime(seconds) {
      const mode = getUptimeMode();
      if (mode === 'seconds') return `${seconds}s`;
      const days = Math.floor(seconds / 86400);
      const hours = Math.floor((seconds % 86400) / 3600);
      const minutes = Math.floor((seconds % 3600) / 60);
      if (mode === 'clock') return `${String(days * 24 + hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}`;
      return `${days}d ${hours}h ${minutes}m`;
    }
    function openServiceOverlay(id) {
      const service = appState.serviceDetails[id];
      if (!service) return;
      document.getElementById('overlay-title').textContent = demoMaskText(service.title || 'Service');
      document.getElementById('overlay-subtitle').textContent = demoMaskText(service.subtitle || 'Details');
      document.getElementById('overlay-body').innerHTML = `
        <div class="stat-grid">${Object.entries(service.details || {}).map(([k, v]) => `<div class="metric"><div class="label">${safeText(k)}</div><div class="value small">${safeText(v, k)}</div></div>`).join('')}</div>
        ${service.url ? `<div class="controls"><a class="chip" href="${service.url}" target="_blank" rel="noreferrer">Open service</a></div>` : ''}
        ${service.notes ? `<div class="hint">${safeText(service.notes, 'notes')}</div>` : ''}
      `;
      document.getElementById('service-overlay').classList.add('open');
    }
    function closeServiceOverlay() {
      document.getElementById('service-overlay').classList.remove('open');
      updateRefreshState();
    }
    function openRawProfile() {
      openTextOverlay('Raw Connection Profile', 'Live cellular profile from NetworkManager', appState.rawProfile || '');
    }
    function openTextOverlay(title, subtitle, text) {
      document.getElementById('text-overlay-title').textContent = title || 'Details';
      document.getElementById('text-overlay-subtitle').textContent = subtitle || 'Text view';
      document.getElementById('text-overlay-body').textContent = demoMaskText(text || 'No content available.');
      document.getElementById('text-overlay').classList.add('open');
      updateRefreshState();
    }
    function closeTextOverlay() {
      document.getElementById('text-overlay').classList.remove('open');
      updateRefreshState();
    }
    function dismissOverlay(event, id) {
      if (event.target.id === id) {
        document.getElementById(id).classList.remove('open');
        updateRefreshState();
      }
    }
    function closeCommandOverlay() {
      document.getElementById('command-overlay').classList.remove('open');
      document.getElementById('command-run').disabled = false;
      appState.commandContext = null;
      updateRefreshState();
    }
    async function openCommandOverlay(title, previewUrl, payload, runner, subtitle = 'Review and run') {
      appState.commandContext = { title, previewUrl, runner };
      document.getElementById('command-title').textContent = title;
      document.getElementById('command-subtitle').textContent = subtitle;
      document.getElementById('command-payload').value = DEMO_MODE ? demoMaskPayload(payload) : JSON.stringify(payload || {}, null, 2);
      document.getElementById('command-run').disabled = DEMO_MODE;
      document.getElementById('command-run').onclick = async () => {
        try {
          const parsed = JSON.parse(document.getElementById('command-payload').value || '{}');
          await runner(parsed);
          closeCommandOverlay();
        } catch (err) {
          alert(err.message || 'Failed to run command');
        }
      };
      await refreshCommandPreview();
      document.getElementById('command-overlay').classList.add('open');
      updateRefreshState();
    }
    async function refreshCommandPreview() {
      if (!appState.commandContext) return;
      if (DEMO_MODE) {
        document.getElementById('command-preview').textContent = demoMaskText('Demo mode: command preview is masked and no backend preview request is sent.');
        return;
      }
      let payload = {};
      try { payload = JSON.parse(document.getElementById('command-payload').value || '{}'); } catch (err) {
        document.getElementById('command-preview').textContent = 'Payload JSON is invalid';
        return;
      }
      try {
        const preview = await fetchJSON(appState.commandContext.previewUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        document.getElementById('command-preview').textContent = demoMaskText((preview.commands || []).join('\n'));
      } catch (err) {
        document.getElementById('command-preview').textContent = demoMaskText(err.message || 'Unable to build command preview');
      }
    }
    function serviceCardMarkup(id, title, state, summary, details, tags = [], url = '', subtitle = '', notes = '') {
      appState.serviceDetails[id] = { title, subtitle, details, url, notes };
      return `
        <div class="item service-card" onclick="openServiceOverlay('${id}')">
          <div class="item-top">
            <div class="item-title">${escapeHtml(title)}</div>
            <div class="badge">${escapeHtml(state)}</div>
          </div>
          <div class="muted">${escapeHtml(summary)}</div>
          <div class="tag-row">${tags.map(tag => `<span class="mini-tag">${escapeHtml(tag)}</span>`).join('')}</div>
        </div>
      `;
    }
    function getServiceUrl(service) {
      const host = window.location.hostname;
      const currentProtocol = window.location.protocol === 'https:' ? 'https:' : 'http:';
      const ports = service.ports || [];
      const hasPort = value => ports.includes(value);
      if (service.name === 'Network Panel') return window.location.origin;
      if (service.name === 'Cockpit' || hasPort('tcp/9090')) return `https://${host}:9090`;
      if (service.name === 'Portainer HTTPS' || hasPort('tcp/9443')) return `https://${host}:9443`;
      if (service.name === 'Portainer' || hasPort('tcp/9000')) return `http://${host}:9000`;
      if (service.name === 'Grafana' || hasPort('tcp/3000')) return `http://${host}:3000`;
      if (service.name === 'Prometheus' || hasPort('tcp/9091')) return `http://${host}:9091`;
      if (service.name === 'Pi-hole' || hasPort('tcp/8081')) return `http://${host}:8081`;
      if (service.name === 'NetAlertX' || hasPort('tcp/20211')) return `http://${host}:20211`;
      if (service.name === 'SSH' || hasPort('tcp/22')) return `ssh://${host}`;
      const tcpPort = ports.find(p => p.startsWith('tcp/'));
      return tcpPort ? `${currentProtocol}//${host}:${tcpPort.split('/')[1]}` : '';
    }
    function piholeToggleMarkup(label, key, enabled, extra = '') {
      return `
        <div class="item">
          <div class="switch-row">
            <div>
              <div class="item-title">${label}</div>
              <div class="muted">${extra || 'Toggle Pi-hole usage for this network.'}</div>
            </div>
            <label class="switch">
              <input type="checkbox" ${enabled ? 'checked' : ''} onchange="togglePiholeNetwork('${key}', this.checked)" />
              <span class="slider"></span>
            </label>
          </div>
        </div>
      `;
    }
    async function togglePiholeNetwork(key, enabled) {
      const payload = {};
      payload[key] = enabled;
      const ok = await postAction('/api/pihole/networks', null, payload);
      if (ok) await render();
    }
    async function restartSystem() {
      if (!confirm('Restart the device now?')) return;
      const ok = await postAction('/api/system/restart', 'Failed to restart the device');
      if (ok) alert('Restart command sent.');
    }
    async function powerOffSystem() {
      if (!confirm('Power off the device now?')) return;
      const ok = await postAction('/api/system/poweroff', 'Failed to power off the device');
      if (ok) alert('Power off command sent.');
    }
    async function saveMainLanConfigPreview() {
      const payload = collectMainLanPayload();
      await openCommandOverlay('Save Main LAN Config', '/api/main-lan/preview', payload, async (edited) => {
        await fetchJSON('/api/main-lan/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(edited) });
        clearDraft('main_lan.');
        await render();
      }, 'Edit the request if you want, then save the profile values.');
    }
    async function applyMainLanPreview() {
      const payload = collectMainLanPayload();
      await openCommandOverlay('Apply Main LAN', '/api/main-lan/preview', payload, async (edited) => {
        await fetchJSON('/api/main-lan/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(edited) });
        await fetchJSON('/api/main-lan/apply', { method: 'POST' });
        clearDraft('main_lan.');
        await render();
      }, 'This saves your current draft and immediately applies it.');
    }
    async function saveServiceLanConfigPreview() {
      const payload = collectServiceLanPayload();
      await openCommandOverlay('Save Service LAN Config', '/api/service-lan/preview', payload, async (edited) => {
        await fetchJSON('/api/service-lan/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(edited) });
        clearDraft('service_lan.');
        await render();
      });
    }
    async function applyServiceLanPreview() {
      const payload = collectServiceLanPayload();
      await openCommandOverlay('Apply Service LAN', '/api/service-lan/preview', payload, async (edited) => {
        await fetchJSON('/api/service-lan/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(edited) });
        await fetchJSON('/api/service-lan/apply', { method: 'POST' });
        clearDraft('service_lan.');
        await render();
      });
    }
    async function saveWifiConfigPreview() {
      const payload = collectWifiPayload();
      await openCommandOverlay('Save Wireless Config', '/api/wifi/preview', payload, async (edited) => {
        await fetchJSON('/api/wifi/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(edited) });
        clearDraft('wifi.');
        await render();
      });
    }
    async function applyWifiPreview() {
      const payload = collectWifiPayload();
      await openCommandOverlay('Apply Wireless', '/api/wifi/preview', payload, async (edited) => {
        await fetchJSON('/api/wifi/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(edited) });
        await fetchJSON('/api/wifi/apply', { method: 'POST' });
        clearDraft('wifi.');
        await render();
      });
    }
    async function applyCellularApnPreview() {
      const payload = collectApnPayload();
      await openCommandOverlay('Apply Cellular APN', '/api/lte/apn/preview', payload, async (edited) => {
        await fetchJSON('/api/lte/apn/apply', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(edited) });
        await render();
      }, 'This will modify the active cellular connection and reconnect it.');
    }
    async function setUplinkPreference(value) {
      const ok = await postAction('/api/wifi/config', 'Failed to update uplink preference', { uplink_preference: value });
      if (ok) await render();
    }
    async function toggleAutoApn(enabled) {
      const ok = await postAction('/api/lte/apn/auto', 'Failed to update auto apply', { enabled });
      if (ok) await render();
    }
    async function setLinkState(name, state) {
      const ok = await postAction(`/api/interfaces/${name}/link/${state}`, `Failed to set ${name} ${state}`);
      if (ok) await render();
    }
    async function toggleLinkState(name, enabled) {
      const pendingKey = `link:${name}`;
      if (isTogglePending(pendingKey)) return;
      setTogglePending(pendingKey, true);
      try {
        await setLinkState(name, enabled ? 'up' : 'down');
      } finally {
        setTogglePending(pendingKey, false);
        await render();
      }
    }
    async function restartLan(endpoint) {
      const ok = await postAction(endpoint, 'Failed to restart connection');
      if (ok) await render();
    }
    async function toggleLanInternet(endpoint) {
      const ok = await postAction(endpoint, 'Failed to change internet state');
      if (ok) await render();
    }
    async function toggleLanInternetState(kind, enabled) {
      const pendingKey = `internet:${kind}`;
      if (isTogglePending(pendingKey)) return;
      setTogglePending(pendingKey, true);
      const endpoint = kind === 'main'
        ? (enabled ? '/api/main-lan/internet/on' : '/api/main-lan/internet/off')
        : (enabled ? '/api/service-lan/internet/on' : '/api/service-lan/internet/off');
      try {
        await toggleLanInternet(endpoint);
      } finally {
        setTogglePending(pendingKey, false);
        await render();
      }
    }
    async function rescanWifi() {
      const ok = await postAction('/api/wifi/scan', 'Failed to rescan Wi-Fi');
      if (ok) await render();
    }
    async function setWifiPower(state) {
      const ok = await postAction(`/api/wifi/power/${state}`, `Failed to set Wi-Fi ${state}`);
      if (ok) await render();
    }
    async function toggleWifiPower(enabled) {
      const pendingKey = 'wifi:power';
      if (isTogglePending(pendingKey)) return;
      setTogglePending(pendingKey, true);
      try {
        await setWifiPower(enabled ? 'on' : 'off');
      } finally {
        setTogglePending(pendingKey, false);
        await render();
      }
    }
    async function setLedState(name, payload) {
      const ok = await postAction('/api/device-io/led', 'Failed to update LED', { name, ...payload });
      if (ok) await render();
    }
    async function controlSamba(action) {
      const ok = await fetchJSON('/api/samba/control', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action }) });
      if (ok) await render();
    }
    async function setSambaPassword() {
      const payload = { username: document.getElementById('samba-username').value, password: document.getElementById('samba-password').value };
      await fetchJSON('/api/samba/user/password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      await render();
    }
    async function setSambaUserState(username, action) {
      await fetchJSON('/api/samba/user/state', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, action }) });
      await render();
    }
    async function deleteSambaUser(username) {
      await fetchJSON('/api/samba/user/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username }) });
      await render();
    }
    async function saveSambaShare() {
      const payload = {
        name: document.getElementById('samba-share-name').value,
        path: document.getElementById('samba-share-path').value,
        read_only: document.getElementById('samba-share-readonly').value,
        guest_ok: document.getElementById('samba-share-guest').value,
        valid_users: document.getElementById('samba-share-users').value,
      };
      await fetchJSON('/api/samba/share', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      await render();
    }
    async function deleteSambaShare(name) {
      await fetchJSON('/api/samba/share/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) });
      await render();
    }
    async function controlPrinting(action) {
      await fetchJSON('/api/printing/control', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action }) });
      await render();
    }
    async function installNetAlertX() {
      if (!confirm('Install and start NetAlertX now?')) return;
      await fetchJSON('/api/netalert/install', { method: 'POST' });
      await render();
    }
    async function syncNetAlertX() {
      await fetchJSON('/api/netalert/sync', { method: 'POST' });
      await render();
    }
    async function runAtCommand() {
      const command = document.getElementById('at-command').value.trim();
      if (!command) return;
      try {
        const result = await fetchJSON('/api/lte/at', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ command }) });
        document.getElementById('at-output').textContent = demoMaskText([result.stdout, result.stderr].filter(Boolean).join('\n') || 'OK');
      } catch (err) {
        const message = String(err.message || 'AT command failed');
        document.getElementById('at-output').textContent = message.includes('debug mode')
          ? demoMaskText(`${message}\n\nHost note: ModemManager must allow debug AT commands first. Regular status queries will still work without it.`)
          : demoMaskText(message);
      }
    }
    function collectMainLanPayload() {
      const fieldValue = (id, fallback = '') => document.getElementById(id)?.value ?? fallback;
      return {
        role: fieldValue('main-lan-role'),
        ipv4_mode: fieldValue('main-lan-ipv4-mode'),
        ipv4_address: fieldValue('main-lan-ipv4-address'),
        ipv4_subnet: fieldValue('main-lan-ipv4-subnet'),
        dhcp_range: fieldValue('main-lan-dhcp-range'),
        ipv6_mode: fieldValue('main-lan-ipv6-mode'),
        ipv6_address: fieldValue('main-lan-ipv6-address'),
        ipv6_prefix: fieldValue('main-lan-ipv6-prefix'),
        dns_servers: fieldValue('main-lan-dns-servers'),
        use_pihole_dns: document.getElementById('main-lan-pihole-toggle').checked ? 'true' : 'false',
      };
    }
    function collectServiceLanPayload() {
      const fieldValue = (id, fallback = '') => document.getElementById(id)?.value ?? fallback;
      return {
        role: fieldValue('service-lan-role'),
        ipv4_mode: fieldValue('service-lan-ipv4-mode'),
        ipv4_gateway: fieldValue('service-lan-ipv4-gateway'),
        ipv4_subnet: fieldValue('service-lan-ipv4-subnet'),
        dhcp_range: fieldValue('service-lan-dhcp-range'),
        ipv6_mode: fieldValue('service-lan-ipv6-mode'),
        ipv6_gateway: fieldValue('service-lan-ipv6-gateway'),
        ipv6_prefix: fieldValue('service-lan-ipv6-prefix'),
        dns_servers: fieldValue('service-lan-dns-servers'),
        use_pihole_dns: document.getElementById('service-lan-pihole-toggle').checked ? 'true' : 'false',
      };
    }
    function collectWifiPayload() {
      const fieldValue = (id, fallback = '') => document.getElementById(id)?.value ?? fallback;
      return {
        mode: fieldValue('wifi-mode'),
        client_trust_mode: fieldValue('wifi-client-trust-mode', 'normal'),
        ssid: fieldValue('wifi-ssid'),
        password: fieldValue('wifi-password'),
        hotspot_ssid: fieldValue('wifi-hotspot-ssid'),
        hotspot_password: fieldValue('wifi-hotspot-password'),
        hotspot_security: fieldValue('wifi-hotspot-security', 'wpa2-personal'),
        country: fieldValue('wifi-country', 'DE'),
        band: fieldValue('wifi-band', '2.4ghz'),
        channel: fieldValue('wifi-channel', 'auto'),
        uplink_preference: fieldValue('wifi-uplink-preference', (((window.appState || {}).wifi || {}).config || {}).uplink_preference || 'prefer-lte'),
        ipv4_method: fieldValue('wifi-ipv4-method'),
        ipv4_address: fieldValue('wifi-ipv4-address'),
        ipv6_method: fieldValue('wifi-ipv6-method'),
        ipv6_address: fieldValue('wifi-ipv6-address'),
        use_pihole_dns: document.getElementById('wifi-pihole-toggle').checked ? 'true' : 'false',
      };
    }
    function collectApnPayload() {
      return {
        profile_id: document.getElementById('cellular-apn-profile').value,
        apn: document.getElementById('cellular-apn-custom').value,
        ipv4_method: document.getElementById('cellular-ipv4-method').value,
        ipv6_method: document.getElementById('cellular-ipv6-method').value,
        remember: document.getElementById('cellular-apn-remember').checked ? 'true' : 'false',
      };
    }
    function stateTone(state) {
      const value = String(state || '').toLowerCase();
      if (['up', 'connected', 'activated', 'online', 'active', 'yes'].some(token => value.includes(token))) return 'online';
      if (['down', 'failed', 'offline', 'disconnected', 'no'].some(token => value.includes(token))) return 'offline';
      return 'standby';
    }
    function renderFlowNode(kind, title, detail, state, positionClass) {
      return `
        <div class="flow-node ${kind} ${stateTone(state)} ${positionClass}">
          <span class="flow-dot"></span>
          <div>
            <div class="flow-title">${escapeHtml(title)}</div>
            <div class="flow-detail">${escapeHtml(detail || '-')}</div>
          </div>
        </div>
      `;
    }
    function renderNetworkCanvas(overview, systemStats, activeSessions) {
      const defaultDev = (overview.uplink_ipv4 || {}).dev || (overview.uplink_ipv6 || {}).dev || '';
      const uplink = (overview.uplinks || []).find(i => i.name === defaultDev) || (overview.uplinks || [])[0] || {};
      const localLans = overview.local_lans || [];
      const lan = localLans.find(i => String(i.role || '').includes('lan')) || localLans[0] || {};
      const wifi = (overview.uplinks || []).find(i => String(i.role || '').includes('wifi')) || localLans.find(i => String(i.name || '').startsWith('wl')) || {};
      const docker = (systemStats.docker || {}).running ?? 0;
      const sessions = sessionCount(activeSessions);
      const routeLabel = defaultDev ? `${defaultDev} -> ${(overview.uplink_ipv4 || {}).via || 'default'}` : 'No default route';
      return `
        <div class="network-canvas" aria-label="Network flow overview">
          <div class="flow-line flow-line-uplink"></div>
          <div class="flow-line flow-line-lan"></div>
          <div class="flow-line flow-line-wifi"></div>
          <div class="flow-line flow-line-services"></div>
          <div class="flow-packet packet-uplink"></div>
          <div class="flow-packet packet-lan"></div>
          <div class="flow-packet packet-services"></div>
          ${renderFlowNode('internet', 'Internet', routeLabel, uplink.state || defaultDev, 'pos-internet')}
          ${renderFlowNode('core', overview.hostname || 'R1000', 'Network panel gateway', 'online', 'pos-core')}
          ${renderFlowNode('lan', 'LAN', `${lan.name || lan.interface || 'local'} / ${(lan.ipv4 || [])[0] || 'no IPv4'}`, lan.state, 'pos-lan')}
          ${renderFlowNode('wifi', 'Wireless', `${wifi.name || wifi.interface || 'radio'} / ${wifi.role || 'standby'}`, wifi.state, 'pos-wifi')}
          ${renderFlowNode('services', 'Services', `${docker} containers / ${sessions} sessions`, docker ? 'active' : 'standby', 'pos-services')}
        </div>
      `;
    }
    function renderStatusPill(label, state) {
      return `<span class="status-pill ${stateTone(state)}"><span class="status-light"></span>${escapeHtml(label)}</span>`;
    }
    function renderInterfaceSummary(interfaces) {
      return (interfaces || []).map(i => {
        const role = i.role ? ` ${escapeHtml(i.role)}` : '';
        return `<div class="line-entry"><span>${escapeHtml(i.name)}${role}</span>${renderStatusPill(i.state || '-', i.state)}</div>`;
      }).join('') || '<span class="muted">No active uplink detected</span>';
    }
    function renderLanSummary(interfaces) {
      return (interfaces || []).map(i => {
        const addresses = `${(i.ipv4 || []).join(', ') || 'no IPv4'} | ${(i.ipv6 || []).join(', ') || 'no IPv6'}`;
        return `<div class="line-entry"><span>${escapeHtml(i.name)}: ${escapeHtml(addresses)}</span>${renderStatusPill(i.state || '-', i.state)}</div>`;
      }).join('') || '<span class="muted">No LAN ports detected</span>';
    }
    function renderClientSummary(clients) {
      return (clients || []).length ? `<div class="item-list compact">${clients.slice(0, 6).map(c => `<div class="item client-item"><div class="item-top"><div class="item-title">${escapeHtml(c.hostname || c.mac || 'Client')}</div>${renderStatusPill(c.state || 'seen', c.state || 'online')}</div><div class="muted">IP: ${escapeHtml(c.ip || '-')} | MAC: ${escapeHtml(c.mac || '-')} | ${escapeHtml(c.interface || '-')}</div></div>`).join('')}</div>` : '<div class="muted">No service LAN clients detected</div>';
    }
    function renderOverview(overview, systemStats, activeSessions, serviceLanClients = []) {
      const hw = overview.hardware || {};
      const mem = systemStats.memory || {};
      const load = systemStats.load || {};
      const docker = systemStats.docker || {};
      return `
        ${renderNetworkCanvas(overview, systemStats, activeSessions)}
        <div class="stat-grid">
          <div class="metric"><div class="label">Hostname</div><div class="value">${escapeHtml(overview.hostname)}</div></div>
          <div class="metric" onclick="cycleUptimeMode()" style="cursor:pointer;"><div class="label">Uptime</div><div class="value">${fmtUptime(overview.uptime_seconds || 0)}</div><div class="hint">Click to cycle format</div></div>
          <div class="metric"><div class="label">CPU Temp</div><div class="value small">${hw.cpu_temp_c ?? '-'}</div></div>
          <div class="metric"><div class="label">NVMe Temp</div><div class="value small">${hw.nvme_temp_c ?? '-'}</div></div>
          <div class="metric"><div class="label">Memory Used</div><div class="value small">${mem.used_mb ?? '-'} MB</div></div>
          <div class="metric"><div class="label">Memory Percent</div><div class="value small">${mem.used_percent ?? '-'}%</div></div>
          <div class="metric"><div class="label">Load</div><div class="value small">${load.load_1 || '-'} / ${load.load_5 || '-'} / ${load.load_15 || '-'}</div></div>
          <div class="metric"><div class="label">Docker Running</div><div class="value">${docker.running ?? 0}</div></div>
        </div>
        <div class="route"><div class="label">IPv4 Default Route</div><div>${escapeHtml((overview.uplink_ipv4 || {}).dev || '-')} via ${escapeHtml((overview.uplink_ipv4 || {}).via || '-')} ${escapeHtml((overview.uplink_ipv4 || {}).src || '')}</div></div>
        <div class="route"><div class="label">IPv6 Default Route</div><div>${escapeHtml((overview.uplink_ipv6 || {}).dev || '-')} via ${escapeHtml((overview.uplink_ipv6 || {}).via || '-')} ${escapeHtml((overview.uplink_ipv6 || {}).src || '')}</div></div>
        <div class="route"><div class="label">Detected Uplinks</div><div class="line-list">${renderInterfaceSummary(overview.uplinks)}</div></div>
        <div class="route"><div class="label">Local LAN Ports</div><div class="line-list">${renderLanSummary(overview.local_lans)}</div></div>
        <div class="route"><div class="label">Service LAN Clients</div>${renderClientSummary(serviceLanClients)}</div>
        <div class="route"><div class="label">Dashboard Sessions</div><div>${(activeSessions || []).slice(0, 5).map(s => `${escapeHtml(s.entry || s.service)}: ${escapeHtml(s.peer_address)} -> ${escapeHtml(s.local_address)}:${escapeHtml(s.local_port)}`).join('<br>') || 'No active sessions detected'}</div></div>
      `;
    }
    function renderDockerBrief(systemStats) {
      const docker = systemStats.docker || {};
      if (!docker.available) return '<div class="muted">Docker not available</div>';
      return (docker.containers || []).length ? `<div class="item-list">${docker.containers.slice(0, 8).map(c => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(c.name)}</div><div class="badge">${escapeHtml(c.status)}</div></div><div class="muted">${escapeHtml(c.image)}</div></div>`).join('')}</div>` : '<div class="muted">No containers running</div>';
    }
    function renderSessions(sessions) {
      const deduped = [];
      const seen = new Set();
      (sessions || []).forEach(session => {
        const key = [
          session.entry || session.service || '',
          session.interface || '',
          session.peer_address || '',
          session.family || '',
        ].join('|');
        if (seen.has(key)) return;
        seen.add(key);
        deduped.push(session);
      });
      return deduped.length ? `<div class="item-list">${deduped.slice(0, 8).map(s => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(s.entry || s.service)}</div><div class="badge">${escapeHtml(s.interface || '-')}</div></div><div class="muted">${escapeHtml(s.peer_address)}:${escapeHtml(s.peer_port)} -> ${escapeHtml(s.local_address)}:${escapeHtml(s.local_port)}</div></div>`).join('')}</div>` : '<div class="muted">No active sessions detected</div>';
    }
    function sessionCount(sessions) {
      const seen = new Set();
      (sessions || []).forEach(session => {
        const key = [
          session.entry || session.service || '',
          session.interface || '',
          session.peer_address || '',
          session.family || '',
        ].join('|');
        seen.add(key);
      });
      return seen.size;
    }
    function sessionCountClass(count) {
      if (count <= 0) return 'badge session-count idle';
      if (count <= 3) return 'badge session-count low';
      return 'badge session-count busy';
    }
    function ipv4ModeLabel(mode) {
      if (mode === 'auto') return 'Auto';
      if (mode === 'shared') return 'DHCP';
      if (mode === 'manual') return 'Static';
      return 'Disabled';
    }
    function ipv6ModeLabel(mode) {
      if (mode === 'auto') return 'Auto';
      if (mode === 'shared') return 'DHCP / RA';
      if (mode === 'routed') return 'RA / Routed';
      if (mode === 'manual') return 'Static';
      return 'Disabled';
    }
    function wifiBandLabel(mode) {
      if (mode === '2.4ghz') return '2.4 GHz';
      if (mode === '5ghz') return '5 GHz';
      return '2.4 GHz';
    }
    function wifiHotspotIpv6Label(mode) {
      if (mode === 'shared') return 'DHCP / RA';
      if (mode === 'manual') return 'Routed';
      return 'Disabled';
    }
    function wifiChannelOptions(band) {
      const channels24 = ['auto','1','6','11'];
      const channels5 = ['auto','36','40','44','48','100','104','108','112','116','120','124','128','132','136','140'];
      if (band === '2.4ghz') return channels24;
      if (band === '5ghz') return channels5;
      return channels24;
    }
    function setLanStackDisabled(kind) {
      appState.drafts[`${kind}_lan.ipv4_mode`] = 'disabled';
      appState.drafts[`${kind}_lan.ipv6_mode`] = 'disabled';
      updateRefreshState();
      render();
    }
    function lanRoleExplanation(role) {
      if (role === 'isolated') {
        return `
          <div class="item">
            <div class="item-title">Isolated</div>
            <div class="muted">Internet works for clients, but access to Main LAN, Wi-Fi, Tailscale, and most device services is blocked.</div>
          </div>
        `;
      }
      if (role === 'external') {
        return `
          <div class="item">
            <div class="item-title">External</div>
            <div class="muted">Clients get internet and stay away from Main LAN. Tailscale-connected devices can still reach the router and this external segment for management.</div>
          </div>
        `;
      }
      return `
        <div class="item">
          <div class="item-title">Internal</div>
          <div class="muted">Trusted LAN. Clients can use local services, management pages, and other internal networks.</div>
        </div>
      `;
    }
    function renderPortBoard(title, subtitle, status, ports = []) {
      const portItems = Array.from({ length: 12 }, (_, index) => {
        const active = index < Math.max(1, Math.min(ports.length || 4, 12));
        return `<span class="visual-port ${active ? 'active' : ''}"></span>`;
      }).join('');
      return `
        <div class="port-visual-card">
          <div class="rail-card floating-service">
            <div class="rail-card-head">
              <span class="rail-icon">${escapeHtml(title.slice(0, 2).toUpperCase())}</span>
              <div>
                <div class="rail-title">${escapeHtml(title)}</div>
                <div class="rail-subtitle">${escapeHtml(subtitle || '-')}</div>
              </div>
            </div>
            <div class="rail-status"><span class="flow-dot"></span>${escapeHtml(status || 'Online')}</div>
          </div>
          <div class="port-board" aria-hidden="true">${portItems}</div>
        </div>
      `;
    }
    function renderLanCard(kind, profile) {
      const prefix = kind === 'main' ? 'main-lan' : 'service-lan';
      const applyFn = kind === 'main' ? 'applyMainLanPreview()' : 'applyServiceLanPreview()';
      const restartFn = kind === 'main' ? `restartLan('/api/main-lan/restart')` : `restartLan('/api/service-lan/restart')`;
      const isServiceLan = kind === 'service';
      const ipv4Address = kind === 'main' ? (profile.ipv4_address || '') : (profile.gateway_ipv4 || '');
      const ipv6Address = kind === 'main' ? (profile.ipv6_address || '') : (profile.gateway_ipv6 || '');
      const internetPending = isTogglePending(`internet:${kind}`);
      const ipv4Mode = draftValue(`${kind}_lan.ipv4_mode`, profile.ipv4_mode || 'shared');
      const ipv6Mode = draftValue(`${kind}_lan.ipv6_mode`, profile.ipv6_mode || 'disabled');
      const role = draftValue(`${kind}_lan.role`, profile.role || 'internal');
      const ipv4Summary = ipv4Mode === 'shared' ? 'DHCP ON' : ipv4Mode === 'manual' ? 'Static IPv4' : 'IPv4 Disabled';
      const ipv6Summary = ipv6Mode === 'routed' ? 'RA ON' : ipv6Mode === 'manual' ? 'Static IPv6' : 'IPv6 Disabled';
      const liveIpv4Summary = kind === 'main'
        ? (profile.connection?.['ipv4.method'] === 'shared'
            ? 'DHCP ON'
            : profile.connection?.['ipv4.method'] === 'manual'
              ? 'Static IPv4'
              : 'IPv4 Disabled')
        : (profile.dhcp_listener_active ? 'DHCP ON' : 'DHCP OFF');
      const liveIpv6Summary = kind === 'main'
        ? (profile.connection?.['ipv6.method'] === 'disabled'
            ? 'IPv6 Disabled'
            : 'Static / Routed IPv6')
        : (profile.router_advertisements_active ? 'RA ON' : 'RA OFF');
      const liveAddressing = `${liveIpv4Summary} / ${liveIpv6Summary}`;
      const desiredAddressing = `${ipv4Summary} / ${ipv6Summary}`;
      const iface = profile.target_interface || profile.interface || '-';
      return `
        ${renderPortBoard(kind === 'main' ? 'Main LAN' : 'Service LAN', `${iface} / ${desiredAddressing}`, ((profile.target_interface_status || {}).state) || (profile.internet_enabled ? 'Online' : 'Standby'), [iface])}
        <div class="stat-grid">
          <div class="metric"><div class="label">Assigned Port</div><div class="value small">${escapeHtml(iface)}</div></div>
          <div class="metric"><div class="label">State</div><div class="value small">${escapeHtml(((profile.target_interface_status || {}).state) || '-')}</div></div>
          <div class="metric"><div class="label">Internet</div><div class="switch-row" style="margin-top:8px;"><div class="muted">${internetPending ? 'Working...' : (profile.internet_enabled ? 'Enabled' : 'Disabled')}</div><label class="switch ${internetPending ? 'busy' : ''}"><input type="checkbox" ${profile.internet_enabled ? 'checked' : ''} ${internetPending ? 'disabled' : ''} onchange="toggleLanInternetState('${kind}', this.checked)"><span class="slider"></span></label></div></div>
          <div class="metric"><div class="label">Pi-hole</div><div class="value small">${profile.use_pihole_dns ? 'ON' : 'OFF'}</div></div>
        </div>
        <details class="config-section">
          <summary><span>Basic</span><span>${escapeHtml(role)} / ${escapeHtml(iface)}</span></summary>
          <div class="stat-grid" style="margin-top:10px;">
            <div class="metric"><div class="label">Role</div><select id="${prefix}-role">${['isolated', 'internal', 'external'].map(v => `<option value="${v}" ${role === v ? 'selected' : ''}>${v}</option>`).join('')}</select></div>
            <div class="metric"><div class="label">Desired State</div><div class="value small">${escapeHtml(desiredAddressing)}</div></div>
            <div class="metric"><div class="label">Live State</div><div class="value small">${escapeHtml(liveAddressing)}</div></div>
          </div>
        </details>
        <details class="config-section">
          <summary><span>Role Behavior</span><span>${escapeHtml(role)}</span></summary>
          <div class="item-list" style="margin-top:10px;">${lanRoleExplanation(role)}</div>
        </details>
        <details class="config-section">
          <summary><span>Addressing</span><span>${escapeHtml(desiredAddressing)}</span></summary>
          <div class="controls"><button class="secondary" onclick="setLanStackDisabled('${kind}')">Disable IPv4 + IPv6</button></div>
          <div class="stat-grid" style="margin-top:10px;">
            <div class="metric"><div class="label">IPv4 Mode</div><select id="${prefix}-ipv4-mode">${(isServiceLan ? ['shared','disabled'] : ['shared','manual','disabled']).map(v => `<option value="${v}" ${ipv4Mode === v ? 'selected' : ''}>${ipv4ModeLabel(v)}</option>`).join('')}</select></div>
            ${ipv4Mode !== 'disabled' ? `<div class="metric"><div class="label">${kind === 'main' ? 'IPv4 Address' : 'IPv4 Gateway'}</div><input id="${prefix}-${kind === 'main' ? 'ipv4-address' : 'ipv4-gateway'}" value="${draftValue(`${kind}_lan.${kind === 'main' ? 'ipv4_address' : 'ipv4_gateway'}`, ipv4Address)}" /></div>` : ''}
            ${ipv4Mode !== 'disabled' ? `<div class="metric"><div class="label">IPv4 Block</div><input id="${prefix}-ipv4-subnet" value="${draftValue(`${kind}_lan.ipv4_subnet`, profile.ipv4_subnet || '')}" /></div>` : ''}
            ${ipv4Mode === 'shared' ? `<div class="metric"><div class="label">DHCP Range</div><input id="${prefix}-dhcp-range" value="${draftValue(`${kind}_lan.dhcp_range`, profile.dhcp_range || profile.dhcp_range_ipv4 || '')}" /></div>` : ''}
            <div class="metric"><div class="label">IPv6 Mode</div><select id="${prefix}-ipv6-mode">${(isServiceLan ? ['routed','disabled'] : ['routed','manual','disabled']).map(v => `<option value="${v}" ${ipv6Mode === v ? 'selected' : ''}>${ipv6ModeLabel(v)}</option>`).join('')}</select></div>
            ${ipv6Mode !== 'disabled' ? `<div class="metric"><div class="label">${kind === 'main' ? 'IPv6 Address' : 'IPv6 Gateway'}</div><input id="${prefix}-${kind === 'main' ? 'ipv6-address' : 'ipv6-gateway'}" value="${draftValue(`${kind}_lan.${kind === 'main' ? 'ipv6_address' : 'ipv6_gateway'}`, ipv6Address)}" /></div>` : ''}
            ${ipv6Mode !== 'disabled' ? `<div class="metric"><div class="label">IPv6 Prefix</div><input id="${prefix}-ipv6-prefix" value="${draftValue(`${kind}_lan.ipv6_prefix`, profile.ipv6_prefix || profile.prefix_ipv6 || '')}" /></div>` : ''}
          </div>
        </details>
        <details class="config-section">
          <summary><span>DNS</span><span>${profile.use_pihole_dns ? 'Pi-hole ON' : 'Pi-hole OFF'}</span></summary>
          <div class="stat-grid" style="margin-top:10px;">
            <div class="metric"><div class="label">DNS Servers</div><input id="${prefix}-dns-servers" value="${draftValue(`${kind}_lan.dns_servers`, (profile.dns_servers || []).join(', '))}" /></div>
            <div class="metric"><div class="label">Pi-hole Policy</div>
              <div class="switch-row" style="margin-top:8px;">
                <div class="muted">Use Pi-hole on this LAN</div>
                <label class="switch"><input id="${prefix}-pihole-toggle" type="checkbox" ${profile.use_pihole_dns ? 'checked' : ''}><span class="slider"></span></label>
              </div>
            </div>
            <div class="metric"><div class="label">Desired DHCP / RA</div><div class="value small">${escapeHtml(desiredAddressing)}</div></div>
            <div class="metric"><div class="label">Live DHCP / RA</div><div class="value small">${escapeHtml(liveAddressing)}</div></div>
            <div class="metric"><div class="label">Current DNS Flow</div><div class="value small">${escapeHtml((profile.dns_servers || []).join(', ') || '-')}</div></div>
          </div>
        </details>
        <div class="controls">
          <button onclick="${applyFn}">Apply Config</button>
          <button class="secondary" onclick="${restartFn}">Restart Connection</button>
        </div>
        <div class="hint">${(profile.notes || []).filter(note => !note.toLowerCase().includes('plugging in a usb ethernet adapter')).join(' ')}</div>
      `;
    }
    function categorizeInterfaces(interfaces) {
      return {
        uplinks: interfaces.filter(i => i.role === 'cellular' || i.role === 'overlay'),
        lan: interfaces.filter(i => i.physical && i.role === 'ethernet'),
        wireless: interfaces.filter(i => i.role === 'wifi'),
        virtual: interfaces.filter(i => !i.physical && !['overlay'].includes(i.role)),
      };
    }
    function renderInterfaceGroup(title, items) {
      return `<div class="route"><div class="label">${escapeHtml(title)}</div><div class="item-list" style="margin-top:10px;">${items.length ? items.map(i => {
        const linkPending = isTogglePending(`link:${i.name}`);
        const linkEnabled = ['up', 'unknown'].includes(String(i.state || '').toLowerCase());
        return `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(i.name)}</div><div class="badge">${escapeHtml(i.state)}</div></div><div class="muted">Role: ${escapeHtml(i.role || '-')} | MAC: ${escapeHtml(i.mac || '-')} | MTU: ${escapeHtml(i.mtu || '-')}</div><div class="muted">IPv4: ${(i.ipv4 || []).join(', ') || '-'} </div><div class="muted">IPv6: ${(i.ipv6 || []).join(', ') || '-'} </div>${i.physical ? `<div class="route"><div class="switch-row"><div><div class="label">Link State</div><div class="muted">${linkPending ? 'Working...' : escapeHtml(i.state || '-')}</div></div><label class="switch ${linkPending ? 'busy' : ''}"><input type="checkbox" ${linkEnabled ? 'checked' : ''} ${linkPending ? 'disabled' : ''} onchange="toggleLinkState('${i.name}', this.checked)"><span class="slider"></span></label></div></div>` : ''}</div>`;
      }).join('') : '<div class="muted">No interfaces in this group</div>'}</div></div>`;
    }
    function renderWireless(wifi, interfaces, wifiClients, piholeNetworks, overview) {
      const wifiPowerPending = isTogglePending('wifi:power');
      const wifiRadioOn = String((wifi.device || {}).wifi_radio || '').toLowerCase() === 'enabled';
      const wifiMode = draftValue('wifi.mode', wifi.config.mode);
      const wifiIpv4Method = draftValue('wifi.ipv4_method', wifi.config.ipv4_method || 'auto');
      const wifiIpv6Method = draftValue('wifi.ipv6_method', wifi.config.ipv6_method || 'disabled');
      const wifiClientTrustMode = draftValue('wifi.client_trust_mode', wifi.config.client_trust_mode || 'normal');
      const wifiBand = draftValue('wifi.band', wifi.config.band || '2.4ghz');
      const wifiChannel = draftValue('wifi.channel', wifi.config.channel || 'auto');
      const hotspotSecurity = draftValue('wifi.hotspot_security', wifi.config.hotspot_security || 'wpa2-personal');
      const channelOptions = wifiChannelOptions(wifiBand);
      return `
        ${renderPortBoard('Wireless', `${wifi.interface || 'radio'} / ${wifiMode === 'hotspot' ? 'Hotspot' : 'Client'}`, (wifi.device || {}).wifi_radio || (wifi.device || {}).state || 'Standby', [wifi.interface || 'wifi'])}
        <div class="stat-grid">
          <div class="metric"><div class="label">Interface</div><div class="value small">${escapeHtml(wifi.interface)}</div></div>
          <div class="metric"><div class="label">Active Mode</div><div class="value small">${escapeHtml((wifi.active || {}).mode || '-')}</div></div>
          <div class="metric"><div class="label">Security</div><div class="value small">${escapeHtml((wifi.active || {}).security || wifi.config.hotspot_security || '-')}</div></div>
          <div class="metric"><div class="label">Radio</div><div class="switch-row" style="margin-top:8px;"><div class="muted">${wifiPowerPending ? 'Working...' : escapeHtml((wifi.device || {}).wifi_radio || '-')}</div><label class="switch ${wifiPowerPending ? 'busy' : ''}"><input type="checkbox" ${wifiRadioOn ? 'checked' : ''} ${wifiPowerPending ? 'disabled' : ''} onchange="toggleWifiPower(this.checked)"><span class="slider"></span></label></div></div>
        </div>
        <details class="config-section" open>
          <summary><span>Live Wireless State</span><span>${escapeHtml((wifi.active || {}).mode || wifiMode)}</span></summary>
          <div class="stat-grid" style="margin-top:10px;">
            <div class="metric"><div class="label">Connection</div><div class="value small">${escapeHtml((wifi.active || {}).connection || (wifi.device || {}).nm_connection || '-')}</div></div>
            <div class="metric"><div class="label">SSID</div><div class="value small">${escapeHtml((wifi.active || {}).ssid || '-')}</div></div>
            <div class="metric"><div class="label">Country</div><div class="value small">${escapeHtml(wifi.country || '-')}</div></div>
            <div class="metric"><div class="label">Band</div><div class="value small">${escapeHtml((wifi.active || {}).band || wifiBandLabel(wifi.config.band || '2.4ghz'))}</div></div>
            <div class="metric"><div class="label">Channel</div><div class="value small">${escapeHtml((wifi.active || {}).channel || wifi.config.channel || '-')}</div></div>
            <div class="metric"><div class="label">IPv4</div><div class="value small">${escapeHtml(((wifi.device || {}).ipv4 || []).join(', ') || '-')}</div></div>
            <div class="metric"><div class="label">IPv6</div><div class="value small">${escapeHtml(((wifi.device || {}).ipv6 || []).join(', ') || '-')}</div></div>
          </div>
        </details>
        <details class="config-section">
          <summary><span>Config</span><span>${escapeHtml(wifiMode)} / ${escapeHtml(wifiBandLabel(wifiBand))}</span></summary>
          <div class="stat-grid" style="margin-top:10px;">
            <div class="metric"><div class="label">Mode</div><select id="wifi-mode">${['client','hotspot'].map(v => `<option value="${v}" ${wifiMode === v ? 'selected' : ''}>${v}</option>`).join('')}</select></div>
            <div class="metric"><div class="label">Country</div><select id="wifi-country">${['DE','TR','US','GB','NL','FR'].map(v => `<option value="${v}" ${draftValue('wifi.country', wifi.config.country || wifi.country || 'DE') === v ? 'selected' : ''}>${v}</option>`).join('')}</select></div>
            <div class="metric"><div class="label">Client Trust</div><select id="wifi-client-trust-mode" ${wifiMode === 'client' ? '' : 'disabled'}>${[{id:'normal',label:'Normal'},{id:'isolated',label:'Isolated'}].map(v => `<option value="${v.id}" ${wifiClientTrustMode === v.id ? 'selected' : ''}>${v.label}</option>`).join('')}</select></div>
            ${wifiMode === 'client' ? `<div class="metric"><div class="label">Client SSID</div><input id="wifi-ssid" value="${draftValue('wifi.ssid', wifi.config.ssid || '')}" /></div>` : ''}
            ${wifiMode === 'client' ? `<div class="metric"><div class="label">Client Password</div><input id="wifi-password" type="password" value="${draftValue('wifi.password', '')}" /></div>` : ''}
            ${wifiMode === 'hotspot' ? `<div class="metric"><div class="label">Hotspot SSID</div><input id="wifi-hotspot-ssid" value="${draftValue('wifi.hotspot_ssid', wifi.config.hotspot_ssid || '')}" /></div>` : ''}
            ${wifiMode === 'hotspot' ? `<div class="metric"><div class="label">Hotspot Password</div><input id="wifi-hotspot-password" type="password" value="${draftValue('wifi.hotspot_password', '')}" placeholder="Leave empty to keep current saved password" /></div>` : ''}
            ${wifiMode === 'hotspot' ? `<div class="metric"><div class="label">Security Profile</div><select id="wifi-hotspot-security">${[{id:'wpa3-personal',label:'WPA3-Personal'},{id:'wpa2-personal',label:'WPA2-Personal'},{id:'open',label:'Open'}].map(v => `<option value="${v.id}" ${hotspotSecurity === v.id ? 'selected' : ''}>${v.label}</option>`).join('')}</select></div>` : ''}
            ${wifiMode === 'hotspot' ? `<div class="metric"><div class="label">Band</div><select id="wifi-band">${[{id:'2.4ghz',label:'2.4 GHz'},{id:'5ghz',label:'5 GHz'}].map(v => `<option value="${v.id}" ${wifiBand === v.id ? 'selected' : ''}>${v.label}</option>`).join('')}</select></div>` : ''}
            ${wifiMode === 'hotspot' ? `<div class="metric"><div class="label">Channel</div><select id="wifi-channel">${channelOptions.map(v => `<option value="${v}" ${wifiChannel === v ? 'selected' : ''}>${v === 'auto' ? 'Auto' : `Channel ${v}`}</option>`).join('')}</select></div>` : ''}
            <div class="metric"><div class="label">IPv4 Mode</div><select id="wifi-ipv4-method">${(wifiMode === 'hotspot' ? ['shared','manual','disabled'] : ['auto','manual','disabled']).map(v => `<option value="${v}" ${wifiIpv4Method === v ? 'selected' : ''}>${ipv4ModeLabel(v)}</option>`).join('')}</select></div>
            ${wifiIpv4Method === 'manual' ? `<div class="metric"><div class="label">IPv4 Address</div><input id="wifi-ipv4-address" value="${draftValue('wifi.ipv4_address', wifi.config.ipv4_address || '')}" /></div>` : ''}
            <div class="metric"><div class="label">IPv6 Mode</div><select id="wifi-ipv6-method">${(wifiMode === 'hotspot' ? ['shared','manual','disabled'] : ['auto','manual','disabled']).map(v => `<option value="${v}" ${wifiIpv6Method === v ? 'selected' : ''}>${wifiMode === 'hotspot' ? wifiHotspotIpv6Label(v) : ipv6ModeLabel(v)}</option>`).join('')}</select></div>
            ${wifiIpv6Method === 'manual' ? `<div class="metric"><div class="label">IPv6 Address / Prefix</div><input id="wifi-ipv6-address" value="${draftValue('wifi.ipv6_address', wifi.config.ipv6_address || '')}" placeholder="fd42:42::1/64" /></div>` : ''}
            <div class="metric"><div class="label">Pi-hole</div><div class="switch-row" style="margin-top:8px;"><div class="muted">Use Pi-hole on Wi-Fi</div><label class="switch"><input id="wifi-pihole-toggle" type="checkbox" ${piholeNetworks.wifi ? 'checked' : ''}><span class="slider"></span></label></div></div>
          </div>
          <div class="hint">${wifiMode === 'client' ? (wifiClientTrustMode === 'isolated' ? 'Isolated client mode blocks inbound access from the upstream Wi-Fi and stops that uplink from reaching local LAN segments. It helps on hotel and public Wi-Fi, but it is not a VPN and does not by itself eliminate upstream MITM risk.' : 'Normal client mode behaves like a regular Wi-Fi client.') : 'Client Trust only applies in client mode. Switch Mode to client if you want to tune upstream Wi-Fi behavior.'}</div>
          <div class="controls"><button onclick="applyWifiPreview()">Apply Config</button><button class="secondary" onclick="rescanWifi()">Rescan</button></div>
        </details>
        <details class="config-section">
          <summary><span>Connected Wi-Fi Clients</span><span>${(wifiClients || []).length}</span></summary>
          <div class="item-list" style="margin-top:10px;">${(wifiClients || []).length ? wifiClients.map(c => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(c.hostname || c.mac || 'Client')}</div><div class="badge">${escapeHtml(c.interface || '-')}</div></div><div class="muted">Primary IP: ${escapeHtml(c.ip)} | MAC: ${escapeHtml(c.mac || '-')} | ${escapeHtml(c.state || '-')}</div>${c.secondary_ips ? `<div class="muted">Extra IPs: ${escapeHtml(c.secondary_ips)}</div>` : ''}</div>`).join('') : '<div class="muted">No Wi-Fi clients detected</div>'}</div>
        </details>
        <details class="config-section">
          <summary><span>Visible Wi-Fi Networks</span><span>${(wifi.scan || []).length}</span></summary>
          <div class="item-list" style="margin-top:10px;">${(wifi.scan || []).length ? wifi.scan.map(n => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(n.ssid)}</div><div class="badge">${escapeHtml(String(n.signal))}%</div></div><div class="muted">Channel ${escapeHtml(n.channel || '-')} | ${escapeHtml(n.security || 'open')} ${n.in_use ? '| connected' : ''}</div></div>`).join('') : '<div class="muted">No scan results</div>'}</div>
        </details>
        <details class="config-section">
          <summary><span>Radio Details</span><span>${escapeHtml((wifi.device || {}).wifi_radio || '-')}</span></summary>
          <div class="route"><div class="label">Wi-Fi Capabilities</div><div>${(wifi.capabilities || {}).band_2ghz === 'yes' ? '2.4 GHz ' : ''}${(wifi.capabilities || {}).band_5ghz === 'yes' ? '| 5 GHz ' : ''}${(wifi.capabilities || {}).ap === 'yes' ? '| AP mode ' : ''}${(wifi.capabilities || {}).wpa2 === 'yes' ? '| WPA2' : ''}</div></div>
          <div class="route"><div class="label">RFKill</div><div>${(wifi.rfkill || []).length ? wifi.rfkill.map(r => `${escapeHtml(r.name || r.type)}: soft=${escapeHtml(r.soft)} hard=${escapeHtml(r.hard)}`).join('<br>') : 'No rfkill entries'}</div></div>
        </details>
        <div class="hint">${(wifi.notes || []).join(' ')}</div>
      `;
    }
    function renderCellular(lte, lteProfile, lteOptions, lteSuggest, lteAuto, atExamples, overview) {
      const suggested = (lteSuggest.suggested || {});
      const rawProfile = lteProfile.raw_profile || '';
      const defaultDev = ((overview || {}).uplink_ipv4 || {}).dev || ((overview || {}).uplink_ipv6 || {}).dev || '';
      const cellularConnection = lteProfile.connection || '';
      const cellularIsDefaultUplink = ['wwan0', 'cdc-wdm0'].includes(defaultDev) || (cellularConnection && defaultDev && cellularConnection.includes(defaultDev));
      const wifiUplinkPreference = draftValue('wifi.uplink_preference', ((appState.wifi || {}).config || {}).uplink_preference || 'prefer-lte');
      const uplinkPreferenceControl = `<select id="cellular-uplink-preference" onchange="setUplinkPreference(this.value)">${[{id:'prefer-lte',label:'Prefer Cellular'},{id:'prefer-wifi',label:'Prefer Wi-Fi'},{id:'failover-only',label:'Failover Only'}].map(v => `<option value="${v.id}" ${wifiUplinkPreference === v.id ? 'selected' : ''}>${v.label}</option>`).join('')}</select>`;
      appState.rawProfile = rawProfile;
      return {
        state: !lte.available ? `<div class="stat-grid"><div class="metric"><div class="label">Modem</div><div class="value small">Not available</div></div><div class="metric"><div class="label">Uplink Preference</div>${uplinkPreferenceControl}</div></div>` : `
          <div class="stat-grid">
            <div class="metric"><div class="label">Operator</div><div class="value small">${escapeHtml(lte.operator_name || '-')} (${escapeHtml(lte.operator_mcc || '-')}${escapeHtml(lte.operator_mnc || '')})</div></div>
            <div class="metric"><div class="label">State</div><div class="value small">${escapeHtml(lte.state || '-')}</div></div>
            <div class="metric"><div class="label">Default Uplink</div><div class="value small">${cellularIsDefaultUplink ? 'Yes' : 'No'}</div></div>
            <div class="metric"><div class="label">Uplink Preference</div>${uplinkPreferenceControl}</div>
            <div class="metric"><div class="label">Access Tech</div><div class="value small">${escapeHtml(lte.access_tech || '-')}</div></div>
            <div class="metric"><div class="label">Signal</div><div class="value small">${escapeHtml(lte.signal_quality || '-')}</div></div>
            <div class="metric"><div class="label">RSRP</div><div class="value small">${escapeHtml(lte.rsrp || '-')}</div></div>
            <div class="metric"><div class="label">RSRQ</div><div class="value small">${escapeHtml(lte.rsrq || '-')}</div></div>
            <div class="metric"><div class="label">SNR</div><div class="value small">${escapeHtml(lte.snr || '-')}</div></div>
            <div class="metric"><div class="label">RSSI</div><div class="value small">${escapeHtml(lte.rssi || '-')}</div></div>
          </div>`,
        apn: `
          <div class="stat-grid">
            <div class="metric"><div class="label">Connection</div><div class="value small">${escapeHtml(lteProfile.connection || '-')}</div></div>
            <div class="metric"><div class="label">Current APN</div><div class="value small">${escapeHtml(lteProfile.apn || '-')}</div></div>
            <div class="metric"><div class="label">IPv4 Method</div><div class="value small">${escapeHtml(lteProfile.ipv4_method || '-')}</div></div>
            <div class="metric"><div class="label">IPv6 Method</div><div class="value small">${escapeHtml(lteProfile.ipv6_method || '-')}</div></div>
          </div>
          <div class="route"><div class="label">Preset Editor</div><div class="stat-grid" style="margin-top:10px;">
            <div class="metric"><div class="label">Auto Apply</div><div class="switch-row" style="margin-top:8px;"><div class="muted">Auto apply matching APN</div><label class="switch"><input type="checkbox" ${lteAuto.enabled ? 'checked' : ''} onchange="fetch('/api/lte/apn/auto',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:this.checked})}).then(()=>render())"><span class="slider"></span></label></div></div>
            <div class="metric"><div class="label">Provider Preset</div><select id="cellular-apn-profile">${(lteOptions.options || []).map(option => `<option value="${option.id}" ${draftValue('cellular.apn_profile', suggested.id || '') === option.id ? 'selected' : ''}>${escapeHtml(option.country)} / ${escapeHtml(option.provider)}</option>`).join('')}</select></div>
            <div class="metric"><div class="label">Manual APN</div><input id="cellular-apn-custom" value="${escapeHtml(draftValue('cellular.apn_custom', lteProfile.apn || suggested.apn || ''))}" /></div>
            <div class="metric"><div class="label">IPv4 Method</div><select id="cellular-ipv4-method">${['auto','disabled'].map(v => `<option value="${v}" ${draftValue('cellular.ipv4_method', lteProfile.ipv4_method || suggested.ipv4_method || 'auto') === v ? 'selected' : ''}>${v}</option>`).join('')}</select></div>
            <div class="metric"><div class="label">IPv6 Method</div><select id="cellular-ipv6-method">${['auto','disabled'].map(v => `<option value="${v}" ${draftValue('cellular.ipv6_method', lteProfile.ipv6_method || suggested.ipv6_method || 'auto') === v ? 'selected' : ''}>${v}</option>`).join('')}</select></div>
            <div class="metric"><div class="label">Remember For SIM</div><div class="switch-row" style="margin-top:8px;"><div class="muted">Store manual override</div><label class="switch"><input id="cellular-apn-remember" type="checkbox" ${draftValue('cellular.apn_remember', !!(lteSuggest.override && lteSuggest.override.apn)) ? 'checked' : ''}><span class="slider"></span></label></div></div>
          </div>
          <div class="controls"><button onclick="applyCellularApnPreview()">Apply Cellular APN</button></div>
          <div class="hint">Uplink Preference decides whether cellular stays primary, Wi-Fi takes priority, or Wi-Fi only takes over after cellular disappears. The APN editor shows the live cellular profile values.</div></div>
          <div class="route"><div class="label">Raw Connection Profile</div><div class="muted">Open the live connection dump in an overlay so auto refresh does not replace what you are reading.</div><div class="controls"><button class="secondary" onclick="openRawProfile()">Open Raw Profile</button></div></div>`,
        at: `
          <div class="hint">${escapeHtml(atExamples.disclaimer || 'AT commands can change modem state. Use carefully.')}</div>
          <div class="route"><div class="label">Examples</div><div class="tag-row">${(atExamples.commands || []).map(cmd => `<span class="mini-tag" onclick='document.getElementById("at-command").value=${JSON.stringify(cmd)}' style="cursor:pointer;">${escapeHtml(cmd)}</span>`).join('')}</div></div>
          <div class="route"><div class="label">AT Command</div><input id="at-command" placeholder='AT+QENG="servingcell"' /><div class="controls"><button onclick="runAtCommand()">Run AT Command</button></div></div>
          <div class="route"><div class="label">Output</div><div class="code-box"><pre id="at-output">No AT command executed yet.</pre></div><div class="hint">If ModemManager says debug mode is required, the command is blocked by the host modem policy rather than by this portal.</div></div>
        `,
      };
    }
    function renderPiHolePanel(pihole, piholeNetworks) {
      return `
        <div class="stat-grid">
          <div class="metric"><div class="label">Admin</div><div class="value small">${pihole.admin_reachable ? 'Reachable' : 'Offline'}</div></div>
          <div class="metric"><div class="label">DNS Binds</div><div class="value small">${escapeHtml((pihole.dns_binds || []).join(', ') || '-')}</div></div>
          <div class="metric"><div class="label">Forwarding</div><div class="value small">${pihole.dns_forwarding_enabled ? 'Enabled' : 'Disabled'}</div></div>
          <div class="metric"><div class="label">Container IP</div><div class="value small">${escapeHtml(pihole.container_ip || '-')}</div></div>
        </div>
        <div class="route"><div class="label">Network Toggles</div><div class="item-list" style="margin-top:10px;">
          ${piholeToggleMarkup('Main LAN', 'main_lan', piholeNetworks.main_lan, 'Use Pi-hole for the main trusted LAN.')}
          ${piholeToggleMarkup('Service LAN', 'service_lan', piholeNetworks.service_lan, 'Use Pi-hole for the isolated service LAN.')}
          ${piholeToggleMarkup('Wi-Fi', 'wifi', piholeNetworks.wifi, 'Use Pi-hole for hotspot or Wi-Fi clients.')}
        </div></div>
        <div class="controls"><button onclick="fetch('/api/pihole/activate',{method:'POST'}).then(()=>render())">Activate Routing</button><a class="chip" href="http://${window.location.hostname}:8081/admin/" target="_blank" rel="noreferrer">Open Pi-hole</a></div>
        <div class="hint">${(pihole.notes || []).join(' ')}</div>
      `;
    }
    function renderNetAlertPanel(netalert) {
      return `
        <div class="stat-grid">
          <div class="metric"><div class="label">Detected</div><div class="value small">${netalert.detected ? 'YES' : 'NO'}</div></div>
          <div class="metric"><div class="label">Web UI</div><div class="value small">${netalert.web_reachable ? `Reachable (${netalert.status_code})` : 'Not reachable'}</div></div>
          <div class="metric"><div class="label">Port</div><div class="value small">${escapeHtml(netalert.port || '-')}</div></div>
          <div class="metric"><div class="label">Service Name</div><div class="value small">${escapeHtml(netalert.name || '-')}</div></div>
          <div class="metric"><div class="label">Last Sync</div><div class="value small">${escapeHtml(netalert.last_sync_at || 'Not synced yet')}</div></div>
          <div class="metric"><div class="label">Scope</div><div class="value small">${escapeHtml((netalert.active_segments || []).join(', ') || 'No active segments')}</div></div>
        </div>
        <div class="route"><div class="label">Active Scan Targets</div><div class="item-list" style="margin-top:10px;">${(netalert.scan_subnets || []).length ? netalert.scan_subnets.map(item => `<div class="item"><div class="item-title">${escapeHtml(item)}</div></div>`).join('') : '<div class="muted">No active scan targets</div>'}</div></div>
        <div class="controls">
          ${netalert.detected ? `<a class="chip" href="http://${window.location.hostname}:${netalert.port}/" target="_blank" rel="noreferrer">Open NetAlertX</a><button class="secondary" onclick="syncNetAlertX()">Sync Topology</button>` : '<button onclick="installNetAlertX()">Install NetAlertX</button>'}
        </div>
        <div class="hint">NetAlertX runs best in host networking mode so it can map your local network directly.</div>
      `;
    }
    function renderTopologyBlueprint(overview, lanProfile, serviceLan, wifi, netalert) {
      const defaultDev = (overview.uplink_ipv4 || {}).dev || (overview.uplink_ipv6 || {}).dev || '';
      const uplink = (overview.uplinks || []).find(i => i.name === defaultDev) || (overview.uplinks || []).find(i => i.role === 'cellular') || (overview.uplinks || [])[0] || {};
      const overlay = (overview.uplinks || []).find(i => i.role === 'overlay') || {};
      const hotspotMode = String((wifi.active || {}).mode || wifi.config.mode || '').toLowerCase() === 'hotspot';
      const mainState = String((lanProfile.target_interface_status || {}).state || '').toUpperCase() || '-';
      const serviceState = String((serviceLan.target_interface_status || {}).state || '').toUpperCase() || '-';
      const wifiState = String((wifi.device || {}).state || '').toUpperCase() || '-';
      const activeTargets = (netalert.scan_subnets || []).length;
      return `
        <div class="stat-grid wide">
          <div class="metric"><div class="label">Default Uplink</div><div class="value small">${escapeHtml(uplink.name || defaultDev || uplink.role || '-')}</div></div>
          <div class="metric"><div class="label">Main LAN</div><div class="value small">${escapeHtml(lanProfile.target_interface || '-')} / ${escapeHtml(mainState)}</div></div>
          <div class="metric"><div class="label">Service LAN</div><div class="value small">${escapeHtml(serviceLan.interface || '-')} / ${escapeHtml(serviceState)}</div></div>
          <div class="metric"><div class="label">Wi-Fi</div><div class="value small">${escapeHtml(hotspotMode ? 'Hotspot' : 'Client')} / ${escapeHtml(wifiState)}</div></div>
          <div class="metric"><div class="label">Overlay</div><div class="value small">${escapeHtml(overlay.name || 'None')}</div></div>
          <div class="metric"><div class="label">Discovery Targets</div><div class="value small">${escapeHtml(String(activeTargets))}</div></div>
        </div>
        <div class="route">
          <div class="label">Discovery Scope</div>
          <div class="item-list" style="margin-top:10px;">
            ${(netalert.scan_subnets || []).length ? netalert.scan_subnets.map(item => `<div class="item"><div class="item-title">${escapeHtml(item)}</div></div>`).join('') : '<div class="muted">No active scan targets</div>'}
          </div>
        </div>
        <div class="controls">
          ${netalert.detected ? `<a class="chip" href="http://${window.location.hostname}:${netalert.port}/" target="_blank" rel="noreferrer">Open NetAlertX</a>` : ''}
        </div>
      `;
    }
    function serviceTone(service) {
      if (service.active) return 'online';
      if ((service.ports || []).length) return 'standby';
      return 'offline';
    }
    function renderServicePortfolioCard(service, url, id) {
      const ports = service.ports || [];
      const tone = serviceTone(service);
      const primaryPort = ports[0] || 'local';
      const source = service.source || service.type || 'system';
      return `
        <div class="portfolio-card ${tone}" onclick="openServiceOverlay('${id}')">
          <div class="portfolio-top">
            <div class="portfolio-icon">${escapeHtml(service.name.slice(0, 2).toUpperCase())}</div>
            <div>
              <div class="portfolio-title">${escapeHtml(service.name)}</div>
              <div class="portfolio-url">${escapeHtml(url || primaryPort)}</div>
            </div>
          </div>
          <div class="portfolio-status"><span class="flow-dot"></span>${service.active ? 'Online' : 'Detected'}</div>
          <div class="port-strip">
            <span>${escapeHtml(primaryPort)}</span>
            <span>${escapeHtml(source)}</span>
            <span>${service.active ? 'Active' : 'Passive'}</span>
            <span>${ports.length ? `${ports.length} port` : 'No port'}</span>
          </div>
        </div>
      `;
    }
    function renderServices(services) {
      const named = [];
      const unnamed = [];
      services.forEach(service => {
        if (['Pi-hole', 'NetAlertX', 'smbd'].includes(service.name)) return;
        const url = getServiceUrl(service);
        const id = `svc-${service.name.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`;
        appState.serviceDetails[id] = {
          title: service.name,
          subtitle: 'Detected service',
          details: {
            'Ports': (service.ports || []).join(', ') || '-',
            'Bind addresses': (service.binds || []).join(', ') || '-',
            'Source': service.source || 'system',
            'Type': service.type || 'listener',
          },
          url,
          notes: 'Tap to inspect details and open the service if a web URL is known.',
        };
        const markup = renderServicePortfolioCard(service, url, id);
        if ((service.name || '').startsWith('Port ')) unnamed.push(markup);
        else named.push(markup);
      });
      return `
        <div class="portfolio-grid">${named.join('') || '<div class="muted">No named services detected</div>'}</div>
        <div class="route"><div class="label">Unnamed Ports</div><div class="portfolio-grid small" style="margin-top:10px;">${unnamed.join('') || '<div class="muted">No port-only listeners detected</div>'}</div></div>
      `;
    }
    function renderLogsPanel(overview, services, activeSessions, systemStats) {
      const rows = [];
      const now = new Date();
      const push = (mins, service, level, message) => {
        const at = new Date(now.getTime() - mins * 60000);
        rows.push({ at, service, level, message });
      };
      push(1, 'panel', 'info', `Dashboard sync completed for ${overview.hostname || 'device'}`);
      (services || []).slice(0, 8).forEach((service, index) => {
        push(index + 2, service.name, service.active ? 'info' : 'warn', `${service.name} ${service.active ? 'listener active' : 'detected without active state'} on ${(service.ports || []).join(', ') || 'no exposed port'}`);
      });
      (activeSessions || []).slice(0, 8).forEach((session, index) => {
        push(index + 6, session.entry || session.service || 'session', 'info', `${session.peer_address || '-'} connected to ${session.local_address || '-'}:${session.local_port || '-'}`);
      });
      const docker = systemStats.docker || {};
      push(12, 'docker', docker.available ? 'info' : 'error', docker.available ? `${docker.running || 0} containers running` : 'Docker is not available');
      rows.sort((a, b) => b.at - a.at);
      return `
        <div class="log-toolbar">
          <span class="chip">10 minutes</span>
          <span class="chip">${rows.length} entries</span>
          <button class="secondary" onclick="render()">Refresh</button>
        </div>
        <div class="log-table">
          <div class="log-row log-head"><span>Date</span><span>Service</span><span>Level</span><span>Message</span></div>
          ${rows.map(row => `<div class="log-row ${row.level}"><span>${escapeHtml(row.at.toLocaleTimeString())}</span><span>${escapeHtml(row.service)}</span><span>${escapeHtml(row.level)}</span><span>${escapeHtml(row.message)}</span></div>`).join('')}
        </div>
      `;
    }
    function renderSamba(samba) {
      return `
        <div class="stat-grid">
          <div class="metric"><div class="label">SMBD</div><div class="value small">${samba.running ? 'Running' : 'Stopped'}</div></div>
          <div class="metric"><div class="label">NMBD</div><div class="value small">${samba.nmbd_running ? 'Running' : 'Stopped'}</div></div>
          <div class="metric"><div class="label">Config</div><div class="value small">${escapeHtml(samba.config_path || 'not found')}</div></div>
          <div class="metric"><div class="label">Shares</div><div class="value">${(samba.shares || []).length}</div></div>
          <div class="metric"><div class="label">Portal Shares</div><div class="value">${(samba.portal_shares || []).length}</div></div>
          <div class="metric"><div class="label">Users</div><div class="value">${(samba.users || []).length}</div></div>
        </div>
        <div class="controls"><button onclick="controlSamba('start')">Start</button><button onclick="controlSamba('restart')">Restart</button><button class="secondary" onclick="controlSamba('stop')">Stop</button></div>
        <div class="route"><div class="label">Shares</div><div class="item-list" style="margin-top:10px;">${(samba.shares || []).length ? samba.shares.map(share => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(share.name)}</div><div class="badge">${escapeHtml(share.source || 'main')}</div></div><div class="muted">Path: ${escapeHtml(share.path || '-')}</div><div class="muted">Guest: ${escapeHtml(share.guest_ok || '-')} | RO: ${escapeHtml(share.read_only || '-')} | Users: ${escapeHtml(share.valid_users || 'configured users')}</div>${share.source === 'portal' ? `<div class="controls"><button class="secondary" onclick="deleteSambaShare('${share.name}')">Delete Share</button></div>` : ''}</div>`).join('') : '<div class="muted">No Samba shares found.</div>'}</div></div>
        <div class="route"><div class="label">Share Management</div><div class="stat-grid" style="margin-top:10px;"><div class="metric"><div class="label">Share Name</div><input id="samba-share-name" placeholder="media" /></div><div class="metric"><div class="label">Path</div><input id="samba-share-path" placeholder="/srv/storage/media" /></div><div class="metric"><div class="label">Read Only</div><select id="samba-share-readonly"><option value="No">No</option><option value="Yes">Yes</option></select></div><div class="metric"><div class="label">Guest OK</div><select id="samba-share-guest"><option value="No">No</option><option value="Yes">Yes</option></select></div><div class="metric"><div class="label">Valid Users</div><input id="samba-share-users" placeholder="evil alice" /></div></div><div class="controls"><button onclick="saveSambaShare()">Save Share</button></div></div>
      `;
    }
    function renderSambaUsers(samba) {
      return `
        <div class="stat-grid">
          <div class="metric"><div class="label">Accounts</div><div class="value">${(samba.users || []).length}</div></div>
          <div class="metric"><div class="label">Service</div><div class="value small">${samba.running ? 'SMBD running' : 'SMBD stopped'}</div></div>
          <div class="metric"><div class="label">Config</div><div class="value small">${escapeHtml(samba.config_path || 'not found')}</div></div>
        </div>
        <div class="route"><div class="label">User Management</div><div class="item-list" style="margin-top:10px;">${(samba.users || []).length ? samba.users.map(user => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(user.username)}</div><div class="badge">SMB</div></div><div class="muted">${escapeHtml(user.description || 'Samba account')}</div><div class="controls"><button class="secondary" onclick="setSambaUserState('${user.username}','disable')">Disable</button><button class="secondary" onclick="setSambaUserState('${user.username}','enable')">Enable</button><button class="secondary" onclick="deleteSambaUser('${user.username}')">Delete</button></div></div>`).join('') : '<div class="muted">No Samba users detected</div>'}</div><div class="stat-grid" style="margin-top:10px;"><div class="metric"><div class="label">Username</div><input id="samba-username" placeholder="evil" /></div><div class="metric"><div class="label">Password</div><input id="samba-password" type="password" /></div></div><div class="controls"><button onclick="setSambaPassword()">Add / Update Samba User</button></div></div>
      `;
    }
    function renderPrinting(printing) {
      return `
        <div class="stat-grid">
          <div class="metric"><div class="label">CUPS</div><div class="value small">${printing.cups_installed ? (printing.cups_active ? 'Running' : 'Stopped') : 'Not installed'}</div></div>
          <div class="metric"><div class="label">Enabled</div><div class="value small">${printing.cups_installed ? (printing.cups_enabled ? 'YES' : 'NO') : '-'}</div></div>
          <div class="metric"><div class="label">Listener</div><div class="value small">${printing.cups_listener ? 'Port 631' : '-'}</div></div>
          <div class="metric"><div class="label">Printer Shares</div><div class="value small">${(printing.printer_shares || []).map(s => s.name).join(', ') || '-'}</div></div>
        </div>
        <div class="controls"><button onclick="controlPrinting('start')">Start</button><button onclick="controlPrinting('restart')">Restart</button><button class="secondary" onclick="controlPrinting('stop')">Stop</button></div>
        <div class="hint">${printing.cups_installed ? 'CUPS controls the local print daemon.' : 'CUPS is not installed on this device yet.'}</div>
      `;
    }
    function renderFileSystem(fs) {
      const noisyMountPrefixes = ['/snap', '/var/lib/docker', '/run/docker', '/proc', '/sys', '/dev'];
      const disks = (fs.disks || []).filter(d => !String(d.name || '').startsWith('loop'));
      const mounts = (fs.mounts || []).filter(m => !noisyMountPrefixes.some(prefix => String(m.mountpoint || '').startsWith(prefix)));
      const external = fs.external || [];
      const primaryMounts = mounts.filter(m => ['/', '/boot', '/boot/efi', '/srv', '/srv/storage'].includes(m.mountpoint) || String(m.mountpoint || '').startsWith('/media') || String(m.mountpoint || '').startsWith('/mnt'));
      const otherMounts = mounts.filter(m => !primaryMounts.includes(m));
      const topLevelDisks = disks.filter(d => ['disk', 'part', 'raid'].includes(String(d.type || '')));
      return `
        <div class="route"><div class="label">Key Mounts</div><div class="item-list" style="margin-top:10px;">${primaryMounts.length ? primaryMounts.map(m => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(m.mountpoint)}</div><div class="badge">${escapeHtml(m.use_percent)}</div></div><div class="muted">${escapeHtml(m.filesystem)} | Size ${escapeHtml(m.size)} | Used ${escapeHtml(m.used)} | Free ${escapeHtml(m.available)}</div></div>`).join('') : '<div class="muted">No key mounts available</div>'}</div></div>
        <div class="route"><div class="label">Storage Devices</div><div class="item-list" style="margin-top:10px;">${topLevelDisks.length ? topLevelDisks.map(d => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(d.name)}</div><div class="badge">${escapeHtml(d.size || '-')}</div></div><div class="muted">Type: ${escapeHtml(d.type || '-')} | FS: ${escapeHtml(d.fstype || '-')} | Mount: ${escapeHtml(d.mountpoint || '-')}</div><div class="muted">Model: ${escapeHtml(d.model || '-')} | Transport: ${escapeHtml(d.tran || '-')}</div></div>`).join('') : '<div class="muted">No storage devices reported</div>'}</div></div>
        <div class="route"><div class="label">External / USB Storage</div><div class="item-list" style="margin-top:10px;">${external.length ? external.map(d => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(d.name)}</div><div class="badge">${escapeHtml(d.size || '-')}</div></div><div class="muted">Transport: ${escapeHtml(d.tran || '-')} | Mount: ${escapeHtml(d.mountpoint || '-')} | Label: ${escapeHtml(d.label || '-')}</div></div>`).join('') : '<div class="muted">No removable or USB storage detected</div>'}</div></div>
        <div class="route"><div class="label">Other Mounts</div><div class="item-list" style="margin-top:10px;">${otherMounts.length ? otherMounts.map(m => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(m.mountpoint)}</div><div class="badge">${escapeHtml(m.use_percent)}</div></div><div class="muted">${escapeHtml(m.filesystem)} | Size ${escapeHtml(m.size)} | Used ${escapeHtml(m.used)} | Free ${escapeHtml(m.available)}</div></div>`).join('') : '<div class="muted">No additional mounts worth showing right now</div>'}</div></div>
      `;
    }
    function renderDeviceIo(deviceIo) {
      const leds = deviceIo.leds || [];
      const serialPorts = deviceIo.serial_ports || [];
      const gpioChips = deviceIo.gpio_chips || [];
      const policy = deviceIo.led_policy || {};
      const online = policy.online === true ? 'Online' : (policy.online === false ? 'Offline' : '-');
      const failures = policy.internet_failure_count ?? 0;
      const successes = policy.internet_success_count ?? 0;
      const ledMarkup = leds.map(led => {
        const triggerOptions = (led.triggers || []).slice(0, 40).map(trigger => `<option value="${escapeHtml(trigger)}" ${led.trigger === trigger ? 'selected' : ''}>${escapeHtml(trigger)}</option>`).join('');
        const role = led.role ? led.role.toUpperCase() : 'LED';
        const polarity = led.active_low ? 'Active-low' : 'Active-high';
        return `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(led.name)}</div><div class="badge">${escapeHtml(role)}</div></div><div class="muted">Trigger: ${escapeHtml(led.trigger || '-')} | Brightness: ${escapeHtml(led.brightness)} / ${escapeHtml(led.max_brightness)} | ${escapeHtml(polarity)} | Source: ${escapeHtml(led.source || '-')}</div><div class="controls"><button class="secondary" onclick="setLedState('${escapeHtml(led.name)}',{trigger:'none',state:'off'})" ${led.can_set_brightness ? '' : 'disabled'}>Off</button><button class="secondary" onclick="setLedState('${escapeHtml(led.name)}',{trigger:'none',state:'on'})" ${led.can_set_brightness ? '' : 'disabled'}>On</button>${triggerOptions ? `<select onchange="setLedState('${escapeHtml(led.name)}',{trigger:this.value})" ${led.can_set_trigger ? '' : 'disabled'}>${triggerOptions}</select>` : ''}</div></div>`;
      }).join('');
      const serialMarkup = serialPorts.map(port => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(port.path)}</div><div class="badge">${escapeHtml(port.kind || 'serial')}</div></div><div class="muted">Read: ${escapeHtml(port.readable)} | Write: ${escapeHtml(port.writable)} | Source: ${escapeHtml(port.source || '-')}</div>${port.link ? `<div class="muted">Stable link: ${escapeHtml(port.link)}</div>` : ''}</div>`).join('');
      const gpioMarkup = gpioChips.map(chip => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(chip.name)}</div><div class="badge">${escapeHtml(chip.ngpio || '-')} GPIO</div></div><div class="muted">Label: ${escapeHtml(chip.label || '-')} | Base: ${escapeHtml(chip.base || '-')}</div><div class="muted">Source: ${escapeHtml(chip.source || '-')}</div></div>`).join('');
      return `
        <div class="stat-grid">
          <div class="metric"><div class="label">LEDs</div><div class="value">${leds.length}</div></div>
          <div class="metric"><div class="label">Serial Ports</div><div class="value">${serialPorts.length}</div></div>
          <div class="metric"><div class="label">GPIO Chips</div><div class="value">${gpioChips.length}</div></div>
          <div class="metric"><div class="label">USER Policy</div><div class="value small">${escapeHtml(policy.last_user_state || 'waiting')}</div></div>
          <div class="metric"><div class="label">Internet LED</div><div class="value small">${escapeHtml(online)}</div></div>
          <div class="metric"><div class="label">Probe Streak</div><div class="value small">${escapeHtml(String(successes))} ok / ${escapeHtml(String(failures))} fail</div></div>
          <div class="metric"><div class="label">ACT Policy</div><div class="value small">${escapeHtml(policy.last_act_trigger || '-')}</div></div>
          <div class="metric"><div class="label">Expected RS485</div><div class="value small">${escapeHtml((deviceIo.expected_rs485 || []).join(', ') || '-')}</div></div>
        </div>
        <div class="hint">${deviceIo.manual_override_active ? 'Manual RGB override is active for the portal controls.' : 'Automatic RGB policy is active.'}</div>
        <div class="route"><div class="label">LEDs</div><div class="item-list" style="margin-top:10px;">${ledMarkup || '<div class="muted">No LEDs exposed by sysfs</div>'}</div></div>
        <div class="route"><div class="label">Serial Ports</div><div class="item-list" style="margin-top:10px;">${serialMarkup || '<div class="muted">No serial ports detected</div>'}</div></div>
        <div class="route"><div class="label">GPIO Controllers</div><div class="item-list" style="margin-top:10px;">${gpioMarkup || '<div class="muted">No GPIO chips detected</div>'}</div></div>
        <div class="hint">${(deviceIo.notes || []).map(escapeHtml).join(' ') || 'Device I/O inventory is available.'}</div>
      `;
    }
    async function render() {
      let [
        overview, systemStats, lte, lteProfile, lteOptions, lteSuggest, lteAuto, atExamples,
        services, pihole, piholeNetworks, netalert, samba, printing, interfaces,
        serviceLan, serviceLanClients, wifiClients, lanProfile, activeSessions, wifi, filesystem, deviceIo
      ] = await Promise.all([
        loadJSON('/api/overview'),
        loadJSON('/api/system/stats'),
        loadJSON('/api/lte'),
        loadJSON('/api/lte/profile'),
        loadJSON('/api/lte/apn/options'),
        loadJSON('/api/lte/apn/suggest'),
        loadJSON('/api/lte/apn/auto'),
        loadJSON('/api/lte/at/examples'),
        loadJSON('/api/services'),
        loadJSON('/api/pihole/status'),
        loadJSON('/api/pihole/networks'),
        loadJSON('/api/netalert/status'),
        loadJSON('/api/samba/status'),
        loadJSON('/api/printing/status'),
        loadJSON('/api/interfaces'),
        loadJSON('/api/service-lan/status'),
        loadJSON('/api/service-lan/clients'),
        loadJSON('/api/wifi/clients'),
        loadJSON('/api/main-lan/status'),
        loadJSON('/api/active-sessions'),
        loadJSON('/api/wifi/status'),
        loadJSON('/api/filesystem'),
        loadJSON('/api/device-io'),
      ]);
      if (DEMO_MODE) {
        ({
          overview, systemStats, lte, lteProfile, lteOptions, lteSuggest, lteAuto, atExamples,
          services, pihole, piholeNetworks, netalert, samba, printing, interfaces,
          serviceLan, serviceLanClients, wifiClients, lanProfile, activeSessions, wifi, filesystem, deviceIo,
        } = demoMaskData({
          overview, systemStats, lte, lteProfile, lteOptions, lteSuggest, lteAuto, atExamples,
          services, pihole, piholeNetworks, netalert, samba, printing, interfaces,
          serviceLan, serviceLanClients, wifiClients, lanProfile, activeSessions, wifi, filesystem, deviceIo,
        }));
      }

      appState.lastSyncAt = Date.now();
      appState.serviceDetails = {};
      appState.wifi = wifi;
      updateRefreshState();

      document.getElementById('overview').innerHTML = renderOverview(overview, systemStats, activeSessions, serviceLanClients);
      document.getElementById('docker-brief').innerHTML = renderDockerBrief(systemStats);
      document.getElementById('dashboard-sessions').innerHTML = renderSessions(activeSessions);
      const sessionBadge = document.getElementById('dashboard-session-count');
      const totalSessions = sessionCount(activeSessions);
      sessionBadge.textContent = String(totalSessions);
      sessionBadge.className = sessionCountClass(totalSessions);

      document.getElementById('main-lan').innerHTML = renderLanCard('main', lanProfile);
      document.getElementById('service-lan').innerHTML = renderLanCard('service', serviceLan);

      const groups = categorizeInterfaces(interfaces);
      document.getElementById('interfaces').innerHTML = [
        renderInterfaceGroup('Uplinks', groups.uplinks),
        renderInterfaceGroup('LAN Ports', groups.lan),
        renderInterfaceGroup('Wireless', groups.wireless),
        renderInterfaceGroup('Virtual / Other', groups.virtual),
      ].join('');

      document.getElementById('service-lan-clients').innerHTML = (serviceLanClients || []).length ? `<div class="item-list">${serviceLanClients.map(c => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(c.hostname || c.mac || 'Client')}</div><div class="badge">${escapeHtml(c.interface || '-')}</div></div><div class="muted">IP: ${escapeHtml(c.ip)} | MAC: ${escapeHtml(c.mac || '-')} | ${escapeHtml(c.family || '-')} | ${escapeHtml(c.state || '-')}</div></div>`).join('')}</div>` : '<div class="muted">No clients detected</div>';
      document.getElementById('wifi-panel').innerHTML = renderWireless(wifi, interfaces, wifiClients, piholeNetworks, overview);

      const cellular = renderCellular(lte, lteProfile, lteOptions, lteSuggest, lteAuto, atExamples, overview);
      document.getElementById('cellular-state').innerHTML = cellular.state;
      document.getElementById('cellular-apn').innerHTML = cellular.apn;
      document.getElementById('cellular-at').innerHTML = cellular.at;

      document.getElementById('pihole-panel').innerHTML = renderPiHolePanel(pihole, piholeNetworks);
      document.getElementById('netalert-panel').innerHTML = renderNetAlertPanel(netalert);
      document.getElementById('topology-panel').innerHTML = renderTopologyBlueprint(overview, lanProfile, serviceLan, wifi, netalert);
      document.getElementById('logs-panel').innerHTML = renderLogsPanel(overview, services, activeSessions, systemStats);
      document.getElementById('services').innerHTML = renderServices(services);

      document.getElementById('samba-panel').innerHTML = renderSamba(samba);
      document.getElementById('samba-users-panel').innerHTML = renderSambaUsers(samba);
      document.getElementById('printing-panel').innerHTML = renderPrinting(printing);
      document.getElementById('filesystem-panel').innerHTML = renderFileSystem(filesystem);
      document.getElementById('deviceio-panel').innerHTML = renderDeviceIo(deviceIo);
      document.getElementById('lorawan-panel').innerHTML = `<div class="stat-grid"><div class="metric"><div class="label">Module State</div><div class="value small">Not installed yet</div></div><div class="metric"><div class="label">Planned Uses</div><div class="value small">LoRaWAN, Meshtastic, profiles and radio settings</div></div></div><div class="hint">This page is ready as a placeholder so future radio modules can live in a dedicated area instead of being scattered across the dashboard.</div>`;

      [
        ['main-lan-role', 'main_lan.role'],
        ['main-lan-ipv4-mode', 'main_lan.ipv4_mode'],
        ['main-lan-ipv4-address', 'main_lan.ipv4_address'],
        ['main-lan-ipv4-subnet', 'main_lan.ipv4_subnet'],
        ['main-lan-dhcp-range', 'main_lan.dhcp_range'],
        ['main-lan-ipv6-mode', 'main_lan.ipv6_mode'],
        ['main-lan-ipv6-address', 'main_lan.ipv6_address'],
        ['main-lan-ipv6-prefix', 'main_lan.ipv6_prefix'],
        ['main-lan-dns-servers', 'main_lan.dns_servers'],
        ['service-lan-role', 'service_lan.role'],
        ['service-lan-ipv4-mode', 'service_lan.ipv4_mode'],
        ['service-lan-ipv4-gateway', 'service_lan.ipv4_gateway'],
        ['service-lan-ipv4-subnet', 'service_lan.ipv4_subnet'],
        ['service-lan-dhcp-range', 'service_lan.dhcp_range'],
        ['service-lan-ipv6-mode', 'service_lan.ipv6_mode'],
        ['service-lan-ipv6-gateway', 'service_lan.ipv6_gateway'],
        ['service-lan-ipv6-prefix', 'service_lan.ipv6_prefix'],
        ['service-lan-dns-servers', 'service_lan.dns_servers'],
        ['wifi-mode', 'wifi.mode'],
        ['wifi-client-trust-mode', 'wifi.client_trust_mode'],
        ['wifi-uplink-preference', 'wifi.uplink_preference'],
        ['wifi-ssid', 'wifi.ssid'],
        ['wifi-password', 'wifi.password'],
        ['wifi-hotspot-ssid', 'wifi.hotspot_ssid'],
        ['wifi-hotspot-password', 'wifi.hotspot_password'],
        ['wifi-hotspot-security', 'wifi.hotspot_security'],
        ['wifi-country', 'wifi.country'],
        ['wifi-band', 'wifi.band'],
        ['wifi-channel', 'wifi.channel'],
        ['wifi-ipv4-method', 'wifi.ipv4_method'],
        ['wifi-ipv4-address', 'wifi.ipv4_address'],
        ['wifi-ipv6-method', 'wifi.ipv6_method'],
        ['wifi-ipv6-address', 'wifi.ipv6_address'],
        ['cellular-apn-profile', 'cellular.apn_profile'],
        ['cellular-apn-custom', 'cellular.apn_custom'],
        ['cellular-ipv4-method', 'cellular.ipv4_method'],
        ['cellular-ipv6-method', 'cellular.ipv6_method'],
        ['cellular-apn-remember', 'cellular.apn_remember'],
        ['at-command', 'cellular.at_command'],
      ].forEach(([id, key]) => bindDraft(id, key));

      const atCommandEl = document.getElementById('at-command');
      if (atCommandEl) atCommandEl.value = draftValue('cellular.at_command', atCommandEl.value);

      setView(appState.activeView);
      updateRefreshState();
      applyDemoMaskToDom();
    }
    async function pollRender() {
      if (document.body.dataset.auth !== 'unlocked') {
        return;
      }
      if (document.hidden) {
        updateRefreshState();
        return;
      }
      if (hasActiveEditing()) {
        updateRefreshState();
        return;
      }
      await render();
    }
    async function boot() {
      loadTheme();
      document.body.dataset.demo = DEMO_MODE ? 'on' : 'off';
      bindNavMenus();
      setView(appState.activeView);
      if (await checkAuth()) {
        await render();
      }
      applyDemoMaskToDom();
    }
    boot();
    setInterval(pollRender, AUTO_REFRESH_MS);
    window.addEventListener('focusin', updateRefreshState);
    window.addEventListener('focusout', () => setTimeout(updateRefreshState, 0));

Object.assign(window, {
  draftValue,
  bindDraft,
  clearDraft,
  isTogglePending,
  setTogglePending,
  escapeHtml,
  setAuthState,
  checkAuth,
  login,
  logout,
  updateCredentials,
  loadJSON,
  fetchJSON,
  postAction,
  hasActiveEditing,
  updateRefreshState,
  setView,
  loadTheme,
  toggleTheme,
  getUptimeMode,
  cycleUptimeMode,
  fmtUptime,
  openServiceOverlay,
  closeServiceOverlay,
  openRawProfile,
  openTextOverlay,
  closeTextOverlay,
  dismissOverlay,
  closeCommandOverlay,
  openCommandOverlay,
  refreshCommandPreview,
  serviceCardMarkup,
  getServiceUrl,
  piholeToggleMarkup,
  togglePiholeNetwork,
  restartSystem,
  powerOffSystem,
  saveMainLanConfigPreview,
  applyMainLanPreview,
  saveServiceLanConfigPreview,
  applyServiceLanPreview,
  saveWifiConfigPreview,
  applyWifiPreview,
  applyCellularApnPreview,
  setUplinkPreference,
  toggleAutoApn,
  setLinkState,
  toggleLinkState,
  restartLan,
  toggleLanInternet,
  toggleLanInternetState,
  rescanWifi,
  setWifiPower,
  toggleWifiPower,
  setLedState,
  controlSamba,
  setSambaPassword,
  setSambaUserState,
  deleteSambaUser,
  saveSambaShare,
  deleteSambaShare,
  controlPrinting,
  installNetAlertX,
  syncNetAlertX,
  runAtCommand,
  collectMainLanPayload,
  collectServiceLanPayload,
  collectWifiPayload,
  collectApnPayload,
  renderOverview,
  renderDockerBrief,
  renderSessions,
  sessionCount,
  sessionCountClass,
  ipv4ModeLabel,
  ipv6ModeLabel,
  wifiBandLabel,
  wifiHotspotIpv6Label,
  wifiChannelOptions,
  setLanStackDisabled,
  lanRoleExplanation,
  renderLanCard,
  categorizeInterfaces,
  renderInterfaceGroup,
  renderWireless,
  renderCellular,
  renderPiHolePanel,
  renderNetAlertPanel,
  renderTopologyBlueprint,
  renderServices,
  renderSamba,
  renderSambaUsers,
  renderPrinting,
  renderFileSystem,
  renderDeviceIo,
  render,
  pollRender,
  boot,
});
