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
      logLimit: Number(sessionStorage.getItem('portal.logLimit') || '100'),
      logLevel: sessionStorage.getItem('portal.logLevel') || '',
      logSource: sessionStorage.getItem('portal.logSource') || '',
      rendering: false,
      renderQueued: false,
      activities: [],
      activitySeq: 0,
      activityUnread: 0,
      terminalOutput: '',
      terminalCommand: sessionStorage.getItem('portal.terminalCommand') || 'ip route show default',
      connectivityTest: null,
      floatingWindow: null,
      interfaceBehaviorDetails: {},
      interfaceConfigDetails: {},
      flowMetricSamples: {},
      settings: { settings: { ui: { visible_tabs: {} } }, tabs: { core: [], optional: [], known: [] } },
    };
    window.appState = appState;
    const VIEW_META = {
      dashboard: { title: 'Dashboard', subtitle: 'Current host, traffic path and live access.' },
      network: { title: 'Network', subtitle: 'Interfaces, clients and policy.' },
      interfaces: { title: 'Interfaces', subtitle: 'Raw ports, addresses and link state.' },
      wireless: { title: 'Wireless', subtitle: 'Wi-Fi client, hotspot and radio state.' },
      cellular: { title: 'Cellular', subtitle: 'Modem state and APN profile control.' },
      diagnostics: { title: 'Diagnostics', subtitle: 'Read-only routing, DNS and provider checks.' },
      routefirewall: { title: 'Routing / Firewall', subtitle: 'Read-only policy model, exposure and gaps.' },
      reconcile: { title: 'Network Reconcile', subtitle: 'Preview commands, verification steps and rollback notes.' },
      monitoring: { title: 'Monitoring', subtitle: 'DNS, discovery and network visibility.' },
      logs: { title: 'Logs', subtitle: 'Events, command output and panel activity.' },
      services: { title: 'Services', subtitle: 'Detected listeners and service cards.' },
      terminal: { title: 'Terminal', subtitle: 'Guarded read-only command console.' },
      filesharing: { title: 'File Sharing', subtitle: 'Samba, printing and shared storage.' },
      users: { title: 'Users', subtitle: 'Panel and Samba account management.' },
      filesystem: { title: 'File System', subtitle: 'Disks, mounts and removable media.' },
      deviceio: { title: 'Device I/O', subtitle: 'LEDs, serial ports and GPIO inventory.' },
      runtime: { title: 'Runtime', subtitle: 'Host dependencies and install readiness.' },
      settings: { title: 'Panel Settings', subtitle: 'UI, safety defaults and panel behavior.' },
      actions: { title: 'Actions', subtitle: 'Preview, execute and audit guarded operations.' },
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
      'wifi.selected_interface',
      'cellular.selected_interface',
      'cellular.apn_country',
      'cellular.apn_provider',
      'cellular.apn_profile',
    ]);
    const AUTO_REFRESH_MS = 5000;
    const TTL = {
      fast: 5000,
      medium: 30000,
      slow: 60000,
      static: 10 * 60 * 1000,
    };
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
    const EMPTY_DATA = {
      overview: { hostname: '', hardware: {}, uplinks: [], local_lans: [], uplink_ipv4: {}, uplink_ipv6: {} },
      systemStats: { memory: {}, load: {}, docker: {} },
      lte: { available: false },
      lteProfile: {},
      lteOptions: { options: [] },
      lteSuggest: { suggested: {} },
      lteAuto: {},
      atExamples: { commands: [] },
      services: [],
      serviceInventory: { summary: {}, groups: {}, services: [], model: {} },
      pihole: { notes: [] },
      piholeNetworks: {},
      netalert: { scan_subnets: [], active_segments: [] },
      samba: { shares: [], portal_shares: [], users: [] },
      printing: {},
      interfaces: [],
      interfaceInventory: { interfaces: [], model: {} },
      serviceLan: { notes: [], dns_servers: [], target_interface_status: {} },
      serviceLanClients: [],
      wifiClients: [],
      lanProfile: { notes: [], dns_servers: [], target_interface_status: {} },
      activeSessions: [],
      wifi: { config: {}, active: {}, device: {}, scan: [], rfkill: [], capabilities: {}, notes: [] },
      networkBehaviors: { interfaces: [], providers: [], wifi_driver_errors: [], model: {} },
      interfaceConfigs: { configs: [], model: {} },
      filesystem: { disks: [], mounts: [], external: [] },
      deviceIo: { leds: [], serial_ports: [], gpio_chips: [], led_policy: {}, expected_rs485: [], notes: [] },
      providers: { providers: [], device_profile: {} },
      capabilities: { capabilities: [], providers: [], device_profile: {} },
      networkDiagnostics: { state: {}, snapshot: {}, findings: [] },
      routeFirewallPolicy: { current: {}, desired: {}, gaps: [], next_steps: [] },
      networkReconcile: { current: {}, desired: {}, plan: { commands: [], verify: [], rollback: [], warnings: [] } },
      eventLog: { events: [] },
      actions: { actions: [] },
      actionHistory: { events: [] },
      settings: { settings: { ui: { visible_tabs: {} } }, tabs: { core: [], optional: [], known: [] } },
    };
    const ENDPOINTS = {
      overview: { url: '/api/overview', ttl: TTL.fast, timeout: 1800, views: ['dashboard', 'logs', 'monitoring', 'cellular'] },
      systemStats: { url: '/api/system/stats', ttl: TTL.fast, timeout: 1800, views: ['dashboard', 'logs'] },
      interfaces: { url: '/api/interfaces', ttl: TTL.fast, views: ['interfaces', 'wireless', 'cellular'] },
      interfaceInventory: { url: '/api/network/inventory', ttl: TTL.medium, views: ['network', 'interfaces', 'wireless', 'cellular'] },
      activeSessions: { url: '/api/active-sessions', ttl: TTL.slow, timeout: 1800, views: ['dashboard', 'logs'] },
      lte: { url: '/api/cellular', ttl: TTL.medium, views: ['cellular'] },
      lteProfile: { url: '/api/cellular/profile', ttl: TTL.static, views: ['cellular'] },
      lteOptions: { url: '/api/cellular/apn/options', ttl: TTL.static, views: ['cellular'] },
      lteSuggest: { url: '/api/cellular/apn/suggest', ttl: TTL.static, views: ['cellular'] },
      lteAuto: { url: '/api/cellular/apn/auto', ttl: TTL.static, views: ['cellular'] },
      atExamples: { url: '/api/cellular/at/examples', ttl: TTL.static, views: ['cellular'] },
      services: { url: '/api/services', ttl: TTL.slow, views: ['services', 'logs'] },
      serviceInventory: { url: '/api/services/inventory', ttl: TTL.slow, views: ['services'] },
      pihole: { url: '/api/pihole/status', ttl: TTL.medium, views: ['monitoring'] },
      piholeNetworks: { url: '/api/pihole/networks', ttl: TTL.static, views: ['monitoring', 'wireless'] },
      netalert: { url: '/api/netalert/status', ttl: TTL.slow, views: ['monitoring'] },
      samba: { url: '/api/samba/status', ttl: TTL.slow, views: ['filesharing', 'users'] },
      printing: { url: '/api/printing/status', ttl: TTL.slow, views: ['filesharing'] },
      serviceLan: { url: '/api/service-lan/status', ttl: TTL.medium, views: ['network', 'monitoring'] },
      serviceLanClients: { url: '/api/local-lan/clients', ttl: TTL.medium, timeout: 1800, views: ['dashboard', 'network'] },
      wifiClients: { url: '/api/wifi/clients', ttl: TTL.medium, views: ['dashboard', 'wireless'] },
      lanProfile: { url: '/api/main-lan/status', ttl: TTL.medium, views: ['network', 'monitoring'] },
      wifi: { url: '/api/wifi/status', ttl: TTL.medium, views: ['wireless', 'monitoring', 'cellular'] },
      networkBehaviors: { url: '/api/network/interface-behaviors', ttl: TTL.medium, views: ['network', 'diagnostics'] },
      interfaceConfigs: { url: '/api/network/interface-configs', ttl: TTL.medium, views: ['network', 'interfaces'] },
      filesystem: { url: '/api/filesystem', ttl: TTL.slow, views: ['filesystem'] },
      deviceIo: { url: '/api/device-io', ttl: TTL.slow, views: ['deviceio'] },
      providers: { url: '/api/providers', ttl: TTL.static, views: ['runtime'] },
      capabilities: { url: '/api/capabilities', ttl: TTL.static, views: ['runtime'] },
      networkDiagnostics: { url: '/api/network/diagnostics', ttl: TTL.slow, views: ['diagnostics'] },
      routeFirewallPolicy: { url: '/api/network/route-firewall-policy', ttl: TTL.slow, views: ['routefirewall'] },
      networkReconcile: { url: '/api/network/reconcile/preview', ttl: TTL.slow, views: ['reconcile'] },
      eventLog: { url: () => `/api/events?${backendLogQuery()}`, ttl: TTL.slow, views: ['logs'] },
      actions: { url: '/api/actions', ttl: TTL.slow, views: ['actions'] },
      actionHistory: { url: '/api/actions/history', ttl: TTL.slow, views: ['actions'] },
      settings: { url: '/api/settings', ttl: TTL.static, views: Object.keys(VIEW_META) },
    };
    const apiCache = new Map();

    function draftValue(key, fallback) {
      return Object.prototype.hasOwnProperty.call(appState.drafts, key) ? appState.drafts[key] : (fallback ?? '');
    }
    let draftRenderTimer = null;
    function scheduleDraftRender() {
      clearTimeout(draftRenderTimer);
      draftRenderTimer = setTimeout(() => render({ allowDuringEditing: true }), 180);
    }
    let dataRenderTimer = null;
    function scheduleDataRender() {
      clearTimeout(dataRenderTimer);
      dataRenderTimer = setTimeout(() => {
        if (!document.hidden && document.body.dataset.auth === 'unlocked' && !hasActiveEditing()) {
          render();
        }
      }, 160);
    }
    function wait(ms, value) {
      return new Promise(resolve => setTimeout(() => resolve(value), ms));
    }
    function bindDraft(id, key) {
      const el = document.getElementById(id);
      if (!el) return;
      const capture = () => {
        appState.drafts[key] = el.type === 'checkbox' ? el.checked : el.value;
        if ((key === 'main_lan.ipv4_mode' || key === 'service_lan.ipv4_mode') && el.value === 'disabled') {
          appState.drafts[key.replace('ipv4_mode', 'ipv6_mode')] = 'disabled';
        }
        if (key === 'cellular.apn_country') {
          delete appState.drafts['cellular.apn_provider'];
          delete appState.drafts['cellular.apn_profile'];
          delete appState.drafts['cellular.apn_custom'];
        }
        if (key === 'cellular.apn_provider') {
          delete appState.drafts['cellular.apn_profile'];
          delete appState.drafts['cellular.apn_custom'];
        }
        if (key === 'cellular.apn_profile') {
          delete appState.drafts['cellular.apn_custom'];
        }
        updateRefreshState();
      };
      el.oninput = () => {
        capture();
      };
      el.onchange = () => {
        capture();
        if (REACTIVE_DRAFT_KEYS.has(key)) {
          scheduleDraftRender();
        }
      };
    }
    function clearDraft(prefix) {
      Object.keys(appState.drafts).filter(key => key.startsWith(prefix)).forEach(key => delete appState.drafts[key]);
      updateRefreshState();
    }
    function setInterfaceSelector(key, value) {
      appState.drafts[key] = value || '';
      sessionStorage.setItem(`portal.${key}`, value || '');
      updateRefreshState();
      scheduleDraftRender();
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
    async function loadJSON(url, timeoutMs = 12000) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetch(url, { signal: controller.signal });
        if (res.status === 401) {
          setAuthState(false);
          throw new Error('Authentication required');
        }
        if (!res.ok) {
          throw new Error(`Request failed: ${res.status}`);
        }
        return await res.json();
      } finally {
        clearTimeout(timeout);
      }
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
      const method = String((options || {}).method || 'GET').toUpperCase();
      if (method !== 'GET') apiCache.clear();
      return payload;
    }
    function endpointUrl(config) {
      return typeof config.url === 'function' ? config.url() : config.url;
    }
    function endpointEnabled(config) {
      return (config.views || []).includes(appState.activeView);
    }
    async function loadCachedEndpoint(key, config, force = false) {
      const url = endpointUrl(config);
      const cached = apiCache.get(key);
      const now = Date.now();
      const fallback = cached?.value !== undefined ? cached.value : EMPTY_DATA[key];
      const paintAfter = config.paintAfter || 650;
      if (!endpointEnabled(config) && cached?.value !== undefined) {
        return cached.value;
      }
      if (!endpointEnabled(config)) {
        return EMPTY_DATA[key];
      }
      if (!force && cached?.value !== undefined && cached.url === url && now - cached.fetchedAt < config.ttl) {
        return cached.value;
      }
      if (cached?.promise && cached.url === url) {
        if (cached.value !== undefined) return cached.value;
        return Promise.race([cached.promise, wait(paintAfter, fallback)]);
      }
      const promise = loadJSON(url, config.timeout || 12000)
        .then(value => {
          const masked = DEMO_MODE ? demoMaskData(value, key) : value;
          apiCache.set(key, { url, value: masked, fetchedAt: Date.now(), promise: null });
          scheduleDataRender();
          return masked;
        })
        .catch(error => {
          const fetchedAt = cached?.value !== undefined ? Date.now() : 0;
          const retryScheduled = !cached?.retryScheduled;
          apiCache.set(key, { url, value: fallback, fetchedAt, promise: null, retryScheduled: true });
          if (retryScheduled) {
            setTimeout(() => {
              const current = apiCache.get(key);
              if (!current?.retryScheduled || current.value !== fallback) return;
              apiCache.set(key, { url, value: fallback, fetchedAt: 0, promise: null, retryScheduled: false });
              if (!document.hidden && endpointEnabled(config) && document.body.dataset.auth === 'unlocked' && !hasActiveEditing()) {
                render();
              }
            }, 4500);
          }
          if (cached?.value !== undefined) return cached.value;
          console.warn(`Using fallback for ${key}:`, error);
          return fallback;
        });
      apiCache.set(key, { url, value: cached?.value, fetchedAt: cached?.fetchedAt || 0, promise });
      if (cached?.value !== undefined) return cached.value;
      return Promise.race([promise, wait(paintAfter, fallback)]);
    }
    async function loadPanelData(force = false) {
      const entries = await Promise.all(Object.entries(ENDPOINTS).map(async ([key, config]) => [
        key,
        await loadCachedEndpoint(key, config, force),
      ]));
      return Object.fromEntries(entries);
    }
    function detailsStateKey(details, root) {
      const parts = [];
      let node = details;
      while (node && node !== root) {
        if (node.tagName === 'DETAILS') {
          const siblings = Array.from((node.parentElement || root).children);
          parts.unshift(`details#${Math.max(0, siblings.indexOf(node))}`);
        }
        node = node.parentElement;
      }
      return parts.join('/');
    }
    function captureDetailsState(root) {
      const state = new Map();
      root.querySelectorAll('details').forEach(details => {
        state.set(detailsStateKey(details, root), details.open);
      });
      return state;
    }
    function restoreDetailsState(root, state) {
      root.querySelectorAll('details').forEach(details => {
        const key = detailsStateKey(details, root);
        if (state.has(key)) details.open = state.get(key);
      });
    }
    function captureScrollState(root) {
      const state = new Map();
      root.querySelectorAll('.scroll-list, .scroll-grid, .log-table, .floating-window-body').forEach((el, index) => {
        state.set(el.id || `${el.className}:${index}`, { top: el.scrollTop, left: el.scrollLeft });
      });
      return state;
    }
    function restoreScrollState(root, state) {
      root.querySelectorAll('.scroll-list, .scroll-grid, .log-table, .floating-window-body').forEach((el, index) => {
        const saved = state.get(el.id || `${el.className}:${index}`);
        if (saved) {
          el.scrollTop = saved.top;
          el.scrollLeft = saved.left;
        }
      });
    }
    function setPanelHTML(id, renderer) {
      const target = document.getElementById(id);
      if (!target) return;
      const detailsState = captureDetailsState(target);
      const scrollState = captureScrollState(target);
      try {
        target.innerHTML = renderer();
        restoreDetailsState(target, detailsState);
        restoreScrollState(target, scrollState);
      } catch (err) {
        console.error(`Render failed for ${id}:`, err);
        target.innerHTML = `<div class="muted">Panel render failed: ${escapeHtml(err.message || 'unknown error')}</div>`;
      }
    }
    function renderActivityLog() {
      const list = document.getElementById('activity-list');
      const drawer = document.getElementById('activity-drawer');
      if (!list) return;
      if (drawer) drawer.classList.toggle('attention', appState.activityUnread > 0 && !drawer.classList.contains('open'));
      list.innerHTML = appState.activities.length
        ? appState.activities.map(item => `<div class="activity-item ${escapeHtml(item.status)}">
            <div class="activity-row"><strong>${escapeHtml(item.title)}</strong><span>${escapeHtml(item.status)}</span></div>
            <div class="muted">${escapeHtml(item.detail || '')}</div>
            <div class="activity-time">${escapeHtml(new Date(item.ts).toLocaleTimeString())}</div>
          </div>`).join('')
        : '<div class="muted">No activity yet</div>';
    }
    function pushToast(title, detail = '', status = 'done') {
      const stack = document.getElementById('toast-stack');
      if (!stack) return;
      const toast = document.createElement('div');
      toast.className = `toast ${status}`;
      toast.innerHTML = `<div class="activity-row"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(status)}</span></div>${detail ? `<div class="muted">${escapeHtml(detail)}</div>` : ''}`;
      stack.prepend(toast);
      setTimeout(() => toast.remove(), status === 'running' ? 1800 : 4200);
    }
    function startActivity(title, detail = '') {
      const id = ++appState.activitySeq;
      appState.activities.unshift({ id, title, detail, status: 'running', ts: Date.now() });
      appState.activities = appState.activities.slice(0, 20);
      appState.activityUnread += 1;
      renderActivityLog();
      pushToast(title, detail || 'Running...', 'running');
      return id;
    }
    function finishActivity(id, status = 'done', detail = '') {
      const item = appState.activities.find(entry => entry.id === id);
      if (item) {
        item.status = status;
        item.detail = detail || item.detail;
        item.ts = Date.now();
      }
      renderActivityLog();
      pushToast(item?.title || 'Command', detail || (status === 'done' ? 'Completed' : 'Failed'), status);
    }
    function endpointLabel(endpoint) {
      return String(endpoint || '').replace(/^\/api\//, '').replaceAll('/', ' ');
    }
    async function trackActivity(title, detail, task) {
      const id = startActivity(title, detail);
      try {
        const result = await task();
        finishActivity(id, 'done', 'Completed');
        return result;
      } catch (err) {
        finishActivity(id, 'error', err.message || 'Failed');
        throw err;
      }
    }
    async function postAction(endpoint, fallbackMessage, payload = null) {
      try {
        const response = await trackActivity(endpointLabel(endpoint), 'Sending command', () => fetchJSON(endpoint, {
            method: 'POST',
            headers: payload ? { 'Content-Type': 'application/json' } : undefined,
            body: payload ? JSON.stringify(payload) : undefined,
          }));
        if (response.ok === false) throw new Error(response.stderr || fallbackMessage);
        return response;
      } catch (err) {
        alert(err.message || fallbackMessage);
        return null;
      }
    }
    function hasActiveEditing() {
      const active = document.activeElement;
      const activeIsVisible = active
        && active.getClientRects
        && active.getClientRects().length > 0
        && !active.closest('.login-screen');
      const focusedEdit = activeIsVisible && ['INPUT', 'SELECT', 'TEXTAREA'].includes(active.tagName);
      const scrollingSurface = document.querySelector('.scroll-list:hover, .scroll-grid:hover, .log-table:hover, .activity-panel:hover');
      return focusedEdit
        || Boolean(scrollingSurface)
        || Object.keys(appState.drafts).length > 0
        || document.querySelector('.custom-select.open, .custom-options.portal-open')
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
      if (detail) detail.textContent = editing ? 'Draft values stay local until you save or run them.' : 'The page refreshes in the background every 60 seconds.';
      if (appState.lastSyncAt) document.getElementById('last-sync').textContent = `Last sync ${new Date(appState.lastSyncAt).toLocaleTimeString()}`;
    }
    function visibleTabs(settingsPayload = appState.settings) {
      return (((settingsPayload || {}).settings || {}).ui || {}).visible_tabs || {};
    }
    function isViewVisible(view, settingsPayload = appState.settings) {
      const tabs = visibleTabs(settingsPayload);
      return tabs[view] !== false;
    }
    function applyVisibleTabs(settingsPayload = appState.settings) {
      Object.keys(VIEW_META).forEach(view => {
        const visible = isViewVisible(view, settingsPayload);
        document.querySelectorAll(`[data-view="${view}"]`).forEach(el => {
          el.classList.toggle('hidden-by-settings', !visible);
        });
      });
      document.querySelectorAll('.nav-menu').forEach(menu => {
        const viewButtons = Array.from(menu.querySelectorAll('[data-view]'));
        if (!viewButtons.length) return;
        const hasVisible = viewButtons.some(button => !button.classList.contains('hidden-by-settings'));
        menu.classList.toggle('hidden-by-settings', !hasVisible);
      });
    }
    function setView(view) {
      if (!isViewVisible(view)) {
        view = 'dashboard';
      }
      const previousView = appState.activeView;
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
      if (previousView !== view && document.body.dataset.auth === 'unlocked' && !document.hidden && !hasActiveEditing()) {
        setTimeout(() => render({ force: true }), 0);
      }
    }
    function closeNavMenus() {
      document.querySelectorAll('.nav-menu.open').forEach(menu => menu.classList.remove('open'));
    }
    function closeActivityDrawer() {
      document.getElementById('activity-drawer')?.classList.remove('open');
    }
    function restoreCustomOptions(root) {
      if (!root) return;
      const options = document.querySelector(`.custom-options[data-owner="${root.id}"]`) || root.querySelector('.custom-options');
      root.classList.remove('open', 'open-up');
      if (!options) return;
      options.classList.remove('portal-open', 'open-up');
      options.style.left = '';
      options.style.top = '';
      options.style.bottom = '';
      options.style.width = '';
      options.style.removeProperty('--options-max-height');
      if (options.parentElement !== root) root.appendChild(options);
    }
    function closeCustomSelects() {
      document.querySelectorAll('.custom-select.open').forEach(restoreCustomOptions);
      document.querySelectorAll('.custom-options.portal-open').forEach(options => {
        const root = document.getElementById(options.dataset.owner || '');
        restoreCustomOptions(root);
      });
    }
    function bindNavMenus() {
      document.querySelectorAll('.nav-menu > .nav-trigger').forEach(trigger => {
        const menu = trigger.closest('.nav-menu');
        if (!menu || !menu.querySelector('.mega-menu')) return;
        let leaveTimer = null;
        menu.addEventListener('mouseenter', () => {
          clearTimeout(leaveTimer);
          closeNavMenus();
          menu.classList.add('open');
        });
        menu.addEventListener('mouseleave', () => {
          clearTimeout(leaveTimer);
          leaveTimer = setTimeout(() => menu.classList.remove('open'), 120);
        });
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
      document.getElementById('activity-drawer')?.addEventListener('click', event => event.stopPropagation());
      document.addEventListener('click', () => {
        closeNavMenus();
        closeCustomSelects();
        closeActivityDrawer();
      });
      document.addEventListener('keydown', event => {
        if (event.key === 'Escape') {
          closeNavMenus();
          closeCustomSelects();
        }
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
    function toggleActivityDrawer() {
      const drawer = document.getElementById('activity-drawer');
      drawer?.classList.toggle('open');
      appState.activityUnread = 0;
      renderActivityLog();
    }
    function clearActivityLog() {
      appState.activities = [];
      appState.activityUnread = 0;
      renderActivityLog();
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
      const capabilities = service.capabilities || [];
      const actions = service.actions || [];
      document.getElementById('overlay-title').textContent = demoMaskText(service.title || 'Service');
      document.getElementById('overlay-subtitle').textContent = demoMaskText(service.subtitle || 'Details');
      document.getElementById('overlay-body').innerHTML = `
        <div class="stat-grid">${Object.entries(service.details || {}).map(([k, v]) => `<div class="metric"><div class="label">${safeText(k)}</div><div class="value small">${safeText(v, k)}</div></div>`).join('')}</div>
        ${capabilities.length ? `<div class="route"><div class="label">Capabilities</div><div class="tag-row">${capabilities.map(capability => `<span class="mini-tag">${safeText(capability)}</span>`).join('')}</div></div>` : ''}
        ${actions.length ? `<div class="route"><div class="label">Actions</div><div class="item-list">${actions.map(action => `<div class="item"><div class="item-top"><div class="item-title">${safeText(action.label || action.id)}</div><div class="badge ${action.enabled ? 'online' : 'idle'}">${action.enabled ? 'available' : 'not yet'}</div></div><div class="muted">${safeText(action.reason || '')}</div></div>`).join('')}</div></div>` : ''}
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
    function openFloatingWindow(title, subtitle, bodyHtml, tone = 'neutral') {
      const win = document.getElementById('floating-window');
      const titleEl = document.getElementById('floating-window-title');
      const subtitleEl = document.getElementById('floating-window-subtitle');
      const body = document.getElementById('floating-window-body');
      if (!win || !titleEl || !subtitleEl || !body) return;
      titleEl.textContent = demoMaskText(title || 'Details');
      subtitleEl.textContent = demoMaskText(subtitle || '');
      body.innerHTML = bodyHtml || '<div class="muted">No details available.</div>';
      win.dataset.tone = tone;
      if (!win.dataset.placed) {
        win.style.left = `${Math.max(18, Math.round(window.innerWidth * 0.5 - 380))}px`;
        win.style.top = `${Math.max(70, Math.round(window.innerHeight * 0.12))}px`;
        win.dataset.placed = 'true';
      }
      win.classList.add('open');
      fitFloatingWindow();
      requestAnimationFrame(fitFloatingWindow);
      updateRefreshState();
    }
    function closeFloatingWindow() {
      document.getElementById('floating-window')?.classList.remove('open');
      updateRefreshState();
    }
    function beginFloatingWindowDrag(event) {
      const win = document.getElementById('floating-window');
      if (!win || event.button !== 0) return;
      event.preventDefault();
      const rect = win.getBoundingClientRect();
      const offsetX = event.clientX - rect.left;
      const offsetY = event.clientY - rect.top;
      const move = (moveEvent) => {
        const margin = 14;
        const current = win.getBoundingClientRect();
        const width = Math.min(current.width, window.innerWidth - margin * 2);
        const height = Math.min(current.height, window.innerHeight - margin * 2);
        const maxLeft = window.innerWidth - width - margin;
        const maxTop = window.innerHeight - height - margin;
        const left = Math.min(Math.max(margin, moveEvent.clientX - offsetX), Math.max(margin, maxLeft));
        const top = Math.min(Math.max(margin, moveEvent.clientY - offsetY), Math.max(margin, maxTop));
        win.style.left = `${Math.round(left)}px`;
        win.style.top = `${Math.round(top)}px`;
        fitFloatingWindow();
      };
      const up = () => {
        fitFloatingWindow();
        document.removeEventListener('pointermove', move);
        document.removeEventListener('pointerup', up);
      };
      document.addEventListener('pointermove', move);
      document.addEventListener('pointerup', up);
    }
    function fitFloatingWindow() {
      const win = document.getElementById('floating-window');
      if (!win || !win.classList.contains('open')) return;
      const margin = 14;
      const minTop = margin;
      const maxWidth = Math.max(320, window.innerWidth - margin * 2);
      const maxHeight = Math.max(260, window.innerHeight - margin * 2);
      let rect = win.getBoundingClientRect();
      let width = Math.min(rect.width || 760, maxWidth);
      let height = Math.min(rect.height || maxHeight, maxHeight);
      let left = Number.parseFloat(win.style.left || `${rect.left}`);
      let top = Number.parseFloat(win.style.top || `${rect.top}`);

      if (!Number.isFinite(left)) left = Math.round((window.innerWidth - width) / 2);
      if (!Number.isFinite(top)) top = Math.round(window.innerHeight * 0.12);
      left = Math.min(Math.max(margin, left), Math.max(margin, window.innerWidth - width - margin));
      top = Math.min(Math.max(minTop, top), Math.max(minTop, window.innerHeight - height - margin));

      const availableHeight = Math.max(260, window.innerHeight - top - margin);
      win.style.left = `${Math.round(left)}px`;
      win.style.top = `${Math.round(top)}px`;
      win.style.maxWidth = `${Math.round(maxWidth)}px`;
      win.style.maxHeight = `${Math.round(availableHeight)}px`;
      win.style.setProperty('--floating-window-max-height', `${Math.round(availableHeight)}px`);
    }
    function openInterfaceBehaviorWindow(id) {
      const detail = appState.interfaceBehaviorDetails[id];
      if (!detail) return;
      openFloatingWindow(detail.title, detail.subtitle, detail.body, detail.tone);
    }
    function openInterfaceConfigWindow(id) {
      const detail = appState.interfaceConfigDetails[id];
      if (!detail) return;
      openFloatingWindow(detail.title, detail.subtitle, detail.body, detail.tone);
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
          await trackActivity(title, subtitle, () => runner(parsed));
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
        const sections = [];
        const plan = preview.plan || {};
        const commandLines = (plan.commands || preview.commands || []).map(item => typeof item === 'string' ? item : `${item.command}  # ${item.reason || item.risk || ''}`.trim());
        const warnings = plan.warnings || preview.warnings || [];
        const verify = plan.verify || preview.verify || [];
        const rollback = plan.rollback || preview.rollback || [];
        if ((preview.errors || []).length) sections.push(`# errors\n${preview.errors.join('\n')}`);
        if (warnings.length) sections.push(`# warnings\n${warnings.join('\n')}`);
        if (commandLines.length) sections.push(`# commands\n${commandLines.join('\n')}`);
        if (verify.length) sections.push(`# verify\n${verify.join('\n')}`);
        if (rollback.length) sections.push(`# rollback\n${rollback.join('\n')}`);
        document.getElementById('command-preview').textContent = demoMaskText(sections.join('\n\n') || 'No commands generated');
      } catch (err) {
        document.getElementById('command-preview').textContent = demoMaskText(err.message || 'Unable to build command preview');
      }
    }
    function defaultActionPayload(action) {
      const payload = { action: action.id };
      if (action.id === 'providers.install.guidance') payload.target = 'kubernetes';
      return payload;
    }
    async function rescanProvider(providerId) {
      await fetchJSON(`/api/providers/${encodeURIComponent(providerId)}/rescan`, { method: 'POST' });
      await render();
    }
    async function previewProviderInstall(providerId) {
      await openCommandOverlay(
        `Install guidance: ${providerId}`,
        '/api/actions/preview',
        { action: 'providers.install.guidance', target: providerId },
        async () => {},
        'Preview only'
      );
      document.getElementById('command-run').disabled = true;
    }
    async function previewRouteFirewallReconcile() {
      await openCommandOverlay(
        'Network Reconcile Preview',
        '/api/network/reconcile/preview',
        { mode: 'preview_only' },
        async () => {},
        'Preview only; no host changes will be applied'
      );
      document.getElementById('command-run').disabled = true;
    }
    async function runConnectivityTest() {
      appState.connectivityTest = await trackActivity(
        'Connectivity test',
        'Per-interface read-only probe',
        () => fetchJSON('/api/network/connectivity-test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        })
      );
      await render({ force: true });
    }
    async function previewPanelAction(actionId) {
      const action = (appState.actions || []).find(item => item.id === actionId);
      if (!action) return;
      await openCommandOverlay(action.title, '/api/actions/preview', defaultActionPayload(action), async () => {}, 'Preview guarded action');
      document.getElementById('command-run').disabled = true;
    }
    async function executePanelAction(actionId) {
      const action = (appState.actions || []).find(item => item.id === actionId);
      if (!action || action.execute_mode === 'preview_only') return;
      await openCommandOverlay(action.title, '/api/actions/preview', defaultActionPayload(action), async (edited) => {
        await fetchJSON('/api/actions/execute', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(edited),
        });
        await render();
      }, 'Preview before execute');
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
      if (service.name === 'LocalPlane') return window.location.origin;
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
    async function activatePiholeRouting() {
      const ok = await postAction('/api/pihole/activate', 'Failed to activate Pi-hole routing');
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
      await openCommandOverlay('Save Trusted LAN Config', '/api/main-lan/preview', payload, async (edited) => {
        await fetchJSON('/api/main-lan/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(edited) });
        clearDraft('main_lan.');
        await render();
      }, 'Edit the request if you want, then save the profile values.');
    }
    async function applyMainLanPreview() {
      const payload = collectMainLanPayload();
      await openCommandOverlay('Apply Trusted LAN', '/api/main-lan/preview', payload, async (edited) => {
        await fetchJSON('/api/main-lan/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(edited) });
        await fetchJSON('/api/main-lan/apply', { method: 'POST' });
        clearDraft('main_lan.');
        await render();
      }, 'This saves your current draft and immediately applies it.');
    }
    async function saveServiceLanConfigPreview() {
      const payload = collectServiceLanPayload();
      await openCommandOverlay('Save Client LAN Config', '/api/service-lan/preview', payload, async (edited) => {
        await fetchJSON('/api/service-lan/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(edited) });
        clearDraft('service_lan.');
        await render();
      });
    }
    async function applyServiceLanPreview() {
      const payload = collectServiceLanPayload();
      await openCommandOverlay('Apply Client LAN', '/api/service-lan/preview', payload, async (edited) => {
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
      await openCommandOverlay('Apply Cellular APN', '/api/cellular/apn/preview', payload, async (edited) => {
        await fetchJSON('/api/cellular/apn/apply', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(edited) });
        await render();
      }, 'This will modify the active cellular connection and reconnect it.');
    }
    async function setUplinkPreference(value) {
      const ok = await postAction('/api/wifi/config', 'Failed to update uplink preference', { uplink_preference: value });
      if (ok) await render();
    }
    async function toggleAutoApn(enabled) {
      const ok = await postAction('/api/cellular/apn/auto', 'Failed to update auto apply', { enabled });
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
    async function saveVisibleTab(view, enabled) {
      const current = visibleTabs();
      const payload = {
        ui: {
          visible_tabs: {
            ...current,
            [view]: Boolean(enabled),
          },
        },
      };
      const ok = await postAction('/api/settings', 'Failed to save settings', payload);
      if (ok) {
        apiCache.delete('settings');
        await render({ force: true });
      }
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
    async function saveInterfaceBehavior(interfaceName, inputId) {
      const profile = document.getElementById(inputId)?.value || 'unassigned';
      const ok = await postAction(
        '/api/network/behavior-bindings',
        `Failed to assign behavior for ${interfaceName}`,
        { interface: interfaceName, behavior: profile }
      );
      if (ok) {
        clearDraft(`interface_behavior.${interfaceName}`);
        apiCache.delete('networkBehaviors');
        closeFloatingWindow();
        await render({ force: true });
      }
    }
    async function saveInterfaceDesiredConfig(configId, inputId, mtuId, autoconnectId, routeMetricId, neverDefaultId, ignoreRoutesId) {
      const displayName = document.getElementById(inputId)?.value || '';
      const mtu = (document.getElementById(mtuId)?.value || '').trim();
      const autoconnect = document.getElementById(autoconnectId)?.value || 'preserve_existing';
      const routeMetric = (document.getElementById(routeMetricId)?.value || '').trim();
      const neverDefault = document.getElementById(neverDefaultId)?.value || 'preserve_existing';
      const ignoreAutoRoutes = document.getElementById(ignoreRoutesId)?.value || 'preserve_existing';
      const ok = await postAction(
        '/api/network/interface-configs/save',
        `Failed to save interface config for ${configId}`,
        {
          id: configId,
          config: {
            display_name: displayName,
            link: {
              mtu,
              autoconnect,
            },
            routing: {
              route_metric: routeMetric,
              never_default: neverDefault,
              ignore_auto_routes: ignoreAutoRoutes,
            },
          },
        }
      );
      if (ok) {
        apiCache.delete('interfaceConfigs');
        apiCache.delete('networkPlan');
        closeFloatingWindow();
        await render({ force: true });
      }
    }
    async function resetInterfaceConfig(configId) {
      const ok = await postAction(
        '/api/network/interface-configs/reset',
        `Failed to reset interface config for ${configId}`,
        { id: configId }
      );
      if (ok) {
        apiCache.delete('interfaceConfigs');
        closeFloatingWindow();
        await render({ force: true });
      }
    }
    async function setLedState(name, payload) {
      const ok = await postAction('/api/device-io/led', 'Failed to update LED', { name, ...payload });
      if (ok) await render();
    }
    async function controlSamba(action) {
      const ok = await trackActivity(`Samba ${action}`, 'Service control', () => fetchJSON('/api/samba/control', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action }) }));
      if (ok) await render();
    }
    async function setSambaPassword() {
      const payload = { username: document.getElementById('samba-username').value, password: document.getElementById('samba-password').value };
      await trackActivity('Samba password', payload.username || 'user', () => fetchJSON('/api/samba/user/password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }));
      await render();
    }
    async function setSambaUserState(username, action) {
      await trackActivity(`Samba user ${action}`, username, () => fetchJSON('/api/samba/user/state', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, action }) }));
      await render();
    }
    async function deleteSambaUser(username) {
      await trackActivity('Delete Samba user', username, () => fetchJSON('/api/samba/user/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username }) }));
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
      await trackActivity('Save Samba share', payload.name, () => fetchJSON('/api/samba/share', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }));
      await render();
    }
    async function deleteSambaShare(name) {
      await trackActivity('Delete Samba share', name, () => fetchJSON('/api/samba/share/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) }));
      await render();
    }
    async function controlPrinting(action) {
      await trackActivity(`Printing ${action}`, 'CUPS service', () => fetchJSON('/api/printing/control', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action }) }));
      await render();
    }
    async function installNetAlertX() {
      if (!confirm('Install and start NetAlertX now?')) return;
      await trackActivity('Install NetAlertX', 'Docker stack', () => fetchJSON('/api/netalert/install', { method: 'POST' }));
      await render();
    }
    async function syncNetAlertX() {
      await trackActivity('Sync NetAlertX', 'Topology refresh', () => fetchJSON('/api/netalert/sync', { method: 'POST' }));
      await render();
    }
    async function runAtCommand() {
      const command = document.getElementById('at-command').value.trim();
      if (!command) return;
      try {
        const result = await fetchJSON('/api/cellular/at', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ command }) });
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
        name: fieldValue('main-lan-name'),
        target_interface: fieldValue('main-lan-target-interface'),
        role: fieldValue('main-lan-role'),
        ipv4_mode: fieldValue('main-lan-ipv4-mode'),
        ipv4_address: fieldValue('main-lan-ipv4-address'),
        ipv4_subnet: fieldValue('main-lan-ipv4-subnet'),
        dhcp_range: fieldValue('main-lan-dhcp-range'),
        ipv6_mode: fieldValue('main-lan-ipv6-mode'),
        ipv6_address: fieldValue('main-lan-ipv6-address'),
        ipv6_prefix: fieldValue('main-lan-ipv6-prefix'),
        dns_servers: fieldValue('main-lan-dns-servers'),
        mtu: fieldValue('main-lan-mtu'),
        autoconnect: fieldValue('main-lan-autoconnect', 'yes'),
        route_metric: fieldValue('main-lan-route-metric'),
        never_default: fieldValue('main-lan-never-default', 'yes'),
        ignore_auto_routes: fieldValue('main-lan-ignore-auto-routes', 'yes'),
        use_pihole_dns: document.getElementById('main-lan-pihole-toggle').checked ? 'true' : 'false',
      };
    }
    function collectServiceLanPayload() {
      const fieldValue = (id, fallback = '') => document.getElementById(id)?.value ?? fallback;
      return {
        name: fieldValue('service-lan-name'),
        interface: fieldValue('service-lan-interface'),
        role: fieldValue('service-lan-role'),
        ipv4_mode: fieldValue('service-lan-ipv4-mode'),
        ipv4_gateway: fieldValue('service-lan-ipv4-gateway'),
        ipv4_subnet: fieldValue('service-lan-ipv4-subnet'),
        dhcp_range: fieldValue('service-lan-dhcp-range'),
        ipv6_mode: fieldValue('service-lan-ipv6-mode'),
        ipv6_gateway: fieldValue('service-lan-ipv6-gateway'),
        ipv6_prefix: fieldValue('service-lan-ipv6-prefix'),
        dns_servers: fieldValue('service-lan-dns-servers'),
        mtu: fieldValue('service-lan-mtu'),
        autoconnect: fieldValue('service-lan-autoconnect', 'yes'),
        route_metric: fieldValue('service-lan-route-metric'),
        never_default: fieldValue('service-lan-never-default', 'yes'),
        ignore_auto_routes: fieldValue('service-lan-ignore-auto-routes', 'yes'),
        use_pihole_dns: document.getElementById('service-lan-pihole-toggle').checked ? 'true' : 'false',
      };
    }
    function collectWifiPayload() {
      const config = (((window.appState || {}).wifi || {}).config || {});
      const fieldValue = (id, fallback = '') => document.getElementById(id)?.value ?? fallback;
      return {
        mode: fieldValue('wifi-mode', config.mode || 'client'),
        client_trust_mode: fieldValue('wifi-client-trust-mode', config.client_trust_mode || 'normal'),
        ssid: fieldValue('wifi-ssid', config.ssid || ''),
        password: fieldValue('wifi-password', ''),
        hotspot_ssid: fieldValue('wifi-hotspot-ssid', config.hotspot_ssid || ''),
        hotspot_password: fieldValue('wifi-hotspot-password', ''),
        hotspot_security: fieldValue('wifi-hotspot-security', config.hotspot_security || 'wpa2-personal'),
        country: fieldValue('wifi-country', config.country || 'DE'),
        band: fieldValue('wifi-band', config.band || '2.4ghz'),
        channel: fieldValue('wifi-channel', config.channel || 'auto'),
        uplink_preference: fieldValue('wifi-uplink-preference', config.uplink_preference || 'prefer-lte'),
        ipv4_method: fieldValue('wifi-ipv4-method', config.ipv4_method || 'auto'),
        ipv4_address: fieldValue('wifi-ipv4-address', config.ipv4_address || ''),
        ipv6_method: fieldValue('wifi-ipv6-method', config.ipv6_method || 'disabled'),
        ipv6_address: fieldValue('wifi-ipv6-address', config.ipv6_address || ''),
        use_pihole_dns: document.getElementById('wifi-pihole-toggle')
          ? (document.getElementById('wifi-pihole-toggle').checked ? 'true' : 'false')
          : (String(config.use_pihole_dns).toLowerCase() === 'true' ? 'true' : 'false'),
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
    function renderFlowNode(kind, title, detail, state, positionClass, metricHtml = '') {
      return `
        <div class="flow-node ${kind} ${stateTone(state)} ${positionClass}">
          <div>
            <div class="flow-title">${escapeHtml(title)}</div>
            <div class="flow-detail">${escapeHtml(detail || '-')}</div>
            ${metricHtml}
          </div>
        </div>
      `;
    }
    function renderFlowMetric(name, counters) {
      const rx = Number((counters || {}).rx_bytes || 0);
      const tx = Number((counters || {}).tx_bytes || 0);
      if (!name || (!rx && !tx)) return '';
      const backendRxRate = Number((counters || {}).rx_bytes_per_sec);
      const backendTxRate = Number((counters || {}).tx_bytes_per_sec);
      if (Number.isFinite(backendRxRate) && Number.isFinite(backendTxRate) && Number((counters || {}).sample_seconds || 0) > 0) {
        return `<div class="flow-metric"><span class="metric-down">↓ ${escapeHtml(formatBytes(backendRxRate))}/s</span><span class="metric-up">↑ ${escapeHtml(formatBytes(backendTxRate))}/s</span></div>`;
      }
      const now = Date.now();
      const samples = appState.flowMetricSamples || {};
      const previous = samples[name];
      let down = 'measuring';
      let up = 'measuring';
      if (previous && previous.rx !== undefined && previous.tx !== undefined) {
        const seconds = Math.max((now - previous.at) / 1000, 1);
        const rxRate = Math.max(0, rx - previous.rx) / seconds;
        const txRate = Math.max(0, tx - previous.tx) / seconds;
        down = `${formatBytes(rxRate)}/s`;
        up = `${formatBytes(txRate)}/s`;
      }
      samples[name] = { rx, tx, at: now };
      appState.flowMetricSamples = samples;
      return `<div class="flow-metric"><span class="metric-down">↓ ${escapeHtml(down)}</span><span class="metric-up">↑ ${escapeHtml(up)}</span></div>`;
    }
    function renderNetworkCanvas(overview, systemStats, activeSessions, serviceLanClients = [], wifiClients = []) {
      const defaultDev = (overview.uplink_ipv4 || {}).dev || (overview.uplink_ipv6 || {}).dev || '';
      const uplink = (overview.uplinks || []).find(i => i.name === defaultDev) || (overview.uplinks || [])[0] || {};
      const localLans = overview.local_lans || [];
      const lan = localLans.find(i => String(i.role || '').includes('lan')) || localLans[0] || {};
      const wifi = (overview.uplinks || []).find(i => String(i.role || '').includes('wifi')) || localLans.find(i => String(i.name || '').startsWith('wl')) || {};
      const docker = (systemStats.docker || {}).running ?? 0;
      const gateway = (overview.uplink_ipv4 || {}).via || (overview.uplink_ipv6 || {}).via || 'default';
      const routeLabel = defaultDev ? `${defaultDev} via ${gateway}` : 'No default route';
      const lanLabel = localLans.length === 1 ? `${lan.name || lan.interface || 'local'} only` : `${localLans.length} local ports`;
      const lanClients = (serviceLanClients || []).length;
      const wirelessClients = (wifiClients || []).length;
      const clientLabel = `${(activeSessions || []).length} live sessions`;
      const hostLabel = overview.hostname || 'R1000';
      return `
        <div class="network-canvas" aria-label="Network flow overview">
          <svg class="flow-lines" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
            <defs>
              <linearGradient id="flowLineGradient" x1="0" x2="1" y1="0" y2="1">
                <stop offset="0%" stop-color="rgba(59, 130, 246, 0.18)" />
                <stop offset="48%" stop-color="rgba(139, 92, 246, 0.62)" />
                <stop offset="100%" stop-color="rgba(236, 72, 153, 0.2)" />
              </linearGradient>
            </defs>
            <path class="flow-path uplink-path" d="M21 24 C31 24 38 42 50 50" />
            <path class="flow-path lan-path" d="M50 50 C61 42 69 24 81 24" />
            <path class="flow-path wifi-path" d="M50 50 C36 58 29 76 21 76" />
            <path class="flow-path services-path" d="M50 50 C61 58 70 76 81 76" />
          </svg>
          ${renderFlowNode('internet', 'Internet', routeLabel, uplink.state || defaultDev, 'pos-internet', renderFlowMetric(uplink.name || defaultDev, uplink.counters))}
          ${renderFlowNode('core', hostLabel, clientLabel, 'online', 'pos-core')}
          ${renderFlowNode('lan', 'Local LAN', `${lanLabel} / ${lanClients} wired client${lanClients === 1 ? '' : 's'}`, lan.state, 'pos-lan', renderFlowMetric(lan.name || lan.interface, lan.counters))}
          ${renderFlowNode('wifi', 'Wi-Fi', `${wifi.name || wifi.interface || 'radio'} / ${wirelessClients} wireless client${wirelessClients === 1 ? '' : 's'}`, wifi.state, 'pos-wifi', renderFlowMetric(wifi.name || wifi.interface, wifi.counters))}
          ${renderFlowNode('services', 'Services', `${docker} container${docker === 1 ? '' : 's'}`, docker ? 'active' : 'standby', 'pos-services')}
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
    function formatBytes(value) {
      const n = Number(value || 0);
      if (!Number.isFinite(n) || n <= 0) return '0 B';
      const units = ['B', 'KB', 'MB', 'GB', 'TB'];
      const index = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
      return `${(n / Math.pow(1024, index)).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
    }
    function formatRate(value) {
      return `${formatBytes(value)}/s`;
    }
    function renderClientSummary(clients, emptyText = 'No clients detected') {
      return (clients || []).length ? `<div class="item-list compact scroll-list mini">${clients.map(c => `<div class="item client-item"><div class="item-top"><div class="item-title">${escapeHtml(c.hostname || c.mac || 'Client')}</div>${renderStatusPill(c.state || 'seen', c.state || 'online')}</div><div class="muted">IP: ${escapeHtml(c.ip || '-')} | MAC: ${escapeHtml(c.mac || '-')} | ${escapeHtml(c.interface || '-')}</div></div>`).join('')}</div>` : `<div class="muted">${escapeHtml(emptyText)}</div>`;
    }
    function renderOverview(overview, systemStats, activeSessions, serviceLanClients = [], wifiClients = []) {
      const hw = overview.hardware || {};
      const mem = systemStats.memory || {};
      const load = systemStats.load || {};
      const docker = systemStats.docker || {};
      return `
        ${renderNetworkCanvas(overview, systemStats, activeSessions, serviceLanClients, wifiClients)}
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
        <div class="route"><div class="label">Local LAN Clients</div>${renderClientSummary(serviceLanClients, 'No wired LAN clients detected')}</div>
        <div class="route"><div class="label">Wi-Fi Clients</div>${renderClientSummary(wifiClients, 'No Wi-Fi clients detected')}</div>
      `;
    }
    function renderDockerBrief(systemStats) {
      const docker = systemStats.docker || {};
      if (!docker.available) return '<div class="muted">Docker not available</div>';
      const containers = docker.containers || [];
      const listClass = containers.length > 8 ? 'item-list scroll-list dashboard-list' : 'item-list dashboard-list natural';
      return containers.length ? `<div class="${listClass}">${containers.map(c => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(c.name)}</div><div class="badge">${String(c.status || '').toLowerCase().startsWith('up') ? 'running' : escapeHtml(c.status || '-')}</div></div><div class="muted">${escapeHtml(c.image)}</div><div class="hint">Container uptime: ${escapeHtml(c.status || '-')}</div></div>`).join('')}</div>` : '<div class="muted">No containers running</div>';
    }
    function renderSessions(sessions) {
      const deduped = [];
      const seen = new Set();
      (sessions || []).filter(session => !String(session.entry || session.service || '').toLowerCase().includes('dashboard')).forEach(session => {
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
      return deduped.length ? `<div class="item-list scroll-list dashboard-list">${deduped.map(s => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(s.entry || s.service)}</div><div class="badge">${escapeHtml(s.interface || '-')}</div></div><div class="muted">${escapeHtml(s.peer_address)}:${escapeHtml(s.peer_port)} -> ${escapeHtml(s.local_address)}:${escapeHtml(s.local_port)}</div></div>`).join('')}</div>` : '<div class="muted">No active sessions detected</div>';
    }
    function sessionCount(sessions) {
      const seen = new Set();
      (sessions || []).filter(session => !String(session.entry || session.service || '').toLowerCase().includes('dashboard')).forEach(session => {
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
    function interfaceNameOf(item) {
      return item.name || item.interface || item.ifname || item.device || '';
    }
    function interfaceKindOf(item) {
      const name = String(interfaceNameOf(item)).toLowerCase();
      const role = String(item.role || item.detected_role || item.detected_kind || item.kind || item.type || '').toLowerCase();
      if (role.includes('cellular') || role.includes('wwan') || /^wwan|^cdc-wdm|^usb/.test(name)) return 'cellular';
      if (role.includes('wifi') || role.includes('wireless') || /^wl|^wlan/.test(name)) return 'wifi';
      if (role.includes('ethernet') || /^eth|^en|^lan/.test(name)) return 'ethernet';
      if (role.includes('overlay') || role.includes('tunnel') || name.includes('tailscale') || name.includes('wg')) return 'tunnel';
      return role || 'interface';
    }
    function interfaceStateOf(item) {
      return String(item.state || item.operstate || item.link_state || '').toLowerCase();
    }
    function interfaceIsUp(item) {
      const state = interfaceStateOf(item);
      return ['up', 'connected', 'activated', 'online'].includes(state) || item.up === true || item.default_route === true;
    }
    function interfaceSubtitle(item) {
      const parts = [];
      const name = interfaceNameOf(item);
      const kind = interfaceKindOf(item);
      const addresses = [...(item.ipv4 || item.ipv4_addresses || []), ...(item.ipv6 || item.ipv6_addresses || [])].filter(Boolean);
      if (kind && kind !== name) parts.push(kind);
      if (item.default_route) parts.push('default route');
      if (addresses.length) parts.push(addresses[0]);
      return parts.join(' / ') || 'discovered interface';
    }
    function interfaceAddresses(item) {
      return [...(item.ipv4 || item.ipv4_addresses || []), ...(item.ipv6 || item.ipv6_addresses || [])].filter(Boolean);
    }
    function selectedInterface(interfaces, selectedName) {
      return uniqueInterfaces(interfaces).find(item => interfaceNameOf(item) === selectedName) || uniqueInterfaces(interfaces)[0] || {};
    }
    function renderSelectedInterfaceFacts(interfaces, selectedName) {
      const item = selectedInterface(interfaces, selectedName);
      if (!interfaceNameOf(item)) return '';
      const addresses = interfaceAddresses(item);
      const state = interfaceStateOf(item) || (interfaceIsUp(item) ? 'up' : 'unknown');
      const path = item.path || item.sys_path || item.driver || item.mac || item.address || '';
      return `
        <div class="interface-facts">
          <div class="metric"><div class="label">Selected</div><div class="value small">${escapeHtml(interfaceNameOf(item))}</div></div>
          <div class="metric"><div class="label">Kind</div><div class="value small">${escapeHtml(interfaceKindOf(item))}</div></div>
          <div class="metric"><div class="label">State</div><div class="value small">${escapeHtml(state.toUpperCase())}</div></div>
          <div class="metric"><div class="label">Route</div><div class="value small">${item.default_route ? 'Default route' : 'No default route'}</div></div>
          <div class="metric wide"><div class="label">Addresses</div><div class="value small">${escapeHtml(addresses.join(', ') || '-')}</div></div>
          ${path ? `<div class="metric wide"><div class="label">Identity</div><div class="value small">${escapeHtml(path)}</div></div>` : ''}
        </div>`;
    }
    function uniqueInterfaces(items) {
      const seen = new Set();
      return (items || []).filter(item => {
        const name = interfaceNameOf(item);
        if (!name || seen.has(name)) return false;
        seen.add(name);
        return true;
      });
    }
    function renderInterfaceSwitcher(title, interfaces, selectedName, draftKey, emptyText) {
      const items = uniqueInterfaces(interfaces);
      if (!items.length) {
        return `<div class="resource-switcher empty"><div><div class="resource-switcher-title">${escapeHtml(title)}</div><div class="muted">${escapeHtml(emptyText || 'No matching interfaces discovered yet.')}</div></div></div>`;
      }
      const activeName = selectedName || interfaceNameOf(items.find(interfaceIsUp) || items[0]);
      return `
        <div class="resource-switcher">
          <div class="resource-switcher-head">
            <div>
              <div class="resource-switcher-title">${escapeHtml(title)}</div>
              <div class="resource-switcher-subtitle">${items.length} discovered ${items.length === 1 ? 'interface' : 'interfaces'}</div>
            </div>
            <span class="badge idle">${escapeHtml(activeName || '-')}</span>
          </div>
          <div class="resource-segments" role="tablist" aria-label="${escapeHtml(title)}">
            ${items.map(item => {
              const name = interfaceNameOf(item);
              const active = name === activeName;
              const up = interfaceIsUp(item);
              return `<button type="button" class="resource-segment ${active ? 'active' : ''} ${up ? 'online' : 'offline'}" onclick='setInterfaceSelector(${JSON.stringify(draftKey)}, ${JSON.stringify(name)})'>
                <span class="resource-segment-dot"></span>
                <span class="resource-segment-text"><strong>${escapeHtml(name)}</strong><small>${escapeHtml(interfaceSubtitle(item))}</small></span>
              </button>`;
            }).join('')}
          </div>
        </div>`;
    }
    function wirelessInterfaces(interfaces, wifi) {
      const discovered = (interfaces || []).filter(item => interfaceKindOf(item) === 'wifi');
      if ((wifi || {}).interface && !discovered.some(item => interfaceNameOf(item) === wifi.interface)) {
        discovered.unshift({ name: wifi.interface, role: 'wifi', state: (wifi.device || {}).state || (wifi.device || {}).wifi_radio, ipv4: (wifi.device || {}).ipv4 || [], ipv6: (wifi.device || {}).ipv6 || [] });
      }
      return discovered;
    }
    function cellularInterfaces(interfaces, lte, lteProfile, overview) {
      const discovered = (interfaces || []).filter(item => interfaceKindOf(item) === 'cellular');
      const defaultDev = ((overview || {}).uplink_ipv4 || {}).dev || ((overview || {}).uplink_ipv6 || {}).dev || '';
      [defaultDev, 'wwan0'].filter(Boolean).forEach(name => {
        if ((name.startsWith('wwan') || name.startsWith('cdc-wdm')) && !discovered.some(item => interfaceNameOf(item) === name)) {
          discovered.unshift({ name, role: 'cellular', state: (lte || {}).state || 'detected', default_route: name === defaultDev });
        }
      });
      if ((lte || {}).available && !discovered.length) {
        discovered.push({ name: (lteProfile || {}).interface || 'cellular modem', role: 'cellular', state: (lte || {}).state || 'available' });
      }
      return discovered;
    }
    function uplinkPreferenceOptions() {
      return [
        { value: 'prefer-lte', label: 'Prefer Cellular' },
        { value: 'prefer-wired', label: 'Prefer Wired' },
        { value: 'prefer-wifi', label: 'Prefer Wi-Fi' },
        { value: 'failover-only', label: 'Failover Only' },
      ];
    }
    function uplinkPreferenceLabel(value) {
      const option = uplinkPreferenceOptions().find(item => item.value === value);
      return option ? option.label : (value || '-');
    }
    function setLanStackDisabled(kind) {
      appState.drafts[`${kind}_lan.ipv4_mode`] = 'disabled';
      appState.drafts[`${kind}_lan.ipv6_mode`] = 'disabled';
      updateRefreshState();
      render();
    }
    function toggleCustomSelect(event, id) {
      event.stopPropagation();
      const root = document.getElementById(`${id}-custom`);
      if (!root) return;
      const wasOpen = root.classList.contains('open');
      closeCustomSelects();
      if (!wasOpen) {
        const trigger = root.querySelector('.custom-select-trigger');
        const options = root.querySelector('.custom-options');
        const triggerBox = trigger?.getBoundingClientRect();
        if (triggerBox && options) {
          const viewportGap = 18;
          const below = window.innerHeight - triggerBox.bottom - viewportGap;
          const above = triggerBox.top - viewportGap;
          const openUp = below < 220 && above > below;
          const maxHeight = Math.max(150, Math.min(260, openUp ? above : below));
          root.classList.add('open');
          root.classList.toggle('open-up', openUp);
          options.dataset.owner = root.id;
          document.body.appendChild(options);
          options.classList.add('portal-open');
          options.classList.toggle('open-up', openUp);
          options.style.left = `${Math.round(triggerBox.left)}px`;
          options.style.width = `${Math.round(triggerBox.width)}px`;
          options.style.top = openUp ? 'auto' : `${Math.round(triggerBox.bottom + 5)}px`;
          options.style.bottom = openUp ? `${Math.round(window.innerHeight - triggerBox.top + 5)}px` : 'auto';
          options.style.setProperty('--options-max-height', `${maxHeight}px`);
          requestAnimationFrame(() => {
            options.querySelector('.custom-option.active')?.scrollIntoView({ block: 'nearest' });
          });
        }
      }
    }
    function selectCustomOption(event, id, key, value, label = '', afterChange = '') {
      event.stopPropagation();
      appState.drafts[key] = value;
      const input = document.getElementById(id);
      const root = document.getElementById(`${id}-custom`);
      if (input) input.value = value;
      if (root) {
        const optionsRoot = document.querySelector(`.custom-options[data-owner="${root.id}"]`) || root.querySelector('.custom-options');
        const button = root.querySelector('.custom-select-trigger span');
        if (button) button.textContent = label || value;
        optionsRoot?.querySelectorAll('.custom-option').forEach(option => {
          option.classList.toggle('active', option.dataset.value === value);
        });
        restoreCustomOptions(root);
      }
      const summary = root?.closest('.config-section')?.querySelector('summary span:nth-child(2)');
      if (summary) summary.textContent = label || value;
      const explanation = document.getElementById(`${id}-explanation`);
      if (explanation && key.endsWith('.role')) explanation.innerHTML = lanRoleExplanation(value);
      updateRefreshState();
      if (REACTIVE_DRAFT_KEYS.has(key)) scheduleDraftRender();
      if (afterChange && typeof window[afterChange] === 'function') window[afterChange](value);
    }
    function customSelectMarkup(id, key, options, value, config = {}) {
      const normalized = options.map(option => typeof option === 'object'
        ? { value: String(option.value ?? option.id ?? ''), label: String(option.label ?? option.name ?? option.value ?? option.id ?? '') }
        : { value: String(option), label: String(option) });
      const active = normalized.find(option => option.value === String(value)) || normalized[0] || { value: String(value || ''), label: String(value || '') };
      const disabled = config.disabled ? 'disabled' : '';
      const afterChange = config.afterChange || '';
      return `
        <input id="${id}" type="hidden" value="${escapeHtml(active.value)}" />
        <div id="${id}-custom" class="custom-select ${config.disabled ? 'disabled' : ''}">
          <button class="custom-select-trigger" type="button" ${disabled} onclick="toggleCustomSelect(event, '${id}')">
            <span>${escapeHtml(active.label)}</span>
          </button>
          <div class="custom-options">
            ${normalized.map(option => `<button type="button" class="custom-option ${option.value === active.value ? 'active' : ''}" data-value="${escapeHtml(option.value)}" onclick="selectCustomOption(event, '${id}', '${key}', '${escapeHtml(option.value)}', '${escapeHtml(option.label)}', '${escapeHtml(afterChange)}')">${escapeHtml(option.label)}</button>`).join('')}
          </div>
        </div>
      `;
    }
    function lanRoleExplanation(role) {
      if (role === 'isolated') {
        return `
          <div class="item">
            <div class="item-title">Isolated</div>
            <div class="muted">Internet works for clients, but access to trusted local interfaces, Wi-Fi, Tailscale, and most device services is blocked.</div>
          </div>
        `;
      }
      if (role === 'external') {
        return `
          <div class="item">
            <div class="item-title">External</div>
            <div class="muted">Clients get internet and stay away from trusted local interfaces. Tailscale-connected devices can still reach the router and this external segment for management.</div>
          </div>
        `;
      }
      return `
        <div class="item">
          <div class="item-title">Internal</div>
          <div class="muted">Trusted local network. Clients can use local services, management pages, and other internal networks.</div>
        </div>
      `;
    }
    function renderLanCard(kind, profile, options = {}) {
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
      const displayName = draftValue(`${kind}_lan.name`, profile.name || (kind === 'main' ? 'Trusted LAN' : 'Client LAN'));
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
      const portKey = kind === 'main' ? 'target_interface' : 'interface';
      const portValue = draftValue(`${kind}_lan.${portKey}`, iface === '-' ? '' : iface);
      const portOptions = Array.from(new Set([portValue, ...(profile.available_interfaces || [])].filter(Boolean)))
        .map(port => ({ value: port, label: port }));
      const interfaceControl = options.fixedInterface
        ? `<input id="${prefix}-${kind === 'main' ? 'target-interface' : 'interface'}" type="hidden" value="${escapeHtml(portValue)}" /><div class="value small">${escapeHtml(portValue || '-')}</div>`
        : customSelectMarkup(`${prefix}-${kind === 'main' ? 'target-interface' : 'interface'}`, `${kind}_lan.${portKey}`, portOptions, portValue);
      const yesNoOptions = [{ value: 'yes', label: 'Yes' }, { value: 'no', label: 'No' }];
      return `
        <div class="stat-grid">
          <div class="metric"><div class="label">Display Name</div><input id="${prefix}-name" value="${escapeHtml(displayName)}" /></div>
          <div class="metric"><div class="label">Interface</div>${interfaceControl}</div>
          <div class="metric"><div class="label">State</div><div class="value small">${escapeHtml(((profile.target_interface_status || {}).state) || '-')}</div></div>
          <div class="metric"><div class="label">Internet</div><div class="switch-row" style="margin-top:8px;"><div class="muted">${internetPending ? 'Working...' : (profile.internet_enabled ? 'Enabled' : 'Disabled')}</div><label class="switch ${internetPending ? 'busy' : ''}"><input type="checkbox" ${profile.internet_enabled ? 'checked' : ''} ${internetPending ? 'disabled' : ''} onchange="toggleLanInternetState('${kind}', this.checked)"><span class="slider"></span></label></div></div>
          <div class="metric"><div class="label">Pi-hole</div><div class="value small">${profile.use_pihole_dns ? 'ON' : 'OFF'}</div></div>
        </div>
        <div class="stat-grid" style="margin-top:8px;">
          <div class="metric"><div class="label">Desired State</div><div class="value small">${escapeHtml(desiredAddressing)}</div></div>
          <div class="metric"><div class="label">Live State</div><div class="value small">${escapeHtml(liveAddressing)}</div></div>
        </div>
        <details class="config-section">
          <summary><span>Client Behavior</span><span>${escapeHtml(role)}</span></summary>
          <div class="stat-grid" style="margin-top:10px;">
            <div class="metric"><div class="label">Behavior</div>${customSelectMarkup(`${prefix}-role`, `${kind}_lan.role`, ['isolated', 'internal', 'external'], role)}</div>
          </div>
          <div id="${prefix}-role-explanation" class="item-list" style="margin-top:10px;">${lanRoleExplanation(role)}</div>
        </details>
        <details class="config-section">
          <summary><span>Addressing</span><span>${escapeHtml(desiredAddressing)}</span></summary>
          <div class="controls"><button class="secondary" onclick="setLanStackDisabled('${kind}')">Disable IPv4 + IPv6</button></div>
          <div class="stat-grid" style="margin-top:10px;">
            <div class="metric"><div class="label">IPv4 Mode</div>${customSelectMarkup(`${prefix}-ipv4-mode`, `${kind}_lan.ipv4_mode`, (isServiceLan ? ['shared','disabled'] : ['shared','manual','disabled']).map(v => ({ value: v, label: ipv4ModeLabel(v) })), ipv4Mode)}</div>
            ${ipv4Mode !== 'disabled' ? `<div class="metric"><div class="label">${kind === 'main' ? 'IPv4 Address' : 'IPv4 Gateway'}</div><input id="${prefix}-${kind === 'main' ? 'ipv4-address' : 'ipv4-gateway'}" value="${draftValue(`${kind}_lan.${kind === 'main' ? 'ipv4_address' : 'ipv4_gateway'}`, ipv4Address)}" /></div>` : ''}
            ${ipv4Mode !== 'disabled' ? `<div class="metric"><div class="label">IPv4 Block</div><input id="${prefix}-ipv4-subnet" value="${draftValue(`${kind}_lan.ipv4_subnet`, profile.ipv4_subnet || '')}" /></div>` : ''}
            ${ipv4Mode === 'shared' ? `<div class="metric"><div class="label">DHCP Range</div><input id="${prefix}-dhcp-range" value="${draftValue(`${kind}_lan.dhcp_range`, profile.dhcp_range || profile.dhcp_range_ipv4 || '')}" /></div>` : ''}
            <div class="metric"><div class="label">IPv6 Mode</div>${customSelectMarkup(`${prefix}-ipv6-mode`, `${kind}_lan.ipv6_mode`, (isServiceLan ? ['routed','disabled'] : ['routed','manual','disabled']).map(v => ({ value: v, label: ipv6ModeLabel(v) })), ipv6Mode)}</div>
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
        <details class="config-section">
          <summary><span>Advanced Link / Routing</span><span>${escapeHtml(profile.mtu || profile.route_metric ? [profile.mtu ? `MTU ${profile.mtu}` : '', profile.route_metric ? `metric ${profile.route_metric}` : ''].filter(Boolean).join(' / ') : 'defaults')}</span></summary>
          <div class="stat-grid" style="margin-top:10px;">
            <div class="metric"><div class="label">MTU</div><input id="${prefix}-mtu" value="${draftValue(`${kind}_lan.mtu`, profile.mtu || '')}" placeholder="adapter default" /></div>
            <div class="metric"><div class="label">Autoconnect</div>${customSelectMarkup(`${prefix}-autoconnect`, `${kind}_lan.autoconnect`, yesNoOptions, draftValue(`${kind}_lan.autoconnect`, profile.autoconnect || 'yes'))}</div>
            <div class="metric"><div class="label">Route Metric</div><input id="${prefix}-route-metric" value="${draftValue(`${kind}_lan.route_metric`, profile.route_metric || '')}" placeholder="NetworkManager default" /></div>
            <div class="metric"><div class="label">Never Default Route</div>${customSelectMarkup(`${prefix}-never-default`, `${kind}_lan.never_default`, yesNoOptions, draftValue(`${kind}_lan.never_default`, profile.never_default || 'yes'))}</div>
            <div class="metric"><div class="label">Ignore Auto Routes</div>${customSelectMarkup(`${prefix}-ignore-auto-routes`, `${kind}_lan.ignore_auto_routes`, yesNoOptions, draftValue(`${kind}_lan.ignore_auto_routes`, profile.ignore_auto_routes || 'yes'))}</div>
          </div>
          <div class="hint">These values are part of the real LAN apply path now. Leave MTU and route metric empty to keep NetworkManager defaults.</div>
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
        uplinks: interfaces.filter(i => i.role === 'cellular' || i.role === 'overlay' || (i.role === 'ethernet' && i.default_route)),
        lan: interfaces.filter(i => i.physical && i.role === 'ethernet' && !i.default_route),
        wireless: interfaces.filter(i => i.role === 'wifi'),
        virtual: interfaces.filter(i => !i.physical && !['overlay'].includes(i.role)),
      };
    }
    function renderInterfaceGroup(title, items) {
      return `<div class="route"><div class="label">${escapeHtml(title)}</div><div class="item-list" style="margin-top:10px;">${items.length ? items.map(i => {
        const linkPending = isTogglePending(`link:${i.name}`);
        const linkEnabled = ['up', 'unknown'].includes(String(i.state || '').toLowerCase());
        const counters = i.counters || {};
        return `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(i.name)}</div><div class="badge ${stateTone(i.state)}">${escapeHtml(i.state)}</div></div><div class="muted">Kind: ${escapeHtml(i.role || '-')} | MAC: ${escapeHtml(i.mac || '-')} | MTU: ${escapeHtml(i.mtu || '-')}</div><div class="muted">IPv4: ${(i.ipv4 || []).join(', ') || '-'} </div><div class="muted">IPv6: ${(i.ipv6 || []).join(', ') || '-'} </div><div class="muted">Traffic: ↓ ${escapeHtml(formatRate(counters.rx_bytes_per_sec))} / ↑ ${escapeHtml(formatRate(counters.tx_bytes_per_sec))} | RX ${escapeHtml(formatBytes(counters.rx_bytes))} | TX ${escapeHtml(formatBytes(counters.tx_bytes))}</div>${i.physical ? `<div class="route"><div class="switch-row"><div><div class="label">Link State</div><div class="muted">${linkPending ? 'Working...' : escapeHtml(i.state || '-')}</div></div><label class="switch ${linkPending ? 'busy' : ''}"><input type="checkbox" ${linkEnabled ? 'checked' : ''} ${linkPending ? 'disabled' : ''} onchange="toggleLinkState('${i.name}', this.checked)"><span class="slider"></span></label></div></div>` : ''}</div>`;
      }).join('') : '<div class="muted">No interfaces in this group</div>'}</div></div>`;
    }
    function profileBadgeClass(profile) {
      if (String(profile || '').includes('uplink')) return 'online';
      if (String(profile || '').includes('lan')) return 'warn';
      if (profile === 'unassigned') return 'idle';
      return 'idle';
    }
    function interfaceBehaviorLabel(behavior, labels = {}) {
      const fallback = {
        management_lan: 'Trusted local network',
        device_lan: 'Isolated client network',
        uplink_ethernet: 'Wired uplink',
        uplink_wifi: 'Wi-Fi uplink',
        hotspot_wifi: 'Wi-Fi hotspot',
        uplink_cellular: 'Cellular uplink',
        management_tunnel: 'Remote management tunnel',
        container: 'Container interface',
        unassigned: 'Observe only',
      };
      return labels[behavior] || fallback[behavior] || String(behavior || 'unassigned').replace(/_/g, ' ');
    }
    function interfaceLiveSummary(item) {
      const identity = item.identity || {};
      const nm = item.nmcli || {};
      const parts = [
        item.interface || '-',
        identity.stable_key || '',
        nm.connection || '',
      ].filter(Boolean);
      return parts.join(' / ');
    }
    function configStatusTone(configItem) {
      const live = configItem.live || {};
      return stateTone(live.state || '');
    }
    function configDisplayName(configItem) {
      const config = configItem.config || {};
      return config.display_name || configItem.interface || configItem.id || 'interface';
    }
    function configLiveSummary(configItem) {
      const live = configItem.live || {};
      const identity = configItem.identity || {};
      const parts = [
        configItem.interface || '-',
        configItem.kind_label || configItem.kind || '',
        identity.stable_key || '',
      ].filter(Boolean);
      return parts.join(' / ');
    }
    function configDesiredSummary(configItem) {
      const config = configItem.config || {};
      const internet = config.internet || {};
      const addressing = config.addressing || {};
      const wireless = config.wireless || {};
      const cellular = config.cellular || {};
      const link = config.link || {};
      const routing = config.routing || {};
      const chips = [];
      if (internet.use_as_uplink) chips.push('uplink');
      if (internet.share_to_clients) chips.push('client egress');
      if (addressing.ipv4_mode && addressing.ipv4_mode !== 'preserve_existing') chips.push(`ipv4 ${addressing.ipv4_mode}`);
      if (addressing.ipv6_mode && addressing.ipv6_mode !== 'preserve_existing') chips.push(`ipv6 ${addressing.ipv6_mode}`);
      if (link.mtu) chips.push(`mtu ${link.mtu}`);
      if (routing.route_metric) chips.push(`metric ${routing.route_metric}`);
      if (wireless.mode) chips.push(`wifi ${wireless.mode}`);
      if (cellular.auto_apn === false) chips.push('manual apn');
      return chips.length ? chips.join(' / ') : 'observe existing state';
    }
    function configBehaviorKey(configItem, behaviorItem = null) {
      if (behaviorItem) {
        return behaviorItem.effective_behavior || behaviorItem.effective_profile || behaviorItem.configured_behavior || behaviorItem.configured_profile || behaviorItem.suggested_behavior || behaviorItem.suggested_profile || 'unassigned';
      }
      const kind = String(configItem.kind || configItem.kind_label || '').toLowerCase();
      const iface = String(configItem.interface || '').toLowerCase();
      const config = configItem.config || {};
      if ((config.internet || {}).use_as_uplink) {
        if (kind.includes('wifi') || /^wl|^wlan/.test(iface)) return 'uplink_wifi';
        if (kind.includes('cellular') || /^wwan|^cdc/.test(iface)) return 'uplink_cellular';
        if (kind.includes('ethernet') || /^eth|^en/.test(iface)) return 'uplink_ethernet';
      }
      if (kind.includes('wifi') || /^wl|^wlan/.test(iface)) return 'hotspot_wifi';
      if (kind.includes('cellular') || /^wwan|^cdc/.test(iface)) return 'uplink_cellular';
      if (kind.includes('tunnel') || iface.includes('tailscale') || iface.includes('wg')) return 'management_tunnel';
      return 'unassigned';
    }
    function interfaceConfigSettingsSurface(configItem, behaviorItem = null, lanProfile = {}, serviceLan = {}) {
      const behaviorKey = configBehaviorKey(configItem, behaviorItem);
      if (behaviorKey === 'management_lan') {
        return `<div class="route"><div class="label">Trusted LAN Settings</div><div style="margin-top:10px;">${renderLanCard('main', lanProfileForInterface('main', lanProfile, { ...configItem.live, interface: configItem.interface }), { fixedInterface: true })}</div></div>`;
      }
      if (behaviorKey === 'device_lan') {
        return `<div class="route"><div class="label">Client LAN Settings</div><div style="margin-top:10px;">${renderLanCard('service', lanProfileForInterface('service', serviceLan, { ...configItem.live, interface: configItem.interface }), { fixedInterface: true })}</div></div>`;
      }
      if (behaviorKey === 'uplink_wifi' || behaviorKey === 'hotspot_wifi') {
        return `<div class="route"><div class="label">Wireless Settings</div><div class="hint">SSID, password, scan and hotspot controls are on the Wireless page for now. This window keeps the selected radio identity and behavior intent together.</div></div>`;
      }
      if (behaviorKey === 'uplink_cellular') {
        return `<div class="route"><div class="label">Cellular Settings</div><div class="hint">APN, SIM/operator and modem controls are on the Cellular page for now. This window keeps the selected modem identity and behavior intent together.</div></div>`;
      }
      if (behaviorKey === 'uplink_ethernet') {
        return `<div class="route"><div class="label">Ethernet Uplink</div><div class="hint">Wired uplink failover scoring is planned. For now this behavior is recorded for route/firewall previews and diagnostics.</div></div>`;
      }
      if (behaviorKey === 'management_tunnel') {
        return `<div class="route"><div class="label">Management Tunnel</div><div class="hint">Tunnel policy is read-only for now. Future settings can control advertised routes and management exposure.</div></div>`;
      }
      return `<div class="route"><div class="label">Settings Surface</div><div class="hint">Choose a compatible behavior to reveal IP, DNS, routing or modem-specific controls here.</div></div>`;
    }
    function interfaceConfigBody(configItem, behaviorItem = null, lanProfile = {}, serviceLan = {}) {
      const config = configItem.config || {};
      const live = configItem.live || {};
      const identity = configItem.identity || {};
      const domId = String(configItem.id || configItem.interface || '').replace(/[^a-zA-Z0-9_-]/g, '-');
      const inputId = `interface-config-name-${domId}`;
      const mtuId = `interface-config-mtu-${domId}`;
      const autoconnectId = `interface-config-autoconnect-${domId}`;
      const routeMetricId = `interface-config-route-metric-${domId}`;
      const neverDefaultId = `interface-config-never-default-${domId}`;
      const ignoreRoutesId = `interface-config-ignore-routes-${domId}`;
      const behaviorId = `interface-config-behavior-${String(configItem.interface || configItem.id || '').replace(/[^a-zA-Z0-9_-]/g, '-')}`;
      const behaviorLabels = {};
      const behaviorOptions = behaviorItem ? (behaviorItem.behavior_options || behaviorItem.profile_options || ['unassigned']) : ['unassigned'];
      const currentBehavior = behaviorItem ? (behaviorItem.effective_behavior || behaviorItem.effective_profile || 'unassigned') : 'unassigned';
      const behaviorOptionItems = behaviorOptions.map(option => ({ value: option, label: interfaceBehaviorLabel(option, behaviorLabels) }));
      const link = config.link || {};
      const routing = config.routing || {};
      const threeStateOptions = [
        { value: 'preserve_existing', label: 'Preserve existing' },
        { value: 'yes', label: 'Yes' },
        { value: 'no', label: 'No' },
      ];
      return `
        <div class="stat-grid">
          <div class="metric"><div class="label">Display Name</div><input id="${inputId}" value="${escapeHtml(config.display_name || configItem.interface || '')}" /></div>
          <div class="metric"><div class="label">Interface</div><div class="value small">${escapeHtml(configItem.interface || '-')}</div></div>
          <div class="metric"><div class="label">Kind</div><div class="value small">${escapeHtml(configItem.kind_label || configItem.kind || '-')}</div></div>
          <div class="metric"><div class="label">Source</div><div class="value small">${escapeHtml(configItem.source || '-')}</div></div>
          <div class="metric"><div class="label">State</div><div class="value small">${escapeHtml(live.state || '-')}</div></div>
        </div>
        <details class="config-section">
          <summary><span>Live Identity</span><span>${escapeHtml(identity.stable_key || configItem.id || '-')}</span></summary>
          <div class="stat-grid" style="margin-top:10px;">
            <div class="metric"><div class="label">Stable ID</div><div class="value small">${escapeHtml(identity.stable_key || configItem.id || '-')}</div></div>
            <div class="metric"><div class="label">Driver / Bus</div><div class="value small">${escapeHtml([identity.driver, identity.bus].filter(Boolean).join(' / ') || '-')}</div></div>
            <div class="metric"><div class="label">MAC</div><div class="value small">${escapeHtml(live.mac || '-')}</div></div>
            <div class="metric"><div class="label">MTU</div><div class="value small">${escapeHtml(live.mtu || '-')}</div></div>
            <div class="metric wide"><div class="label">IPv4</div><div class="value small">${escapeHtml((live.ipv4 || []).join(', ') || '-')}</div></div>
            <div class="metric wide"><div class="label">IPv6</div><div class="value small">${escapeHtml((live.ipv6 || []).join(', ') || '-')}</div></div>
          </div>
        </details>
        <details class="config-section">
          <summary><span>Desired Config</span><span>${escapeHtml(configDesiredSummary(configItem))}</span></summary>
          <div class="stat-grid" style="margin-top:10px;">
            <div class="metric"><div class="label">IPv4</div><div class="value small">${escapeHtml((config.addressing || {}).ipv4_mode || 'preserve_existing')}</div></div>
            <div class="metric"><div class="label">IPv6</div><div class="value small">${escapeHtml((config.addressing || {}).ipv6_mode || 'preserve_existing')}</div></div>
            <div class="metric"><div class="label">DNS</div><div class="value small">${escapeHtml((config.dns || {}).mode || 'preserve_existing')}</div></div>
            <div class="metric"><div class="label">Uplink</div><div class="value small">${(config.internet || {}).use_as_uplink ? 'Yes' : 'No'}</div></div>
            <div class="metric"><div class="label">Client Egress</div><div class="value small">${(config.internet || {}).share_to_clients ? 'Yes' : 'No'}</div></div>
            <div class="metric"><div class="label">MTU</div><div class="value small">${escapeHtml((config.link || {}).mtu || 'preserve existing')}</div></div>
            <div class="metric"><div class="label">Route Metric</div><div class="value small">${escapeHtml((config.routing || {}).route_metric || 'preserve existing')}</div></div>
            <div class="metric"><div class="label">Firewall</div><div class="value small">${escapeHtml((config.firewall || {}).isolation || 'preserve_existing')}</div></div>
          </div>
          <div class="hint">This is desired state only. Saving here does not restart interfaces or apply routing/firewall changes.</div>
        </details>
        <details class="config-section">
          <summary><span>Advanced Settings</span><span>link / routing</span></summary>
          <div class="stat-grid" style="margin-top:10px;">
            <div class="metric"><div class="label">MTU</div><input id="${mtuId}" value="${escapeHtml(link.mtu || '')}" placeholder="${escapeHtml(live.mtu || 'preserve existing')}" /></div>
            <div class="metric"><div class="label">Autoconnect</div>${customSelectMarkup(autoconnectId, `interface_config.${domId}.autoconnect`, threeStateOptions, link.autoconnect || 'preserve_existing')}</div>
            <div class="metric"><div class="label">Route Metric</div><input id="${routeMetricId}" value="${escapeHtml(routing.route_metric || '')}" placeholder="preserve existing" /></div>
            <div class="metric"><div class="label">Never Default</div>${customSelectMarkup(neverDefaultId, `interface_config.${domId}.never_default`, threeStateOptions, routing.never_default || 'preserve_existing')}</div>
            <div class="metric"><div class="label">Ignore Auto Routes</div>${customSelectMarkup(ignoreRoutesId, `interface_config.${domId}.ignore_auto_routes`, threeStateOptions, routing.ignore_auto_routes || 'preserve_existing')}</div>
          </div>
          <div class="hint">These values are saved as desired state only. They feed readiness and plan preview; they do not change live NetworkManager profiles yet.</div>
        </details>
        ${behaviorItem ? `<details class="config-section" open><summary><span>Behavior</span><span>${escapeHtml(interfaceBehaviorLabel(currentBehavior))}</span></summary><div class="stat-grid" style="margin-top:10px;"><div class="metric"><div class="label">Behavior</div>${customSelectMarkup(behaviorId, `interface_behavior.${configItem.interface}`, behaviorOptionItems, currentBehavior)}</div><div class="metric"><div class="label">Source</div><div class="value small">${escapeHtml((behaviorItem.configured_behavior || behaviorItem.configured_profile) ? 'configured' : 'live discovery')}</div></div></div><div class="controls"><button type="button" onclick="saveInterfaceBehavior('${escapeHtml(configItem.interface || '')}', '${behaviorId}')">Save Behavior</button></div><div class="hint">Behavior selects which settings surface belongs to this discovered interface.</div></details>` : ''}
        ${interfaceConfigSettingsSurface(configItem, behaviorItem, lanProfile, serviceLan)}
        <div class="controls">
          <button type="button" onclick="saveInterfaceDesiredConfig('${escapeHtml(configItem.id || '')}', '${inputId}', '${mtuId}', '${autoconnectId}', '${routeMetricId}', '${neverDefaultId}', '${ignoreRoutesId}')">Save Desired Config</button>
          <button type="button" class="secondary" onclick="resetInterfaceConfig('${escapeHtml(configItem.id || '')}')">Reset Saved Config</button>
        </div>
      `;
    }
    function renderInterfaceConfigs(configPayload = {}, behaviorPayload = {}, lanProfile = {}, serviceLan = {}) {
      const configs = configPayload.configs || [];
      const behaviorsByInterface = Object.fromEntries((behaviorPayload.interfaces || []).map(item => [item.interface, item]));
      appState.interfaceConfigDetails = {};
      return `
        <div class="portfolio-grid small">
          ${configs.length ? configs.map((item, index) => {
            const tone = configStatusTone(item);
            const detailId = `interface-config-${index}`;
            const behaviorItem = behaviorsByInterface[item.interface] || null;
            appState.interfaceConfigDetails[detailId] = {
              title: `${configDisplayName(item)} / ${item.interface || '-'}`,
              subtitle: `${item.kind_label || item.kind || '-'} | ${item.source || 'observed'}`,
              body: interfaceConfigBody(item, behaviorItem, lanProfile, serviceLan),
              tone,
            };
            return `<div class="portfolio-card ${tone}">
              <div class="portfolio-top">
                <div>
                  <div class="portfolio-title">${escapeHtml(configDisplayName(item))}</div>
                  <div class="portfolio-url">${escapeHtml(configLiveSummary(item))}</div>
                </div>
              </div>
              <div class="portfolio-status ${tone}">${escapeHtml((item.live || {}).state || 'unknown')}</div>
              <div class="muted">${escapeHtml(configDesiredSummary(item))}</div>
              <button class="window-button" type="button" onclick="openInterfaceConfigWindow('${detailId}')"><span>Configure</span><span>${escapeHtml(item.source || 'observed')}</span></button>
            </div>`;
          }).join('') : '<div class="muted">No configurable interfaces discovered</div>'}
        </div>
        <div class="hint">Interfaces are discovered from the host. Save Name only records LocalPlane desired state; apply flows remain preview-gated.</div>
      `;
    }
    function lanProfileForInterface(kind, profile, item) {
      const base = { ...(profile || {}) };
      const iface = item.interface || base.target_interface || base.interface || '';
      return {
        ...base,
        target_interface: iface,
        interface: iface,
        available_interfaces: Array.from(new Set([iface, ...((base.available_interfaces || []))].filter(Boolean))),
        target_interface_status: {
          ...(base.target_interface_status || {}),
          state: item.state || (base.target_interface_status || {}).state,
          mac: item.mac || (base.target_interface_status || {}).mac,
          ipv4: item.ipv4 || (base.target_interface_status || {}).ipv4,
          ipv6: item.ipv6 || (base.target_interface_status || {}).ipv6,
        },
      };
    }
    function behaviorSurfaceBody(item, behaviorLabels, lanProfile, serviceLan, assignmentId, assignedBehavior, behaviorOptionItems) {
      const identity = item.identity || {};
      const nm = item.nmcli || {};
      const genericLabel = item.effective_behavior || item.effective_profile || item.configured_behavior || item.configured_profile || item.suggested_behavior || item.suggested_profile || 'unassigned';
      const warnings = item.warnings || [];
      const roleControls = `
        <div class="route">
          <div class="label">Behavior Assignment</div>
          <div class="stat-grid" style="margin-top:10px;">
            <div class="metric"><div class="label">Behavior</div>${customSelectMarkup(assignmentId, `interface_behavior.${item.interface}`, behaviorOptionItems, assignedBehavior)}</div>
            <div class="metric"><div class="label">Source</div><div class="value small">${escapeHtml((item.configured_behavior || item.configured_profile) ? 'configured' : 'live discovery')}</div></div>
            <div class="metric"><div class="label">Detected Kind</div><div class="value small">${escapeHtml(item.detected_kind || item.detected_role || '-')}</div></div>
            <div class="metric"><div class="label">State</div><div class="value small">${escapeHtml(item.state || '-')}</div></div>
          </div>
          <div class="controls"><button type="button" onclick="saveInterfaceBehavior('${escapeHtml(item.interface || '')}', '${assignmentId}')">Save Behavior</button></div>
          <div class="hint">Saving behavior records intent for this discovered interface. It does not restart links or apply routing by itself.</div>
        </div>
      `;
      const liveFacts = `
        <div class="stat-grid" style="margin-top:12px;">
          <div class="metric"><div class="label">Interface</div><div class="value small">${escapeHtml(item.interface || '-')}</div></div>
          <div class="metric"><div class="label">Stable ID</div><div class="value small">${escapeHtml(identity.stable_key || '-')}</div></div>
          <div class="metric"><div class="label">Driver / Bus</div><div class="value small">${escapeHtml([identity.driver, identity.bus].filter(Boolean).join(' / ') || '-')}</div></div>
          <div class="metric"><div class="label">Connection</div><div class="value small">${escapeHtml(nm.connection || 'no profile')}</div></div>
          <div class="metric"><div class="label">IPv4</div><div class="value small">${escapeHtml((item.ipv4 || []).join(', ') || '-')}</div></div>
          <div class="metric"><div class="label">IPv6</div><div class="value small">${escapeHtml((item.ipv6 || []).join(', ') || '-')}</div></div>
        </div>
      `;
      let settingsSurface = '';
      if (genericLabel === 'management_lan') {
        settingsSurface = `<div class="route"><div class="label">Trusted LAN Settings</div><div style="margin-top:10px;">${renderLanCard('main', lanProfileForInterface('main', lanProfile, item), { fixedInterface: true })}</div></div>`;
      } else if (genericLabel === 'device_lan') {
        settingsSurface = `<div class="route"><div class="label">Client LAN Settings</div><div style="margin-top:10px;">${renderLanCard('service', lanProfileForInterface('service', serviceLan, item), { fixedInterface: true })}</div></div>`;
      } else if (genericLabel === 'uplink_wifi' || genericLabel === 'hotspot_wifi') {
        settingsSurface = `<div class="route"><div class="label">Wireless Settings</div><div class="hint">This interface is shown here as inventory. Detailed SSID, hotspot and radio settings remain on the Wireless page until Wi-Fi becomes multi-radio.</div></div>`;
      } else if (genericLabel === 'uplink_cellular') {
        settingsSurface = `<div class="route"><div class="label">Cellular Settings</div><div class="hint">This modem is shown here as inventory. APN, SIM and operator controls remain on the Cellular page until modem profiles become per-device.</div></div>`;
      } else if (genericLabel === 'uplink_ethernet') {
        settingsSurface = `<div class="route"><div class="label">Ethernet Uplink</div><div class="hint">Wired uplink failover scoring is planned. For now this behavior is recorded for route/firewall previews and diagnostics.</div></div>`;
      } else if (genericLabel === 'management_tunnel') {
        settingsSurface = `<div class="route"><div class="label">Management Tunnel</div><div class="hint">Tunnel policy is read-only for now. Future settings will control advertised routes and management exposure.</div></div>`;
      } else {
        settingsSurface = `<div class="route"><div class="label">No Settings Surface Yet</div><div class="hint">Choose compatible behavior for this interface to reveal the matching configuration surface.</div></div>`;
      }
      return `${roleControls}${settingsSurface}${liveFacts}${warnings.length ? `<div class="hint warn-text">${warnings.map(escapeHtml).join(' ')}</div>` : ''}`;
    }
    function renderInterfaceBehaviors(payload, lanProfile = {}, serviceLan = {}) {
      const behaviors = payload.interfaces || [];
      const errors = payload.wifi_driver_errors || [];
      const behaviorLabels = (payload.model || {}).behavior_labels || (payload.model || {}).role_labels || {};
      appState.interfaceBehaviorDetails = {};
      return `
        <div class="portfolio-grid small">
          ${behaviors.length ? behaviors.map((item, index) => {
            const identity = item.identity || {};
            const genericLabel = item.effective_behavior || item.effective_profile || item.configured_behavior || item.configured_profile || item.suggested_behavior || item.suggested_profile || 'unassigned';
            const genericText = item.effective_behavior_label || item.effective_label || interfaceBehaviorLabel(genericLabel, behaviorLabels);
            const stateClass = stateTone(item.state || '');
            const detailId = `profile-${index}`;
            const assignmentId = `behavior-assignment-${index}`;
            const behaviorOptions = item.behavior_options || item.profile_options || ['unassigned'];
            const behaviorOptionItems = behaviorOptions.map(option => ({ value: option, label: interfaceBehaviorLabel(option, behaviorLabels) }));
            const assignedBehavior = draftValue(`interface_behavior.${item.interface}`, genericLabel);
            appState.interfaceBehaviorDetails[detailId] = {
              title: `${genericText} / ${item.interface || '-'}`,
              subtitle: `${identity.stable_key || item.detected_kind || item.detected_role || '-'} | ${item.state || 'unknown'}`,
              body: behaviorSurfaceBody(item, behaviorLabels, lanProfile, serviceLan, assignmentId, assignedBehavior, behaviorOptionItems),
              tone: stateClass,
            };
            return `<div class="portfolio-card ${stateClass}">
              <div class="portfolio-top">
                <div>
                  <div class="portfolio-title">${escapeHtml(genericText)}</div>
                  <div class="portfolio-url">${escapeHtml(interfaceLiveSummary(item))}</div>
                </div>
              </div>
              <div class="portfolio-status ${stateClass}">${escapeHtml(item.state || 'unknown')}</div>
              <button class="window-button" type="button" onclick="openInterfaceBehaviorWindow('${detailId}')"><span>Configure</span><span>${escapeHtml((item.configured_behavior || item.configured_profile) ? 'configured' : 'suggested')}</span></button>
            </div>`;
          }).join('') : '<div class="muted">No interfaces discovered</div>'}
        </div>
        ${errors.length ? `<details class="config-section"><summary><span>Wi-Fi Driver Notes</span><span>brcmfmac</span></summary><div class="code-box"><pre>${escapeHtml(errors.join('\n'))}</pre></div><div class="hint">Use Wireless readiness for active Wi-Fi apply warnings.</div></details>` : ''}
      `;
    }
    function renderWireless(wifi, interfaces, wifiClients, piholeNetworks, overview) {
      const radioInterfaces = wirelessInterfaces(interfaces, wifi);
      const selectedWifiInterface = draftValue('wifi.selected_interface', sessionStorage.getItem('portal.wifi.selected_interface') || wifi.interface || interfaceNameOf((radioInterfaces || [])[0]));
      const wifiPowerPending = isTogglePending('wifi:power');
      const wifiRadioOn = String((wifi.device || {}).wifi_radio || '').toLowerCase() === 'enabled';
      const wifiMode = draftValue('wifi.mode', wifi.config.mode);
      const wifiIpv4Method = draftValue('wifi.ipv4_method', wifi.config.ipv4_method || 'auto');
      const wifiIpv6Method = draftValue('wifi.ipv6_method', wifi.config.ipv6_method || 'disabled');
      const wifiClientTrustMode = draftValue('wifi.client_trust_mode', wifi.config.client_trust_mode || 'normal');
      const wifiBand = draftValue('wifi.band', wifi.config.band || '2.4ghz');
      const wifiChannel = draftValue('wifi.channel', wifi.config.channel || 'auto');
      const wifiUplinkPreference = draftValue('wifi.uplink_preference', wifi.config.uplink_preference || 'prefer-lte');
      const hotspotSecurity = draftValue('wifi.hotspot_security', wifi.config.hotspot_security || 'wpa2-personal');
      const channelOptions = wifiChannelOptions(wifiBand);
      const wifiWarnings = [...(wifi.errors || []), ...(wifi.warnings || [])];
      return `
        ${renderInterfaceSwitcher('Wireless Interfaces', radioInterfaces, selectedWifiInterface, 'wifi.selected_interface', 'No Wi-Fi radios discovered yet. USB Wi-Fi adapters will appear here when the host sees them.')}
        ${renderSelectedInterfaceFacts(radioInterfaces, selectedWifiInterface)}
        ${wifiWarnings.length ? `<div class="route"><div class="label">Apply Readiness</div><div class="item-list" style="margin-top:10px;">${wifiWarnings.map((warning, index) => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(warning)}</div><div class="badge ${index < (wifi.errors || []).length ? 'offline' : 'warn'}">${index < (wifi.errors || []).length ? 'error' : 'warn'}</div></div></div>`).join('')}</div></div>` : ''}
        <div class="stat-grid">
          <div class="metric"><div class="label">Selected Interface</div><div class="value small">${escapeHtml(selectedWifiInterface || wifi.interface || '-')}</div></div>
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
            <div class="metric"><div class="label">Mode</div>${customSelectMarkup('wifi-mode', 'wifi.mode', ['client','hotspot'], wifiMode)}</div>
            <div class="metric"><div class="label">Country</div>${customSelectMarkup('wifi-country', 'wifi.country', ['DE','TR','US','GB','NL','FR'], draftValue('wifi.country', wifi.config.country || wifi.country || 'DE'))}</div>
            <div class="metric"><div class="label">Client Trust</div>${customSelectMarkup('wifi-client-trust-mode', 'wifi.client_trust_mode', [{value:'normal',label:'Normal'},{value:'isolated',label:'Isolated'}], wifiClientTrustMode, { disabled: wifiMode !== 'client' })}</div>
            <div class="metric"><div class="label">Uplink Preference</div>${customSelectMarkup('wifi-uplink-preference', 'wifi.uplink_preference', uplinkPreferenceOptions(), wifiUplinkPreference, { disabled: wifiMode !== 'client', afterChange: 'setUplinkPreference' })}</div>
            ${wifiMode === 'client' ? `<div class="metric"><div class="label">Client SSID</div><input id="wifi-ssid" value="${draftValue('wifi.ssid', wifi.config.ssid || '')}" /></div>` : ''}
            ${wifiMode === 'client' ? `<div class="metric"><div class="label">Client Password</div><input id="wifi-password" type="password" value="${draftValue('wifi.password', '')}" /></div>` : ''}
            ${wifiMode === 'hotspot' ? `<div class="metric"><div class="label">Hotspot SSID</div><input id="wifi-hotspot-ssid" value="${draftValue('wifi.hotspot_ssid', wifi.config.hotspot_ssid || '')}" /></div>` : ''}
            ${wifiMode === 'hotspot' ? `<div class="metric"><div class="label">Hotspot Password</div><input id="wifi-hotspot-password" type="password" value="${draftValue('wifi.hotspot_password', '')}" placeholder="Leave empty to keep current saved password" /></div>` : ''}
            ${wifiMode === 'hotspot' ? `<div class="metric"><div class="label">Security Profile</div>${customSelectMarkup('wifi-hotspot-security', 'wifi.hotspot_security', [{value:'wpa3-personal',label:'WPA3-Personal'},{value:'wpa2-personal',label:'WPA2-Personal'},{value:'open',label:'Open'}], hotspotSecurity)}</div>` : ''}
            ${wifiMode === 'hotspot' ? `<div class="metric"><div class="label">Band</div>${customSelectMarkup('wifi-band', 'wifi.band', [{value:'2.4ghz',label:'2.4 GHz'},{value:'5ghz',label:'5 GHz'}], wifiBand)}</div>` : ''}
            ${wifiMode === 'hotspot' ? `<div class="metric"><div class="label">Channel</div>${customSelectMarkup('wifi-channel', 'wifi.channel', channelOptions.map(v => ({ value: v, label: v === 'auto' ? 'Auto' : `Channel ${v}` })), wifiChannel)}</div>` : ''}
            <div class="metric"><div class="label">IPv4 Mode</div>${customSelectMarkup('wifi-ipv4-method', 'wifi.ipv4_method', (wifiMode === 'hotspot' ? ['shared','manual','disabled'] : ['auto','manual','disabled']).map(v => ({ value: v, label: ipv4ModeLabel(v) })), wifiIpv4Method)}</div>
            ${wifiIpv4Method === 'manual' ? `<div class="metric"><div class="label">IPv4 Address</div><input id="wifi-ipv4-address" value="${draftValue('wifi.ipv4_address', wifi.config.ipv4_address || '')}" /></div>` : ''}
            <div class="metric"><div class="label">IPv6 Mode</div>${customSelectMarkup('wifi-ipv6-method', 'wifi.ipv6_method', (wifiMode === 'hotspot' ? ['shared','manual','disabled'] : ['auto','manual','disabled']).map(v => ({ value: v, label: wifiMode === 'hotspot' ? wifiHotspotIpv6Label(v) : ipv6ModeLabel(v) })), wifiIpv6Method)}</div>
            ${wifiIpv6Method === 'manual' ? `<div class="metric"><div class="label">IPv6 Address / Prefix</div><input id="wifi-ipv6-address" value="${draftValue('wifi.ipv6_address', wifi.config.ipv6_address || '')}" placeholder="fd42:42::1/64" /></div>` : ''}
            <div class="metric"><div class="label">Pi-hole</div><div class="switch-row" style="margin-top:8px;"><div class="muted">Use Pi-hole on Wi-Fi</div><label class="switch"><input id="wifi-pihole-toggle" type="checkbox" ${piholeNetworks.wifi ? 'checked' : ''}><span class="slider"></span></label></div></div>
          </div>
          <div class="hint">${wifiMode === 'client' ? `${uplinkPreferenceLabel(wifiUplinkPreference)} controls route metric and default-route behavior for Wi-Fi. ${wifiClientTrustMode === 'isolated' ? 'Isolated client mode blocks inbound access from the upstream Wi-Fi and stops that uplink from reaching local LAN segments. It helps on hotel and public Wi-Fi, but it is not a VPN and does not by itself eliminate upstream MITM risk.' : 'Normal client mode behaves like a regular Wi-Fi client.'}` : 'Client Trust and uplink preference apply in client mode. Switch Mode to client if you want to tune upstream Wi-Fi behavior.'}</div>
          <div class="controls"><button onclick="applyWifiPreview()">Apply Config</button><button class="secondary" onclick="rescanWifi()">Rescan</button></div>
        </details>
        <details class="config-section">
          <summary><span>Connected Wi-Fi Clients</span><span>${(wifiClients || []).length}</span></summary>
          <div class="item-list scroll-list" style="margin-top:10px;">${(wifiClients || []).length ? wifiClients.map(c => `<div class="item client-item"><div class="item-top"><div class="item-title">${escapeHtml(c.hostname || c.mac || 'Client')}</div><div class="badge">${escapeHtml(c.interface || '-')}</div></div><div class="muted">Primary IP: ${escapeHtml(c.ip)} | MAC: ${escapeHtml(c.mac || '-')} | ${escapeHtml(c.state || '-')}</div>${c.secondary_ips ? `<div class="muted">Extra IPs: ${escapeHtml(c.secondary_ips)}</div>` : ''}</div>`).join('') : '<div class="muted">No Wi-Fi clients detected</div>'}</div>
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
    function renderCellular(lte, lteProfile, lteOptions, lteSuggest, lteAuto, atExamples, overview, interfaces = []) {
      const suggested = (lteSuggest.suggested || {});
      const rawProfile = lteProfile.raw_profile || '';
      const apnSource = String(lteSuggest.source || 'manual').replaceAll('_', ' ');
      const allApnOptions = lteOptions.options || [];
      const countryGroups = lteOptions.countries || [];
      const suggestedCountry = suggested.country || (allApnOptions.find(option => option.id === suggested.id) || {}).country || '';
      const selectedCountry = draftValue('cellular.apn_country', suggestedCountry || (countryGroups[0] || {}).code || '');
      const countryGroup = countryGroups.find(country => country.code === selectedCountry) || countryGroups[0] || { providers: [] };
      const suggestedProvider = suggested.provider || '';
      const selectedProviderDraft = draftValue('cellular.apn_provider', suggestedProvider || ((countryGroup.providers || [])[0] || {}).name || '');
      const providerGroup = (countryGroup.providers || []).find(provider => provider.name === selectedProviderDraft) || (countryGroup.providers || [])[0] || { name: '', options: [] };
      const selectedProvider = providerGroup.name || selectedProviderDraft;
      const providerOptions = providerGroup.options || [];
      const selectedProfile = draftValue('cellular.apn_profile', suggested.id || (providerOptions[0] || {}).id || '');
      const selectedOption = allApnOptions.find(option => option.id === selectedProfile) || providerOptions[0] || suggested || {};
      const regionName = code => {
        try {
          if (String(code || '').length === 2 && window.Intl && Intl.DisplayNames) {
            return new Intl.DisplayNames([navigator.language || 'en'], { type: 'region' }).of(code) || code;
          }
        } catch (err) {}
        return code || 'Unknown';
      };
      const defaultDev = ((overview || {}).uplink_ipv4 || {}).dev || ((overview || {}).uplink_ipv6 || {}).dev || '';
      const cellularConnection = lteProfile.connection || '';
      const modemInterfaces = cellularInterfaces(interfaces, lte, lteProfile, overview);
      const selectedCellularInterface = draftValue('cellular.selected_interface', sessionStorage.getItem('portal.cellular.selected_interface') || defaultDev || interfaceNameOf(modemInterfaces[0]));
      const cellularIsDefaultUplink = ['wwan0', 'cdc-wdm0'].includes(defaultDev) || (cellularConnection && defaultDev && cellularConnection.includes(defaultDev));
      const wifiUplinkPreference = draftValue('wifi.uplink_preference', ((appState.wifi || {}).config || {}).uplink_preference || 'prefer-lte');
      const uplinkPreferenceControl = customSelectMarkup('cellular-uplink-preference', 'wifi.uplink_preference', uplinkPreferenceOptions(), wifiUplinkPreference, { afterChange: 'setUplinkPreference' });
      appState.rawProfile = rawProfile;
      return {
        state: !lte.available ? `${renderInterfaceSwitcher('Cellular Interfaces', modemInterfaces, selectedCellularInterface, 'cellular.selected_interface', 'No cellular modems discovered yet. USB 4G/5G modems will appear here when ModemManager or the kernel exposes them.')}${renderSelectedInterfaceFacts(modemInterfaces, selectedCellularInterface)}<div class="stat-grid"><div class="metric"><div class="label">Modem</div><div class="value small">Not available</div></div><div class="metric"><div class="label">Uplink Preference</div>${uplinkPreferenceControl}</div></div>` : `
          ${renderInterfaceSwitcher('Cellular Interfaces', modemInterfaces, selectedCellularInterface, 'cellular.selected_interface', 'No cellular modems discovered yet. USB 4G/5G modems will appear here when ModemManager or the kernel exposes them.')}
          ${renderSelectedInterfaceFacts(modemInterfaces, selectedCellularInterface)}
          <div class="stat-grid">
            <div class="metric"><div class="label">Operator</div><div class="value small">${escapeHtml(lte.operator_name || '-')} (${escapeHtml(lte.operator_mcc || '-')}${escapeHtml(lte.operator_mnc || '')})</div></div>
            <div class="metric"><div class="label">State</div><div class="value small">${escapeHtml(lte.state || '-')}</div></div>
            <div class="metric"><div class="label">Selected Interface</div><div class="value small">${escapeHtml(selectedCellularInterface || '-')}</div></div>
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
            <div class="metric"><div class="label">Auto Source</div><div class="value small">${escapeHtml(apnSource)}</div></div>
          </div>
          <div class="route"><div class="label">Preset Editor</div><div class="stat-grid" style="margin-top:10px;">
            <div class="metric"><div class="label">Auto Apply</div><div class="switch-row" style="margin-top:8px;"><div class="muted">Use SIM/operator preset when known</div><label class="switch"><input type="checkbox" ${lteAuto.enabled ? 'checked' : ''} onchange="toggleAutoApn(this.checked)"><span class="slider"></span></label></div></div>
            <div class="metric"><div class="label">Country</div>${customSelectMarkup('cellular-apn-country', 'cellular.apn_country', countryGroups.map(country => ({ value: country.code, label: regionName(country.code) })), selectedCountry)}</div>
            <div class="metric"><div class="label">Operator</div>${customSelectMarkup('cellular-apn-provider', 'cellular.apn_provider', (countryGroup.providers || []).map(provider => ({ value: provider.name, label: provider.name })), selectedProvider)}</div>
            <div class="metric"><div class="label">Provider Preset</div>${customSelectMarkup('cellular-apn-profile', 'cellular.apn_profile', providerOptions.map(option => ({ value: option.id, label: option.name || option.apn })), selectedProfile)}</div>
            <div class="metric"><div class="label">Manual APN</div><input id="cellular-apn-custom" value="${escapeHtml(draftValue('cellular.apn_custom', lteProfile.apn || selectedOption.apn || ''))}" /></div>
            <div class="metric"><div class="label">IPv4 Method</div>${customSelectMarkup('cellular-ipv4-method', 'cellular.ipv4_method', ['auto','disabled'], draftValue('cellular.ipv4_method', lteProfile.ipv4_method || selectedOption.ipv4_method || 'auto'))}</div>
            <div class="metric"><div class="label">IPv6 Method</div>${customSelectMarkup('cellular-ipv6-method', 'cellular.ipv6_method', ['auto','disabled'], draftValue('cellular.ipv6_method', lteProfile.ipv6_method || selectedOption.ipv6_method || 'auto'))}</div>
            <div class="metric"><div class="label">Remember For SIM</div><div class="switch-row" style="margin-top:8px;"><div class="muted">Store manual override</div><label class="switch"><input id="cellular-apn-remember" type="checkbox" ${draftValue('cellular.apn_remember', !!(lteSuggest.override && lteSuggest.override.apn)) ? 'checked' : ''}><span class="slider"></span></label></div></div>
          </div>
          <div class="controls"><button onclick="applyCellularApnPreview()">Apply Cellular APN</button></div>
          <div class="hint">Auto APN uses modem operator MCC/MNC and saved SIM overrides when available. Manual values remain editable and can be remembered per SIM.</div></div>
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
      const health = pihole.health || {};
      const healthState = String(health.state || 'unknown').toUpperCase();
      const healthTone = health.state === 'ok' ? 'online' : (health.state === 'broken' ? 'offline' : 'standby');
      const healthMessages = [...(health.issues || []), ...(health.warnings || [])];
      return `
        <div class="stat-grid">
          <div class="metric"><div class="label">DNS Health</div><div class="value small">${escapeHtml(healthState)}</div></div>
          <div class="metric"><div class="label">Admin</div><div class="value small">${pihole.admin_reachable ? 'Reachable' : 'Offline'}</div></div>
          <div class="metric"><div class="label">DNS Binds</div><div class="value small">${escapeHtml((pihole.dns_binds || []).join(', ') || '-')}</div></div>
          <div class="metric"><div class="label">Forwarding</div><div class="value small">${pihole.dns_forwarding_enabled ? 'Enabled' : 'Disabled'}</div></div>
          <div class="metric"><div class="label">Container IP</div><div class="value small">${escapeHtml(pihole.container_ip || '-')}</div></div>
        </div>
        <div class="item ${healthTone}">
          <div class="item-top"><div class="item-title">DNS Path</div><div class="badge">${escapeHtml(healthState)}</div></div>
          <div class="muted">${escapeHtml(healthMessages[0] || 'Pi-hole DNS path looks consistent.')}</div>
          ${healthMessages.length > 1 ? `<div class="tag-row">${healthMessages.slice(1).map(item => `<span class="mini-tag">${escapeHtml(item)}</span>`).join('')}</div>` : ''}
        </div>
        <div class="route"><div class="label">Network Toggles</div><div class="item-list" style="margin-top:10px;">
          ${piholeToggleMarkup('Trusted LAN', 'main_lan', piholeNetworks.main_lan, 'Use Pi-hole for the trusted local segment.')}
          ${piholeToggleMarkup('Client LAN', 'service_lan', piholeNetworks.service_lan, 'Use Pi-hole for the client segment.')}
          ${piholeToggleMarkup('Wi-Fi', 'wifi', piholeNetworks.wifi, 'Use Pi-hole for hotspot or Wi-Fi clients.')}
        </div></div>
        <div class="controls"><button onclick="activatePiholeRouting()">Activate Routing</button><a class="chip" href="http://${window.location.hostname}:8081/admin/" target="_blank" rel="noreferrer">Open Pi-hole</a></div>
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
        <details class="config-section compact">
          <summary><span>Active Scan Targets</span><span>${escapeHtml(String((netalert.scan_subnets || []).length))} targets</span></summary>
          <div class="item-list" style="margin-top:10px;">${(netalert.scan_subnets || []).length ? netalert.scan_subnets.map(item => `<div class="item"><div class="item-title">${escapeHtml(item)}</div></div>`).join('') : '<div class="muted">No active scan targets</div>'}</div>
        </details>
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
          <div class="metric"><div class="label">Trusted LAN</div><div class="value small">${escapeHtml(lanProfile.target_interface || '-')} / ${escapeHtml(mainState)}</div></div>
          <div class="metric"><div class="label">Client LAN</div><div class="value small">${escapeHtml(serviceLan.interface || '-')} / ${escapeHtml(serviceState)}</div></div>
          <div class="metric"><div class="label">Wi-Fi</div><div class="value small">${escapeHtml(hotspotMode ? 'Hotspot' : 'Client')} / ${escapeHtml(wifiState)}</div></div>
          <div class="metric"><div class="label">Overlay</div><div class="value small">${escapeHtml(overlay.name || 'None')}</div></div>
          <div class="metric"><div class="label">Discovery Targets</div><div class="value small">${escapeHtml(String(activeTargets))}</div></div>
        </div>
        <details class="config-section compact">
          <summary>
            <span>Discovery Scope</span>
            <span>${escapeHtml(String(activeTargets))} targets</span>
          </summary>
          <div class="item-list" style="margin-top:10px;">
            ${(netalert.scan_subnets || []).length ? netalert.scan_subnets.map(item => `<div class="item"><div class="item-title">${escapeHtml(item)}</div></div>`).join('') : '<div class="muted">No active scan targets</div>'}
          </div>
        </details>
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
      return `
        <div class="resource-card ${tone}" onclick="openServiceOverlay('${id}')">
          <div class="resource-card-main">
            <div class="portfolio-top">
              <div>
                <div class="portfolio-title">${escapeHtml(service.name)}</div>
                <div class="portfolio-url">${escapeHtml(url || primaryPort)}</div>
              </div>
            </div>
            <div class="portfolio-status ${tone}">${service.active ? 'Online' : (service.registry_state === 'missing' ? 'Missing' : 'Detected')}</div>
          </div>
        </div>
      `;
    }
    function renderDockerResourceCard(container, index) {
      const id = `docker-${String(container.name || index).replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`;
      const running = String(container.status || '').toLowerCase().startsWith('up');
      appState.serviceDetails[id] = {
        title: container.name || 'Container',
        subtitle: 'Docker container',
        details: {
          Image: container.image || '-',
          Status: container.status || '-',
          Source: 'docker',
        },
        notes: 'Container details come from the local Docker inventory.',
      };
      return `
        <div class="resource-card ${running ? 'online' : 'offline'}" onclick="openServiceOverlay('${id}')">
          <div class="resource-card-main">
            <div class="portfolio-top">
              <div>
                <div class="portfolio-title">${escapeHtml(container.name || 'Container')}</div>
                <div class="portfolio-url">${escapeHtml(container.image || '-')}</div>
              </div>
            </div>
            <div class="portfolio-status ${running ? 'online' : 'offline'}">${running ? 'Running' : 'Stopped'}</div>
          </div>
        </div>
      `;
    }
    function renderServices(services, systemStats = {}, serviceInventory = {}) {
      const named = [];
      const unnamed = [];
      const inventorySummary = serviceInventory.summary || {};
      const inventoryGroups = serviceInventory.groups || {};
      const inventoryContainers = inventoryGroups.containers || [];
      const dockerContainers = (inventoryContainers.length ? inventoryContainers : ((systemStats.docker || {}).containers || [])).map(renderDockerResourceCard);
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
            'Registry': service.registry_state || 'present',
            'Last seen': service.last_seen_at ? new Date(Number(service.last_seen_at) * 1000).toLocaleString() : '-',
          },
          capabilities: service.capabilities || [],
          actions: service.actions || [],
          url,
          notes: 'Capabilities are read-only. Unsafe operations stay unavailable until LocalPlane has preview, confirmation and audit for that provider.',
        };
        const markup = renderServicePortfolioCard(service, url, id);
        if ((service.name || '').startsWith('Port ')) unnamed.push(markup);
        else named.push(markup);
      });
      return `
        <div class="section-stack">
          <div class="stat-grid">
            <div class="metric"><div class="label">Present</div><div class="value">${escapeHtml(String(inventorySummary.present ?? named.length))}</div></div>
            <div class="metric"><div class="label">Listeners</div><div class="value">${escapeHtml(String(inventorySummary.listeners ?? named.length))}</div></div>
            <div class="metric"><div class="label">Containers</div><div class="value">${escapeHtml(String(inventorySummary.containers ?? dockerContainers.length))}</div></div>
            <div class="metric"><div class="label">Missing Seen Before</div><div class="value">${escapeHtml(String(inventorySummary.missing ?? 0))}</div></div>
          </div>
          ${(Number(inventorySummary.missing || 0) > 0) ? `<div class="controls"><button class="secondary" onclick="pruneMissingServices()">Clear Missing Registry</button><span class="hint">This only removes stale LocalPlane registry entries. It does not stop or delete services.</span></div>` : ''}
          <section class="resource-section">
            <div class="section-row"><div><div class="label">Service Listeners</div><div class="muted">Host and listener inventory from open local ports.</div></div><span class="chip">${named.length} services</span></div>
            <div class="resource-grid">${named.join('') || '<div class="empty-state">No named services detected</div>'}</div>
          </section>
          <section class="resource-section">
            <div class="section-row"><div><div class="label">Docker Containers</div><div class="muted">Running container resources are grouped separately from listeners.</div></div><span class="chip">${dockerContainers.length} containers</span></div>
            <div class="resource-grid">${dockerContainers.join('') || '<div class="empty-state">No Docker containers reported</div>'}</div>
          </section>
          <details class="config-section">
            <summary><span>Port-only listeners</span><span>${unnamed.length}</span></summary>
            <div class="resource-grid small" style="margin-top:10px;">${unnamed.join('') || '<div class="muted">No port-only listeners detected</div>'}</div>
          </details>
        </div>
      `;
    }
    function eventLevelClass(level) {
      if (level === 'warn' || level === 'warning') return 'warn';
      if (level === 'error' || level === 'critical') return 'error';
      return 'info';
    }
    function backendLogQuery() {
      const params = new URLSearchParams();
      params.set('limit', String(appState.logLimit || 100));
      if (appState.logLevel) params.set('level', appState.logLevel);
      if (appState.logSource) params.set('source', appState.logSource);
      return params.toString();
    }
    async function applyLogFilters() {
      const limit = document.getElementById('log-limit');
      const level = document.getElementById('log-level');
      const source = document.getElementById('log-source');
      appState.logLimit = Number(limit?.value || 100);
      appState.logLevel = level?.value || '';
      appState.logSource = source?.value || '';
      sessionStorage.setItem('portal.logLimit', String(appState.logLimit));
      sessionStorage.setItem('portal.logLevel', appState.logLevel);
      sessionStorage.setItem('portal.logSource', appState.logSource);
      await render();
    }
    async function deleteFilteredEvents() {
      const params = new URLSearchParams();
      if (appState.logLevel) params.set('level', appState.logLevel);
      if (appState.logSource) params.set('source', appState.logSource);
      const label = [appState.logLevel || 'all levels', appState.logSource || 'all sources'].join(' / ');
      if (!confirm(`Delete backend events matching: ${label}?`)) return;
      await fetchJSON(`/api/events?${params.toString()}`, { method: 'DELETE' });
      await render();
    }
    async function pruneMissingServices() {
      if (!confirm('Remove missing services from the local registry? Running services and containers will not be touched.')) return;
      await trackActivity('Prune missing services', 'Service registry cleanup', () => fetchJSON('/api/services/registry/missing', { method: 'DELETE' }));
      apiCache.delete('services');
      apiCache.delete('serviceInventory');
      apiCache.delete('eventLog');
      await render({ force: true });
    }
    function renderLogsPanel(overview, services, activeSessions, systemStats, eventPayload) {
      const rows = [];
      const now = new Date();
      const push = (mins, service, level, message) => {
        const at = new Date(now.getTime() - mins * 60000);
        rows.push({ at, service, level, message });
      };
      (eventPayload.events || []).forEach(event => {
        rows.push({
          at: new Date((event.ts || 0) * 1000),
          service: event.source || 'event',
          level: eventLevelClass(event.level || 'info'),
          message: event.message || event.action || 'Event',
        });
      });
      push(1, 'panel', 'info', `Dashboard sync completed for ${overview.hostname || 'device'}`);
      (services || []).slice(0, 8).forEach((service, index) => {
        push(index + 2, service.name, service.active ? 'info' : 'warn', `${service.name} ${service.active ? 'listener active' : 'detected without active state'} on ${(service.ports || []).join(', ') || 'no exposed port'}`);
      });
      (activeSessions || []).slice(0, 8).forEach((session, index) => {
        push(index + 6, session.entry || session.service || 'session', 'info', `${session.peer_address || '-'} connected to ${session.local_address || '-'}:${session.local_port || '-'}`);
      });
      const docker = systemStats.docker || {};
      push(12, 'docker', docker.available ? 'info' : 'error', docker.available ? `${docker.running || 0} containers running` : 'Docker is not available');
      const sources = Array.from(new Set(rows.map(row => row.service).filter(Boolean))).sort();
      const filteredRows = rows
        .filter(row => !appState.logLevel || row.level === appState.logLevel)
        .filter(row => !appState.logSource || row.service === appState.logSource)
        .sort((a, b) => b.at - a.at);
      const recentRows = filteredRows.slice(0, Math.min(Number(appState.logLimit || 100), 200));
      const errorCount = filteredRows.filter(row => row.level === 'error').length;
      const warnCount = filteredRows.filter(row => row.level === 'warn').length;
      const memUsed = Number(((systemStats.memory || {}).used_mb) || 0);
      const loadNow = Number(((systemStats.load || {}).load_1) || 0);
      const chartMetrics = [
        { title: 'CPU Load', subtitle: `${loadNow || 0} load avg`, unit: 'load', points: [0.2, 0.22, 0.18, 0.25, 0.31, 0.28, 0.35, 0.41, 0.38, 0.46, 0.5, loadNow || 0.4] },
        { title: 'Memory Usage', subtitle: `${memUsed || '-'} MB used`, unit: 'MB', points: [Math.max(0, memUsed - 110), Math.max(0, memUsed - 95), Math.max(0, memUsed - 80), Math.max(0, memUsed - 70), Math.max(0, memUsed - 62), Math.max(0, memUsed - 44), Math.max(0, memUsed - 35), Math.max(0, memUsed - 22), Math.max(0, memUsed - 14), Math.max(0, memUsed - 8), Math.max(0, memUsed - 4), memUsed] },
        { title: 'Event Volume', subtitle: `${filteredRows.length} rows`, unit: 'rows', points: [2, 3, 4, 5, 7, 8, 10, 13, 16, 20, 24, filteredRows.length] },
        { title: 'Docker Containers', subtitle: `${docker.running || 0} running`, unit: 'ct', points: [docker.running || 0, docker.running || 0, docker.running || 0, docker.running || 0, docker.running || 0, docker.running || 0, docker.running || 0, docker.running || 0, docker.running || 0, docker.running || 0, docker.running || 0, docker.running || 0] },
        { title: 'Error Events', subtitle: `${errorCount} errors`, unit: 'err', points: [0, 0, 1, 0, 1, 0, 2, 1, errorCount, Math.max(0, errorCount - 1), errorCount, errorCount] },
        { title: 'Warning Events', subtitle: `${warnCount} warnings`, unit: 'warn', points: [0, 1, 1, 2, 2, 1, 3, 2, warnCount, Math.max(0, warnCount - 1), warnCount, warnCount] },
      ];
      const metricMax = (points) => Math.max(...points.map(Number), 1);
      const metricMin = (points) => Math.min(...points.map(Number), 0);
      const metricValue = (value, unit) => `${Number(value || 0).toFixed(unit === 'load' ? 2 : 0)} ${unit}`;
      const chartPath = (points) => {
        const min = metricMin(points);
        const max = metricMax(points);
        const span = Math.max(max - min, 1);
        return points.map((point, index) => `${(index / Math.max(points.length - 1, 1)) * 100},${92 - (((Number(point) - min) / span) * 76)}`).join(' ');
      };
      const chartCard = (metric) => {
        const points = metric.points || [];
        const min = metricMin(points);
        const max = metricMax(points);
        const latest = points[points.length - 1] || 0;
        return `<div class="log-chart-card">
          <div class="log-chart-head">
            <div><div class="log-chart-title">${escapeHtml(metric.title)}</div><div class="muted">${escapeHtml(metric.subtitle)}</div></div>
            <div class="log-chart-latest">${escapeHtml(metricValue(latest, metric.unit))}</div>
          </div>
          <div class="chart-frame">
            <div class="chart-axis y-axis"><span>${escapeHtml(metricValue(max, metric.unit))}</span><span>${escapeHtml(metricValue(min, metric.unit))}</span></div>
            <svg class="line-chart" viewBox="0 0 100 100" preserveAspectRatio="none">
              <line x1="0" y1="16" x2="100" y2="16"></line>
              <line x1="0" y1="54" x2="100" y2="54"></line>
              <line x1="0" y1="92" x2="100" y2="92"></line>
              <polyline points="${chartPath(points)}"></polyline>
            </svg>
          </div>
          <div class="chart-x-axis"><span>older</span><span>now</span></div>
        </div>`;
      };
      const timelineRows = filteredRows.slice(0, 10);
      const timeline = timelineRows.length ? timelineRows.map(row => `
        <details class="timeline-item ${escapeHtml(row.level)}">
          <summary>
            <span class="timeline-rail"></span>
            <span class="timeline-main">
              <span class="timeline-title">${escapeHtml(row.message)}</span>
              <span class="timeline-meta">${escapeHtml(row.at.toLocaleTimeString())} / ${escapeHtml(row.service)}</span>
            </span>
            <span class="badge ${row.level === 'error' ? 'offline' : row.level === 'warn' ? 'warn' : 'online'}">${escapeHtml(row.level)}</span>
          </summary>
          <div class="timeline-detail">
            <div class="code-inline">source: ${escapeHtml(row.service)}</div>
            <div class="code-inline">time: ${escapeHtml(row.at.toLocaleString())}</div>
            <div class="code-inline">message: ${escapeHtml(row.message)}</div>
          </div>
        </details>
      `).join('') : '<div class="empty-state">No events yet.</div>';
      return `
        <div class="logs-shell">
          <div class="logs-head">
            <button class="secondary" type="button" onclick="render({force:true})">Refresh</button>
          </div>
          <details id="log-settings" class="config-section log-settings">
            <summary><span>Filters</span><span>${escapeHtml(appState.logLevel || 'all levels')}</span></summary>
            <div class="log-toolbar">
              <span class="chip">${filteredRows.length} entries</span>
              <label class="log-control"><span>Limit <span id="log-limit-label">${escapeHtml(String(appState.logLimit || 100))}</span></span><input id="log-limit" type="range" min="25" max="500" step="25" value="${escapeHtml(String(appState.logLimit || 100))}" oninput="document.getElementById('log-limit-label').textContent=this.value" onchange="applyLogFilters()" /></label>
              <select id="log-level" onchange="applyLogFilters()">
                <option value="" ${!appState.logLevel ? 'selected' : ''}>All levels</option>
                <option value="info" ${appState.logLevel === 'info' ? 'selected' : ''}>info</option>
                <option value="warn" ${appState.logLevel === 'warn' ? 'selected' : ''}>warn</option>
                <option value="error" ${appState.logLevel === 'error' ? 'selected' : ''}>error</option>
              </select>
              <select id="log-source" onchange="applyLogFilters()">
                <option value="" ${!appState.logSource ? 'selected' : ''}>All sources</option>
                ${sources.map(source => `<option value="${escapeHtml(source)}" ${appState.logSource === source ? 'selected' : ''}>${escapeHtml(source)}</option>`).join('')}
              </select>
              <button class="secondary" onclick="render({force:true})">Refresh</button>
              <button class="danger" onclick="deleteFilteredEvents()">Delete filtered</button>
            </div>
          </details>
          <div class="log-console">
            <div class="log-console-head">
              <div>
                <div class="log-console-title">Error logs</div>
                <div class="muted">Backend events, command output and panel activity.</div>
              </div>
              <span class="chip">${escapeHtml(appState.logLevel || 'all levels')}</span>
            </div>
            <div class="log-table">
              <div class="log-row log-head"><span>Date</span><span>Service</span><span>Level</span><span>Message</span></div>
              ${recentRows.length ? recentRows.map(row => `<div class="log-row ${row.level}"><span>${escapeHtml(row.at.toLocaleTimeString())}</span><span>${escapeHtml(row.service)}</span><span>${escapeHtml(row.level)}</span><span>${escapeHtml(row.message)}</span></div>`).join('') : '<div class="empty-state">No log entries match this filter.</div>'}
            </div>
          </div>
          <div class="log-chart-grid">${chartMetrics.map(chartCard).join('')}</div>
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
        <div class="route"><div class="label">Share Management</div><div class="stat-grid" style="margin-top:10px;"><div class="metric"><div class="label">Share Name</div><input id="samba-share-name" placeholder="media" /></div><div class="metric"><div class="label">Path</div><input id="samba-share-path" placeholder="/srv/storage/media" /></div><div class="metric"><div class="label">Read Only</div>${customSelectMarkup('samba-share-readonly', 'samba.share_readonly', [{value:'No',label:'No'},{value:'Yes',label:'Yes'}], 'No')}</div><div class="metric"><div class="label">Guest OK</div>${customSelectMarkup('samba-share-guest', 'samba.share_guest', [{value:'No',label:'No'},{value:'Yes',label:'Yes'}], 'No')}</div><div class="metric"><div class="label">Valid Users</div><input id="samba-share-users" placeholder="evil alice" /></div></div><div class="controls"><button onclick="saveSambaShare()">Save Share</button></div></div>
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
        <details class="config-section"><summary><span>Key Mounts</span><span>${primaryMounts.length}</span></summary><div class="item-list">${primaryMounts.length ? primaryMounts.map(m => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(m.mountpoint)}</div><div class="badge">${escapeHtml(m.use_percent)}</div></div><div class="muted">${escapeHtml(m.filesystem)} | Size ${escapeHtml(m.size)} | Used ${escapeHtml(m.used)} | Free ${escapeHtml(m.available)}</div></div>`).join('') : '<div class="muted">No key mounts available</div>'}</div></details>
        <details class="config-section"><summary><span>Storage Devices</span><span>${topLevelDisks.length}</span></summary><div class="item-list">${topLevelDisks.length ? topLevelDisks.map(d => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(d.name)}</div><div class="badge">${escapeHtml(d.size || '-')}</div></div><div class="muted">Type: ${escapeHtml(d.type || '-')} | FS: ${escapeHtml(d.fstype || '-')} | Mount: ${escapeHtml(d.mountpoint || '-')}</div><div class="muted">Model: ${escapeHtml(d.model || '-')} | Transport: ${escapeHtml(d.tran || '-')}</div></div>`).join('') : '<div class="muted">No storage devices reported</div>'}</div></details>
        <details class="config-section"><summary><span>External / USB Storage</span><span>${external.length}</span></summary><div class="item-list">${external.length ? external.map(d => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(d.name)}</div><div class="badge">${escapeHtml(d.size || '-')}</div></div><div class="muted">Transport: ${escapeHtml(d.tran || '-')} | Mount: ${escapeHtml(d.mountpoint || '-')} | Label: ${escapeHtml(d.label || '-')}</div></div>`).join('') : '<div class="muted">No removable or USB storage detected</div>'}</div></details>
        <details class="config-section"><summary><span>Other Mounts</span><span>${otherMounts.length}</span></summary><div class="item-list">${otherMounts.length ? otherMounts.map(m => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(m.mountpoint)}</div><div class="badge">${escapeHtml(m.use_percent)}</div></div><div class="muted">${escapeHtml(m.filesystem)} | Size ${escapeHtml(m.size)} | Used ${escapeHtml(m.used)} | Free ${escapeHtml(m.available)}</div></div>`).join('') : '<div class="muted">No additional mounts worth showing right now</div>'}</div></details>
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
        <details class="config-section"><summary><span>LEDs</span><span>${leds.length}</span></summary><div class="item-list">${ledMarkup || '<div class="muted">No LEDs exposed by sysfs</div>'}</div></details>
        <details class="config-section"><summary><span>Serial Ports</span><span>${serialPorts.length}</span></summary><div class="item-list">${serialMarkup || '<div class="muted">No serial ports detected</div>'}</div></details>
        <details class="config-section"><summary><span>GPIO Controllers</span><span>${gpioChips.length}</span></summary><div class="item-list">${gpioMarkup || '<div class="muted">No GPIO chips detected</div>'}</div></details>
        <div class="hint">${(deviceIo.notes || []).map(escapeHtml).join(' ') || 'Device I/O inventory is available.'}</div>
      `;
    }
    function providerBadgeClass(provider) {
      const state = provider.state || 'missing';
      if (state === 'available') return 'online';
      if (state === 'installable') return 'warn';
      if (state === 'unsupported') return 'idle';
      return 'offline';
    }
    function providerStateLabel(provider) {
      const state = provider.state || 'missing';
      if (state === 'available') return provider.active === false ? 'Installed' : 'Available';
      if (state === 'installable') return 'Installable';
      if (state === 'unsupported') return 'Unsupported';
      return 'Missing';
    }
    function capabilityTitle(id) {
      return String(id || '')
        .split('-')
        .map(part => part ? part.charAt(0).toUpperCase() + part.slice(1) : part)
        .join(' ');
    }
    function renderSettings(settingsPayload = {}) {
      const settings = settingsPayload.settings || {};
      const tabs = settingsPayload.tabs || {};
      const visible = ((settings.ui || {}).visible_tabs || {});
      const optional = tabs.optional || [];
      const safety = settings.network_safety || {};
      const security = settings.security || {};
      const tabRows = optional.map(view => `
        <div class="item">
          <div class="switch-row">
            <div>
              <div class="item-title">${escapeHtml((VIEW_META[view] || {}).title || view)}</div>
              <div class="muted">${escapeHtml((VIEW_META[view] || {}).subtitle || 'Optional page')}</div>
            </div>
            <label class="switch">
              <input type="checkbox" ${visible[view] !== false ? 'checked' : ''} onchange="saveVisibleTab('${escapeHtml(view)}', this.checked)">
              <span class="slider"></span>
            </label>
          </div>
        </div>
      `).join('');
      return `
        <div class="route">
          <div class="label">Visible Optional Tabs</div>
          <div class="item-list compact" style="margin-top:10px;">${tabRows || '<div class="muted">No optional tabs registered.</div>'}</div>
        </div>
        <div class="stat-grid" style="margin-top:12px;">
          <div class="metric"><div class="label">Preview Required</div><div class="value small">${safety.require_preview_for_apply ? 'Yes' : 'No'}</div></div>
          <div class="metric"><div class="label">Protect Default Route</div><div class="value small">${safety.protect_default_route_interfaces ? 'Yes' : 'No'}</div></div>
          <div class="metric"><div class="label">Backup Before Writes</div><div class="value small">${safety.backup_before_host_writes ? 'Yes' : 'No'}</div></div>
          <div class="metric"><div class="label">Firewall Apply</div><div class="value small">${safety.allow_route_firewall_apply ? 'Enabled' : 'Preview only'}</div></div>
        </div>
        <div class="route"><div class="label">Security Targets</div><div class="tag-row" style="margin-top:10px;">
          <span class="mini-tag">CSRF ${security.csrf_protection_target ? 'planned' : 'off'}</span>
          <span class="mini-tag">Rate limit ${security.login_rate_limit_target ? 'planned' : 'off'}</span>
          <span class="mini-tag">API keys ${security.api_keys_target ? 'planned' : 'off'}</span>
          <span class="mini-tag">Secure cookie ${security.cookie_secure ? 'on' : 'off'}</span>
        </div></div>
      `;
    }
    function renderProviders(payload, capabilityPayload = {}, settingsPayload = {}) {
      const providers = payload.providers || [];
      const capabilities = capabilityPayload.capabilities || [];
      const profile = payload.device_profile || {};
      const totals = providers.reduce((acc, provider) => {
        const state = provider.state || 'missing';
        acc[state] = (acc[state] || 0) + 1;
        return acc;
      }, {});
      return `
        <div class="stat-grid">
          <div class="metric"><div class="label">Device Profile</div><div class="value small">${escapeHtml(profile.name || 'Generic Linux')}</div></div>
          <div class="metric"><div class="label">Architecture</div><div class="value small">${escapeHtml(profile.architecture || '-')}</div></div>
          <div class="metric"><div class="label">Available</div><div class="value">${totals.available || 0}</div></div>
          <div class="metric"><div class="label">Installable</div><div class="value">${totals.installable || 0}</div></div>
          <div class="metric"><div class="label">Missing</div><div class="value">${totals.missing || 0}</div></div>
          <div class="metric"><div class="label">Experimental</div><div class="value">${providers.filter(p => p.experimental).length}</div></div>
        </div>
        <div class="route"><div class="label">Detected Model</div><div>${escapeHtml(profile.model || 'Unknown Linux device')}</div></div>
        <div class="route">
          <div class="label">Capability Matrix</div>
          <div class="item-list compact" style="margin-top:10px;">
            ${capabilities.length ? capabilities.map(capability => `
              <div class="item capability-item">
                <div class="item-top">
                  <div class="item-title">${escapeHtml(capabilityTitle(capability.id))}</div>
                  <div class="badge ${providerBadgeClass(capability)}">${escapeHtml(providerStateLabel(capability))}</div>
                </div>
                <div class="muted">Provider: ${escapeHtml(capability.provider || '-')}</div>
                <div class="hint">${escapeHtml(capability.reason || '')}</div>
              </div>
            `).join('') : '<div class="muted">No capabilities reported</div>'}
          </div>
        </div>
        <div class="item-list" style="margin-top:12px;">
          ${providers.map(provider => {
            const commands = ((provider.install_hint || {}).commands || []).map(command => `<div class="code-inline">${escapeHtml(command)}</div>`).join('');
            const features = (provider.features || []).join(', ');
            return `
              <div class="item">
                <div class="item-top">
                  <div class="item-title">${escapeHtml(provider.name)}</div>
                  <div class="badge ${providerBadgeClass(provider)}">${escapeHtml(providerStateLabel(provider))}</div>
                </div>
                <div class="muted">${escapeHtml(provider.reason || '-')}</div>
                ${features ? `<div class="muted">Features: ${escapeHtml(features)}</div>` : ''}
                ${provider.fallback ? `<div class="hint">${escapeHtml(provider.fallback)}</div>` : ''}
                ${commands ? `<details><summary>Install guidance</summary><div class="code-list">${commands}</div><div class="hint">${escapeHtml((provider.install_hint || {}).note || '')}</div></details>` : ''}
                <div class="controls">
                  <button class="secondary" onclick="rescanProvider('${escapeHtml(provider.id)}')">Rescan</button>
                  ${provider.installable || commands ? `<button onclick="previewProviderInstall('${escapeHtml(provider.id)}')">Preview Install</button>` : ''}
                </div>
              </div>
            `;
          }).join('')}
        </div>
      `;
    }
    function renderActions(actionPayload, historyPayload) {
      const actions = actionPayload.actions || [];
      const history = historyPayload.events || [];
      appState.actions = actions;
      return `
        <div class="stat-grid">
          <div class="metric"><div class="label">Actions</div><div class="value">${actions.length}</div></div>
          <div class="metric"><div class="label">Executable</div><div class="value">${actions.filter(action => action.execute_mode !== 'preview_only').length}</div></div>
          <div class="metric"><div class="label">Preview Only</div><div class="value">${actions.filter(action => action.execute_mode === 'preview_only').length}</div></div>
          <div class="metric"><div class="label">History</div><div class="value">${history.length}</div></div>
        </div>
        <div class="route"><div class="label">Catalog</div><div class="item-list" style="margin-top:10px;">
          ${actions.map(action => `
            <div class="item">
              <div class="item-top"><div class="item-title">${escapeHtml(action.title)}</div><div class="badge ${action.risk === 'low' ? 'online' : 'warn'}">${escapeHtml(action.risk)}</div></div>
              <div class="muted">${escapeHtml(action.description || '')}</div>
              <div class="hint">${escapeHtml(action.execute_mode)}${action.requires_confirmation ? ' | confirmation required' : ' | no confirmation required'}</div>
              <div class="controls">
                <button class="secondary" onclick="previewPanelAction('${escapeHtml(action.id)}')">Preview</button>
                ${action.execute_mode !== 'preview_only' ? `<button onclick="executePanelAction('${escapeHtml(action.id)}')">Run</button>` : ''}
              </div>
            </div>
          `).join('')}
        </div></div>
        <div class="route"><div class="label">Action History</div><div class="item-list scroll-list action-history" style="margin-top:10px;">
          ${history.length ? history.slice().reverse().map(event => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(event.message || event.action)}</div><div class="badge idle">${escapeHtml(event.level || 'info')}</div></div><div class="muted">${escapeHtml(new Date((event.ts || 0) * 1000).toLocaleString())} | ${escapeHtml(event.action || '-')}</div></div>`).join('') : '<div class="muted">No action history yet</div>'}
        </div></div>
      `;
    }
    function renderTerminal() {
      const examples = [
        'ip route show default',
        'ip addr',
        'nmcli device status',
        'resolvectl status',
        'nft list ruleset',
        'docker ps',
        'tailscale status',
        'mmcli -L',
      ];
      return `
        <div class="route">
          <div class="label">Command</div>
          <textarea id="terminal-command" rows="3" spellcheck="false">${escapeHtml(appState.terminalCommand)}</textarea>
          <div class="controls">
            <button class="secondary" onclick="previewTerminalCommand()">Preview</button>
            <button onclick="runTerminalCommand()">Run</button>
          </div>
          <div class="hint">Only allowlisted read-only commands run here. Shell operators, pipes and redirects are blocked.</div>
        </div>
        <details class="config-section" open>
          <summary><span>Examples</span><span>${examples.length}</span></summary>
          <div class="tag-row" style="margin-top:10px;">${examples.map(command => `<button class="mini-tag" onclick="setTerminalCommand('${escapeHtml(command)}')">${escapeHtml(command)}</button>`).join('')}</div>
        </details>
        <div class="route"><div class="label">Output</div><div class="code-box"><pre>${escapeHtml(appState.terminalOutput || 'No command output yet.')}</pre></div></div>
      `;
    }
    function terminalPayload() {
      const input = document.getElementById('terminal-command');
      const command = input ? input.value.trim() : appState.terminalCommand;
      appState.terminalCommand = command;
      sessionStorage.setItem('portal.terminalCommand', command);
      return { action: 'terminal.command', command };
    }
    function setTerminalCommand(command) {
      appState.terminalCommand = command;
      sessionStorage.setItem('portal.terminalCommand', command);
      const input = document.getElementById('terminal-command');
      if (input) input.value = command;
    }
    async function previewTerminalCommand() {
      const payload = terminalPayload();
      await openCommandOverlay('Terminal Command Preview', '/api/actions/preview', payload, async () => {}, 'Read-only allowlisted command');
      document.getElementById('command-run').disabled = true;
    }
    async function runTerminalCommand() {
      const payload = terminalPayload();
      await trackActivity('Terminal Command', payload.command, async () => {
        const result = await fetchJSON('/api/actions/execute', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const output = result.result || {};
        appState.terminalOutput = [
          `$ ${payload.command}`,
          output.stdout || '',
          output.stderr ? `stderr:\n${output.stderr}` : '',
          `exit=${output.returncode} duration=${output.duration_ms || 0}ms`,
        ].filter(Boolean).join('\n');
        await render();
      });
    }
    function commandStatus(command) {
      if (!command) return '<span class="badge idle">unknown</span>';
      return `<span class="badge ${command.ok ? 'online' : 'offline'}">${command.ok ? 'ok' : 'missing'}</span>`;
    }
    function routeSummary(route) {
      if (!route || !Object.keys(route).length) return 'No default route';
      const parts = [];
      if (route.dev) parts.push(`dev ${route.dev}`);
      if (route.via) parts.push(`via ${route.via}`);
      if (route.prefsrc) parts.push(`src ${route.prefsrc}`);
      if (route.metric) parts.push(`metric ${route.metric}`);
      return parts.join(' | ') || JSON.stringify(route);
    }
    function compactJson(value) {
      return demoMaskText(JSON.stringify(value || {}, null, 2));
    }
    function renderSnapshotCommand(key, command) {
      const title = key.replaceAll('_', ' ');
      const body = [
        `$ ${((command || {}).command || []).join(' ') || title}`,
        (command || {}).stdout || (command || {}).stderr || 'No output',
      ].join('\n').trim();
      return `
        <details class="config-section">
          <summary><span>${escapeHtml(title)}</span>${commandStatus(command)}</summary>
          <div class="code-box scroll-code"><pre>${escapeHtml(demoMaskText(body))}</pre></div>
        </details>
      `;
    }
    function renderRawSnapshotDetails(snapshot) {
      const routes = snapshot.routes || {};
      const commands = snapshot.commands || {};
      const commandKeys = [
        'ip_rule',
        'resolvectl',
        'nmcli_devices',
        'nmcli_active',
        'ipv4_forward',
        'ipv6_forward',
        'nft_ruleset',
        'iptables_save',
        'docker_networks',
        'tailscale_status',
      ];
      return `
        <details class="config-section">
          <summary><span>Raw Snapshot</span><span>${escapeHtml(snapshot.hostname || 'host')}</span></summary>
          <details class="config-section">
            <summary><span>Interfaces</span><span>${(snapshot.interfaces || []).length}</span></summary>
            <div class="code-box scroll-code"><pre>${escapeHtml(compactJson(snapshot.interfaces || []))}</pre></div>
          </details>
          <details class="config-section">
            <summary><span>Routes</span><span>IPv4 ${(routes.ipv4 || []).length} / IPv6 ${(routes.ipv6 || []).length}</span></summary>
            <div class="code-box scroll-code"><pre>${escapeHtml(compactJson(routes))}</pre></div>
          </details>
          <details class="config-section">
            <summary><span>Collectors Output</span><span>${Object.keys(commands).length}</span></summary>
            <div class="snapshot-command-list">
              ${commandKeys.map(key => renderSnapshotCommand(key, commands[key])).join('')}
            </div>
          </details>
        </details>
      `;
    }
    function renderConnectivityResults(payload) {
      if (!payload) return '<div class="muted">Run a read-only probe to test uplinks per interface.</div>';
      const results = payload.results || [];
      return `
        <div class="item-list" style="margin-top:10px;">
          ${results.length ? results.map(item => `
            <div class="item">
              <div class="item-top">
                <div class="item-title">${escapeHtml(item.interface)} <span class="muted">/${escapeHtml(item.role || '-')}</span></div>
                <div class="badge ${item.ok ? 'online' : 'offline'}">${item.ok ? 'reachable' : 'no egress'}</div>
              </div>
              ${(item.checks || []).map(check => `<div class="muted">${escapeHtml(check.family)} ${escapeHtml(check.target || '-')}: ${check.ok ? 'ok' : escapeHtml(check.stderr || `exit ${check.returncode}`)}${check.duration_ms ? ` (${escapeHtml(check.duration_ms)}ms)` : ''}</div>`).join('')}
            </div>
          `).join('') : '<div class="muted">No uplink candidates were tested</div>'}
        </div>
      `;
    }
    function renderReconcilePreview(payload) {
      const plan = payload.plan || {};
      const current = payload.current || {};
      const commands = plan.commands || [];
      const warnings = plan.warnings || [];
      const verify = plan.verify || [];
      const rollback = plan.rollback || [];
      return `
        <div class="route">
          <div class="item-top">
            <div>
              <div class="label">Network Reconciler</div>
              <div class="muted">Preview-only replacement path for legacy LAN helper scripts.</div>
            </div>
            <div class="badge warn">${escapeHtml(payload.mode || 'preview_only')}</div>
          </div>
          <div class="stat-grid" style="margin-top:10px;">
            <div class="metric"><div class="label">Active Uplink</div><div class="value small">${escapeHtml(current.active_uplink || '-')}</div></div>
            <div class="metric"><div class="label">Planned Commands</div><div class="value">${escapeHtml(String(commands.length))}</div></div>
            <div class="metric"><div class="label">Verify Steps</div><div class="value">${escapeHtml(String(verify.length))}</div></div>
            <div class="metric"><div class="label">Rollback Steps</div><div class="value">${escapeHtml(String(rollback.length))}</div></div>
          </div>
          ${warnings.length ? `<div class="item-list" style="margin-top:10px;">${warnings.map(item => `<div class="item"><div class="item-title">${escapeHtml(item)}</div></div>`).join('')}</div>` : ''}
          <details class="config-section compact">
            <summary><span>Planned Commands</span><span>${escapeHtml(String(commands.length))}</span></summary>
            <div class="code-box scroll-code"><pre>${escapeHtml(commands.map(item => typeof item === 'string' ? item : `${item.command}  # ${item.reason || item.risk || ''}`.trim()).join('\n') || 'No commands planned')}</pre></div>
          </details>
          <details class="config-section compact">
            <summary><span>Verify / Rollback</span><span>${escapeHtml(String(verify.length + rollback.length))}</span></summary>
            <div class="code-box scroll-code"><pre>${escapeHtml(['# verify', ...verify, '', '# rollback', ...rollback].join('\n'))}</pre></div>
          </details>
        </div>
      `;
    }
    function renderRouteFirewallPolicy(payload) {
      const current = payload.current || {};
      const desired = payload.desired || {};
      const roles = desired.behaviors || desired.roles || {};
      const firewall = desired.firewall || {};
      const forwarding = current.forwarding || {};
      const nat = current.nat || {};
      const tables = current.nft_tables || [];
      const exposure = current.exposure || {};
      const exposureCounts = exposure.counts || {};
      const reachabilityCounts = exposure.reachability_counts || {};
      const listeners = exposure.listeners || [];
      const gaps = payload.gaps || [];
      const uplinkCandidates = current.uplink_candidates || [];
      const failoverOrder = current.failover_order || [];
      return `
        <div class="stat-grid">
          <div class="metric"><div class="label">Active Uplink</div><div class="value small">${escapeHtml(current.active_uplink || 'none')}</div></div>
          <div class="metric"><div class="label">Failover Order</div><div class="value small">${escapeHtml(failoverOrder.join(' > ') || 'none')}</div></div>
          <div class="metric"><div class="label">Forwarding</div><div class="value small">IPv4 ${forwarding.ipv4 ? 'ON' : 'OFF'} / IPv6 ${forwarding.ipv6 ? 'ON' : 'OFF'}</div></div>
          <div class="metric"><div class="label">NAT</div><div class="value small">${nat.has_nat ? 'Detected' : 'Not detected'}</div></div>
          <div class="metric"><div class="label">Owned Tables</div><div class="value small">${tables.filter(t => t.managed_by_panel).length}/${tables.length}</div></div>
          <div class="metric"><div class="label">Exposure</div><div class="value small">${escapeHtml(exposureCounts.high || 0)} high / ${escapeHtml(exposureCounts.medium || 0)} medium</div></div>
          <div class="metric"><div class="label">Reachability</div><div class="value small">${escapeHtml(reachabilityCounts.likely_reachable || 0)} likely / ${escapeHtml(reachabilityCounts.loopback_only || 0)} loopback</div></div>
        </div>
        <div class="route"><div class="label">Uplink Candidates</div><div class="item-list" style="margin-top:10px;">
          ${uplinkCandidates.length ? uplinkCandidates.map(item => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(item.interface || '-')}</div><div class="inline-controls"><div class="badge ${item.default_route ? 'online' : item.link_ready ? 'warn' : 'idle'}">${item.default_route ? 'active' : item.link_ready ? 'ready' : 'standby'}</div><div class="badge idle">metric ${escapeHtml(item.route_metric ?? '-')}</div></div></div><div class="muted">${escapeHtml(item.role || '-')} | ${escapeHtml(item.state || '-')} | IP ${item.has_ip ? 'yes' : 'no'} | ↓ ${escapeHtml(formatRate((item.counters || {}).rx_bytes_per_sec))} ↑ ${escapeHtml(formatRate((item.counters || {}).tx_bytes_per_sec))}</div></div>`).join('') : '<div class="muted">No uplink candidates detected</div>'}
        </div><div class="hint">Ethernet, Wi-Fi and cellular can all be modeled as uplinks; route metrics decide priority before any hard apply.</div></div>
        <div class="route"><div class="label">Desired Behavior</div><div class="item-list" style="margin-top:10px;">
          ${Object.entries(roles).map(([behavior, values]) => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(String(behavior).replaceAll('_', ' '))}</div><div class="badge idle">${Array.isArray(values) ? values.length : 0}</div></div><div class="muted">${escapeHtml((values || []).join(', ') || 'none')}</div></div>`).join('')}
        </div></div>
        <div class="route"><div class="label">Firewall Ownership</div><div class="item-list" style="margin-top:10px;">
          <div class="item"><div class="item-top"><div class="item-title">${escapeHtml(firewall.owned_table || 'inet network_panel')}</div><div class="badge ${tables.some(t => t.name === 'network_panel') ? 'online' : 'idle'}">owned</div></div><div class="muted">${escapeHtml(firewall.rule || 'only manage owned chains')}</div></div>
          ${tables.slice(0, 8).map(table => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(table.family)} ${escapeHtml(table.name)}</div><div class="badge ${table.managed_by_panel ? 'online' : 'idle'}">${table.managed_by_panel ? 'panel' : 'foreign'}</div></div></div>`).join('')}
        </div></div>
        <div class="route"><div class="label">Service Exposure</div><div class="item-list scroll-list" style="margin-top:10px;">
          ${listeners.length ? listeners.map(listener => {
            const riskClass = listener.risk === 'high' ? 'offline' : listener.risk === 'medium' ? 'warn' : listener.risk === 'low' ? 'online' : 'idle';
            const reachability = listener.reachability || {};
            const reachClass = reachability.status === 'likely_reachable' ? 'warn' : reachability.status === 'probably_blocked' ? 'online' : reachability.status === 'loopback_only' ? 'idle' : 'idle';
            return `<div class="item">
              <div class="item-top"><div class="item-title">${escapeHtml(listener.name)}</div><div class="inline-controls"><div class="badge ${reachClass}">${escapeHtml(String(reachability.status || 'unknown').replaceAll('_', ' '))}</div><div class="badge ${riskClass}">${escapeHtml(listener.risk)}</div></div></div>
              <div class="muted">${escapeHtml((listener.ports || []).join(', ') || '-')} | binds ${escapeHtml((listener.binds || []).join(', ') || '-')} | ${escapeHtml((listener.scopes || []).join(', ') || '-')}</div>
              <div class="hint">${escapeHtml(listener.reason || '')} ${escapeHtml(reachability.detail || '')}</div>
            </div>`;
          }).join('') : '<div class="muted">No listening services detected</div>'}
        </div><div class="hint">${escapeHtml((exposure.notes || []).join(' '))}</div></div>
        <div class="route"><div class="label">Policy Gaps</div><div class="item-list" style="margin-top:10px;">
          ${gaps.map(gap => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(gap.title)}</div><div class="badge ${gap.severity === 'high' ? 'offline' : gap.severity === 'medium' ? 'warn' : 'idle'}">${escapeHtml(gap.severity)}</div></div><div class="muted">${escapeHtml(gap.detail || '')}</div></div>`).join('')}
        </div></div>
        <details class="config-section">
          <summary><span>Next Apply Model</span><span>preview / verify / rollback</span></summary>
          <div class="item-list" style="margin-top:10px;">${(payload.next_steps || []).map(step => `<div class="item"><div class="item-title">${escapeHtml(step)}</div></div>`).join('')}</div>
        </details>
        <div class="controls">
          <button class="secondary" onclick="previewRouteFirewallReconcile()">Preview Reconcile Plan</button>
        </div>
      `;
    }
    function renderNetworkDiagnostics(payload) {
      const state = payload.state || {};
      const snapshot = payload.snapshot || {};
      const findings = payload.findings || [];
      const candidates = state.uplink_candidates || [];
      const routes = snapshot.routes || {};
      const commands = snapshot.commands || {};
      const generated = snapshot.generated_at ? new Date(snapshot.generated_at * 1000).toLocaleTimeString() : '-';
      return `
        <div class="stat-grid">
          <div class="metric"><div class="label">Active Uplink</div><div class="value small">${escapeHtml(state.active_uplink || 'none')}</div></div>
          <div class="metric"><div class="label">IPv4 Forwarding</div><div class="value small">${escapeHtml(state.ipv4_forwarding === '1' ? 'Enabled' : (state.ipv4_forwarding || 'Unknown'))}</div></div>
          <div class="metric"><div class="label">Findings</div><div class="value">${findings.length}</div></div>
          <div class="metric"><div class="label">Snapshot</div><div class="value small">${escapeHtml(generated)}</div></div>
        </div>
        <div class="route"><div class="label">Default Routes</div><div class="item-list" style="margin-top:10px;">
          <div class="item"><div class="item-top"><div class="item-title">IPv4</div><div class="badge ${routes.default_ipv4 && Object.keys(routes.default_ipv4).length ? 'online' : 'offline'}">route</div></div><div class="muted">${escapeHtml(routeSummary(routes.default_ipv4))}</div></div>
          <div class="item"><div class="item-top"><div class="item-title">IPv6</div><div class="badge ${routes.default_ipv6 && Object.keys(routes.default_ipv6).length ? 'online' : 'idle'}">route</div></div><div class="muted">${escapeHtml(routeSummary(routes.default_ipv6))}</div></div>
        </div></div>
        <div class="route"><div class="label">Uplink Candidates</div><div class="item-list" style="margin-top:10px;">
          ${candidates.length ? candidates.map(item => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(item.interface)}</div><div class="badge ${item.default_route ? 'online' : item.link_ready ? 'warn' : 'idle'}">${item.default_route ? 'active' : item.link_ready ? 'ready' : String(item.score)}</div></div><div class="muted">${escapeHtml(item.role)} | ${escapeHtml(item.state)} | IP: ${item.has_ip ? 'yes' : 'no'} | Metric: ${escapeHtml(item.route_metric ?? '-')} | ↓ ${escapeHtml(formatRate((item.counters || {}).rx_bytes_per_sec))} ↑ ${escapeHtml(formatRate((item.counters || {}).tx_bytes_per_sec))}</div></div>`).join('') : '<div class="muted">No uplink candidates detected</div>'}
        </div></div>
        <div class="route"><div class="label">Collectors</div><div class="item-list" style="margin-top:10px;">
          ${['nmcli_devices', 'nmcli_active', 'resolvectl', 'ip_rule', 'ipv4_forward', 'nft_ruleset'].map(key => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(key.replaceAll('_', ' '))}</div>${commandStatus(commands[key])}</div><div class="muted">${escapeHtml(((commands[key] || {}).command || []).join(' ') || (commands[key] || {}).stderr || '-')}</div></div>`).join('')}
        </div></div>
        ${renderRawSnapshotDetails(snapshot)}
        <div class="route">
          <div class="item-top">
            <div><div class="label">Connectivity</div><div class="muted">Manual per-interface probe; no routes or firewall rules are changed.</div></div>
            <button class="secondary" onclick="runConnectivityTest()">Run Test</button>
          </div>
          ${renderConnectivityResults(appState.connectivityTest)}
        </div>
        <div class="route"><div class="label">Findings</div><div class="item-list" style="margin-top:10px;">
          ${findings.length ? findings.map(finding => `<div class="item"><div class="item-top"><div class="item-title">${escapeHtml(finding.title)}</div><div class="badge ${finding.severity === 'high' ? 'offline' : finding.severity === 'medium' ? 'warn' : 'idle'}">${escapeHtml(finding.severity)}</div></div><div class="muted">${escapeHtml(finding.impact || '')}</div><div class="hint">${escapeHtml(finding.suggested_fix || '')}</div></div>`).join('') : '<div class="muted">No network findings detected</div>'}
        </div></div>
      `;
    }
    async function render(options = {}) {
      if (appState.rendering) {
        appState.renderQueued = true;
        return;
      }
      if (!options.force && !options.allowDuringEditing && hasActiveEditing()) {
        updateRefreshState();
        return;
      }
      appState.rendering = true;
      try {
      let {
        overview, systemStats, lte, lteProfile, lteOptions, lteSuggest, lteAuto, atExamples,
        services, serviceInventory, pihole, piholeNetworks, netalert, samba, printing, interfaces, interfaceInventory,
        serviceLan, serviceLanClients, wifiClients, lanProfile, activeSessions, wifi, networkBehaviors, filesystem, deviceIo, providers, capabilities,
        networkDiagnostics, routeFirewallPolicy, networkReconcile, eventLog, actions, actionHistory, settings, interfaceConfigs
      } = await loadPanelData(Boolean(options.force));

      appState.lastSyncAt = Date.now();
      appState.serviceDetails = {};
      appState.wifi = wifi;
      appState.settings = settings;
      const inventoryInterfaces = (interfaceInventory || {}).interfaces || interfaces;
      applyVisibleTabs(settings);
      const crumbRoot = document.querySelector('.crumb-root');
      if (crumbRoot) crumbRoot.textContent = overview.hostname || 'device';
      if (overview.hostname) document.title = `${overview.hostname} Device Admin`;
      updateRefreshState();

      setPanelHTML('overview', () => renderOverview(overview, systemStats, activeSessions, serviceLanClients, wifiClients));
      setPanelHTML('docker-brief', () => renderDockerBrief(systemStats));
      setPanelHTML('dashboard-sessions', () => renderSessions(activeSessions));
      const sessionBadge = document.getElementById('dashboard-session-count');
      const totalSessions = sessionCount(activeSessions);
      if (sessionBadge) {
        sessionBadge.textContent = String(totalSessions);
        sessionBadge.className = sessionCountClass(totalSessions);
      }

      setPanelHTML('interface-profiles', () => renderInterfaceConfigs(interfaceConfigs, networkBehaviors, lanProfile, serviceLan));

      setPanelHTML('interfaces', () => {
        const groups = categorizeInterfaces(interfaces);
        return [
          renderInterfaceGroup('Uplinks', groups.uplinks),
          renderInterfaceGroup('LAN Ports', groups.lan),
          renderInterfaceGroup('Wireless', groups.wireless),
          renderInterfaceGroup('Virtual / Other', groups.virtual),
        ].join('');
      });
      setPanelHTML('route-firewall-policy', () => renderRouteFirewallPolicy(routeFirewallPolicy));
      setPanelHTML('reconcile-panel', () => renderReconcilePreview(networkReconcile));
      setPanelHTML('network-diagnostics', () => renderNetworkDiagnostics(networkDiagnostics));

      setPanelHTML('service-lan-clients', () => (serviceLanClients || []).length ? `<div class="item-list scroll-list">${serviceLanClients.map(c => `<div class="item client-item"><div class="item-top"><div class="item-title">${escapeHtml(c.hostname || c.mac || 'Client')}</div><div class="badge">${escapeHtml(c.interface || '-')}</div></div><div class="muted">IP: ${escapeHtml(c.ip)} | MAC: ${escapeHtml(c.mac || '-')} | ${escapeHtml(c.family || '-')} | ${escapeHtml(c.state || '-')}</div></div>`).join('')}</div>` : '<div class="muted">No clients detected</div>');
      setPanelHTML('wifi-panel', () => renderWireless(wifi, inventoryInterfaces, wifiClients, piholeNetworks, overview));

      const cellular = {};
      setPanelHTML('cellular-state', () => {
        Object.assign(cellular, renderCellular(lte, lteProfile, lteOptions, lteSuggest, lteAuto, atExamples, overview, inventoryInterfaces));
        return cellular.state;
      });
      setPanelHTML('cellular-apn', () => cellular.apn || renderCellular(lte, lteProfile, lteOptions, lteSuggest, lteAuto, atExamples, overview, inventoryInterfaces).apn);
      setPanelHTML('cellular-at', () => cellular.at || renderCellular(lte, lteProfile, lteOptions, lteSuggest, lteAuto, atExamples, overview, inventoryInterfaces).at);

      setPanelHTML('pihole-panel', () => renderPiHolePanel(pihole, piholeNetworks));
      setPanelHTML('netalert-panel', () => renderNetAlertPanel(netalert));
      setPanelHTML('topology-panel', () => renderTopologyBlueprint(overview, lanProfile, serviceLan, wifi, netalert));
      setPanelHTML('logs-panel', () => renderLogsPanel(overview, services, activeSessions, systemStats, eventLog));
      setPanelHTML('services', () => renderServices((serviceInventory || {}).services || services, systemStats, serviceInventory));
      setPanelHTML('terminal-panel', () => renderTerminal());

      setPanelHTML('samba-panel', () => renderSamba(samba));
      setPanelHTML('samba-users-panel', () => renderSambaUsers(samba));
      setPanelHTML('printing-panel', () => renderPrinting(printing));
      setPanelHTML('filesystem-panel', () => renderFileSystem(filesystem));
      setPanelHTML('deviceio-panel', () => renderDeviceIo(deviceIo));
      setPanelHTML('providers-panel', () => renderProviders(providers, capabilities, settings));
      setPanelHTML('settings-panel', () => renderSettings(settings));
      setPanelHTML('actions-panel', () => renderActions(actions, actionHistory));
      setPanelHTML('lorawan-panel', () => `<div class="stat-grid"><div class="metric"><div class="label">Module State</div><div class="value small">Not installed yet</div></div><div class="metric"><div class="label">Planned Uses</div><div class="value small">LoRaWAN, Meshtastic, profiles and radio settings</div></div></div><div class="hint">This page is ready as a placeholder so future radio modules can live in a dedicated area instead of being scattered across the dashboard.</div>`);

      [
        ['main-lan-name', 'main_lan.name'],
        ['main-lan-target-interface', 'main_lan.target_interface'],
        ['main-lan-role', 'main_lan.role'],
        ['main-lan-ipv4-mode', 'main_lan.ipv4_mode'],
        ['main-lan-ipv4-address', 'main_lan.ipv4_address'],
        ['main-lan-ipv4-subnet', 'main_lan.ipv4_subnet'],
        ['main-lan-dhcp-range', 'main_lan.dhcp_range'],
        ['main-lan-ipv6-mode', 'main_lan.ipv6_mode'],
        ['main-lan-ipv6-address', 'main_lan.ipv6_address'],
        ['main-lan-ipv6-prefix', 'main_lan.ipv6_prefix'],
        ['main-lan-dns-servers', 'main_lan.dns_servers'],
        ['service-lan-name', 'service_lan.name'],
        ['service-lan-interface', 'service_lan.interface'],
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
        ['cellular-apn-country', 'cellular.apn_country'],
        ['cellular-apn-provider', 'cellular.apn_provider'],
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
      } finally {
        appState.rendering = false;
        if (appState.renderQueued) {
          appState.renderQueued = false;
          setTimeout(() => render({ force: true }), 0);
        }
      }
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
      renderActivityLog();
      if (await checkAuth()) {
        await render({ force: true });
        setTimeout(() => {
          if (!appState.lastSyncAt && document.body.dataset.auth === 'unlocked' && !document.hidden) {
            render({ force: true });
          }
        }, 1800);
      }
      applyDemoMaskToDom();
    }
    boot();
    setInterval(pollRender, AUTO_REFRESH_MS);
    window.addEventListener('focusin', updateRefreshState);
    window.addEventListener('focusout', () => setTimeout(updateRefreshState, 0));
    window.addEventListener('resize', fitFloatingWindow);
    document.addEventListener('visibilitychange', () => {
      updateRefreshState();
      if (!document.hidden && document.body.dataset.auth === 'unlocked' && !hasActiveEditing()) {
        render();
      }
    });

Object.assign(window, {
  draftValue,
  bindDraft,
  clearDraft,
  setInterfaceSelector,
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
  backendLogQuery,
  applyLogFilters,
  deleteFilteredEvents,
  pruneMissingServices,
  updateRefreshState,
  setView,
  loadTheme,
  toggleTheme,
  toggleActivityDrawer,
  clearActivityLog,
  trackActivity,
  getUptimeMode,
  cycleUptimeMode,
  fmtUptime,
  openServiceOverlay,
  closeServiceOverlay,
  openRawProfile,
  openTextOverlay,
  closeTextOverlay,
  openFloatingWindow,
  closeFloatingWindow,
  beginFloatingWindowDrag,
  openInterfaceBehaviorWindow,
  openInterfaceConfigWindow,
  dismissOverlay,
  closeCommandOverlay,
  openCommandOverlay,
  refreshCommandPreview,
  activatePiholeRouting,
  rescanProvider,
  previewProviderInstall,
  previewRouteFirewallReconcile,
  runConnectivityTest,
  previewPanelAction,
  executePanelAction,
  setTerminalCommand,
  previewTerminalCommand,
  runTerminalCommand,
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
  saveVisibleTab,
  saveInterfaceBehavior,
  saveInterfaceDesiredConfig,
  resetInterfaceConfig,
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
  toggleCustomSelect,
  selectCustomOption,
  closeCustomSelects,
  lanRoleExplanation,
  renderLanCard,
  categorizeInterfaces,
  renderInterfaceGroup,
  renderInterfaceConfigs,
  renderWireless,
  renderCellular,
  renderPiHolePanel,
  renderNetAlertPanel,
  renderTopologyBlueprint,
  renderServices,
  renderTerminal,
  renderSamba,
  renderSambaUsers,
  renderPrinting,
  renderFileSystem,
  renderDeviceIo,
  renderActions,
  render,
  pollRender,
  boot,
});
