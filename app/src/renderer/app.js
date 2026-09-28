const $ = (id) => document.getElementById(id);
const state = { status: null, busy: false, platform: null, page: 'overview', profiles: [], countries: [], countryFilter: '', sortKey: 'rank', sortDir: 'asc' };

function setText(id, value) { const el = $(id); if (el) el.textContent = value ?? '—'; }
function safeArray(v) { return Array.isArray(v) ? v : v ? [v] : []; }

function showToast(message, error = false) {
  const toast = $('toast');
  toast.textContent = message;
  toast.className = 'toast show' + (error ? ' error' : '');
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.className = 'toast', 3600);
}

function setBusy(on, action = '') {
  state.busy = on;
  $('busyOverlay').classList.toggle('show', on);
  if (on) {
    const names = { connect:'Connecting', disconnect:'Disconnecting', refresh:'Refreshing config pool', ensure:'Repairing connection', 'connect-profile':'Switching relay', 'benchmark-active':'Measuring real tunnel speed', 'benchmark-all-fast':'Testing all relays in parallel', 'factory-refresh':'Refreshing config pool', 'auto-install':'Installing recovery', 'auto-remove':'Removing recovery', 'console-enable':'Enabling console gateway', 'console-disable':'Disabling console gateway', 'console-status':'Checking console gateway' };
    setText('busyTitle', names[action] || 'Working…');
  }
}

function renderStatus(s) {
  state.status = s || {};
  const connected = !!s.connected;
  $('powerButton').classList.toggle('connected', connected);
  $('sidebarDot').classList.toggle('online', connected);
  setText('sidebarStatus', connected ? 'Protected' : 'Direct connection');
  setText('sidebarCountry', connected ? ((s.country || 'Foreign') + ' egress') : 'Tunnel disconnected');
  setText('connectionTitle', connected ? 'Internet protected' : 'Protection is off');
  setText('connectionDetail', connected ? ('Traffic exits through ' + (s.country || 'validated relay') + ' · ' + (s.ip || 'IP pending')) : 'Connect to establish a validated full-device route.');
  setText('ipStat', s.ip || '—');
  setText('countryStat', s.country || 'Direct');
  setText('dnsStat', safeArray(s.dns).join(' · ') || '—');
  setText('routesStat', String(s.fullRoutes ?? 0) + ' / 2');
  setText('relayName', s.relay || (connected ? 'Validated relay' : 'Not connected'));
  setText('relayMeta', connected ? ((s.engine === 'HeadlessConnector' ? 'Headless · sticky' : (s.interface || 'Tunnel interface')) + ' · anti-flap') : 'Validated endpoint · stable mode');

  const routeOk = Number(s.fullRoutes || 0) >= 2;
  const dnsOk = s.poison === false;
  const recoveryState = String(s.autoRecoveryState || '').toLowerCase();
  const recoveryOk = !!s.autoRecovery && !['inactive','failed','missing'].includes(recoveryState);
  const pool = s.configPool || {};
  const factoryOk = !!pool.healthy && Number(pool.pool || 0) >= 3;
  markHealth('routeIcon', 'routeHealth', routeOk, routeOk ? 'All IPv4 traffic protected' : 'Full-route not active');
  markHealth('dnsIcon', 'dnsHealth', dnsOk, dnsOk ? 'Poison fingerprint absent' : 'DNS protection incomplete');
  markHealth('recoveryIcon', 'recoveryHealth', recoveryOk, recoveryOk ? (s.autoRecoveryState || 'Installed') : 'Not installed');
  markHealth('factoryIcon', 'factoryHealth', factoryOk, factoryOk ? (String(pool.validated || 0) + ' validated · ' + String(pool.pool || 0) + ' total') : 'Pool needs regeneration');
  const score = [routeOk, dnsOk, recoveryOk, factoryOk].filter(Boolean).length;
  setText('healthScore', Math.round(score / 4 * 100) + '%');
  $('autoButton').textContent = recoveryOk ? 'Installed' : 'Install';
  $('powerButton').title = connected ? 'Disconnect' : 'Connect';

  setText('poolValidated', String(pool.validated ?? 0));
  setText('poolStandby', String(pool.standby ?? 0));
  setText('poolQuarantined', String(pool.quarantined ?? 0));
  setText('poolGenerations', String(pool.generations ?? 0));
  const protocols = pool.protocols && typeof pool.protocols === 'object'
    ? Object.entries(pool.protocols).filter(([,v]) => Number(v) > 0).map(([k,v]) => String(k).toUpperCase() + ' ' + v).join(' · ')
    : '—';
  setText('poolProtocols', protocols || '—');
  setText('poolAge', pool.ageHours == null ? '—' : (Number(pool.ageHours).toFixed(1) + 'h'));
  setText('factorySource', pool.source ? ('Source: ' + pool.source) : 'Maintains multiple validated and standby tunnel profiles automatically.');
}

function markHealth(iconId, textId, ok, label) {
  const icon = $(iconId);
  icon.textContent = ok ? '✓' : '!';
  icon.className = 'health-icon ' + (ok ? 'ok' : 'bad');
  setText(textId, label);
}

async function refreshStatus(silent = true) {
  try {
    const s = await window.gateway.status();
    renderStatus(s);
    if (!silent && s.error) showToast(s.error, true);
  } catch (e) {
    if (!silent) showToast(e.message, true);
  }
}

async function runAction(action, message, options = {}) {
  if (state.busy) return;
  setBusy(true, action);
  try {
    const result = await window.gateway.action(action, options);
    if (result?.status) renderStatus(result.status);
    else await refreshStatus();
    showToast(message || 'Action completed.');
    return result;
  } catch (e) {
    showToast(e.message || 'Action failed.', true);
  } finally {
    setBusy(false);
  }
}

function metric(value, suffix = '') {
  return value == null || Number.isNaN(Number(value)) ? '—' : (String(value) + suffix);
}

function renderBenchmarkSummary() {
  const active = state.profiles.find(p => p.active);
  const b = active?.benchmark;
  const box = $('benchmarkSummary');
  if (!box) return;
  const values = [
    (b?.icmpPingMs ?? b?.fastPingMs) == null ? 'Blocked / —' : metric(b.icmpPingMs ?? b.fastPingMs, ' ms'),
    b?.httpsLatencyMs == null ? '—' : metric(b.httpsLatencyMs, ' ms'),
    b?.downloadMbps == null ? '—' : metric(b.downloadMbps, ' Mbps'),
    b?.uploadMbps == null ? '—' : metric(b.uploadMbps, ' Mbps')
  ];
  box.querySelectorAll('b').forEach((el,i) => { el.textContent = values[i] || '—'; });
}

function connectionStatusRank(p) {
  if (p.active) return 0;
  if (p.preferred) return 1;
  if (p.validated) return 2;
  if (p.quarantined) return 9;
  return 3;
}

function connectionSortValue(p, key) {
  if (key === 'country') return (p.country || '').toUpperCase();
  if (key === 'relay') return (p.host || p.ip || '').toLowerCase();
  if (key === 'protocol') return p.protocol || '';
  if (key === 'sourcePing') return p.sourcePingMs;
  if (key === 'livePing') return p.benchmark?.fastPingMs ?? p.benchmark?.icmpPingMs ?? p.benchmark?.httpsLatencyMs;
  if (key === 'download') return p.benchmark?.downloadMbps;
  if (key === 'upload') return p.benchmark?.uploadMbps;
  if (key === 'status') return connectionStatusRank(p);
  return p.rank;
}

function compareConnections(a, b) {
  const av = connectionSortValue(a, state.sortKey);
  const bv = connectionSortValue(b, state.sortKey);
  const aMissing = av == null || av === '';
  const bMissing = bv == null || bv === '';
  if (aMissing !== bMissing) return aMissing ? 1 : -1;
  let cmp = 0;
  if (typeof av === 'number' && typeof bv === 'number') cmp = av - bv;
  else cmp = String(av ?? '').localeCompare(String(bv ?? ''), undefined, { numeric: true, sensitivity: 'base' });
  if (!cmp) cmp = Number(a.rank || 0) - Number(b.rank || 0);
  return state.sortDir === 'desc' ? -cmp : cmp;
}

function updateSortHeaders() {
  document.querySelectorAll('.connection-table th[data-sort]').forEach(th => {
    const active = th.dataset.sort === state.sortKey;
    th.classList.toggle('active-sort', active);
    th.setAttribute('aria-sort', active ? (state.sortDir === 'asc' ? 'ascending' : 'descending') : 'none');
    const mark = th.querySelector('span');
    if (mark) mark.textContent = active ? (state.sortDir === 'asc' ? '↑' : '↓') : '↕';
  });
}

function renderConnections() {
  const body = $('connectionRows');
  if (!body) return;
  body.innerHTML = '';
  const filter = state.countryFilter || '';
  const rows = state.profiles.filter(p => !filter || p.country === filter).slice().sort(compareConnections);
  updateSortHeaders();
  if (!rows.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td'); td.colSpan = 9; td.className = 'empty'; td.textContent = 'No relays match this country filter.';
    tr.appendChild(td); body.appendChild(tr); renderBenchmarkSummary(); return;
  }
  for (const p of rows) {
    const tr = document.createElement('tr');
    if (p.active) tr.classList.add('active-row');
    if (p.quarantined) tr.classList.add('quarantined');

    const country = document.createElement('td');
    const cc = document.createElement('span'); cc.className = 'country-chip'; cc.textContent = p.country || '—'; country.appendChild(cc);

    const relay = document.createElement('td'); relay.className = 'relay-cell';
    const rb = document.createElement('b'); rb.textContent = p.host || p.ip || 'Relay';
    const rs = document.createElement('small'); rs.textContent = (p.ip || '—') + ':' + (p.port || '—');
    relay.append(rb, rs);

    const protocol = document.createElement('td');
    const pc = document.createElement('span'); pc.className = 'protocol-chip'; pc.textContent = p.protocol || '—'; protocol.appendChild(pc);

    const sourcePing = document.createElement('td'); sourcePing.className = 'metric-source';
    sourcePing.textContent = p.sourcePingMs == null ? '—' : (p.sourcePingMs + ' ms');

    const livePing = document.createElement('td'); livePing.className = 'metric-real';
    const fastPing = p.benchmark?.fastPingMs;
    livePing.textContent = fastPing != null
      ? (fastPing + ' ms ' + String(p.benchmark?.fastMethod || 'live').toUpperCase())
      : (p.benchmark?.icmpPingMs != null
          ? (p.benchmark.icmpPingMs + ' ms ICMP')
          : (p.benchmark?.httpsLatencyMs != null ? (p.benchmark.httpsLatencyMs + ' ms HTTPS') : '—'));

    const down = document.createElement('td'); down.className = 'metric-real';
    down.textContent = p.benchmark?.downloadMbps == null ? 'Not tested' : (p.benchmark.downloadMbps + ' Mbps');

    const up = document.createElement('td'); up.className = 'metric-real';
    up.textContent = p.benchmark?.uploadMbps == null ? 'Not tested' : (p.benchmark.uploadMbps + ' Mbps');

    const status = document.createElement('td');
    const sc = document.createElement('span');
    sc.className = 'state-chip ' + (p.active ? 'active' : p.quarantined ? 'bad' : p.validated ? 'validated' : '');
    sc.textContent = p.active ? 'ACTIVE' : p.quarantined ? 'QUARANTINED' : p.validated ? 'VALIDATED' : p.preferred ? 'PREFERRED' : 'STANDBY';
    status.appendChild(sc);

    const actions = document.createElement('td'); actions.className = 'row-actions';
    const connect = document.createElement('button'); connect.className = 'btn secondary'; connect.textContent = p.active ? 'Active' : 'Connect';
    connect.disabled = p.active || p.quarantined;
    connect.dataset.action = 'connect-profile'; connect.dataset.sha = p.sha256;
    const test = document.createElement('button'); test.className = 'btn'; test.textContent = 'Speed';
    test.disabled = p.quarantined; test.dataset.action = 'test-profile'; test.dataset.sha = p.sha256;
    actions.append(connect, test);

    tr.append(country, relay, protocol, sourcePing, livePing, down, up, status, actions);
    body.appendChild(tr);
  }
  renderBenchmarkSummary();
}

async function loadConnections() {
  const body = $('connectionRows');
  if (body) body.innerHTML = '<tr><td colspan="9" class="empty">Loading connection inventory…</td></tr>';
  try {
    const result = await window.gateway.profiles();
    state.profiles = result?.profiles || [];
    state.countries = result?.countries || [];
    const select = $('countryFilter');
    const previous = state.countryFilter;
    select.innerHTML = '<option value="">All countries</option>';
    for (const country of state.countries) {
      const option = document.createElement('option'); option.value = country; option.textContent = country; select.appendChild(option);
    }
    if (previous && state.countries.includes(previous)) select.value = previous;
    else state.countryFilter = '';
    renderConnections();
  } catch (e) {
    if (body) body.innerHTML = '<tr><td colspan="9" class="empty">Unable to read connection inventory.</td></tr>';
    showToast(e.message || 'Unable to load connections.', true);
  }
}

async function connectOrTestProfile(sha256, testAfter = false) {
  if (state.busy) return;
  setBusy(true, 'connect-profile');
  try {
    const selected = state.profiles.find(p => p.sha256 === sha256);
    if (!selected?.active) {
      const connected = await window.gateway.action('connect-profile', { sha256 });
      if (connected?.status) renderStatus(connected.status);
    }
    if (testAfter) {
      setBusy(true, 'benchmark-active');
      const measured = await window.gateway.action('benchmark-active');
      if (measured?.status) renderStatus(measured.status);
      const b = measured?.benchmark;
      showToast(b ? ('Measured ' + b.downloadMbps + ' Mbps down · ' + b.uploadMbps + ' Mbps up') : 'Measurement completed.');
    } else {
      showToast('Relay selected and validated.');
    }
    await loadConnections();
  } catch (e) {
    showToast(e.message || 'Relay operation failed.', true);
  } finally {
    setBusy(false);
  }
}

async function benchmarkCurrent() {
  if (state.busy) return;
  setBusy(true, 'benchmark-all-fast');
  try {
    const result = await window.gateway.action('benchmark-all-fast');
    if (result?.status) renderStatus(result.status);
    const seconds = Math.max(0.1, Number(result?.elapsedMs || 0) / 1000).toFixed(1);
    showToast('Tested ' + String(result?.tested || 0) + ' relays in ' + seconds + 's · ' + String(result?.reachable || 0) + ' replied.');
    await loadConnections();
  } catch (e) {
    showToast(e.message || 'Fast relay test failed.', true);
  } finally {
    setBusy(false);
  }
}

async function loadDiagnostics() {
  const box = $('diagnosticRows');
  box.innerHTML = '<div class="empty">Running live checks…</div>';
  try {
    const d = await window.gateway.diagnostics();
    box.innerHTML = '';
    for (const check of d.checks || []) {
      const row = document.createElement('div');
      row.className = 'diagnostic-row';
      row.innerHTML = '<div><b></b><small></small></div><span class="check-pill"></span>';
      row.querySelector('b').textContent = check.name;
      row.querySelector('small').textContent = check.detail || '';
      const pill = row.querySelector('.check-pill');
      pill.textContent = check.ok ? 'PASS' : 'CHECK';
      if (!check.ok) pill.classList.add('fail');
      box.appendChild(row);
    }
    $('diagnosticRaw').textContent = JSON.stringify(d, null, 2);
  } catch (e) {
    box.innerHTML = '<div class="empty">Diagnostic error: ' + escapeHtml(e.message) + '</div>';
  }
}

async function loadActivity() {
  const box = $('activityList');
  box.innerHTML = '<div class="empty">Loading evidence…</div>';
  try {
    const items = await window.gateway.activity();
    box.innerHTML = '';
    if (!items.length) box.innerHTML = '<div class="empty">No activity evidence yet.</div>';
    for (const item of items) {
      const el = document.createElement('div');
      el.className = 'timeline-item';
      const strong = document.createElement('strong');
      strong.textContent = item.file;
      const pre = document.createElement('pre');
      pre.textContent = JSON.stringify(item.data, null, 2);
      el.append(strong, pre);
      box.appendChild(el);
    }
  } catch (e) { box.innerHTML = '<div class="empty">Unable to read activity.</div>'; }
}

function escapeHtml(s='') { return s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c])); }

function setPage(name) {
  state.page = name;
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.page === name));
  document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id === 'page-' + name));
  const meta = {
    overview:['Overview','Private, resilient, full-device Internet routing.'],
    connections:['Connections','Choose countries and relays, then measure real tunnel performance.'],
    diagnostics:['Diagnostics','Verify egress, DNS integrity and recovery readiness.'],
    activity:['Activity','Evidence from connection and recovery events.'],
    settings:['Settings','Appearance, recovery and runtime information.']
  }[name];
  setText('pageTitle', meta[0]); setText('pageSubtitle', meta[1]);
  if (name === 'connections') loadConnections();
  if (name === 'diagnostics') loadDiagnostics();
  if (name === 'activity') loadActivity();
}

async function init() {
  document.querySelectorAll('.nav-item').forEach(b => b.addEventListener('click', () => setPage(b.dataset.page)));
  $('powerButton').addEventListener('click', () => runAction(state.status?.connected ? 'disconnect' : 'connect', state.status?.connected ? 'Disconnected.' : 'Connected and validated.'));
  $('reloadConnections').addEventListener('click', loadConnections);
  $('benchmarkCurrent').addEventListener('click', benchmarkCurrent);
  $('countryFilter').addEventListener('change', e => { state.countryFilter = e.target.value; renderConnections(); });
  document.querySelectorAll('.connection-table th[data-sort]').forEach(th => th.addEventListener('click', () => {
    const key = th.dataset.sort;
    if (state.sortKey === key) state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
    else { state.sortKey = key; state.sortDir = 'asc'; }
    renderConnections();
  }));
  $('connectionRows').addEventListener('click', e => {
    const button = e.target.closest('button[data-action]');
    if (!button || button.disabled) return;
    if (button.dataset.action === 'connect-profile') connectOrTestProfile(button.dataset.sha, false);
    if (button.dataset.action === 'test-profile') connectOrTestProfile(button.dataset.sha, true);
  });
  $('refreshConnect').addEventListener('click', () => runAction('refresh', 'Config pool refreshed. Active relay was not changed.'));
  $('ensureButton').addEventListener('click', () => runAction('ensure', 'Health check completed.'));
  $('refreshStatus').addEventListener('click', () => refreshStatus(false));
  $('runDiagnostics').addEventListener('click', loadDiagnostics);
  $('reloadActivity').addEventListener('click', loadActivity);
  $('autoButton').addEventListener('click', () => setPage('settings'));
  $('consoleButton').addEventListener('click', () => runAction('console-status', 'Console gateway status checked.'));
  $('factoryRefresh').addEventListener('click', () => runAction('factory-refresh', 'Config pool refreshed and validated structurally.'));
  $('installRecovery').addEventListener('click', () => runAction('auto-install', 'Auto-Recovery installed.'));
  $('removeRecovery').addEventListener('click', () => runAction('auto-remove', 'Auto-Recovery removed.'));
  $('openLogs').addEventListener('click', () => window.gateway.openLogs());

  document.querySelectorAll('[data-theme-value]').forEach(b => b.addEventListener('click', async () => {
    const theme = b.dataset.themeValue;
    document.querySelectorAll('[data-theme-value]').forEach(x => x.classList.toggle('active', x === b));
    if (theme === 'system') {
      document.documentElement.removeAttribute('data-theme');
      const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    } else document.documentElement.dataset.theme = theme;
    localStorage.setItem('oig-theme', theme);
    await window.gateway.setTheme(theme);
  }));

  window.gateway.onBackendEvent(payload => {
    if (payload.type === 'busy') setBusy(payload.busy, payload.action);
    if (payload.type === 'status' && payload.status) renderStatus(payload.status);
    if (payload.type === 'error') showToast(payload.message, true);
  });

  const savedTheme = localStorage.getItem('oig-theme') || 'dark';
  const themeBtn = document.querySelector('[data-theme-value="' + savedTheme + '"]');
  themeBtn?.click();

  state.platform = await window.gateway.platform();
  setText('platformBadge', (state.platform.platform === 'win32' ? 'Windows' : 'Linux') + ' · ' + state.platform.arch);
  setText('appVersion', 'v' + (state.platform.version || '—') + ' · Stable Headless');
  $('systemInfo').innerHTML = [
    ['Version', state.platform.version],
    ['Platform', state.platform.platform],
    ['Architecture', state.platform.arch],
    ['Hostname', state.platform.hostname],
    ['Backend', state.platform.backendRoot]
  ].map(([k,v]) => '<div class="sys-row"><small>'+escapeHtml(k)+'</small><b>'+escapeHtml(String(v || '—'))+'</b></div>').join('');

  await refreshStatus(false);
  setInterval(() => { if (!state.busy && document.visibilityState === 'visible') refreshStatus(true); }, 10000);
}

init();
