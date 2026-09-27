const $ = (id) => document.getElementById(id);
const state = { status: null, busy: false, platform: null, page: 'overview' };

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
    const names = { connect:'Connecting', disconnect:'Disconnecting', refresh:'Refreshing config pool', ensure:'Repairing connection', 'factory-refresh':'Refreshing config pool', 'auto-install':'Installing recovery', 'auto-remove':'Removing recovery', 'console-enable':'Enabling console gateway', 'console-disable':'Disabling console gateway', 'console-status':'Checking console gateway' };
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

async function runAction(action, message) {
  if (state.busy) return;
  setBusy(true, action);
  try {
    const result = await window.gateway.action(action);
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
    diagnostics:['Diagnostics','Verify egress, DNS integrity and recovery readiness.'],
    activity:['Activity','Evidence from connection and recovery events.'],
    settings:['Settings','Appearance, recovery and runtime information.']
  }[name];
  setText('pageTitle', meta[0]); setText('pageSubtitle', meta[1]);
  if (name === 'diagnostics') loadDiagnostics();
  if (name === 'activity') loadActivity();
}

async function init() {
  document.querySelectorAll('.nav-item').forEach(b => b.addEventListener('click', () => setPage(b.dataset.page)));
  $('powerButton').addEventListener('click', () => runAction(state.status?.connected ? 'disconnect' : 'connect', state.status?.connected ? 'Disconnected.' : 'Connected and validated.'));
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
  $('systemInfo').innerHTML = [
    ['Platform', state.platform.platform],
    ['Architecture', state.platform.arch],
    ['Hostname', state.platform.hostname],
    ['Backend', state.platform.backendRoot]
  ].map(([k,v]) => '<div class="sys-row"><small>'+escapeHtml(k)+'</small><b>'+escapeHtml(String(v || '—'))+'</b></div>').join('');

  await refreshStatus(false);
  setInterval(() => { if (!state.busy && document.visibilityState === 'visible') refreshStatus(true); }, 10000);
}

init();
