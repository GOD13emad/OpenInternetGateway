const $ = (id) => document.getElementById(id);
const state = { status: null, busy: false, busyAction: '', platform: null, page: 'overview', profiles: [], countries: [], countryFilter: '', sortKey: 'rank', sortDir: 'asc', updateInfo: null, directBenchmark: null };

function setText(id, value) { const el = $(id); if (el) el.textContent = value ?? '—'; }
function safeArray(v) { return Array.isArray(v) ? v : v ? [v] : []; }

function showToast(message, error = false) {
  const toast = $('toast');
  toast.textContent = message;
  toast.className = 'toast show' + (error ? ' error' : '');
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.className = 'toast', 3600);
}

function userErrorMessage(error, fallback = 'Action failed.') {
  let raw = String(error?.message || error || '').replace(/\x1B\[[0-?]*[ -\/]*[@-~]/g, '').trim();
  if (!raw) return fallback;
  raw = raw.replace(/^Error invoking remote method '[^']+':\s*/i, '').replace(/^Error:\s*/i, '').replace(/^Exception:\s*/i, '');
  const lines = raw.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  const cleaned = lines.map(line => line.replace(/^\|\s*/, '')).filter(line =>
    !/^[~^+]+$/.test(line) &&
    !/^at <ScriptBlock>/i.test(line) &&
    !/^[A-Z]:\\.*\.ps1:\s*line\s+\d+/i.test(line) &&
    !/^\+\s*(CategoryInfo|FullyQualifiedErrorId)/i.test(line)
  );
  const semantic = cleaned.find(line => /^(Selected relay|Selected profile|Profile |Previous relay|No physical|Direct ISP|Real download|Real upload|Connect a relay|The active relay|Unable|Could not)/i.test(line));
  return semantic || cleaned[0] || fallback;
}

function setBusy(on, action = '', detail = '') {
  state.busy = on;
  state.busyAction = on ? action : '';
  $('busyOverlay').classList.toggle('show', on);
  if (on) {
    const names = { connect:'Connecting', disconnect:'Disconnecting', refresh:'Refreshing config pool', ensure:'Repairing connection', 'connect-profile':'Switching relay', 'benchmark-active':'Measuring real tunnel speed', 'benchmark-all-fast':'Testing all relays from direct Internet', 'benchmark-direct-internet':'Measuring direct ISP speed', 'update-check':'Checking GitHub release', 'update-download':'Downloading verified update', 'factory-refresh':'Refreshing config pool', 'auto-install':'Installing recovery', 'auto-remove':'Removing recovery', 'console-enable':'Enabling console gateway', 'console-disable':'Disabling console gateway', 'console-status':'Checking console gateway' };
    setText('busyTitle', names[action] || 'Working…');
    setText('busyDetail', detail || (action === 'connect-profile'
      ? 'The selected relay is being switched and validated. This can take several seconds.'
      : action === 'benchmark-active'
        ? 'Measuring ping, download and upload through the active relay.'
        : 'Validating the network path.'));
  }
}

function syncConnectionInventoryToStatus(s) {
  if (!state.profiles.length) return;
  const connected = !!s?.connected;
  const activeSha = String(s?.activeSha || '').toLowerCase();
  const relay = String(s?.relay || '');
  const relayMatch = relay.match(/^(.+):(\d+)$/);
  const relayIP = relayMatch?.[1] || '';
  const relayPort = Number(relayMatch?.[2] || 0);
  let matched = false;
  state.profiles = state.profiles.map(profile => {
    const bySha = !!activeSha && String(profile.sha256 || '').toLowerCase() === activeSha;
    const byEndpoint = !activeSha && !!relayIP && profile.ip === relayIP && Number(profile.port || 0) === relayPort;
    const active = connected && (bySha || byEndpoint);
    if (active) matched = true;
    return profile.active === active ? profile : { ...profile, active };
  });
  if (state.page === 'connections') {
    if (connected && !matched) {
      loadConnections();
      return;
    }
    renderConnections();
  }
}

function renderStatus(s) {
  state.status = s || {};
  const connected = !!s.connected;
  syncConnectionInventoryToStatus(s);
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
  const recoveryOk = !!s.autoRecovery && !['inactive','failed','missing','disabled'].includes(recoveryState);
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
    return s;
  } catch (e) {
    if (!silent) showToast(e.message, true);
    return null;
  }
}

async function reconcileStartupTunnel(initialStatus) {
  const s = initialStatus || {};
  if (s.connected || s.desiredState !== 'on' || !s.autoRecovery) return s;
  setBusy(true, 'ensure', 'Restoring the protected tunnel requested before the app was reopened…');
  try {
    const result = await window.gateway.action('ensure');
    const finalStatus = result?.status || await window.gateway.status();
    renderStatus(finalStatus);
    if (finalStatus?.connected) showToast('Previous protected tunnel restored.');
    return finalStatus;
  } catch (e) {
    showToast(e.message || 'Could not restore the previous protected tunnel.', true);
    return await refreshStatus(true);
  } finally {
    setBusy(false);
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

function renderDirectInternet() {
  const b = state.directBenchmark;
  setText('directPing', b?.pingMs == null ? (b?.httpsLatencyMs == null ? '—' : (b.httpsLatencyMs + ' ms HTTPS')) : (b.pingMs + ' ms'));
  setText('directDownload', b?.downloadMbps == null ? '—' : (b.downloadMbps + ' Mbps'));
  setText('directUpload', b?.uploadMbps == null ? '—' : (b.uploadMbps + ' Mbps'));
  setText('directIP', b?.publicIP || '—');
  setText('directCountry', b?.country || '—');
  const pathText = b
    ? ((b.interface || 'Physical adapter') + ' · ' + (b.localIP || 'local IP unavailable') + (b.gateway ? (' · gateway ' + b.gateway) : '') + ' · proxy bypass ON')
    : 'Not tested yet · VPN/proxy bypass is enforced by binding the physical adapter.';
  setText('directPath', pathText);
  const proof = $('directVerification');
  if (proof) {
    proof.classList.toggle('verified', !!b?.bypassObserved);
    proof.textContent = !b
      ? 'No direct-path measurement recorded yet.'
      : (b.bypassObserved
          ? ('Bypass verified: normal routed egress ' + (b.normalEgressCountry || '—') + ' / ' + (b.normalEgressIP || '—') + ' differs from direct ISP ' + (b.country || '—') + ' / ' + (b.publicIP || '—') + '.')
          : ('Physical adapter binding verified. Current normal route has ' + (b.normalEgressIP === b.publicIP ? 'the same' : 'an unavailable comparison') + ' public egress; proxy bypass remains enforced.'));
  }
}

async function benchmarkDirectInternet() {
  if (state.busy) return;
  setBusy(true, 'benchmark-direct-internet');
  try {
    const result = await window.gateway.action('benchmark-direct-internet');
    state.directBenchmark = result?.benchmark || null;
    renderDirectInternet();
    const b = state.directBenchmark;
    showToast(b ? ('Direct ISP: ' + b.downloadMbps + ' Mbps down · ' + b.uploadMbps + ' Mbps up · ' + (b.pingMs ?? b.httpsLatencyMs ?? '—') + ' ms') : 'Direct Internet test completed.');
  } catch (e) {
    showToast(e.message || 'Direct Internet speed test failed.', true);
  } finally {
    setBusy(false);
  }
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
    const wasFastTested = !!p.benchmark?.fastAt;
    livePing.textContent = fastPing != null
      ? (fastPing + ' ms ' + String(p.benchmark?.fastMethod || 'live').toUpperCase())
      : (p.benchmark?.icmpPingMs != null
          ? (p.benchmark.icmpPingMs + ' ms ICMP')
          : (p.benchmark?.httpsLatencyMs != null
              ? (p.benchmark.httpsLatencyMs + ' ms HTTPS')
              : (wasFastTested ? 'No reply' : 'Not tested')));
    livePing.classList.toggle('metric-unavailable', fastPing == null && p.benchmark?.icmpPingMs == null && p.benchmark?.httpsLatencyMs == null);
    livePing.title = wasFastTested && fastPing == null
      ? 'Direct probe completed, but this relay did not answer the ICMP/TCP reachability probe. Source ping is shown separately.'
      : (!wasFastTested ? 'Run Test all relays for a direct reachability probe, or Speed for a real tunnel measurement.' : '');

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
    state.directBenchmark = result?.directBenchmark || state.directBenchmark;
    renderDirectInternet();
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
  if (state.busy) {
    showToast('Another gateway operation is still finishing. Please wait for it to complete.', true);
    return;
  }
  const selected = state.profiles.find(p => p.sha256 === sha256);
  const target = selected ? ((selected.country || '—') + ' · ' + (selected.host || selected.ip || 'relay')) : 'selected relay';
  setBusy(true, 'connect-profile', testAfter
    ? ('Connecting ' + target + ' first; speed is measured only after that exact tunnel is validated.')
    : ('Connecting ' + target + ' and verifying that the exact relay became active.'));
  try {
    if (!selected?.active) {
      const connected = await window.gateway.action('connect-profile', { sha256 });
      if (connected?.status) renderStatus(connected.status);
      if (connected?.recovered) {
        showToast(connected.message || 'Selected relay failed validation. Previous working relay was restored.');
        await loadConnections();
        return;
      }
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
    showToast(userErrorMessage(e, 'Relay operation failed.'), true);
  } finally {
    setBusy(false);
  }
}

async function benchmarkCurrent() {
  if (state.busy) return;
  setBusy(true, 'benchmark-all-fast');
  try {
    const result = await window.gateway.action('benchmark-all-fast');
    const measured = new Map((result?.results || []).map(item => [item.sha256, item]));
    state.profiles = state.profiles.map(profile => {
      const quick = measured.get(profile.sha256);
      return quick ? { ...profile, benchmark: { ...(profile.benchmark || {}), ...quick } } : profile;
    });
    renderConnections();
    const seconds = Math.max(0.1, Number(result?.elapsedMs || 0) / 1000).toFixed(1);
    const via = result?.directPath?.interface ? (' via ' + result.directPath.interface) : '';
    showToast('Tested ' + String(result?.tested || 0) + ' relays in ' + seconds + 's • ' + String(result?.reachable || 0) + ' replied • ' + String(result?.noReply || 0) + ' no reply' + via + ' • direct Internet / proxy bypass.');
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

function formatDate(value) {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

function renderUpdateInfo(info) {
  state.updateInfo = info || null;
  const nav = document.querySelector('[data-page="updates"]');
  const pill = $('updateState');
  const button = $('installUpdate');
  const available = !!info?.updateAvailable;
  nav?.classList.toggle('has-update', available);
  setText('updateCurrent', info?.currentVersion || state.platform?.version || '—');
  setText('updateLatest', info?.latestVersion || '—');
  setText('updatePublished', formatDate(info?.publishedAt));
  setText('updateAsset', info?.asset?.name || 'No compatible asset');
  setText('updateChecksum', info?.asset?.sha256 || '—');
  if (pill) {
    pill.className = 'update-pill ' + (available ? 'ready' : (info?.upToDate ? 'current' : ''));
    pill.textContent = available ? 'Update available' : (info?.currentAhead ? 'Development build' : (info?.upToDate ? 'Up to date' : 'Checked'));
  }
  if (button) {
    button.disabled = !available || !info?.asset;
    button.textContent = available ? ('Download v' + info.latestVersion) : 'No update needed';
  }
}

async function loadUpdates(force = false) {
  const pill = $('updateState');
  if (pill) { pill.className = 'update-pill'; pill.textContent = 'Checking…'; }
  try {
    const info = await window.gateway.updateInfo(force);
    renderUpdateInfo(info);
    return info;
  } catch (e) {
    if (pill) { pill.className = 'update-pill error'; pill.textContent = 'Check failed'; }
    showToast(e.message || 'Unable to check GitHub releases.', true);
    return null;
  }
}

async function installUpdate() {
  if (state.busy) return;
  setBusy(true, 'update-download');
  try {
    const result = await window.gateway.installUpdate();
    if (result?.alreadyCurrent) {
      renderUpdateInfo(result.info);
      showToast('This installation already matches the latest GitHub release.');
      return;
    }
    if (result?.applying) {
      showToast('Verified update is installing. Open Internet Gateway will restart automatically.');
    } else if (result?.path) {
      showToast('Verified update downloaded, but automatic apply did not start.', true);
    }
    if (result?.info) renderUpdateInfo(result.info);
  } catch (e) {
    showToast(e.message || 'Update download failed.', true);
  } finally {
    setBusy(false);
  }
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
    updates:['Updates','Check, verify and install releases directly from GitHub without administrator prompts.'],
    settings:['Settings','Appearance, recovery and runtime information.']
  }[name];
  setText('pageTitle', meta[0]); setText('pageSubtitle', meta[1]);
  if (name === 'connections') loadConnections();
  if (name === 'diagnostics') loadDiagnostics();
  if (name === 'activity') loadActivity();
  if (name === 'updates') loadUpdates(false);
}

async function init() {
  document.querySelectorAll('.nav-item').forEach(b => b.addEventListener('click', () => setPage(b.dataset.page)));
  $('powerButton').addEventListener('click', () => runAction(state.status?.connected ? 'disconnect' : 'connect', state.status?.connected ? 'Disconnected.' : 'Connected and validated.'));
  $('reloadConnections').addEventListener('click', loadConnections);
  $('benchmarkCurrent').addEventListener('click', benchmarkCurrent);
  $('benchmarkDirect').addEventListener('click', benchmarkDirectInternet);
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
  $('checkUpdates').addEventListener('click', () => loadUpdates(true));
  $('installUpdate').addEventListener('click', installUpdate);
  $('openRelease').addEventListener('click', () => window.gateway.openRelease());

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
    if (payload.type === 'busy') {
      if (payload.busy || !state.busyAction || state.busyAction === payload.action) setBusy(payload.busy, payload.action);
    }
    if (payload.type === 'progress') setBusy(true, payload.action, payload.message || 'Working…');
    if (payload.type === 'status' && payload.status) {
      renderStatus(payload.status);
      if (payload.busy === false && state.busyAction === payload.action) setBusy(false);
    }
    if (payload.type === 'error') {
      if (payload.busy === false && state.busyAction === payload.action) setBusy(false);
      showToast(userErrorMessage(payload.message, 'Action failed.'), true);
    }
  });

  const savedTheme = localStorage.getItem('oig-theme') || 'dark';
  const themeBtn = document.querySelector('[data-theme-value="' + savedTheme + '"]');
  themeBtn?.click();

  state.platform = await window.gateway.platform();
  setText('platformBadge', (state.platform.platform === 'win32' ? 'Windows' : 'Linux') + ' · ' + state.platform.arch);
  setText('appVersion', 'v' + (state.platform.version || '—') + ' · Stable Headless');
  setText('updateCurrent', state.platform.version || '—');
  $('systemInfo').innerHTML = [
    ['Version', state.platform.version],
    ['Platform', state.platform.platform],
    ['Architecture', state.platform.arch],
    ['Hostname', state.platform.hostname],
    ['Backend', state.platform.backendRoot]
  ].map(([k,v]) => '<div class="sys-row"><small>'+escapeHtml(k)+'</small><b>'+escapeHtml(String(v || '—'))+'</b></div>').join('');

  const startupStatus = await refreshStatus(false);
  await reconcileStartupTunnel(startupStatus);
  window.gateway.updateInfo(false).then(renderUpdateInfo).catch(() => {});
  setInterval(() => { if (!state.busy && document.visibilityState === 'visible') refreshStatus(true); }, 10000);
}

init();
