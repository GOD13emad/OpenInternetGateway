const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const net = require('net');
const https = require('https');
const crypto = require('crypto');

function run(file, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, {
      cwd: options.cwd,
      windowsHide: true,
      shell: false,
      env: { ...process.env, ...(options.env || {}) }
    });
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', d => stdout += d.toString());
    child.stderr?.on('data', d => stderr += d.toString());
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error('Command timed out: ' + file));
    }, options.timeout || 120000);
    child.on('error', err => { clearTimeout(timer); reject(err); });
    child.on('close', code => {
      clearTimeout(timer);
      const result = { code, stdout: stdout.trim(), stderr: stderr.trim() };
      if (code === 0 || options.allowFailure) resolve(result);
      else reject(Object.assign(new Error(stderr || stdout || ('Command failed (' + code + ')')), { result }));
    });
  });
}

function copyDir(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const item of fs.readdirSync(src, { withFileTypes: true })) {
    const from = path.join(src, item.name);
    const to = path.join(dst, item.name);
    if (item.isDirectory()) copyDir(from, to);
    else fs.copyFileSync(from, to);
  }
}

class Backend {
  constructor({ version, resourcesPath, appPath, userData, emit }) {
    this.version = version || '';
    this.resourcesPath = resourcesPath;
    this.appPath = appPath;
    this.userData = userData;
    this.emit = emit || (() => {});
    this.platform = process.platform;
    this.backendRoot = null;
  }

  async initialize() {
    if (this.platform === 'win32') {
      const installed = path.join(process.env.LOCALAPPDATA || os.homedir(), 'OpenInternetGateway');
      const packaged = path.join(this.resourcesPath, 'backend', 'windows');
      const development = path.join(this.appPath, 'backend', 'windows');
      const resource = fs.existsSync(packaged) ? packaged : development;
      if (fs.existsSync(resource)) {
        fs.mkdirSync(installed, { recursive: true });
        // Upgrade executable control code on every app release while preserving machine-specific runtime/state/evidence.
        for (const file of ['OpenInternetGateway.ps1','OpenInternetGateway-Menu.ps1','Install.ps1','README.md']) {
          const src = path.join(resource, file);
          if (fs.existsSync(src)) fs.copyFileSync(src, path.join(installed, file));
        }
        const scriptsSrc = path.join(resource, 'scripts');
        if (fs.existsSync(scriptsSrc)) copyDir(scriptsSrc, path.join(installed, 'scripts'));
        const installedIndex = path.join(installed, 'runtime', 'udp-cache', 'index.json');
        if (!fs.existsSync(installedIndex)) {
          const seedRuntime = path.join(resource, 'runtime', 'udp-cache');
          if (fs.existsSync(seedRuntime)) copyDir(seedRuntime, path.join(installed, 'runtime', 'udp-cache'));
        }
        const installedMirror = path.join(installed, 'evidence', 'vpngate-mirror-api.csv');
        const seedMirror = path.join(resource, 'evidence', 'vpngate-mirror-api.csv');
        if (!fs.existsSync(installedMirror) && fs.existsSync(seedMirror)) {
          fs.mkdirSync(path.dirname(installedMirror), { recursive: true });
          fs.copyFileSync(seedMirror, installedMirror);
        }
      }
      this.backendRoot = fs.existsSync(path.join(installed, 'OpenInternetGateway.ps1')) ? installed : resource;
    } else {
      const stable = path.join(os.homedir(), '.local', 'share', 'OpenInternetGateway');
      const packagedLinux = path.join(this.resourcesPath, 'backend', 'linux');
      const packagedCommon = path.join(this.resourcesPath, 'backend', 'common');
      const resourceLinux = fs.existsSync(packagedLinux) ? packagedLinux : path.join(this.appPath, 'backend', 'linux');
      const resourceCommon = fs.existsSync(packagedCommon) ? packagedCommon : path.join(this.appPath, 'common');
      fs.mkdirSync(stable, { recursive: true });
      if (fs.existsSync(resourceLinux)) copyDir(resourceLinux, path.join(stable, 'linux'));
      const stableIndex = path.join(stable, 'common', 'runtime', 'udp-cache', 'index.json');
      if (!fs.existsSync(stableIndex) && fs.existsSync(resourceCommon)) {
        copyDir(resourceCommon, path.join(stable, 'common'));
      } else if (fs.existsSync(resourceCommon)) {
        const shippedMirror = path.join(resourceCommon, 'evidence', 'vpngate-mirror-api.csv');
        const stableMirror = path.join(stable, 'common', 'evidence', 'vpngate-mirror-api.csv');
        if (!fs.existsSync(stableMirror) && fs.existsSync(shippedMirror)) {
          fs.mkdirSync(path.dirname(stableMirror), { recursive: true });
          fs.copyFileSync(shippedMirror, stableMirror);
        }
      }
      this.backendRoot = stable;
      for (const file of ['oig-linux.sh', 'watch-parent.sh']) {
        try { fs.chmodSync(path.join(stable, 'linux', file), 0o755); } catch {}
      }

      // Repair legacy per-user desktop overrides that shadow the packaged system
      // desktop entry. Older OIG builds created such an override without the
      // desktop Quit action, so GNOME Dock would never expose Quit+disconnect.
      const systemDesktop = '/usr/share/applications/OpenInternetGateway.desktop';
      const userDesktop = path.join(os.homedir(), '.local', 'share', 'applications', 'OpenInternetGateway.desktop');
      try {
        if (fs.existsSync(systemDesktop) && fs.existsSync(userDesktop)) {
          const current = fs.readFileSync(userDesktop, 'utf8');
          const legacyOig = /Name=Open Internet Gateway/.test(current)
            && /Exec=.*(?:open-internet-gateway|OpenInternetGateway)/i.test(current);
          const lacksQuitAction = !/\[Desktop Action Quit\]/.test(current);
          if (legacyOig && lacksQuitAction) {
            fs.copyFileSync(systemDesktop, userDesktop);
            fs.chmodSync(userDesktop, 0o644);
          }
        }
      } catch {}
    }
  }

  platformInfo() {
    return {
      platform: this.platform,
      version: this.version,
      release: os.release(),
      arch: os.arch(),
      hostname: os.hostname(),
      backendRoot: this.backendRoot
    };
  }

  async _windows(action) {
    const main = path.join(this.backendRoot, 'OpenInternetGateway.ps1');
    const map = {
      connect: 'Connect',
      disconnect: 'Disconnect',
      refresh: 'ConfigRefresh',
      ensure: 'Ensure',
      'auto-install': 'AutoRecoveryInstall',
      'auto-remove': 'AutoRecoveryRemove',
      'console-status': 'ConsoleStatus',
      'console-enable': 'ConsoleEnable',
      'console-disable': 'ConsoleDisable',
      'factory-status': 'ConfigStatus',
      'factory-refresh': 'ConfigRefresh'
    };

    if (action === 'status') {
      const statePath = path.join(this.backendRoot, 'state', 'current-openvpn-profile.json').replace(/'/g, "''");
      const script = [
        "$routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})",
        "$cf=@(curl.exe -4 --max-time 4 -s https://www.cloudflare.com/cdn-cgi/trace)",
        "$ip=[string]((($cf|Where-Object{$_ -like 'ip=*'}|Select-Object -First 1)-replace '^ip=',''));$ip=$ip.Trim()",
        "$loc=[string]((($cf|Where-Object{$_ -like 'loc=*'}|Select-Object -First 1)-replace '^loc=',''));$loc=$loc.Trim()",
        "$dns=@(Resolve-DnsName dns.google -Type A -DnsOnly -ErrorAction SilentlyContinue|Where-Object IPAddress|Select-Object -ExpandProperty IPAddress)",
        "$task=Get-ScheduledTask -TaskName 'OpenInternetGateway-AutoRecovery' -ErrorAction SilentlyContinue",
        "$svc=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue",
        "$guardPath='" + path.join(this.backendRoot, 'state', 'anti-flap.json').replace(/'/g,"''") + "'",
        "$guard=$null;if(Test-Path $guardPath){try{$guard=Get-Content -Raw $guardPath|ConvertFrom-Json}catch{}}",
        "$desiredPath='" + path.join(this.backendRoot, 'state', 'desired-state.json').replace(/'/g,"''") + "'",
        "$desired='on';if(Test-Path $desiredPath){try{$desired=[string](Get-Content -Raw $desiredPath|ConvertFrom-Json).desired}catch{}}",
        "$state='" + statePath + "'",
        "$relay='';if(Test-Path $state){try{$s=Get-Content -Raw $state|ConvertFrom-Json;$relay=([string]$s.serverIP)+':'+([string]$s.port)}catch{}}",
        "[ordered]@{connected=($routes.Count -ge 2 -and $loc -and $loc -ne 'IR' -and -not($dns -contains '10.10.34.35'));ip=$ip.Trim();country=$loc.Trim();dns=$dns;poison=($dns -contains '10.10.34.35');fullRoutes=$routes.Count;relay=$relay;autoRecovery=[bool]$task;autoRecoveryState=$(if($task){[string]$task.State}else{'Missing'});interface=($routes|Select-Object -First 1 -ExpandProperty InterfaceAlias -ErrorAction SilentlyContinue);engine=$(if($svc){'HeadlessConnector'}else{'Missing'});connectorService=$(if($svc){[string]$svc.Status}else{'Missing'});desiredState=$desired;failureStreak=$(if($guard){[int]$guard.failureStreak}else{0});rotations24h=$(if($guard){@($guard.rotations).Count}else{0})}|ConvertTo-Json -Compress"
      ].join(';');
      const r = await run('pwsh.exe', ['-NoProfile','-Command',script], { timeout: 12000 });
      return JSON.parse(r.stdout || '{}');
    }

    const mapped = map[action];
    if (!mapped) throw new Error('Unsupported action: ' + action);
    const elevated = ['console-enable','console-disable'].includes(action);
    if (elevated) {
      const escapedMain = main.replace(/'/g, "''");
      const inner = "& '" + escapedMain + "' -Action " + mapped;
      const outer = "$p=Start-Process pwsh.exe -Verb RunAs -Wait -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-Command'," + JSON.stringify(inner) + "); exit $p.ExitCode";
      const r = await run('pwsh.exe', ['-NoProfile','-Command',outer], { timeout: 180000 });
      return { ok: true, output: r.stdout };
    }

    const r = await run('pwsh.exe', ['-NoProfile','-ExecutionPolicy','Bypass','-File',main,'-Action',mapped], {
      cwd: this.backendRoot,
      timeout: 240000
    });
    return { ok: true, output: r.stdout || r.stderr };
  }

  async _linux(action, extraArgs = []) {
    const script = path.join(this.backendRoot, 'linux', 'oig-linux.sh');
    const env = {
      OIG_HOME: this.backendRoot,
      OIG_COMMON: path.join(this.backendRoot, 'common')
    };
    const r = await run('/bin/bash', [script, action, ...extraArgs], {
      cwd: this.backendRoot,
      env,
      timeout: action === 'status' ? 12000 : 240000
    });
    if (action === 'status') return JSON.parse(r.stdout || '{}');
    return { ok: true, output: r.stdout || r.stderr };
  }

  _profileIndexPath() {
    return this.platform === 'win32'
      ? path.join(this.backendRoot, 'runtime', 'udp-cache', 'index.json')
      : path.join(this.backendRoot, 'common', 'runtime', 'udp-cache', 'index.json');
  }

  _profileStatePath() {
    return this.platform === 'win32'
      ? path.join(this.backendRoot, 'state', 'current-openvpn-profile.json')
      : path.join(this.backendRoot, 'state', 'current-linux-profile.json');
  }

  _readJson(file, fallback = null) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '')); }
    catch { return fallback; }
  }

  _writeJson(file, value) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const partial = file + '.partial';
    fs.writeFileSync(partial, JSON.stringify(value, null, 2));
    fs.renameSync(partial, file);
  }

  _factoryRoot() {
    return this.platform === 'win32'
      ? path.join(this.backendRoot, 'runtime', 'config-factory')
      : path.join(this.backendRoot, 'common', 'runtime', 'config-factory');
  }

  async profiles() {
    const items = this._readJson(this._profileIndexPath(), []);
    const liveStatus = await this.status();
    const factory = this._factoryRoot();
    const successes = this._readJson(path.join(factory, 'successes.json'), {}) || {};
    const quarantine = this._readJson(path.join(factory, 'quarantine.json'), {}) || {};
    const current = this._readJson(this._profileStatePath(), {}) || {};
    const preferred = this._readJson(path.join(this.backendRoot, 'state', 'preferred-profile.json'), {}) || {};
    const benchmarks = this._readJson(path.join(this.backendRoot, 'state', 'connection-benchmarks.json'), {}) || {};
    const activeSha = String(current.sha256 || '').toLowerCase();
    const preferredSha = String(preferred.sha256 || '').toLowerCase();
    const profiles = (Array.isArray(items) ? items : []).map(item => {
      const sha = String(item.SHA256 || '').toLowerCase();
      const ping = Number.parseFloat(String(item.Ping ?? ''));
      return {
        rank: Number(item.Rank || 0),
        host: String(item.Host || ''),
        ip: String(item.IP || ''),
        port: Number(item.Port || 0),
        protocol: String(item.Protocol || '').toLowerCase(),
        country: String(item.Country || current.configuredCountry || ''),
        countryName: String(item.CountryName || ''),
        sourcePingMs: Number.isFinite(ping) ? ping : null,
        sourceScore: Number(item.Score || 0),
        sourceSpeed: Number(item.Speed || 0),
        sessions: Number(item.Sessions || 0),
        sha256: sha,
        source: String(item.Source || ''),
        active: !!liveStatus.connected && !!sha && sha === activeSha,
        preferred: !!sha && sha === preferredSha,
        validated: !!successes[sha],
        quarantined: !!quarantine[sha],
        benchmark: benchmarks[sha] || null
      };
    }).sort((a,b) => a.rank - b.rank);
    const countries = [...new Set(profiles.map(p => p.country).filter(Boolean))];
    return { profiles, countries, activeSha, preferredSha };
  }

  async connectProfile(sha256) {
    const wanted = String(sha256 || '').toLowerCase();
    if (!wanted) throw new Error('Profile SHA-256 is required.');
    const list = await this.profiles();
    const profile = list.profiles.find(p => p.sha256 === wanted);
    if (!profile) throw new Error('Selected profile is no longer in the active config pool.');
    if (profile.quarantined) throw new Error('Selected profile is quarantined after repeated failures.');
    this._writeJson(path.join(this.backendRoot, 'state', 'preferred-profile.json'), {
      sha256: wanted, country: profile.country, host: profile.host, at: new Date().toISOString()
    });
    if (profile.active) return { ok: true, profile, status: await this.status() };
    if (this.platform === 'win32') {
      this._writeJson(path.join(this.backendRoot, 'state', 'exact-profile.request'), {
        sha256: wanted, at: new Date().toISOString()
      });
      try {
        await this._windows('disconnect');
        await this._windows('connect');
      } catch (error) {
        try { fs.unlinkSync(path.join(this.backendRoot, 'state', 'exact-profile.request')); } catch {}
        throw error;
      }
    } else {
      await this._linux('connect-profile', [wanted]);
    }
    const status = await this.status();
    if (!status.connected) throw new Error('Selected profile did not produce a validated tunnel.');
    if (profile.country && status.country && profile.country !== status.country) {
      throw new Error('Selected relay exit country did not match its advertised country.');
    }
    return { ok: true, profile, status };
  }

  async _icmpPing(ip, fast = false) {
    if (!ip) return null;
    try {
      if (this.platform === 'win32') {
        const r = await run('ping.exe', fast ? ['-n','1','-w','900',ip] : ['-n','2','-w','1500',ip], {
          timeout: fast ? 2200 : 5000, allowFailure: true
        });
        const one = r.stdout.match(/time[=<]\s*(\d+)ms/i);
        if (one) return Number(one[1]);
        const avg = r.stdout.match(/Average\s*=\s*(\d+)ms/i);
        return avg ? Number(avg[1]) : null;
      }
      const r = await run('ping', fast ? ['-n','-c','1','-W','1',ip] : ['-n','-c','2','-W','2',ip], {
        timeout: fast ? 2500 : 6000, allowFailure: true
      });
      const one = r.stdout.match(/time[=<]([\d.]+)\s*ms/i);
      if (one) return Math.round(Number(one[1]) * 10) / 10;
      const avg = r.stdout.match(/=\s*[\d.]+\/([\d.]+)\/[\d.]+\/[\d.]+\s*ms/);
      return avg ? Number(avg[1]) : null;
    } catch {
      return null;
    }
  }

  _tcpConnectMs(ip, port, timeoutMs = 1100) {
    if (!ip || !port) return Promise.resolve(null);
    return new Promise(resolve => {
      const started = Date.now();
      const socket = net.createConnection({ host: ip, port: Number(port) });
      let done = false;
      const finish = value => {
        if (done) return;
        done = true;
        try { socket.destroy(); } catch {}
        resolve(value);
      };
      socket.setTimeout(timeoutMs, () => finish(null));
      socket.once('connect', () => finish(Date.now() - started));
      socket.once('error', () => finish(null));
    });
  }

  async _quickProbeProfile(profile) {
    const started = Date.now();
    const pingPromise = this._icmpPing(profile.ip, true);
    const tcpPromise = profile.protocol === 'tcp'
      ? this._tcpConnectMs(profile.ip, profile.port)
      : Promise.resolve(null);
    const [icmpPingMs, tcpConnectMs] = await Promise.all([pingPromise, tcpPromise]);
    const candidates = [icmpPingMs, tcpConnectMs].filter(v => Number.isFinite(v));
    const fastPingMs = candidates.length ? Math.min(...candidates) : null;
    return {
      fastAt: new Date().toISOString(),
      fastPingMs,
      tcpConnectMs,
      fastReachable: fastPingMs != null,
      fastMethod: tcpConnectMs != null && (icmpPingMs == null || tcpConnectMs <= icmpPingMs) ? 'tcp' : (icmpPingMs != null ? 'icmp' : 'none'),
      fastElapsedMs: Date.now() - started
    };
  }

  async benchmarkAllFast() {
    const started = Date.now();
    const inventory = await this.profiles();
    const targets = inventory.profiles.filter(p => !p.quarantined && p.ip);
    const file = path.join(this.backendRoot, 'state', 'connection-benchmarks.json');
    const all = this._readJson(file, {}) || {};
    const results = new Array(targets.length);
    let cursor = 0;
    const worker = async () => {
      while (true) {
        const index = cursor++;
        if (index >= targets.length) return;
        const profile = targets[index];
        const quick = await this._quickProbeProfile(profile);
        all[profile.sha256] = { ...(all[profile.sha256] || {}), ...quick };
        results[index] = { sha256: profile.sha256, ...quick };
      }
    };
    const concurrency = Math.min(12, Math.max(1, targets.length));
    await Promise.all(Array.from({ length: concurrency }, () => worker()));
    this._writeJson(file, all);
    return {
      ok: true,
      tested: results.length,
      reachable: results.filter(x => x?.fastReachable).length,
      elapsedMs: Date.now() - started,
      results
    };
  }

  async _httpsLatencyMs(sink) {
    const samples = [];
    for (let i = 0; i < 2; i++) {
      const r = await run('curl', [
        '-4','-L','--max-time','5','-sS','-o',sink,'-w','%{http_code}|%{time_starttransfer}',
        'https://www.cloudflare.com/cdn-cgi/trace'
      ], { timeout: 7000, allowFailure: true });
      const [code, seconds] = String(r.stdout || '').trim().split('|');
      const value = Number(seconds);
      if (code === '200' && Number.isFinite(value) && value > 0) samples.push(value * 1000);
    }
    if (!samples.length) return null;
    samples.sort((a,b) => a-b);
    return Math.round(samples[Math.floor(samples.length / 2)] * 10) / 10;
  }

  async benchmarkActive() {
    const status = await this.status();
    if (!status.connected) throw new Error('Connect a relay before running a real throughput test.');
    const inventory = await this.profiles();
    const active = inventory.profiles.find(p => p.active);
    if (!active) throw new Error('The active relay could not be mapped to the config inventory.');

    const sink = this.platform === 'win32' ? 'NUL' : '/dev/null';
    const [latencyMs, icmpPingMs] = await Promise.all([
      this._httpsLatencyMs(sink),
      this._icmpPing(active.ip)
    ]);

    const downBytes = 2_000_000;
    const down = await run('curl', [
      '-4','-L','--max-time','12','-sS','-o',sink,'-w','%{http_code}|%{time_total}|%{speed_download}',
      'https://speed.cloudflare.com/__down?bytes=' + String(downBytes)
    ], { timeout: 15000, allowFailure: true });
    const [downCode, downTime, downSpeed] = String(down.stdout || '').trim().split('|');
    if (downCode !== '200' || !(Number(downSpeed) > 0)) throw new Error('Real download test did not complete successfully.');

    const upBytes = 512_000;
    const tempUpload = path.join(this.backendRoot, 'state', 'benchmark-upload.bin');
    fs.mkdirSync(path.dirname(tempUpload), { recursive: true });
    fs.writeFileSync(tempUpload, Buffer.alloc(upBytes));
    let up;
    try {
      up = await run('curl', [
        '-4','-L','--max-time','12','-sS','-o',sink,'-w','%{http_code}|%{time_total}|%{speed_upload}',
        '-X','POST','--data-binary','@' + tempUpload,'https://speed.cloudflare.com/__up'
      ], { timeout: 15000, allowFailure: true });
    } finally {
      try { fs.unlinkSync(tempUpload); } catch {}
    }
    const [upCode, upTime, upSpeed] = String(up.stdout || '').trim().split('|');
    if (upCode !== '200' || !(Number(upSpeed) > 0)) throw new Error('Real upload test did not complete successfully.');

    const previous = active.benchmark || {};
    const result = {
      ...previous,
      at: new Date().toISOString(),
      sha256: active.sha256,
      host: active.host,
      serverIP: active.ip,
      country: status.country || active.country,
      publicIP: status.ip || '',
      icmpPingMs,
      httpsLatencyMs: latencyMs,
      downloadMbps: Math.round(Number(downSpeed) * 8 / 1_000_000 * 100) / 100,
      uploadMbps: Math.round(Number(upSpeed) * 8 / 1_000_000 * 100) / 100,
      downloadBytes: downBytes,
      uploadBytes: upBytes,
      downloadSeconds: Number(downTime) || null,
      uploadSeconds: Number(upTime) || null,
      endpoint: 'speed.cloudflare.com'
    };
    const file = path.join(this.backendRoot, 'state', 'connection-benchmarks.json');
    const all = this._readJson(file, {}) || {};
    all[active.sha256] = result;
    this._writeJson(file, all);
    return { ok: true, benchmark: result, status };
  }

  _githubHeaders() {
    return {
      'User-Agent': 'OpenInternetGateway/' + (this.version || 'unknown'),
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28'
    };
  }

  _httpsText(url, redirects = 5) {
    return new Promise((resolve, reject) => {
      const req = https.get(url, { headers: this._githubHeaders() }, res => {
        const code = Number(res.statusCode || 0);
        if ([301,302,303,307,308].includes(code) && res.headers.location && redirects > 0) {
          res.resume();
          const next = new URL(res.headers.location, url).toString();
          this._httpsText(next, redirects - 1).then(resolve, reject);
          return;
        }
        if (code < 200 || code >= 300) {
          let body = '';
          res.on('data', d => body += d.toString());
          res.on('end', () => reject(new Error('GitHub request failed (' + code + '): ' + body.slice(0,180))));
          return;
        }
        let body = '';
        res.setEncoding('utf8');
        res.on('data', d => body += d);
        res.on('end', () => resolve(body));
      });
      req.setTimeout(12000, () => req.destroy(new Error('GitHub request timed out.')));
      req.on('error', reject);
    });
  }

  async _githubJson(url) {
    return JSON.parse(await this._httpsText(url));
  }

  _versionParts(value) {
    const core = String(value || '').trim().replace(/^v/i, '').split('-')[0];
    const parts = core.split('.').slice(0,3).map(x => Number.parseInt(x,10));
    while (parts.length < 3) parts.push(0);
    return parts.map(x => Number.isFinite(x) ? x : 0);
  }

  _compareVersions(a, b) {
    const av = this._versionParts(a);
    const bv = this._versionParts(b);
    for (let i = 0; i < 3; i++) {
      if (av[i] !== bv[i]) return av[i] > bv[i] ? 1 : -1;
    }
    return 0;
  }

  _selectUpdateAsset(assets, version) {
    const list = Array.isArray(assets) ? assets : [];
    if (this.platform === 'win32') {
      return list.find(a => a.name === 'OpenInternetGateway-Setup-' + version + '.exe')
        || list.find(a => /^OpenInternetGateway-Setup-.*\.exe$/i.test(a.name || ''));
    }
    if (this.platform === 'linux') {
      return list.find(a => a.name === 'OpenInternetGateway-' + version + '-amd64.deb')
        || list.find(a => /^OpenInternetGateway-.*-amd64\.deb$/i.test(a.name || ''))
        || list.find(a => /\.AppImage$/i.test(a.name || ''));
    }
    return null;
  }

  async updateInfo(force = false) {
    const stateFile = path.join(this.backendRoot, 'state', 'github-update.json');
    if (!force) {
      const cached = this._readJson(stateFile, null);
      const checked = cached?.checkedAt ? Date.parse(cached.checkedAt) : 0;
      if (checked && Date.now() - checked < 5 * 60 * 1000) return cached;
    }

    const release = await this._githubJson('https://api.github.com/repos/GOD13emad/OpenInternetGateway/releases/latest');
    const latestVersion = String(release.tag_name || '').replace(/^v/i, '');
    if (!latestVersion) throw new Error('GitHub latest release did not contain a version tag.');
    const asset = this._selectUpdateAsset(release.assets, latestVersion);
    const sums = (release.assets || []).find(a => a.name === 'SHA256SUMS.txt');
    const comparison = this._compareVersions(this.version, latestVersion);
    const digest = String(asset?.digest || '');
    const info = {
      checkedAt: new Date().toISOString(),
      currentVersion: this.version,
      latestVersion,
      updateAvailable: comparison < 0,
      currentAhead: comparison > 0,
      upToDate: comparison === 0,
      releaseUrl: String(release.html_url || 'https://github.com/GOD13emad/OpenInternetGateway/releases/latest'),
      publishedAt: release.published_at || null,
      releaseName: release.name || release.tag_name || '',
      asset: asset ? {
        name: asset.name,
        url: asset.browser_download_url,
        size: Number(asset.size || 0),
        digest,
        sha256: digest.startsWith('sha256:') ? digest.slice(7).toLowerCase() : ''
      } : null,
      checksumsUrl: sums?.browser_download_url || null
    };
    this._writeJson(stateFile, info);
    return info;
  }

  _downloadWithSha256(url, destination, redirects = 5) {
    return new Promise((resolve, reject) => {
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      const partial = destination + '.partial';
      try { fs.unlinkSync(partial); } catch {}
      const request = currentUrl => {
        const req = https.get(currentUrl, { headers: this._githubHeaders() }, res => {
          const code = Number(res.statusCode || 0);
          if ([301,302,303,307,308].includes(code) && res.headers.location && redirects > 0) {
            res.resume();
            redirects -= 1;
            request(new URL(res.headers.location, currentUrl).toString());
            return;
          }
          if (code < 200 || code >= 300) {
            res.resume();
            reject(new Error('Update download failed with HTTP ' + code + '.'));
            return;
          }
          const hash = crypto.createHash('sha256');
          const out = fs.createWriteStream(partial, { flags: 'w' });
          let bytes = 0;
          res.on('data', chunk => { hash.update(chunk); bytes += chunk.length; });
          res.pipe(out);
          out.on('error', err => {
            try { res.destroy(); } catch {}
            try { fs.unlinkSync(partial); } catch {}
            reject(err);
          });
          out.on('finish', () => {
            out.close(() => {
              try {
                fs.renameSync(partial, destination);
                resolve({ sha256: hash.digest('hex').toLowerCase(), bytes });
              } catch (error) {
                try { fs.unlinkSync(partial); } catch {}
                reject(error);
              }
            });
          });
        });
        req.setTimeout(30000, () => req.destroy(new Error('Update download stalled.')));
        req.on('error', error => {
          try { fs.unlinkSync(partial); } catch {}
          reject(error);
        });
      };
      request(url);
    });
  }

  async downloadUpdate() {
    const info = await this.updateInfo(true);
    if (!info.asset?.url || !info.asset?.name) throw new Error('No compatible update asset was published for this platform.');
    if (!info.updateAvailable) {
      return { ok: true, alreadyCurrent: true, info, path: null };
    }
    if (!info.asset.sha256) throw new Error('GitHub release asset has no SHA-256 digest; refusing an unverifiable update.');

    if (info.checksumsUrl) {
      const sums = await this._httpsText(info.checksumsUrl);
      const line = sums.split(/\r?\n/).find(x => x.trim().endsWith('  ' + info.asset.name));
      if (!line) throw new Error('Published SHA256SUMS does not include the selected update asset.');
      const checksum = line.trim().split(/\s+/)[0].toLowerCase();
      if (checksum !== info.asset.sha256) throw new Error('GitHub digest and SHA256SUMS disagree; update refused.');
    }

    const destination = path.join(this.backendRoot, 'updates', 'v' + info.latestVersion, info.asset.name);
    if (fs.existsSync(destination)) {
      const existing = crypto.createHash('sha256').update(fs.readFileSync(destination)).digest('hex').toLowerCase();
      if (existing === info.asset.sha256) return { ok: true, cached: true, info, path: destination, sha256: existing };
      try { fs.unlinkSync(destination); } catch {}
    }

    const downloaded = await this._downloadWithSha256(info.asset.url, destination);
    if (downloaded.sha256 !== info.asset.sha256) {
      try { fs.unlinkSync(destination); } catch {}
      throw new Error('Downloaded update SHA-256 does not match the published GitHub release digest.');
    }
    if (this.platform === 'linux' && /\.AppImage$/i.test(destination)) {
      try { fs.chmodSync(destination, 0o755); } catch {}
    }
    return { ok: true, cached: false, info, path: destination, sha256: downloaded.sha256, bytes: downloaded.bytes };
  }

  _factoryStatusPath() {
    return this.platform === 'win32'
      ? path.join(this.backendRoot, 'runtime', 'config-factory', 'status.json')
      : path.join(this.backendRoot, 'common', 'runtime', 'config-factory', 'status.json');
  }

  async _factoryStatus() {
    const p = this._factoryStatusPath();
    if (!fs.existsSync(p)) {
      try {
        if (this.platform === 'win32') await this._windows('factory-status');
        else await this._linux('factory-status');
      } catch {}
    }
    if (fs.existsSync(p)) {
      try { return JSON.parse(fs.readFileSync(p, 'utf8').replace(/^\uFEFF/, '')); } catch {}
    }
    return { pool:0, validated:0, standby:0, quarantined:0, generations:0, protocols:{}, healthy:false, source:'', ageHours:null, lastRefresh:null };
  }

  async status() {
    try {
      const base = await (this.platform === 'win32' ? this._windows('status') : this._linux('status'));
      const configPool = await this._factoryStatus();
      return { ...base, configPool };
    } catch (error) {
      return {
        connected: false,
        error: error.message,
        country: '',
        ip: '',
        dns: [],
        poison: null,
        fullRoutes: 0,
        relay: '',
        autoRecovery: false,
        autoRecoveryState: 'Unavailable',
        configPool: { pool:0, validated:0, standby:0, quarantined:0, generations:0, protocols:{}, healthy:false, source:'', ageHours:null }
      };
    }
  }

  async action(action, options = {}) {
    this.emit({ type: 'busy', action, busy: true });
    try {
      let result;
      if (action === 'connect-profile') result = await this.connectProfile(options.sha256);
      else if (action === 'benchmark-active') result = await this.benchmarkActive();
      else if (action === 'benchmark-all-fast') result = await this.benchmarkAllFast();
      else result = await (this.platform === 'win32' ? this._windows(action) : this._linux(action));
      const status = result?.status || await this.status();
      this.emit({ type: 'status', action, busy: false, status });
      return { ...result, status };
    } catch (error) {
      this.emit({ type: 'error', action, busy: false, message: error.message });
      throw error;
    }
  }

  async diagnostics() {
    const status = await this.status();
    const info = this.platformInfo();
    return {
      timestamp: new Date().toISOString(),
      status,
      platform: info,
      checks: [
        { name: 'Foreign egress', ok: !!status.connected, detail: status.country ? (status.country + ' / ' + status.ip) : 'Unavailable' },
        { name: 'DNS de-poisoning', ok: status.poison === false, detail: Array.isArray(status.dns) ? status.dns.join(', ') : String(status.dns || '') },
        { name: 'Full-route', ok: Number(status.fullRoutes || 0) >= 2, detail: String(status.fullRoutes || 0) + ' protected routes' },
        { name: 'Config Factory', ok: !!status.configPool?.healthy, detail: status.configPool ? (String(status.configPool.validated || 0) + ' validated / ' + String(status.configPool.pool || 0) + ' total') : 'Unavailable' },
        { name: 'Headless engine', ok: this.platform !== 'win32' || status.engine === 'HeadlessConnector', detail: this.platform === 'win32' ? ((status.engine || 'Missing') + ' · failures ' + String(status.failureStreak || 0) + ' · rotations24h ' + String(status.rotations24h || 0)) : 'NetworkManager headless backend' },
        { name: 'Auto-Recovery', ok: !!status.autoRecovery, detail: status.autoRecoveryState || 'Not installed' }
      ]
    };
  }

  async activity() {
    const factoryRoot = this.platform === 'win32'
      ? path.join(this.backendRoot, 'runtime', 'config-factory')
      : path.join(this.backendRoot, 'common', 'runtime', 'config-factory');
    const candidates = [
      path.join(this.backendRoot, 'evidence', 'auto-recovery-last.json'),
      path.join(this.backendRoot, 'evidence', 'connect-last-success.json'),
      path.join(this.backendRoot, 'state', 'current-openvpn-profile.json'),
      path.join(factoryRoot, 'status.json'),
      path.join(factoryRoot, 'successes.json'),
      path.join(factoryRoot, 'quarantine.json')
    ];
    const items = [];
    for (const file of candidates) {
      if (fs.existsSync(file)) {
        try { items.push({ file: path.basename(file), data: JSON.parse(fs.readFileSync(file, 'utf8')) }); } catch {}
      }
    }
    return items;
  }

  async logsPath() {
    const p = path.join(this.backendRoot, 'evidence');
    fs.mkdirSync(p, { recursive: true });
    return p;
  }
}

module.exports = Backend;
