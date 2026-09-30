const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const crypto = require('crypto');

function stripAnsi(value) {
  return String(value || '').replace(/\x1B\[[0-?]*[ -\/]*[@-~]/g, '');
}

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
      const result = { code, stdout: stripAnsi(stdout).trim(), stderr: stripAnsi(stderr).trim() };
      if (code === 0 || options.allowFailure) resolve(result);
      else reject(Object.assign(new Error(result.stderr || result.stdout || ('Command failed (' + code + ')')), { result }));
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
    this.sandboxHardening = null;
  }

  async _hardenLinuxChromiumSandbox() {
    const base = {
      supported: false,
      hardened: false,
      changed: false,
      restartRequired: false,
      currentProcessNoSandbox: false,
      runtimeRoot: '',
      helper: '',
      reason: 'Native packaged Linux runtime is unavailable.'
    };
    if (process.platform !== 'linux' || !this.backendRoot) return base;
    const runtimeRoot = path.dirname(process.execPath || '');
    const appRun = path.join(runtimeRoot, 'AppRun');
    const helperScript = path.join(this.backendRoot, 'linux', 'harden_sandbox.py');
    if (!runtimeRoot || !fs.existsSync(appRun) || !fs.existsSync(helperScript)) {
      return { ...base, runtimeRoot };
    }
    try {
      const r = await run('python3', [helperScript, runtimeRoot], { timeout: 10000 });
      const parsed = JSON.parse(String(r.stdout || '{}').trim() || '{}');
      let currentProcessNoSandbox = false;
      try {
        const argv = fs.readFileSync('/proc/' + String(process.pid) + '/cmdline', 'utf8').split('\0').filter(Boolean);
        currentProcessNoSandbox = argv.includes('--no-sandbox');
      } catch {}
      const result = {
        ...base,
        ...parsed,
        runtimeRoot,
        currentProcessNoSandbox,
        restartRequired: !!parsed.hardened
          && currentProcessNoSandbox
          && process.env.OIG_SANDBOX_RESTARTED !== '1',
        version: this.version,
        at: new Date().toISOString()
      };
      try { this._writeJson(path.join(this.backendRoot, 'evidence', 'linux-sandbox-hardening.json'), result); } catch {}
      return result;
    } catch (error) {
      const result = {
        ...base,
        runtimeRoot,
        reason: 'Sandbox hardening helper failed safely: ' + String(error?.message || error),
        version: this.version,
        at: new Date().toISOString()
      };
      try { this._writeJson(path.join(this.backendRoot, 'evidence', 'linux-sandbox-hardening.json'), result); } catch {}
      return result;
    }
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
      // v2.5.3 and older could leave this Windows-era coordination file behind
      // on Linux even though oig-linux.sh receives the SHA as an argument.
      try { fs.unlinkSync(path.join(stable, 'state', 'exact-profile.request')); } catch {}

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
      this.sandboxHardening = await this._hardenLinuxChromiumSandbox();
    }
    return { sandboxHardening: this.sandboxHardening };
  }

  platformInfo() {
    return {
      platform: this.platform,
      version: this.version,
      release: os.release(),
      arch: os.arch(),
      hostname: os.hostname(),
      backendRoot: this.backendRoot,
      sandboxHardening: this.sandboxHardening
    };
  }

  async _windows(action, extraArgs = []) {
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
        "$relay='';$profileIP='';$profileCountry='';if(Test-Path $state){try{$s=Get-Content -Raw $state|ConvertFrom-Json;$relay=([string]$s.serverIP)+':'+([string]$s.port);$profileIP=[string]$s.observedIP;if(-not $profileIP){$profileIP=[string]$s.serverIP};$profileCountry=[string]$s.country;if(-not $profileCountry){$profileCountry=[string]$s.configuredCountry}}catch{}}",
        "$managedActive=($svc -and $svc.Status -eq 'Running')",
        "$probeDegraded=$false;if(-not $loc -and $managedActive -and $routes.Count -ge 2 -and -not($dns -contains '10.10.34.35') -and $profileCountry){$loc=$profileCountry;if(-not $ip){$ip=$profileIP};$probeDegraded=$true}",
        "[ordered]@{connected=($routes.Count -ge 2 -and $managedActive -and $loc -and $loc -ne 'IR' -and -not($dns -contains '10.10.34.35'));ip=$ip.Trim();country=$loc.Trim();dns=$dns;poison=($dns -contains '10.10.34.35');fullRoutes=$routes.Count;relay=$relay;autoRecovery=[bool]$task;autoRecoveryState=$(if(-not $task){'Missing'}elseif(-not [bool]$task.Settings.Enabled){'Disabled'}else{[string]$task.State});interface=($routes|Select-Object -First 1 -ExpandProperty InterfaceAlias -ErrorAction SilentlyContinue);engine=$(if($svc){'HeadlessConnector'}else{'Missing'});connectorService=$(if($svc){[string]$svc.Status}else{'Missing'});managedTunnelActive=[bool]$managedActive;healthProbeDegraded=[bool]$probeDegraded;desiredState=$desired;failureStreak=$(if($guard){[int]$guard.failureStreak}else{0});rotations24h=$(if($guard){@($guard.rotations).Count}else{0})}|ConvertTo-Json -Compress"
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

    const r = await run('pwsh.exe', ['-NoProfile','-ExecutionPolicy','Bypass','-File',main,'-Action',mapped,...extraArgs], {
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

  async profiles(liveStatusOverride = null) {
    const items = this._readJson(this._profileIndexPath(), []);
    const liveStatus = liveStatusOverride || await this.status();
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

    if (liveStatus.connected && activeSha && !profiles.some(p => p.active)) {
      profiles.unshift({
        rank: 0,
        host: String(current.host || 'Active managed relay'),
        ip: String(current.serverIP || liveStatus.ip || ''),
        port: Number(current.port || 0),
        protocol: String(current.protocol || '').toLowerCase(),
        country: String(current.configuredCountry || current.country || liveStatus.country || ''),
        countryName: '',
        sourcePingMs: null,
        sourceScore: 0,
        sourceSpeed: 0,
        sessions: 0,
        sha256: activeSha,
        source: 'Active tunnel state',
        active: true,
        preferred: activeSha === preferredSha,
        validated: true,
        quarantined: false,
        benchmark: benchmarks[activeSha] || null,
        syntheticActive: true
      });
    }
    const countries = [...new Set(profiles.map(p => p.country).filter(Boolean))];
    const directBenchmark = this._readJson(path.join(this.backendRoot, 'state', 'direct-internet-benchmark.json'), null);
    return { profiles, countries, activeSha, preferredSha, directBenchmark };
  }

  async connectProfile(sha256) {
    const wanted = String(sha256 || '').toLowerCase();
    if (!wanted) throw new Error('Profile SHA-256 is required.');
    const list = await this.profiles();
    const profile = list.profiles.find(p => p.sha256 === wanted);
    if (!profile) throw new Error('Selected profile is no longer in the active config pool.');
    if (profile.quarantined) throw new Error('Selected profile is quarantined after repeated failures.');
    const previousActive = list.profiles.find(p => p.active);
    const previousSha = String(previousActive?.sha256 || list.preferredSha || '').toLowerCase();
    const previousProfile = previousActive || list.profiles.find(p => String(p.sha256 || '').toLowerCase() === previousSha);
    const preferredPath = path.join(this.backendRoot, 'state', 'preferred-profile.json');
    const savePreferred = () => this._writeJson(preferredPath, {
      sha256: wanted, country: profile.country, host: profile.host, at: new Date().toISOString()
    });
    if (profile.active) {
      savePreferred();
      return { ok: true, profile, status: await this.status() };
    }

    const request = path.join(this.backendRoot, 'state', 'exact-profile.request');
    const requestExact = async (sha, country, host) => {
      // Both Windows and Linux receive the selected SHA explicitly. Legacy
      // request files are removed so an old/stale exact request can never
      // affect a later app session.
      try { fs.unlinkSync(request); } catch {}
      this.emit({
        type: 'progress',
        action: 'connect-profile',
        stage: 'switching',
        message: 'Switching to ' + (country || 'selected') + ' relay ' + (host || '') + '…'
      });
      if (this.platform === 'win32') await this._windows('connect', ['-ProfileSha', sha]);
      else await this._linux('connect-profile', [sha]);
    };
    const restorePrevious = async () => {
      if (!previousSha || previousSha === wanted) return false;
      this.emit({
        type: 'progress',
        action: 'connect-profile',
        stage: 'restoring',
        message: 'Selected relay failed. Restoring the previous working relay…'
      });
      try {
        await requestExact(previousSha, previousProfile?.country || '', previousProfile?.host || previousProfile?.ip || '');
        const restored = this._readJson(this._profileStatePath(), {}) || {};
        const restoredSha = String(restored.sha256 || '').toLowerCase();
        return restoredSha === previousSha;
      } catch {
        try { fs.unlinkSync(request); } catch {}
        return false;
      }
    };
    const recoveredResult = async (code, message) => ({
      ok: false,
      recovered: true,
      code,
      profile,
      message,
      status: await this.status()
    });

    try {
      await requestExact(wanted, profile.country, profile.host || profile.ip);
    } catch {
      try { fs.unlinkSync(request); } catch {}
      const restored = await restorePrevious();
      if (restored) return recoveredResult(
        'SELECTED_RELAY_FAILED_RESTORED',
        'Selected relay failed validation. Previous working relay was restored.'
      );
      throw new Error('Selected relay failed validation, and the previous working relay could not be restored automatically. Choose another validated relay or run Repair now.');
    }

    this.emit({
      type: 'progress',
      action: 'connect-profile',
      stage: 'validating',
      message: 'Validating the selected relay and exit country…'
    });
    const status = await this.status();
    const current = this._readJson(this._profileStatePath(), {}) || {};
    const actualSha = String(current.sha256 || '').toLowerCase();
    if (!status.connected || !actualSha || actualSha !== wanted) {
      const restored = await restorePrevious();
      if (restored) return recoveredResult(
        'SELECTED_RELAY_NOT_ACTIVE_RESTORED',
        'Selected relay did not become active. Previous working relay was restored.'
      );
      throw new Error('Selected relay did not become active. No fallback relay was accepted; choose another validated relay or run Repair now.');
    }
    if (profile.country && status.country && profile.country !== status.country) {
      const restored = await restorePrevious();
      if (restored) return recoveredResult(
        'SELECTED_RELAY_COUNTRY_MISMATCH_RESTORED',
        'Selected relay exit country did not match its advertised country. Previous working relay was restored.'
      );
      throw new Error('Selected relay exit country did not match its advertised country. No fallback relay was accepted; choose another validated relay.');
    }
    savePreferred();
    return { ok: true, profile, status };
  }

  async _directInternetPath() {
    if (this.platform === 'win32') {
      const script = [
        "$routes=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue|Where-Object{$_.InterfaceAlias -notmatch 'OpenVPN|TAP|Wintun|OIG|WireGuard|Cloudflare|vEthernet|Loopback'}|Sort-Object RouteMetric,InterfaceMetric)",
        "$r=$routes|Where-Object{(Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).HardwareInterface}|Select-Object -First 1",
        "if(-not $r){$r=$routes|Select-Object -First 1}",
        "if(-not $r){throw 'No physical IPv4 Internet route was found.'}",
        "$a=Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue",
        "$ip=Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue|Where-Object{$_.IPAddress -notlike '169.254*'}|Select-Object -First 1",
        "if(-not $ip){throw 'Physical Internet adapter has no IPv4 address.'}",
        "[ordered]@{interface=[string]$a.Name;index=[int]$r.InterfaceIndex;ip=[string]$ip.IPAddress;gateway=[string]$r.NextHop}|ConvertTo-Json -Compress"
      ].join(';');
      const r = await run('pwsh.exe', ['-NoProfile','-Command',script], { timeout: 5000 });
      const info = JSON.parse(r.stdout || '{}');
      return {
        interface: String(info.interface || ''),
        index: Number(info.index || 0),
        localIP: String(info.ip || ''),
        gateway: String(info.gateway || ''),
        curlInterface: 'host!' + String(info.ip || ''),
        bindMode: 'physical-ip'
      };
    }

    if (this.platform === 'linux') {
      // A connected VPN often installs the lowest-metric default route on tun0.
      // Direct-ISP tests must instead bind a real connected Ethernet/Wi-Fi NIC.
      const routeScript = [
        "iface=$(nmcli -t -f DEVICE,TYPE,STATE device status 2>/dev/null | awk -F: '$3==\"connected\" && ($2==\"ethernet\" || $2==\"wifi\"){print $1;exit}')",
        "if [ -n \"$iface\" ]; then ip -4 route show default | grep -F \" dev $iface \" | head -n1; else ip -4 route show default | grep -Ev ' dev (tun|tap|wg|tailscale|ppp|zt|vpn)[^ ]*' | head -n1; fi"
      ].join('; ');
      const route = await run('/bin/bash', ['-lc', routeScript], { timeout: 5000 });
      const line = String(route.stdout || '').trim();
      const iface = (line.match(/\bdev\s+(\S+)/) || [])[1] || '';
      const gateway = (line.match(/\bvia\s+(\S+)/) || [])[1] || '';
      if (!iface || /^(tun|tap|wg|tailscale|ppp|zt|vpn)/i.test(iface)) {
        throw new Error('No physical IPv4 Internet route was found.');
      }
      const addr = await run('/bin/bash', ['-lc', "ip -4 -o addr show dev " + JSON.stringify(iface) + " | awk '{print $4}' | cut -d/ -f1 | head -n1"], { timeout: 5000 });
      const localIP = String(addr.stdout || '').trim();
      if (!localIP) throw new Error('Physical Internet interface has no IPv4 address.');
      return {
        interface: iface,
        index: 0,
        localIP,
        gateway,
        curlInterface: 'if!' + iface,
        bindMode: 'physical-interface'
      };
    }

    throw new Error('Direct Internet test is supported only on Windows and Linux.');
  }

  _directCurlArgs(pathInfo) {
    return ['-4','--noproxy','*','--interface',pathInfo.curlInterface];
  }

  async _directTrace(pathInfo) {
    const marker = '__OIG_DIRECT_META__';
    const r = await run('curl', [
      ...this._directCurlArgs(pathInfo),'-L','--fail','--connect-timeout','5','--max-time','8',
      '-sS','-w','\\n' + marker + '%{http_code}|%{time_starttransfer}',
      'https://www.cloudflare.com/cdn-cgi/trace'
    ], { timeout: 11000, allowFailure: true });
    const raw = String(r.stdout || '');
    const pos = raw.lastIndexOf(marker);
    if (pos < 0) throw new Error('Direct physical-interface egress validation did not return metadata.');
    const body = raw.slice(0, pos);
    const meta = raw.slice(pos + marker.length).trim().split('|');
    if (meta[0] !== '200') throw new Error('Direct physical-interface egress validation failed.');
    const ip = (body.match(/^ip=(.+)$/m) || [])[1]?.trim() || '';
    const country = (body.match(/^loc=(.+)$/m) || [])[1]?.trim() || '';
    const colo = (body.match(/^colo=(.+)$/m) || [])[1]?.trim() || '';
    const seconds = Number(meta[1]);
    return {
      publicIP: ip,
      country,
      colo,
      httpsLatencyMs: Number.isFinite(seconds) ? Math.round(seconds * 1000 * 10) / 10 : null
    };
  }

  async _icmpPing(ip, fast = false, pathInfo = null) {
    if (!ip) return null;
    try {
      if (this.platform === 'win32') {
        const args = fast ? ['-n','1','-w','650'] : ['-n','2','-w','1500'];
        if (pathInfo?.localIP) args.push('-S',pathInfo.localIP);
        args.push(ip);
        const r = await run('ping.exe', args, { timeout: fast ? 1400 : 5000, allowFailure: true });
        const one = r.stdout.match(/time[=<]\s*(\d+)ms/i);
        if (one) return Number(one[1]);
        const avg = r.stdout.match(/Average\s*=\s*(\d+)ms/i);
        return avg ? Number(avg[1]) : null;
      }
      const args = ['-n'];
      if (pathInfo?.interface) args.push('-I',pathInfo.interface);
      args.push(...(fast ? ['-c','1','-W','1',ip] : ['-c','2','-W','2',ip]));
      const r = await run('ping', args, { timeout: fast ? 2500 : 6000, allowFailure: true });
      const one = r.stdout.match(/time[=<]([\d.]+)\s*ms/i);
      if (one) return Math.round(Number(one[1]) * 10) / 10;
      const avg = r.stdout.match(/=\s*[\d.]+\/([\d.]+)\/[\d.]+\/[\d.]+\s*ms/);
      return avg ? Number(avg[1]) : null;
    } catch {
      return null;
    }
  }

  async _directTcpConnectMs(ip, port, pathInfo, timeoutSeconds = 0.8) {
    if (!ip || !port || !pathInfo) return null;
    const sink = this.platform === 'win32' ? 'NUL' : '/dev/null';
    try {
      const r = await run('curl', [
        ...this._directCurlArgs(pathInfo),
        '--connect-timeout',String(timeoutSeconds),'--max-time',String(timeoutSeconds),
        '-sS','-o',sink,'-w','%{time_connect}',
        'telnet://' + ip + ':' + String(port)
      ], { timeout: Math.ceil((timeoutSeconds + 1) * 1000), allowFailure: true });
      const seconds = Number(String(r.stdout || '').trim());
      return Number.isFinite(seconds) && seconds > 0 ? Math.round(seconds * 1000 * 10) / 10 : null;
    } catch {
      return null;
    }
  }

  async _quickProbeProfile(profile, pathInfo) {
    const started = Date.now();
    const pingPromise = this._icmpPing(profile.ip, true, pathInfo);
    const tcpPromise = profile.protocol === 'tcp'
      ? this._directTcpConnectMs(profile.ip, profile.port, pathInfo)
      : Promise.resolve(null);
    const [icmpPingMs, tcpConnectMs] = await Promise.all([pingPromise, tcpPromise]);
    const candidates = [icmpPingMs, tcpConnectMs].filter(v => Number.isFinite(v));
    const fastPingMs = candidates.length ? Math.min(...candidates) : null;
    return {
      fastAt: new Date().toISOString(),
      fastPingMs,
      tcpConnectMs,
      fastReachable: fastPingMs != null,
      fastMethod: tcpConnectMs != null && (icmpPingMs == null || tcpConnectMs <= icmpPingMs) ? 'tcp-direct' : (icmpPingMs != null ? 'icmp-direct' : 'none'),
      fastElapsedMs: Date.now() - started,
      directInterface: pathInfo.interface,
      directLocalIP: pathInfo.localIP
    };
  }

  async benchmarkDirectInternet() {
    const started = Date.now();
    const pathInfo = await this._directInternetPath();
    const sink = this.platform === 'win32' ? 'NUL' : '/dev/null';
    const [trace, pingMs] = await Promise.all([
      this._directTrace(pathInfo),
      this._icmpPing('1.1.1.1', false, pathInfo)
    ]);

    const downBytes = 5_000_000;
    const down = await run('curl', [
      ...this._directCurlArgs(pathInfo),'-L','--fail','--connect-timeout','6','--max-time','20',
      '-sS','-o',sink,'-w','%{http_code}|%{time_total}|%{speed_download}',
      'https://speed.cloudflare.com/__down?bytes=' + String(downBytes)
    ], { timeout: 24000, allowFailure: true });
    const [downCode, downTime, downSpeed] = String(down.stdout || '').trim().split('|');
    if (downCode !== '200' || !(Number(downSpeed) > 0)) throw new Error('Direct ISP download test did not complete successfully.');

    const upBytes = 1_000_000;
    const tempUpload = path.join(this.backendRoot, 'state', 'direct-benchmark-upload.bin');
    fs.mkdirSync(path.dirname(tempUpload), { recursive: true });
    fs.writeFileSync(tempUpload, Buffer.alloc(upBytes));
    let up;
    try {
      up = await run('curl', [
        ...this._directCurlArgs(pathInfo),'-L','--fail','--connect-timeout','6','--max-time','20',
        '-sS','-o',sink,'-w','%{http_code}|%{time_total}|%{speed_upload}',
        '-X','POST','--data-binary','@' + tempUpload,'https://speed.cloudflare.com/__up'
      ], { timeout: 24000, allowFailure: true });
    } finally {
      try { fs.unlinkSync(tempUpload); } catch {}
    }
    const [upCode, upTime, upSpeed] = String(up.stdout || '').trim().split('|');
    if (upCode !== '200' || !(Number(upSpeed) > 0)) throw new Error('Direct ISP upload test did not complete successfully.');

    let normalEgress = { ip: '', country: '' };
    try {
      const n = await run('curl', ['-4','--noproxy','*','--max-time','6','-sS','https://www.cloudflare.com/cdn-cgi/trace'], { timeout: 8000, allowFailure: true });
      const body = String(n.stdout || '');
      normalEgress = {
        ip: (body.match(/^ip=(.+)$/m) || [])[1]?.trim() || '',
        country: (body.match(/^loc=(.+)$/m) || [])[1]?.trim() || ''
      };
    } catch {}

    const result = {
      at: new Date().toISOString(),
      mode: 'direct-physical-internet',
      interface: pathInfo.interface,
      localIP: pathInfo.localIP,
      gateway: pathInfo.gateway,
      bindMode: pathInfo.bindMode,
      proxyBypassed: true,
      publicIP: trace.publicIP,
      country: trace.country,
      colo: trace.colo,
      pingMs,
      httpsLatencyMs: trace.httpsLatencyMs,
      downloadMbps: Math.round(Number(downSpeed) * 8 / 1_000_000 * 100) / 100,
      uploadMbps: Math.round(Number(upSpeed) * 8 / 1_000_000 * 100) / 100,
      downloadBytes: downBytes,
      uploadBytes: upBytes,
      downloadSeconds: Number(downTime) || null,
      uploadSeconds: Number(upTime) || null,
      endpoint: 'speed.cloudflare.com',
      normalEgressIP: normalEgress.ip,
      normalEgressCountry: normalEgress.country,
      bypassObserved: !!trace.publicIP && !!normalEgress.ip && trace.publicIP !== normalEgress.ip,
      elapsedMs: Date.now() - started
    };
    this._writeJson(path.join(this.backendRoot, 'state', 'direct-internet-benchmark.json'), result);
    return { ok: true, benchmark: result };
  }

  async benchmarkAllFast() {
    const started = Date.now();
    const directPath = await this._directInternetPath();
    const items = this._readJson(this._profileIndexPath(), []);
    // Read-only direct-path probe: cover the entire current pool, including
    // quarantined rows, without connecting, promoting, or unquarantining them.
    const targets = (Array.isArray(items) ? items : []).map(item => ({
      sha256: String(item.SHA256 || '').toLowerCase(),
      ip: String(item.IP || ''),
      port: Number(item.Port || 0),
      protocol: String(item.Protocol || '').toLowerCase()
    })).filter(p => p.sha256 && p.ip);
    const file = path.join(this.backendRoot, 'state', 'connection-benchmarks.json');
    const all = this._readJson(file, {}) || {};
    const results = new Array(targets.length);
    let cursor = 0;
    const worker = async () => {
      while (true) {
        const index = cursor++;
        if (index >= targets.length) return;
        const profile = targets[index];
        const quick = await this._quickProbeProfile(profile, directPath);
        all[profile.sha256] = { ...(all[profile.sha256] || {}), ...quick };
        results[index] = { sha256: profile.sha256, ...quick };
      }
    };
    const concurrency = Math.min(16, Math.max(1, targets.length));
    await Promise.all(Array.from({ length: concurrency }, () => worker()));
    this._writeJson(file, all);
    return {
      ok: true,
      tested: results.length,
      reachable: results.filter(x => x?.fastReachable).length,
      noReply: results.filter(x => x && x.fastAt && !x.fastReachable).length,
      elapsedMs: Date.now() - started,
      directPath: { interface: directPath.interface, localIP: directPath.localIP, gateway: directPath.gateway, proxyBypassed: true },
      results
    };
  }

  async _httpsLatencyMs(sink) {
    const samples = [];
    for (let i = 0; i < 2; i++) {
      const r = await run('curl', [
        '-4','--noproxy','*','-L','--max-time','5','-sS','-o',sink,'-w','%{http_code}|%{time_starttransfer}',
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
    const inventory = await this.profiles(status);
    const active = inventory.profiles.find(p => p.active);
    if (!active) throw new Error('The active relay could not be mapped to the config inventory.');

    const sink = this.platform === 'win32' ? 'NUL' : '/dev/null';
    const [latencyMs, icmpPingMs] = await Promise.all([
      this._httpsLatencyMs(sink),
      this._icmpPing(active.ip)
    ]);

    const downBytes = 2_000_000;
    const down = await run('curl', [
      '-4','--noproxy','*','-L','--max-time','12','-sS','-o',sink,'-w','%{http_code}|%{time_total}|%{speed_download}',
      'https://speed.cloudflare.com/__down?bytes=' + String(downBytes)
    ], { timeout: 15000, allowFailure: true });
    const [downCode, downTime, downSpeed] = String(down.stdout || '').trim().split('|');
    if (downCode !== '200' || !(Number(downSpeed) > 0)) throw new Error('Real download test did not complete successfully.');

    const upBytes = 512_000;
    const tempUpload = path.join(this.backendRoot, 'state', 'benchmark-upload.bin');
    fs.mkdirSync(path.dirname(tempUpload), { recursive: true });
    fs.writeFileSync(tempUpload, Buffer.alloc(upBytes));
    let up;
    let uploadAttempts = 0;
    try {
      const uploadArgs = [
        '-4','--noproxy','*','-L','--connect-timeout','8','--max-time','20','-sS','-o',sink,'-w','%{http_code}|%{time_total}|%{speed_upload}',
        '-X','POST','--data-binary','@' + tempUpload,'https://speed.cloudflare.com/__up'
      ];
      for (let attempt = 0; attempt < 2; attempt++) {
        uploadAttempts++;
        up = await run('curl', uploadArgs, { timeout: 24000, allowFailure: true });
        const [code,,speed] = String(up.stdout || '').trim().split('|');
        if (code === '200' && Number(speed) > 0) break;
      }
    } finally {
      try { fs.unlinkSync(tempUpload); } catch {}
    }
    const [upCode, upTime, upSpeed] = String(up?.stdout || '').trim().split('|');
    if (upCode !== '200' || !(Number(upSpeed) > 0)) throw new Error('Real upload test did not complete successfully after a bounded retry.');

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
      uploadAttempts,
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
      // Automatic Linux updates must remain user-space and never invoke apt/dpkg/sudo.
      // Prefer the AppImage release asset; the DEB remains available for manual/system installs.
      return list.find(a => a.name === 'OpenInternetGateway-' + version + '-x86_64.AppImage')
        || list.find(a => /^OpenInternetGateway-.*-x86_64\.AppImage$/i.test(a.name || ''))
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

  async _curlText(url, maxSeconds = 20) {
    const r = await run('curl', [
      '-4','-L','--fail','--connect-timeout','8','--max-time',String(maxSeconds),
      '--retry','2','--retry-delay','1','-sS',url
    ], { timeout: (maxSeconds + 8) * 1000 });
    return String(r.stdout || '');
  }

  async _downloadWithSha256(url, destination) {
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    const partial = destination + '.partial';
    try { fs.unlinkSync(partial); } catch {}
    try {
      await run('curl', [
        '-4','-L','--fail','--connect-timeout','8','--max-time','300',
        '--retry','2','--retry-delay','1','-sS','-o',partial,url
      ], { timeout: 310000 });
      const bytes = fs.statSync(partial).size;
      const sha256 = crypto.createHash('sha256').update(fs.readFileSync(partial)).digest('hex').toLowerCase();
      fs.renameSync(partial, destination);
      return { sha256, bytes };
    } catch (error) {
      try { fs.unlinkSync(partial); } catch {}
      throw error;
    }
  }

  _updateResultPath(version) {
    return path.join(this.backendRoot, 'updates', 'v' + String(version || 'unknown'), 'apply-result.json');
  }

  _windowsPerUserExecutable() {
    return path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'Programs', 'open-internet-gateway', 'Open Internet Gateway.exe');
  }

  async launchDownloadedUpdate(downloaded, { appPid = process.pid, currentExecutable = process.execPath } = {}) {
    if (!downloaded?.path || !downloaded?.info?.latestVersion || !downloaded?.sha256) {
      throw new Error('Verified update payload is incomplete; refusing to launch an update.');
    }
    const version = String(downloaded.info.latestVersion);
    const expectedSha = String(downloaded.sha256).toLowerCase();
    const updateDir = path.dirname(downloaded.path);
    const resultFile = this._updateResultPath(version);
    fs.mkdirSync(updateDir, { recursive: true });

    if (this.platform === 'win32') {
      if (!/\.exe$/i.test(downloaded.path)) throw new Error('Windows automatic update requires the verified NSIS installer.');
      const helper = path.join(updateDir, 'apply-update.ps1');
      const target = this._windowsPerUserExecutable();
      const script = String.raw`param(
  [Parameter(Mandatory=$true)][string]$Installer,
  [Parameter(Mandatory=$true)][string]$ExpectedSha,
  [Parameter(Mandatory=$true)][string]$Version,
  [Parameter(Mandatory=$true)][int]$WaitPid,
  [Parameter(Mandatory=$true)][string]$Target,
  [Parameter(Mandatory=$true)][string]$Fallback,
  [Parameter(Mandatory=$true)][string]$ResultFile
)
$ErrorActionPreference='Stop'
function Save-Result([hashtable]$Data){
  $dir=Split-Path -Parent $ResultFile
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $Data.at=(Get-Date).ToString('o')
  $Data | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultFile -Encoding UTF8
}
$startedFile=$ResultFile+'.started'
Set-Content -LiteralPath $startedFile -Value (Get-Date).ToString('o') -Encoding UTF8
try {
  $deadline=(Get-Date).AddSeconds(120)
  while(Get-Process -Id $WaitPid -ErrorAction SilentlyContinue){
    if((Get-Date) -gt $deadline){throw 'Timed out waiting for the old app process to exit.'}
    Start-Sleep -Milliseconds 200
  }
  $actual=(Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash.ToLowerInvariant()
  if($actual -ne $ExpectedSha.ToLowerInvariant()){throw 'Verified installer hash changed before apply.'}
  $p=Start-Process -FilePath $Installer -ArgumentList @('/S') -PassThru -Wait
  if($p.ExitCode -ne 0){throw ('NSIS updater failed with exit code '+$p.ExitCode)}
  if(-not(Test-Path -LiteralPath $Target)){throw 'Per-user installation target was not created.'}
  $installed=[string](Get-Item -LiteralPath $Target).VersionInfo.ProductVersion
  if($installed -notlike ($Version+'*')){throw ('Installed version mismatch: '+$installed)}
  Save-Result @{ok=$true;version=$Version;sha256=$actual;target=$Target;installScope='current-user';exitCode=$p.ExitCode}
  Start-Process -FilePath $Target
  exit 0
} catch {
  Save-Result @{ok=$false;version=$Version;error=$_.Exception.Message;target=$Target;installScope='current-user'}
  if(Test-Path -LiteralPath $Target){Start-Process -FilePath $Target}
  elseif(Test-Path -LiteralPath $Fallback){Start-Process -FilePath $Fallback}
  exit 1
}
`;
      fs.writeFileSync(helper, script, 'utf8');
      const wrapper = path.join(updateDir, 'apply-update.cmd');
      const startedFile = resultFile + '.started';
      const launchLog = path.join(updateDir, 'apply-update-launch.log');
      for (const stale of [resultFile, startedFile, launchLog]) {
        try { fs.unlinkSync(stale); } catch {}
      }
      const wrapperScript = String.raw`@echo off
setlocal
where.exe pwsh.exe >nul 2>nul
if errorlevel 1 (
  > "%~dp0apply-update-launch.log" echo pwsh.exe was not found.
  exit /b 127
)
pwsh.exe %* > "%~dp0apply-update-launch.log" 2>&1
exit /b %errorlevel%
`;
      fs.writeFileSync(wrapper, wrapperScript, 'utf8');
      const pwshArgs = [
        '-NoProfile','-WindowStyle','Hidden','-ExecutionPolicy','Bypass','-File',helper,
        '-Installer',downloaded.path,
        '-ExpectedSha',expectedSha,
        '-Version',version,
        '-WaitPid',String(appPid),
        '-Target',target,
        '-Fallback',String(currentExecutable || ''),
        '-ResultFile',resultFile
      ];
      const child = spawn(process.env.ComSpec || 'cmd.exe', ['/d','/c',wrapper,...pwshArgs], {
        detached: true, windowsHide: true, stdio: 'ignore'
      });
      await new Promise((resolve, reject) => {
        child.once('spawn', resolve);
        child.once('error', reject);
      });
      child.unref();
      const startedDeadline = Date.now() + 5000;
      while (!fs.existsSync(startedFile) && Date.now() < startedDeadline) {
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      if (!fs.existsSync(startedFile)) {
        let detail = '';
        try { detail = fs.readFileSync(launchLog, 'utf8').trim(); } catch {}
        throw new Error('Windows update helper failed to start.' + (detail ? ' ' + detail : ''));
      }
      return { ok: true, applying: true, restart: true, installScope: 'current-user', resultFile, target };
    }

    if (this.platform === 'linux') {
      if (!/\.AppImage$/i.test(downloaded.path)) throw new Error('Linux automatic update requires the verified AppImage asset.');
      const helper = path.join(updateDir, 'apply-update.sh');
      const target = path.join(os.homedir(), '.local', 'opt', 'OpenInternetGateway-' + version + '-final');
      const script = `#!/usr/bin/env bash
set -euo pipefail
image="$1"
expected="$2"
version="$3"
wait_pid="$4"
result_file="$5"
target="$6"
fallback="$7"
write_result() {
  local ok="$1" message="$2" sandbox_hardened="\${3:-false}"
  python3 - "$result_file" "$ok" "$message" "$version" "$target" "$sandbox_hardened" <<'PY'
import datetime,json,os,sys
path,ok,message,version,target,sandbox_hardened=sys.argv[1:]
os.makedirs(os.path.dirname(path),exist_ok=True)
with open(path,'w',encoding='utf-8') as f:
    json.dump({'ok':ok=='true','message':message,'version':version,'target':target,
               'installScope':'current-user','sandboxHardened':sandbox_hardened=='true',
               'at':datetime.datetime.now().astimezone().isoformat()},f,indent=2)
PY
}
fail() {
  local msg="$1"
  write_result false "$msg" || true
  if [ -x "$target/AppRun" ]; then nohup "$target/AppRun" >/tmp/oig-update-fallback.log 2>&1 </dev/null &
  elif [ -n "$fallback" ] && [ -x "$fallback" ]; then nohup "$fallback" >/tmp/oig-update-fallback.log 2>&1 </dev/null &
  fi
  exit 1
}
deadline=$((SECONDS+120))
while kill -0 "$wait_pid" 2>/dev/null; do
  [ "$SECONDS" -lt "$deadline" ] || fail "Timed out waiting for the old app process to exit."
  sleep 0.2
done
actual="$(sha256sum "$image" | awk '{print tolower($1)}')"
[ "$actual" = "\${expected,,}" ] || fail "Verified AppImage hash changed before apply."
chmod 755 "$image" || fail "Could not mark AppImage executable."
base="$HOME/.local/opt"
stage="$base/.OpenInternetGateway-\${version}-stage-$$"
candidate="$stage/squashfs-root"
mkdir -p "$base"
rm -rf "$stage"
mkdir -p "$stage"
(
  cd "$stage"
  "$image" --appimage-extract >/dev/null
) || fail "AppImage extraction failed."
[ -x "$candidate/AppRun" ] || fail "Extracted AppImage does not contain AppRun."
previous="\${target}.previous"
rm -rf "$previous"
if [ -d "$target" ]; then mv "$target" "$previous" || fail "Could not preserve previous app directory."; fi
mv "$candidate" "$target" || {
  [ -d "$previous" ] && mv "$previous" "$target" || true
  fail "Could not promote extracted AppImage."
}
rm -rf "$stage"
sandbox_hardened=false
sandbox_script="$target/resources/backend/linux/harden_sandbox.py"
if [ -f "$sandbox_script" ]; then
  sandbox_json="$(python3 "$sandbox_script" "$target" 2>/dev/null || true)"
  if printf '%s' "$sandbox_json" | python3 -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin).get("hardened") else 1)' 2>/dev/null; then
    sandbox_hardened=true
  fi
fi
desktop_dir="$HOME/.local/share/applications"
desktop="$desktop_dir/OpenInternetGateway.desktop"
desktop_tmp="\${desktop}.tmp.$$"
mkdir -p "$desktop_dir"
cat >"$desktop_tmp" <<EOF
[Desktop Entry]
Type=Application
Name=Open Internet Gateway
Comment=Stable multi-country Internet gateway
Exec=$target/AppRun %U
Icon=$target/open-internet-gateway.png
Terminal=false
Categories=Network;
StartupWMClass=OpenInternetGateway
X-AppImage-Version=$version
Actions=Quit;

[Desktop Action Quit]
Name=Quit and disconnect
Exec=$target/AppRun --quit
EOF
chmod 644 "$desktop_tmp"
mv "$desktop_tmp" "$desktop"
update-desktop-database "$desktop_dir" >/dev/null 2>&1 || true
write_result true "Update applied." "$sandbox_hardened" || true
nohup "$target/AppRun" >/tmp/oig-update-\${version}.log 2>&1 </dev/null &
exit 0
`;
      fs.writeFileSync(helper, script, 'utf8');
      try { fs.chmodSync(helper, 0o755); } catch {}
      const child = spawn('/bin/bash', [
        helper, downloaded.path, expectedSha, version, String(appPid), resultFile, target, String(currentExecutable || '')
      ], { detached: true, stdio: 'ignore', env: { ...process.env } });
      child.unref();
      return { ok: true, applying: true, restart: true, installScope: 'current-user', resultFile, target };
    }

    throw new Error('Automatic update apply is unsupported on this platform.');
  }

  async downloadUpdate() {
    const info = await this.updateInfo(true);
    if (!info.asset?.url || !info.asset?.name) throw new Error('No compatible update asset was published for this platform.');
    if (!info.updateAvailable) {
      return { ok: true, alreadyCurrent: true, info, path: null };
    }
    if (!info.asset.sha256) throw new Error('GitHub release asset has no SHA-256 digest; refusing an unverifiable update.');

    if (info.checksumsUrl) {
      const sums = await this._curlText(info.checksumsUrl, 20);
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
      const current = this._readJson(this._profileStatePath(), {}) || {};
      const activeSha = base?.connected ? String(current.sha256 || '').toLowerCase() : '';
      return { ...base, activeSha, configPool };
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
      else if (action === 'benchmark-direct-internet') result = await this.benchmarkDirectInternet();
      else if (action === 'benchmark-all-fast') result = await this.benchmarkAllFast();
      else result = await (this.platform === 'win32' ? this._windows(action) : this._linux(action));
      if (action === 'benchmark-all-fast' || action === 'benchmark-direct-internet') {
        this.emit({ type: 'busy', action, busy: false });
        return result;
      }
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
