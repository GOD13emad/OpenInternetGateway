const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

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
      try { fs.chmodSync(path.join(stable, 'linux', 'oig-linux.sh'), 0o755); } catch {}
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
        "[ordered]@{connected=($routes.Count -ge 2 -and $loc -eq 'JP' -and -not($dns -contains '10.10.34.35'));ip=$ip.Trim();country=$loc.Trim();dns=$dns;poison=($dns -contains '10.10.34.35');fullRoutes=$routes.Count;relay=$relay;autoRecovery=[bool]$task;autoRecoveryState=$(if($task){[string]$task.State}else{'Missing'});interface=($routes|Select-Object -First 1 -ExpandProperty InterfaceAlias -ErrorAction SilentlyContinue);engine=$(if($svc){'HeadlessConnector'}else{'Missing'});connectorService=$(if($svc){[string]$svc.Status}else{'Missing'});desiredState=$desired;failureStreak=$(if($guard){[int]$guard.failureStreak}else{0});rotations24h=$(if($guard){@($guard.rotations).Count}else{0})}|ConvertTo-Json -Compress"
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

  async _linux(action) {
    const script = path.join(this.backendRoot, 'linux', 'oig-linux.sh');
    const env = {
      OIG_HOME: this.backendRoot,
      OIG_COMMON: path.join(this.backendRoot, 'common')
    };
    const r = await run('/bin/bash', [script, action], {
      cwd: this.backendRoot,
      env,
      timeout: action === 'status' ? 12000 : 240000
    });
    if (action === 'status') return JSON.parse(r.stdout || '{}');
    return { ok: true, output: r.stdout || r.stderr };
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
      const result = await (this.platform === 'win32' ? this._windows(action) : this._linux(action));
      const status = await this.status();
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
