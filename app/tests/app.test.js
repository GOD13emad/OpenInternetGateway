const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const root = path.resolve(__dirname,'..');

test('renderer exposes all primary product workflows',()=>{
  const html=fs.readFileSync(path.join(root,'src/renderer/index.html'),'utf8');
  for(const text of ['Refresh configs','Repair now','Automatic recovery','Console Gateway','Self-Healing Config Factory','Refresh configs','Diagnostics','Activity','Settings']) assert.match(html,new RegExp(text,'i'));
});

test('secure Electron boundary is configured',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  assert.match(main,/contextIsolation:\s*true/);
  assert.match(main,/nodeIntegration:\s*false/);
  assert.match(main,/sandbox:\s*true/);
});

test('Linux backend implements required actions',()=>{
  const sh=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  for(const action of ['connect','disconnect','refresh','ensure','auto-install','auto-remove','console-status','console-enable','console-disable']) assert.ok(sh.includes(action));
});

test('package includes no-admin Windows installer and Linux update formats',()=>{
  const pkg=JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8'));
  assert.equal(pkg.build.win.target[0].target,'nsis');
  assert.equal(pkg.build.win.requestedExecutionLevel,'asInvoker');
  assert.equal(pkg.build.nsis.oneClick,true);
  assert.equal(pkg.build.nsis.perMachine,false);
  assert.equal(pkg.build.nsis.allowElevation,false);
  assert.equal(pkg.build.nsis.packElevateHelper,false);
  assert.ok(pkg.build.linux.target.includes('AppImage'));
  assert.ok(pkg.build.linux.target.includes('deb'));
});


test('Config Factory is wired through platform and renderer',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  assert.match(backend,/factory-refresh/);
  assert.match(backend,/configPool/);
  assert.match(renderer,/poolValidated/);
  assert.match(renderer,/factoryRefresh/);
});


test('desktop app enforces single-instance tray UX',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  assert.match(main,/requestSingleInstanceLock\(\{ intent: launchIntent \}\)/);
  assert.match(main,/if \(gotSingleInstanceLock\) \{/);
  assert.match(main,/second-instance/);
  assert.match(main,/additionalData\?\.intent/);
  assert.match(main,/function showDashboard\(\)/);
  const guarded=main.slice(main.indexOf('if (gotSingleInstanceLock) {'));
  assert.match(guarded,/app\.whenReady\(\)/);
  assert.match(guarded,/startLinuxExitWatchdog\(\)/);
});


test('Windows backend is fully headless, self-healing, and independent from OpenVPN UI', { skip: !fs.existsSync(path.resolve(root,'backend/windows/scripts')) }, ()=>{
  const base=path.resolve(root,'backend/windows/scripts');
  const connect=fs.readFileSync(path.join(base,'Connect-OpenInternet.ps1'),'utf8');
  const disconnect=fs.readFileSync(path.join(base,'Disconnect-OpenInternet.ps1'),'utf8');
  const ensure=fs.readFileSync(path.join(base,'Ensure-OpenInternet.ps1'),'utf8');
  const factory=fs.readFileSync(path.join(base,'Config-Factory.ps1'),'utf8');
  const headless=fs.readFileSync(path.join(base,'Headless-Control.ps1'),'utf8');
  const bootstrap=fs.readFileSync(path.join(base,'Bootstrap-HeadlessConnector.ps1'),'utf8');
  const auto=fs.readFileSync(path.join(base,'Install-AutoRecovery.ps1'),'utf8');
  const production=connect+'\n'+disconnect+'\n'+ensure+'\n'+headless+'\n'+bootstrap;

  assert.match(headless,/ovpnconnector\.exe/i);
  assert.match(headless,/OVPNConnectorService/i);
  assert.match(headless,/ProgramData\\OpenInternetGateway/i);
  assert.match(headless,/function Stop-ServiceForConfig/);
  assert.match(headless,/Connector service must be stopped before configuration changes/);
  const ensureInstalled=headless.slice(headless.indexOf('function Ensure-ServiceInstalled'),headless.indexOf('function Schedule-ManualServiceMode'));
  assert.match(ensureInstalled,/Stop-ServiceForConfig[\s\S]*set-config','profile'/);
  assert.match(factory,/successes\.json/i);
  assert.match(factory,/quarantine\.json/i);
  assert.match(auto,/OpenInternetGateway-AutoRecovery/i);
  assert.doesNotMatch(production,/OpenVPNConnect(?:\.exe)?/i);
  assert.doesNotMatch(production,/--connect-shortcut/i);
  assert.ok(fs.existsSync(path.join(base,'Headless-Control.ps1')));
  assert.ok(fs.existsSync(path.join(base,'Bootstrap-HeadlessConnector.ps1')));
});


test('Windows disconnect cancels queued reconnect requests before Auto-Recovery',()=>{
  const disconnect=fs.readFileSync(path.join(root,'backend/windows/scripts/Disconnect-OpenInternet.ps1'),'utf8');
  const desired=disconnect.indexOf("desired='off'");
  const exact=disconnect.indexOf('exact-profile.request');
  const known=disconnect.indexOf('headless-known-recover.request');
  const pool=disconnect.indexOf('headless-pool-probe.request');
  const probe=disconnect.indexOf('connector-probe.request');
  const run=disconnect.indexOf('schtasks.exe /Run');
  assert.ok(desired >= 0 && exact > desired && known > desired && pool > desired && probe > desired);
  assert.ok(run > exact && run > known && run > pool && run > probe);
});

test('desktop app owns a dynamic OIG tray and background startup',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  assert.match(main,/function renderTray/);
  assert.match(main,/OpenInternetGateway —/);
  assert.match(main,/setLoginItemSettings/);
  assert.match(main,/--background/);
  assert.match(main,/setInterval\(refreshTrayStatus/);
});


test('version is runtime-derived and quit disconnects the managed tunnel',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const html=fs.readFileSync(path.join(root,'src/renderer/index.html'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  assert.match(main,/version:\s*app\.getVersion\(\)/);
  assert.match(main,/backend\.action\('disconnect'\)/);
  assert.match(main,/SIGTERM/);
  assert.match(main,/watch-parent\.sh/);
  assert.match(main,/app-process\.lease/);
  assert.match(main,/detached:\s*true/);
  assert.match(backend,/version:\s*this\.version/);
  assert.doesNotMatch(html,/R2\.2\.1/);
  assert.match(html,/id="appVersion"/);
  assert.match(renderer,/state\.platform\.version/);
  assert.match(linux,/DESIRED=.*desired-state/);
  assert.match(linux,/set_desired off/);
  assert.match(linux,/DESIRED OFF/);
});

test('Windows upgrade shutdown preserves tunnel intent while explicit Quit disconnects',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  assert.match(main,/function requestProcessExitPreservingTunnel/);
  assert.match(main,/process\.platform === 'win32'\) requestProcessExitPreservingTunnel/);
  assert.match(main,/else requestQuit\(\)/);
  assert.match(main,/click: \(\) => requestQuit\(\)/);
  assert.match(main,/await disconnectBeforeQuit\(\)/);
  const explicitQuit=main.slice(main.indexOf('async function disconnectBeforeQuit'),main.indexOf('async function requestQuit'));
  assert.match(explicitQuit,/await backend\.action\('disconnect'\)/);
  assert.doesNotMatch(explicitQuit,/backend\.status\(\)/);
  const preserve=main.slice(main.indexOf('function requestProcessExitPreservingTunnel'),main.indexOf('if (gotSingleInstanceLock)'));
  assert.doesNotMatch(preserve,/backend\.action\('disconnect'\)/);
});

test('shutdown event emission tolerates destroyed renderer',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  assert.match(main,/!mainWindow\.isDestroyed\(\)/);
  assert.match(main,/!mainWindow\.webContents\.isDestroyed\(\)/);
});

test('Linux close-to-dock and desktop Quit lifecycle are explicit',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const afterInstall=fs.readFileSync(path.join(root,'build/linux-after-install.sh'),'utf8');
  assert.match(main,/win\.on\('close'/);
  assert.match(main,/win\.hide\(\)/);
  assert.match(main,/argv\.includes\('--quit'\)/);
  assert.match(main,/quitRequestedAtLaunch/);
  assert.doesNotMatch(main,/process\.platform === 'linux'\) requestQuit/);
  assert.match(afterInstall,/Actions=Quit/);
  assert.match(afterInstall,/Desktop Action Quit/);
  assert.match(afterInstall,/--quit/);
  assert.match(backend,/OpenInternetGateway\.desktop/);
  assert.match(backend,/Desktop Action Quit/);
  assert.match(backend,/copyFileSync\(systemDesktop, userDesktop\)/);
});

test('tray app survives last window destruction until explicit Quit',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  assert.match(main,/app\.on\('window-all-closed', \(\) => \{\}\)/);
  assert.match(main,/win\.on\('closed'/);
  assert.match(main,/if \(mainWindow === win\) mainWindow = null/);
  assert.match(main,/function isLiveWindow/);
});

test('Linux independent exit watchdog enforces disconnect safely',()=>{
  const watchdog=fs.readFileSync(path.join(root,'backend/linux/watch-parent.sh'),'utf8');
  assert.match(watchdog,/\/proc\/\$pid\/stat/);
  assert.match(watchdog,/app-process\.lease/);
  assert.match(watchdog,/replacement-active/);
  assert.match(watchdog,/oig-linux\.sh" disconnect/);
});

test('multi-country config factories retain country metadata and no JP-only gate',()=>{
  const linuxFactory=fs.readFileSync(path.join(root,'backend/linux/config_factory.py'),'utf8');
  const linuxBackend=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  const winFactory=fs.readFileSync(path.join(root,'backend/windows/scripts/Build-VpnGateUdpCache.ps1'),'utf8');
  const winControl=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8');
  const winStatus=fs.readFileSync(path.join(root,'backend/windows/scripts/Status-OpenInternet.ps1'),'utf8');
  const platform=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  assert.match(linuxFactory,/COUNTRY_PRIORITY/);
  assert.match(linuxFactory,/CountryName/);
  assert.doesNotMatch(linuxFactory,/p\[6\] != "JP"/);
  assert.match(linuxBackend,/OIG-VPN-LIVE/);
  assert.match(winFactory,/PerCountry=6/);
  assert.match(winFactory,/CountryName/);
  assert.doesNotMatch(winFactory,/\$p\[6\] -ne 'JP'/);
  assert.match(winControl,/ExpectedCountry/);
  assert.doesNotMatch(winControl,/\$loc -eq 'JP'/);
  assert.doesNotMatch(winStatus,/\$loc -eq 'JP'/);
  assert.match(winStatus,/\$loc -ne 'IR'/);
  assert.match(winStatus,/Get-Service OVPNConnectorService/);
  assert.match(winStatus,/\$svc\.Status -eq 'Running'/);
  assert.match(platform,/\$loc -ne 'IR'/);
});

test('Linux status tolerates a transient geo probe failure only for a real managed tunnel',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  const statusBlock=linux.slice(linux.indexOf('json_status()'),linux.indexOf('\nhealthy()'));
  assert.match(statusBlock,/managed_active=false/);
  assert.match(statusBlock,/connection show --active/);
  assert.match(statusBlock,/\$1==n && \$2=="vpn"/);
  assert.doesNotMatch(statusBlock,/\$3 ~ \/\^\(tun\|tap\)\//);
  assert.match(statusBlock,/probe_degraded=false/);
  assert.match(statusBlock,/\[\[ -z "\$loc" && "\$managed_active" == true && "\$routes" -ge 2/);
  assert.match(statusBlock,/healthProbeDegraded/);
  assert.match(statusBlock,/connected=\(r>=2 and managed=="true"/);
});

test('Windows status tolerates a transient geo probe failure only for a real managed tunnel',()=>{
  const winStatus=fs.readFileSync(path.join(root,'backend/windows/scripts/Status-OpenInternet.ps1'),'utf8');
  const platform=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const winBlock=platform.slice(platform.indexOf("if (action === 'status')"),platform.indexOf('const mapped = map[action]'));
  assert.match(winStatus,/\$managedActive=\(\$svc -and \$svc\.Status -eq 'Running'\)/);
  assert.match(winStatus,/\$probeDegraded=\$false/);
  assert.match(winStatus,/if\(-not \$loc -and \$managedActive -and \$routes\.Count -ge 2/);
  assert.match(winStatus,/HealthProbeDegraded=\[bool\]\$probeDegraded/);
  assert.match(winBlock,/\$managedActive=\(\$svc -and \$svc\.Status -eq 'Running'\)/);
  assert.match(winBlock,/\$probeDegraded=\$false/);
  assert.match(winBlock,/healthProbeDegraded=\[bool\]\$probeDegraded/);
  assert.match(winBlock,/connected=\(\$routes\.Count -ge 2 -and \$managedActive/);
});

test('Linux failed exact relay does not turn desired gateway intent off',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8').replace(/\r\n/g,'\n');
  const failure=linux.slice(linux.indexOf('rm -f "$KEEP"',linux.indexOf('connect_gateway()')),linux.indexOf('\n}\n\ndisconnect_gateway()',linux.indexOf('connect_gateway()')));
  assert.match(failure,/Selected relay failed validation/);
  assert.doesNotMatch(failure,/set_desired off/);
});

test('Linux foreground actions wait for the operation lock while periodic Ensure yields safely',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  const block=linux.slice(linux.indexOf('action="${1:-status}"'),linux.indexOf('case "$action" in'));
  assert.match(block,/if \[\[ "\$action" == "ensure" \]\]/);
  assert.match(block,/flock -n 9/);
  assert.match(block,/periodic recovery skipped/);
  assert.match(block,/flock -w 90 9/);
  assert.match(block,/exit 75/);
});

test('Linux connection watchdog is fully detached and reaps its sleeper on cancellation',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  const block=linux.slice(linux.indexOf('start_watchdog()'),linux.indexOf('profile_lines()'));
  assert.match(block,/exec 9>&-/);
  assert.match(block,/sleeper=''/);
  assert.match(block,/trap '[^']*kill "\$sleeper"[^']*wait "\$sleeper"[^']*' TERM INT/);
  assert.match(block,/sleep 180 &/);
  assert.match(block,/wait "\$sleeper" \|\| exit 0/);
  assert.match(block,/<\/dev\/null >\/dev\/null 2>&1 &/);
});

test('Windows exact relay switch is atomic, bounded and SHA verified',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const connect=fs.readFileSync(path.join(root,'backend/windows/scripts/Connect-OpenInternet.ps1'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const block=backend.slice(backend.indexOf('async connectProfile'),backend.indexOf('async _directInternetPath'));
  assert.doesNotMatch(block,/this\._windows\('disconnect'\)[\s\S]*this\._windows\('connect'\)/);
  assert.match(block,/const request = path\.join\(this\.backendRoot, 'state', 'exact-profile\.request'\)/);
  assert.match(block,/try \{ fs\.unlinkSync\(request\); \} catch \{\}/);
  assert.doesNotMatch(block,/this\._writeJson\(request/);
  assert.match(block,/_windows\('connect', \['-ProfileSha', sha\]\)/);
  assert.match(block,/actualSha[\s\S]*actualSha !== wanted/);
  assert.match(block,/type: 'progress'[\s\S]*stage: 'switching'/);
  assert.match(connect,/\$expectedSha/);
  assert.match(connect,/\$idleUntil=\(Get-Date\)\.AddSeconds\(90\)/);
  assert.match(connect,/\$waitSeconds=\$\(if\(\$expectedSha\)\{150\}else\{150\}\)/);
  assert.match(connect,/Gateway intent remains on/);
  assert.match(connect,/CONNECTED EXACT/);
  assert.match(connect,/Selected relay failed validation\. Gateway intent remains on so the previous preferred relay can be restored/);
  assert.match(renderer,/payload\.type === 'progress'/);
  assert.match(block,/restorePrevious/);
  assert.match(block,/Previous working relay was restored/);
  assert.match(block,/const savePreferred = \(\) => this\._writeJson\(preferredPath/);
  assert.match(block,/if \(profile\.active\)[\s\S]*savePreferred\(\)/);
  assert.match(block,/neither exact rollback nor general recovery[\s\S]*savePreferred\(\);[\s\S]*return \{ ok: true/);
  assert.match(block,/catch \{[\s\S]*fs\.unlinkSync\(request\)[\s\S]*return false/);
  assert.match(renderer,/Connecting .* speed is measured only after that exact tunnel is validated/);
});

test('failed exact relay attempt preserves preferred metadata and clears stale request',async()=>{
  const os=require('os');
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-exact-fail-'));
  const stateDir=path.join(tmp,'state');
  fs.mkdirSync(stateDir,{recursive:true});
  const previous={sha256:'a'.repeat(64),country:'TH',host:'working',at:'before'};
  const target={sha256:'b'.repeat(64),country:'HK',host:'dead',ip:'198.51.100.7',active:false,quarantined:false};
  fs.writeFileSync(path.join(stateDir,'preferred-profile.json'),JSON.stringify(previous));
  const backend=new Backend({version:'test',resourcesPath:tmp,appPath:tmp,userData:tmp,emit:()=>{}});
  backend.platform='win32';
  backend.backendRoot=tmp;
  backend.profiles=async()=>({profiles:[{...previous,active:true,quarantined:false},target]});
  backend._windows=async()=>{throw new Error('SIMULATED_EXACT_FAIL')};
  await assert.rejects(backend.connectProfile(target.sha256),/neither exact rollback nor general recovery could restore protection/i);
  const after=JSON.parse(fs.readFileSync(path.join(stateDir,'preferred-profile.json'),'utf8'));
  assert.equal(after.sha256,previous.sha256);
  assert.equal(fs.existsSync(path.join(stateDir,'exact-profile.request')),false);
  fs.rmSync(tmp,{recursive:true,force:true});
});

test('Windows foreground exact connect owns its request and preserves gateway intent on failure',()=>{
  const connect=fs.readFileSync(path.join(root,'backend/windows/scripts/Connect-OpenInternet.ps1'),'utf8');
  const main=fs.readFileSync(path.join(root,'backend/windows/OpenInternetGateway.ps1'),'utf8');
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const headless=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8');
  assert.match(connect,/param\(\[string\]\$ProfileSha=''/);
  assert.match(connect,/Remove-Item -LiteralPath \$exact[\s\S]*\$idleUntil=\(Get-Date\)\.AddSeconds\(90\)/);
  assert.match(connect,/requestId=\$requestId/);
  assert.match(connect,/State -ne 'Running'[\s\S]*Selected relay failed validation\. Gateway intent remains on/);
  assert.match(main,/\[string\]\$ProfileSha=''/);
  assert.match(main,/Connect-OpenInternet\.ps1" -ProfileSha \$ProfileSha/);
  assert.match(backend,/async _windows\(action, extraArgs = \[\]\)/);
  assert.match(backend,/_windows\('connect', \['-ProfileSha', sha\]\)/);
  const failure=headless.slice(headless.indexOf('if(-not $connected)'),headless.indexOf('& (Join-Path $PSScriptRoot',headless.indexOf('if(-not $connected)')));
  assert.doesNotMatch(failure,/Save-Desired 'off'/);
  assert.doesNotMatch(failure,/Stop-Connector/);
});

test('selected relay connection is exact rather than fallback',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  const windows=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8');
  const ensure=fs.readFileSync(path.join(root,'backend/windows/scripts/Ensure-OpenInternet.ps1'),'utf8');
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  assert.match(linux,/connect-profile\)/);
  assert.match(linux,/connect_gateway "\$2"/);
  assert.match(linux,/profile_lines "\$exact_sha"/);
  assert.match(linux,/set_desired off/);
  assert.match(windows,/\$ProfileSha/);
  const exactFailure=windows.slice(windows.indexOf('if(-not $connected)'),windows.indexOf('& (Join-Path $PSScriptRoot',windows.indexOf('if(-not $connected)')));
  assert.doesNotMatch(exactFailure,/Save-Desired 'off'/);
  assert.match(windows,/Get-Candidates \$ProfileSha/);
  assert.match(ensure,/exact-profile\.request/);
  assert.match(ensure,/-ProfileSha \$sha/);
  assert.match(backend,/exact-profile\.request/);
  assert.match(backend,/_linux\('connect-profile', \[sha\]\)/);
});

test('explicit Windows disconnect cancels queued recovery and exact requests before running recovery task',()=>{
  const disconnect=fs.readFileSync(path.join(root,'backend/windows/scripts/Disconnect-OpenInternet.ps1'),'utf8');
  assert.match(disconnect,/exact-profile\.request/);
  assert.match(disconnect,/headless-known-recover\.request/);
  assert.match(disconnect,/headless-pool-probe\.request/);
  assert.match(disconnect,/connector-probe\.request/);
  assert.match(disconnect,/Remove-Item -LiteralPath/);
  const off=disconnect.indexOf("desired='off'");
  const cleanup=disconnect.indexOf("exact-profile.request");
  const runTask=disconnect.indexOf("schtasks.exe /Run");
  assert.ok(off >= 0 && cleanup > off && runTask > cleanup);
});

test('disabled Windows Auto-Recovery task is reported unhealthy and self-reenabled by Repair',()=>{
  const ensure=fs.readFileSync(path.join(root,'backend/windows/scripts/Ensure-OpenInternet.ps1'),'utf8');
  const status=fs.readFileSync(path.join(root,'backend/windows/scripts/Status-OpenInternet.ps1'),'utf8');
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  assert.match(ensure,/Enable-ScheduledTask -TaskName \$taskName/);
  assert.match(ensure,/task is disabled and could not be re-enabled/);
  assert.match(status,/AutoRecovery=.*Disabled/);
  assert.match(backend,/autoRecoveryState=.*Disabled/);
  assert.match(renderer,/\['inactive','failed','missing','disabled'\]/);
});

test('Windows non-admin Ensure delegates to the elevated recovery task and startup reconciles desired-on state',()=>{
  const ensure=fs.readFileSync(path.join(root,'backend/windows/scripts/Ensure-OpenInternet.ps1'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  assert.match(ensure,/if\(-not\(Test-Admin\)\)/);
  assert.match(ensure,/schtasks\.exe \/Run \/TN \$taskName/);
  assert.match(ensure,/ELEVATED ENSURE PASS/);
  assert.match(ensure,/AddSeconds\(150\)/);
  assert.match(renderer,/async function reconcileStartupTunnel/);
  assert.match(renderer,/s\.desiredState !== 'on'/);
  assert.match(renderer,/window\.gateway\.action\('ensure'\)/);
  assert.match(renderer,/const startupStatus = await refreshStatus\(false\)/);
  assert.match(renderer,/await reconcileStartupTunnel\(startupStatus\)/);
});

test('Linux direct ISP path rejects tunnel defaults and stale exact request files are removed',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const block=backend.slice(backend.indexOf("if (this.platform === 'linux')",backend.indexOf('async _directInternetPath')),backend.indexOf("throw new Error('Direct Internet test is supported",backend.indexOf('async _directInternetPath')));
  assert.match(block,/nmcli -t -f DEVICE,TYPE,STATE/);
  assert.match(block,/ethernet/);
  assert.match(block,/wifi/);
  assert.match(block,/tun\|tap\|wg\|tailscale\|ppp\|zt\|vpn/);
  assert.match(backend,/fs\.unlinkSync\(path\.join\(stable, 'state', 'exact-profile\.request'\)\)/);
  const connect=backend.slice(backend.indexOf('async connectProfile'),backend.indexOf('async _directInternetPath'));
  assert.doesNotMatch(connect,/this\._writeJson\(request/);
  assert.match(connect,/fs\.unlinkSync\(request\)/);
});

test('native UI typography applies to form controls and select sizing is valid',()=>{
  const css=fs.readFileSync(path.join(root,'src/renderer/styles.css'),'utf8');
  assert.match(css,/body\{[^}]*font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif/);
  assert.match(css,/button,input,select,textarea\{font:inherit\}/);
  assert.match(css,/\.select-control\{[^}]*font-size:11px/);
  assert.doesNotMatch(css,/font:11px inherit/);
});

test('all-relay probe covers the full pool and UI explains missing live replies',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const css=fs.readFileSync(path.join(root,'src/renderer/styles.css'),'utf8');
  const block=backend.slice(backend.indexOf('async benchmarkAllFast()'),backend.indexOf('async _httpsLatencyMs'));
  assert.match(block,/\.filter\(p => p\.sha256 && p\.ip\)/);
  assert.doesNotMatch(block,/!quarantine\[p\.sha256\]/);
  assert.match(block,/noReply: results\.filter/);
  assert.match(renderer,/wasFastTested \? 'No reply' : 'Not tested'/);
  assert.match(renderer,/result\?\.noReply/);
  assert.match(css,/font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif/);
  assert.match(css,/ui-monospace,"Cascadia Mono"/);
});

test('connection inventory exposes honest source-vs-live metrics and selectable profiles',()=>{
  const html=fs.readFileSync(path.join(root,'src/renderer/index.html'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const preload=fs.readFileSync(path.join(root,'src/preload/preload.js'),'utf8');
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  const win=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8');
  assert.match(html,/data-page="connections"/);
  assert.match(html,/Source ping/);
  assert.match(html,/Actual download/);
  assert.match(html,/Actual upload/);
  assert.match(html,/Some relays block ICMP/);
  assert.match(renderer,/benchmark-active/);
  assert.match(renderer,/connect-profile/);
  assert.match(preload,/gateway:profiles/);
  assert.match(main,/gateway:profiles/);
  assert.match(backend,/async profiles\(liveStatusOverride = null\)/);
  assert.match(backend,/connection-benchmarks\.json/);
  assert.match(backend,/preferred-profile\.json/);
  assert.match(backend,/speed\.cloudflare\.com\/__down/);
  assert.match(backend,/speed\.cloudflare\.com\/__up/);
  assert.match(linux,/preferred-profile\.json/);
  assert.match(linux,/configuredCountry/);
  assert.match(win,/preferred-profile\.json/);
  assert.match(win,/Preferred/);
});

test('Linux packaged payload stays readable to desktop user',()=>{
  const afterPack=fs.readFileSync(path.join(root,'tools/afterPack.js'),'utf8');
  const afterInstall=fs.readFileSync(path.join(root,'build/linux-after-install.sh'),'utf8');
  assert.match(afterPack,/mode \| 0o044/);
  assert.match(afterPack,/normalizeLinuxPayload/);
  assert.match(afterInstall,/find "\$APPDIR" -type f -exec chmod a\+r/);
});

test('Connections stays synchronized with externally recovered active tunnel',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  assert.match(backend,/const activeSha = base\?\.connected \? String\(current\.sha256/);
  assert.match(backend,/syntheticActive: true/);
  assert.match(backend,/!profiles\.some\(p => p\.active\)/);
  assert.match(renderer,/function syncConnectionInventoryToStatus/);
  assert.match(renderer,/String\(s\?\.activeSha/);
  assert.match(renderer,/if \(state\.page === 'connections'\)/);
  assert.match(renderer,/if \(connected && !matched\)[\s\S]*loadConnections\(\)/);
  assert.match(renderer,/syncConnectionInventoryToStatus\(s\)/);
});

test('connection inventory active state requires live tunnel',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  assert.match(backend,/const liveStatus = liveStatusOverride \|\| await this\.status\(\)/);
  assert.match(backend,/active: !!liveStatus\.connected && !!sha && sha === activeSha/);
});

test('fast Test all probes relays in parallel and table sorting is explicit',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const html=fs.readFileSync(path.join(root,'src/renderer/index.html'),'utf8');
  assert.match(backend,/async benchmarkAllFast\(\)/);
  assert.match(backend,/Math\.min\(16/);
  assert.match(backend,/benchmark-all-fast/);
  assert.match(backend,/fastPingMs/);
  assert.match(backend,/action === 'benchmark-all-fast'[\s\S]*type: 'busy'[\s\S]*return result/);
  assert.match(renderer,/connectionSortValue/);
  assert.match(renderer,/compareConnections/);
  assert.match(renderer,/benchmark-all-fast/);
  assert.match(renderer,/new Map\(\(result\?\.results \|\| \[\]\)/);
  assert.doesNotMatch(renderer.slice(renderer.indexOf('async function benchmarkCurrent'),renderer.indexOf('async function loadDiagnostics')),/loadConnections\(\)/);
  assert.match(renderer,/test\.textContent = 'Speed'/);
  assert.match(html,/>Test all relays</);
  for(const key of ['country','relay','protocol','sourcePing','livePing','download','upload','status']) assert.match(html,new RegExp('data-sort="'+key+'"'));
});

test('TCP fast probe requires socket connectivity even if host ICMP responds', async()=>{
  const Backend=require('../src/main/platform-backend');
  const b=new Backend({});
  b._icmpPing=async()=>20;
  b._directTcpConnectMs=async()=>null;
  const physical={ interface:'eth0', localIP:'192.0.2.10' };
  const tcpClosed=await b._quickProbeProfile({ip:'192.0.2.9',port:443,protocol:'tcp'},physical);
  assert.equal(tcpClosed.fastPingMs,20);
  assert.equal(tcpClosed.fastMethod,'icmp-only');
  assert.equal(tcpClosed.fastReachable,false);
  b._icmpPing=async()=>12;
  b._directTcpConnectMs=async()=>390;
  const tcpOpen=await b._quickProbeProfile({ip:'192.0.2.9',port:1604,protocol:'tcp'},physical);
  assert.equal(tcpOpen.fastReachable,true);
  assert.equal(tcpOpen.fastMethod,'tcp-direct');
  assert.equal(tcpOpen.fastPingMs,390);
  b._directTcpConnectMs=async()=>{throw new Error('UDP must not attempt a TCP connection')};
  const udp=await b._quickProbeProfile({ip:'192.0.2.8',port:1195,protocol:'udp'},physical);
  assert.equal(udp.fastReachable,true);
  assert.equal(udp.fastMethod,'icmp-direct');
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  const windows=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8');
  assert.match(linux,/if proto=="tcp" and b\.get\("fastReachable"\) is False: score -= 180\.0\s+elif fast is not None/);
  assert.match(windows,/if\(\$proto -eq 'tcp'.*fastReachable.*\$score-=180\}\s+elseif\(\$null -ne \$fast\)/);
});

test('Linux direct TCP probe closes curl stdin and measures an actual loopback connection', { skip: process.platform !== 'linux' }, async()=>{
  const net=require('node:net');
  const Backend=require('../src/main/platform-backend');
  const sockets=new Set();
  const server=net.createServer(socket=>{
    sockets.add(socket);
    socket.on('close',()=>sockets.delete(socket));
  });
  await new Promise((resolve,reject)=>{
    server.once('error',reject);
    server.listen(0,'127.0.0.1',resolve);
  });
  try {
    const b=new Backend({});
    const latency=await b._directTcpConnectMs('127.0.0.1',server.address().port,
      { curlInterface:'if!lo' },0.4);
    assert.ok(latency !== null && latency >= 0, 'A live loopback socket must not become a false TCP-negative from an open stdin pipe');
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve=>server.close(resolve));
  }
});

test('direct ISP benchmark binds physical Internet and bypasses proxies',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const html=fs.readFileSync(path.join(root,'src/renderer/index.html'),'utf8');
  assert.match(backend,/async _directInternetPath\(\)/);
  assert.match(backend,/--noproxy','\*','--interface/);
  assert.match(backend,/host!' \+ String\(info\.ip/);
  assert.match(backend,/curlInterface: 'if!' \+ iface/);
  assert.match(backend,/async benchmarkDirectInternet\(\)/);
  assert.match(backend,/mode: 'direct-physical-internet'/);
  assert.match(backend,/downloadMbps/);
  assert.match(backend,/uploadMbps/);
  assert.match(backend,/bypassObserved/);
  assert.match(backend,/icmp-direct/);
  assert.match(backend,/tcp-direct/);
  assert.match(backend,/benchmark-direct-internet/);
  assert.match(renderer,/benchmarkDirectInternet/);
  assert.match(renderer,/renderDirectInternet/);
  assert.match(html,/id="benchmarkDirect"/);
  assert.match(html,/DIRECT INTERNET \/ ISP BASELINE/);
  assert.match(html,/id="directDownload"/);
  assert.match(html,/id="directUpload"/);
  assert.match(html,/Test all relays/);
});

test('GitHub updater checks latest release and verifies published SHA-256',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  const preload=fs.readFileSync(path.join(root,'src/preload/preload.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const html=fs.readFileSync(path.join(root,'src/renderer/index.html'),'utf8');
  assert.match(backend,/releases\/latest/);
  assert.match(backend,/SHA256SUMS/);
  assert.match(backend,/GitHub digest and SHA256SUMS disagree/);
  assert.match(backend,/Downloaded update SHA-256 does not match/);
  assert.match(backend,/async _curlText/);
  assert.match(backend,/--max-time','300/);
  assert.match(backend,/--retry','2/);
  assert.match(backend,/async updateInfo\(force = false\)/);
  assert.match(backend,/async downloadUpdate\(\)/);
  assert.match(main,/gateway:updateInfo/);
  assert.match(main,/gateway:installUpdate/);
  assert.match(main,/launchDownloadedUpdate/);
  assert.match(main,/requestProcessExitPreservingTunnel/);
  assert.doesNotMatch(main,/shell\.openPath\(result\.path\)/);
  assert.match(backend,/async launchDownloadedUpdate/);
  assert.match(backend,/installScope: 'current-user'/);
  assert.ok(backend.includes("Programs', 'open-internet-gateway', 'Open Internet Gateway.exe'"));
  assert.match(backend,/pwsh-helper/);
  assert.match(backend,/copyDir\(bundledPwshRoot, helperRuntime\)/);
  assert.match(backend,/spawn\(updatePwsh, pwshArgs/);
  assert.match(backend,/resultFile \+ '\.started'/);
  assert.match(backend,/Windows update helper failed to start/);
  assert.doesNotMatch(backend,/spawn\('pwsh\.exe'/);
  assert.match(backend,/--appimage-extract/);
  assert.match(backend,/update-desktop-database/);
  assert.match(preload,/updateInfo/);
  assert.match(preload,/installUpdate/);
  assert.match(renderer,/renderUpdateInfo/);
  assert.match(renderer,/loadUpdates/);
  assert.match(html,/data-page="updates"/);
  assert.match(html,/GITHUB RELEASES/);
  assert.match(html,/Install verified update/);
});


test('Linux Chromium sandbox hardening is fail-safe and update-persistent',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  const helper=fs.readFileSync(path.join(root,'backend/linux/harden_sandbox.py'),'utf8');
  assert.match(backend,/_hardenLinuxChromiumSandbox/);
  assert.match(backend,/linux-sandbox-hardening.json/);
  assert.match(backend,/sandboxHardened/);
  assert.match(backend,/resources\/backend\/linux\/harden_sandbox\.py/);
  assert.match(main,/OIG_SANDBOX_RESTARTED/);
  assert.ok(main.includes('initialized?.sandboxHardening?.restartRequired'));
  assert.match(helper,/0o4755/);
  assert.match(helper,/hash-compatible root-owned setuid Chromium sandbox/);
  assert.match(helper,/OIG sandbox hardening: prefer a compatible root-owned setuid helper/);
  assert.match(helper,/CHROME_DEVEL_SANDBOX/);
  assert.match(helper,/readlink -f .*chrome-sandbox/);
  assert.match(helper,/LEGACY_REPLACEMENT/);
  assert.doesNotMatch(helper,/sysctl|apparmor_parser|sudo|pkexec/);
});

test('GitHub workflows use current hosted-runner actions and Node LTS',()=>{
  const build=fs.readFileSync(path.resolve(root,'..','.github','workflows','build.yml'),'utf8');
  const release=fs.readFileSync(path.resolve(root,'..','.github','workflows','release.yml'),'utf8');
  for(const wf of [build,release]) {
    assert.doesNotMatch(wf,/actions\/checkout@v4/);
    assert.doesNotMatch(wf,/actions\/setup-node@v4/);
    assert.doesNotMatch(wf,/node-version:\s*['"]22['"]/);
    assert.match(wf,/actions\/checkout@v7/);
    assert.match(wf,/npm audit --omit=dev --audit-level=high/);
    assert.match(wf,/npm audit --audit-level=critical/);
  }
  assert.match(build,/actions\/setup-node@v7/);
  assert.match(build,/actions\/upload-artifact@v7/);
  assert.match(build,/permissions:\s*\n\s*contents:\s*read/);
  assert.match(release,/actions\/setup-node@v7/);
  assert.match(release,/actions\/upload-artifact@v7/);
  assert.match(release,/actions\/download-artifact@v8/);
  assert.match(build,/node-version:\s*['"]24['"]/);
  assert.match(release,/node-version:\s*['"]24['"]/);
});

test('Linux Debian desktop entry is normalized to world-readable mode after packaging',()=>{
  const pkg=require(path.join(root,'package.json'));
  const hook=fs.readFileSync(path.join(root,'tools/afterAllArtifactBuild.js'),'utf8');
  assert.equal(pkg.build.afterAllArtifactBuild,'tools/afterAllArtifactBuild.js');
  assert.match(hook,/--raw-extract/);
  assert.match(hook,/fs\.chmodSync\(desktop, 0o644\)/);
  assert.match(hook,/fs\.chmodSync\(icon, 0o644\)/);
  assert.match(hook,/fs\.chmodSync\(controlDir, 0o755\)/);
  assert.match(hook,/--root-owner-group/);
  assert.match(hook,/desktop entry mode is not 0644/);
  assert.match(hook,/application icon mode is not 0644/);
  assert.ok(hook.includes('artifactPaths') && hook.includes('.deb$/i.test(file)'));
});

test('Linux Debian package path is sandbox-safe',()=>{
  const afterPack=fs.readFileSync(path.join(root,'tools/afterPack.js'),'utf8');
  const afterInstall=fs.readFileSync(path.join(root,'build/linux-after-install.sh'),'utf8');
  assert.match(afterPack,/sanitizedProductName\s*=\s*['"]open-internet-gateway['"]/);
  assert.match(afterInstall,/APPDIR="\/opt\/open-internet-gateway"/);
  assert.doesNotMatch(afterInstall,/\/opt\/Open Internet Gateway/);
});

test('disconnected exact relay failure restores saved preferred relay',async()=>{
  const os=require('os');
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-preferred-restore-'));
  const stateDir=path.join(tmp,'state');
  fs.mkdirSync(stateDir,{recursive:true});
  const previous={sha256:'c'.repeat(64),country:'VN',host:'saved-working',ip:'203.0.113.9',active:false,quarantined:false};
  const target={sha256:'d'.repeat(64),country:'JP',host:'dead-target',ip:'198.51.100.7',active:false,quarantined:false};
  fs.writeFileSync(path.join(stateDir,'preferred-profile.json'),JSON.stringify(previous));
  const backend=new Backend({version:'test',resourcesPath:tmp,appPath:tmp,userData:tmp,emit:()=>{}});
  backend.platform='win32';
  backend.backendRoot=tmp;
  backend.profiles=async()=>({profiles:[previous,target],preferredSha:previous.sha256});
  backend.status=async()=>({connected:true,country:'VN'});
  const calls=[];
  backend._windows=async(_action,args)=>{
    const sha=String(args?.[1]||'');
    calls.push(sha);
    if(sha===target.sha256) throw new Error('SIMULATED_EXACT_FAIL');
    fs.writeFileSync(path.join(stateDir,'current-openvpn-profile.json'),JSON.stringify({sha256:previous.sha256}));
    return {ok:true};
  };
  const result=await backend.connectProfile(target.sha256);
  assert.equal(result.ok,false);
  assert.equal(result.recovered,true);
  assert.equal(result.code,'SELECTED_RELAY_FAILED_RESTORED');
  assert.match(result.message,/Previous working relay was restored/);
  assert.deepEqual(calls,[target.sha256,previous.sha256]);
  const preferred=JSON.parse(fs.readFileSync(path.join(stateDir,'preferred-profile.json'),'utf8'));
  assert.equal(preferred.sha256,previous.sha256);
  fs.rmSync(tmp,{recursive:true,force:true});
});

test('backend strips ANSI terminal formatting before surfacing command errors',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  assert.match(backend,/function stripAnsi\(value\)/);
  assert.match(backend,/stdout: stripAnsi\(stdout\)\.trim\(\), stderr: stripAnsi\(stderr\)\.trim\(\)/);
  assert.match(backend,/new Error\(result\.stderr \|\| result\.stdout/);
});


test('renderer terminal backend events close only the matching busy overlay',()=>{
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  assert.match(renderer,/busyAction:\s*''/);
  assert.match(renderer,/state\.busyAction = on \? action : ''/);
  assert.match(renderer,/payload\.type === 'status'[\s\S]*payload\.busy === false && state\.busyAction === payload\.action[\s\S]*setBusy\(false\)/);
  assert.match(renderer,/payload\.type === 'error'[\s\S]*payload\.busy === false && state\.busyAction === payload\.action[\s\S]*setBusy\(false\)/);
  assert.match(renderer,/payload\.type === 'busy'[\s\S]*payload\.busy \|\| !state\.busyAction \|\| state\.busyAction === payload\.action/);
});


test('recovered relay failure is a structured non-error outcome and Speed does not benchmark fallback',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  assert.match(backend,/recovered:\s*true/);
  assert.match(backend,/SELECTED_RELAY_FAILED_RESTORED/);
  assert.match(backend,/if \(restored\) return recoveredResult/);
  assert.match(renderer,/if \(connected\?\.recovered\)[\s\S]*showToast\(connected\.message[\s\S]*await loadConnections\(\);[\s\S]*return;/);
  const connectBlock=renderer.slice(renderer.indexOf('async function connectOrTestProfile'),renderer.indexOf('async function benchmarkCurrent'));
  const recoveredPos=connectBlock.indexOf('if (connected?.recovered)');
  const benchmarkPos=connectBlock.indexOf("window.gateway.action('benchmark-active')");
  assert.ok(recoveredPos >= 0 && benchmarkPos > recoveredPos);
});

test('renderer strips Electron IPC and PowerShell framing from user-facing errors',()=>{
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  assert.match(renderer,/function userErrorMessage\(error, fallback/);
  assert.match(renderer,/Error invoking remote method/);
  assert.match(renderer,/CategoryInfo\|FullyQualifiedErrorId/);
  assert.match(renderer,/showToast\(userErrorMessage\(e, 'Relay operation failed\.'\), true\)/);
  assert.match(renderer,/showToast\(userErrorMessage\(payload\.message, 'Action failed\.'\), true\)/);
});

test('profiles can reuse an already validated live status without a second transient probe',async()=>{
  const os=require('os');
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-status-reuse-'));
  fs.mkdirSync(path.join(tmp,'runtime','udp-cache'),{recursive:true});
  fs.mkdirSync(path.join(tmp,'runtime','config-factory'),{recursive:true});
  fs.mkdirSync(path.join(tmp,'state'),{recursive:true});
  const sha='e'.repeat(64);
  fs.writeFileSync(path.join(tmp,'runtime','udp-cache','index.json'),JSON.stringify([{Rank:1,Host:'relay',IP:'203.0.113.10',Port:443,Protocol:'tcp',Country:'VN',SHA256:sha}]));
  fs.writeFileSync(path.join(tmp,'state','current-openvpn-profile.json'),JSON.stringify({sha256:sha,host:'relay',serverIP:'203.0.113.10',port:443,protocol:'tcp',configuredCountry:'VN'}));
  const backend=new Backend({version:'test',resourcesPath:tmp,appPath:tmp,userData:tmp,emit:()=>{}});
  backend.platform='win32'; backend.backendRoot=tmp;
  let statusCalls=0; backend.status=async()=>{statusCalls++;return {connected:false};};
  const inventory=await backend.profiles({connected:true});
  assert.equal(statusCalls,0); assert.equal(inventory.profiles.length,1); assert.equal(inventory.profiles[0].active,true);
  fs.rmSync(tmp,{recursive:true,force:true});
});

test('active throughput benchmark reuses its validated status for inventory mapping',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const start=backend.indexOf('async benchmarkActive()');
  const block=backend.slice(start,backend.indexOf('async diagnostics()',start));
  assert.match(block,/const status = await this\.status\(\)/);
  assert.match(block,/const inventory = await this\.profiles\(status\)/);
});


test('active throughput upload tolerates one transient Cloudflare POST failure without accepting an unverified result',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const start=backend.indexOf('async benchmarkActive()');
  const block=backend.slice(start,backend.indexOf('_githubHeaders()',start));
  assert.match(block,/let uploadAttempts = 0/);
  assert.match(block,/for \(let attempt = 0; attempt < 2; attempt\+\+\)/);
  assert.match(block,/--connect-timeout','8','--max-time','20'/);
  assert.match(block,/timeout: 24000, allowFailure: true/);
  assert.match(block,/code === '200' && Number\(speed\) > 0/);
  assert.match(block,/after a bounded retry/);
  assert.match(block,/uploadAttempts,/);
});


test('Linux exact relay switch preserves gateway intent atomically and records provenance',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8').replace(/\r\n/g,'\n');
  const start=linux.indexOf('  connect-profile)');
  const end=linux.indexOf('    ;;',start);
  const block=linux.slice(start,end);
  assert.ok(start>=0 && end>start);
  assert.match(block,/set_desired on "connect-profile"/);
  assert.match(block,/teardown_gateway/);
  assert.match(block,/connect_gateway "\$2"/);
  assert.doesNotMatch(block,/disconnect_gateway/);
  assert.ok(block.indexOf('set_desired on') < block.indexOf('teardown_gateway'));
  assert.ok(block.indexOf('teardown_gateway') < block.indexOf('connect_gateway'));
  const intent=linux.slice(linux.indexOf('record_intent()'),linux.indexOf('\ndesired_state()'));
  assert.match(intent,/intent-history\.jsonl/);
  assert.match(intent,/\/proc\/\$PPID\/cmdline/);
  assert.match(intent,/parentCommand/);
  const disconnect=linux.slice(linux.indexOf('disconnect_gateway()'),linux.indexOf('\nrefresh_cache()'));
  assert.match(disconnect,/set_desired off/);
  assert.match(disconnect,/teardown_gateway/);
});


test('automatic updater prefers user-space assets and avoids elevation paths',()=>{
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const tmp=fs.mkdtempSync(path.join(require('os').tmpdir(),'oig-update-select-'));
  const backend=new Backend({version:'2.5.13',resourcesPath:tmp,appPath:tmp,userData:tmp,emit:()=>{}});
  const assets=[
    {name:'OpenInternetGateway-2.5.14-amd64.deb'},
    {name:'OpenInternetGateway-2.5.14-x86_64.AppImage'},
    {name:'OpenInternetGateway-Setup-2.5.14.exe'}
  ];
  backend.platform='linux';
  assert.equal(backend._selectUpdateAsset(assets,'2.5.14').name,'OpenInternetGateway-2.5.14-x86_64.AppImage');
  backend.platform='win32';
  assert.equal(backend._selectUpdateAsset(assets,'2.5.14').name,'OpenInternetGateway-Setup-2.5.14.exe');
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  const source=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  assert.ok(source.includes("ArgumentList @('/S')"));
  const launchBlock=source.slice(source.indexOf('async launchDownloadedUpdate'),source.indexOf('async downloadUpdate'));
  assert.doesNotMatch(launchBlock,/-Verb RunAs/);
  assert.ok(main.includes('app-process.lease'));
  fs.rmSync(tmp,{recursive:true,force:true});
});

test('Linux OpenVPN quality engine uses multi-source refresh and safe public-profile filtering',()=>{
  const factory=fs.readFileSync(path.join(root,'backend/linux/config_factory.py'),'utf8');
  assert.match(factory,/https:\/\/www\.vpngate\.net/);
  assert.match(factory,/ThreadPoolExecutor/);
  assert.match(factory,/max_sources=3/);
  assert.match(factory,/usedMirrors/);
  assert.match(factory,/sourceCount/);
  assert.match(factory,/allow_partial=True/);
  assert.match(factory,/proc\.returncode == 28/);
  assert.match(factory,/partialSourceCount/);
  assert.match(factory,/len\(rows\) >= 8/);
  assert.match(factory,/not data\.endswith/);
  assert.match(factory,/mergedRows/);
  assert.match(factory,/count=48/);
  assert.match(factory,/preserve_count=8/);
  for(const token of ['script-security','route-up','route-pre-down','ipchange','plugin','client-connect','client-disconnect','learn-address']) assert.ok(factory.includes(token));
});

test('Linux adaptive OpenVPN ranking consumes direct probes and persistent quality history',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8').replace(/\r\n/g,'\n');
  const start=linux.indexOf('profile_lines()');
  const end=linux.indexOf('\nconnect_one()',start);
  const block=linux.slice(start,end);
  assert.match(block,/connection-benchmarks\.json/);
  assert.match(block,/successes\.json/);
  assert.match(block,/failures\.json/);
  assert.match(block,/fastPingMs/);
  assert.match(block,/downloadMbps/);
  assert.match(block,/uploadMbps/);
  assert.match(block,/httpsLatencyMs/);
  assert.match(block,/fresh_iso\(f\.get\("last"\),6\)/);
  assert.match(block,/score -= 320\.0/);
  assert.match(block,/proto=="udp"/);
  assert.match(block,/proto=="tcp" and b\.get\("fastReachable"\) is False/);
  assert.match(block,/if n >= \(1 if only_sha else 16\): break/);
});

test('Linux exact OpenVPN switch preflights beside the working tunnel before teardown',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8').replace(/\r\n/g,'\n');
  const pre=linux.slice(linux.indexOf('preflight_one()'),linux.indexOf('\nconnect_one()'));
  assert.match(pre,/OIG-VPN-PREFLIGHT/);
  assert.match(pre,/ipv4\.never-default yes/);
  assert.match(pre,/ipv4\.ignore-auto-routes yes/);
  assert.match(pre,/ipv4\.ignore-auto-dns yes/);
  assert.match(pre,/nmcli -w 10 connection up/);
  assert.match(pre,/defaultRoutePreserved/);
  assert.match(pre,/dnsStatePreserved/);
  assert.match(linux,/dns_server_fingerprint/);
  assert.match(pre,/route_ok and dns_ok/);
  const start=linux.indexOf('  connect-profile)');
  const end=linux.indexOf('    ;;',start);
  const block=linux.slice(start,end);
  assert.ok(block.indexOf('preflight_one') >= 0);
  assert.ok(block.indexOf('preflight_one') < block.indexOf('teardown_gateway'));
  assert.match(block,/current tunnel preserved/);
  assert.match(block,/rc=\$\?/);
});

test('Linux foreground connect and refresh qualify the OpenVPN pool over physical Internet first',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const start=backend.indexOf('async action(action, options = {})');
  const end=backend.indexOf('\n  async diagnostics()',start);
  const block=backend.slice(start,end);
  assert.match(block,/this\.platform === 'linux' && action === 'connect'[\s\S]*benchmarkAllFast\(\)[\s\S]*_linux\('connect'\)/);
  assert.match(block,/this\.platform === 'linux' && action === 'refresh'[\s\S]*_linux\('factory-refresh'\)[\s\S]*benchmarkAllFast\(\)[\s\S]*_linux\('connect'\)/);
  assert.match(block,/this\.platform === 'linux' && action === 'factory-refresh'[\s\S]*fastQualification/);
});


test('Linux interrupted OpenVPN activation records pending identity without trusting pending geo fallback',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8').replace(/\r\n/g,'\n');
  assert.match(linux,/validationPending/);
  assert.match(linux,/profile_ip="" if pending/);
  assert.match(linux,/profile_country="" if pending/);
  const start=linux.indexOf('connect_one()');
  const end=linux.indexOf('\nrecord_success()',start);
  const block=linux.slice(start,end);
  assert.ok(block.indexOf('write_profile_state') > block.indexOf('nmcli -w 30 connection up'));
  assert.ok(block.indexOf('write_profile_state') < block.indexOf('for _ in 1 2 3 4 5 6'));
  assert.match(block,/current-linux-profile\.before-connect\.json/);
  assert.match(block,/mv -f "\$previous_state" "\$state_file"/);
});

test('Linux teardown waits on observed NetworkManager state instead of fixed outage delay',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8').replace(/\r\n/g,'\n');
  const start=linux.indexOf('teardown_gateway()');
  const end=linux.indexOf('\ndisconnect_gateway()',start);
  const block=linux.slice(start,end);
  assert.doesNotMatch(block,/sleep 2/);
  assert.match(block,/connection show --active/);
  assert.match(block,/sleep 0\.1/);
});


test('Linux intent provenance tolerates a disappearing parent process',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  const start=linux.indexOf('record_intent()');
  const end=linux.indexOf('\nset_desired()',start);
  const block=linux.slice(start,end);
  assert.match(block,/\[\[ -r "\/proc\/\$PPID\/cmdline" \]\]/);
  assert.match(block,/2>\/dev\/null \|\| true/);
});

test('Linux exact relay failure falls through to adaptive recovery when exact rollback is unavailable',async()=>{
  const os=require('os');
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-linux-general-recovery-'));
  const stateDir=path.join(tmp,'state');
  fs.mkdirSync(stateDir,{recursive:true});
  const previous={sha256:'e'.repeat(64),country:'JP',host:'previous',ip:'203.0.113.10',active:true,quarantined:false};
  const target={sha256:'f'.repeat(64),country:'JP',host:'target',ip:'198.51.100.20',active:false,quarantined:false};
  const recoveredSha='1'.repeat(64);
  fs.writeFileSync(path.join(stateDir,'preferred-profile.json'),JSON.stringify(previous));
  const backend=new Backend({version:'test',resourcesPath:tmp,appPath:tmp,userData:tmp,emit:()=>{}});
  backend.platform='linux';
  backend.backendRoot=tmp;
  backend.profiles=async()=>({profiles:[previous,target],preferredSha:previous.sha256});
  let connected=false;
  backend.status=async()=>({connected,country:connected?'TH':''});
  const calls=[];
  backend._linux=async(action,args)=>{
    calls.push([action,...(args||[])]);
    if(action==='connect-profile') throw new Error('SIMULATED_EXACT_FAILURE');
    if(action==='connect'){
      connected=true;
      fs.writeFileSync(path.join(stateDir,'current-linux-profile.json'),JSON.stringify({
        sha256:recoveredSha,country:'TH',host:'adaptive-recovery',serverIP:'203.0.113.77'
      }));
      return {ok:true};
    }
    throw new Error('UNEXPECTED_ACTION');
  };
  const result=await backend.connectProfile(target.sha256);
  assert.equal(result.ok,false);
  assert.equal(result.recovered,true);
  assert.equal(result.code,'SELECTED_RELAY_FAILED_GENERAL_RECOVERY');
  assert.equal(result.status.connected,true);
  assert.deepEqual(calls,[
    ['connect-profile',target.sha256],
    ['connect-profile',previous.sha256],
    ['connect']
  ]);
  const preferred=JSON.parse(fs.readFileSync(path.join(stateDir,'preferred-profile.json'),'utf8'));
  assert.equal(preferred.sha256,recoveredSha);
  assert.equal(preferred.country,'TH');
  fs.rmSync(tmp,{recursive:true,force:true});
});

test('Linux general recovery is present in every post-selection validation failure branch',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const block=backend.slice(backend.indexOf('async connectProfile'),backend.indexOf('async _directInternetPath'));
  assert.match(block,/const recoverAnyLinux = async/);
  assert.match(block,/this\.platform !== 'linux'/);
  assert.match(block,/await this\._linux\('connect'\)/);
  assert.match(block,/SELECTED_RELAY_FAILED_GENERAL_RECOVERY/);
  assert.match(block,/SELECTED_RELAY_NOT_ACTIVE_GENERAL_RECOVERY/);
  assert.match(block,/SELECTED_RELAY_COUNTRY_MISMATCH_GENERAL_RECOVERY/);
});


test('Windows OpenVPN quality engine mirrors evidence-backed pool and profile safety controls',()=>{
  const build=fs.readFileSync(path.join(root,'backend/windows/scripts/Build-VpnGateUdpCache.ps1'),'utf8');
  assert.match(build,/Count=48/);
  assert.match(build,/PerCountry=6/);
  assert.match(build,/PreserveOld=8/);
  // Do not rely on an untrusted directive denylist. The shared allowlist must
  // be invoked at generation, during LKG preservation and before connector use.
  const policy=fs.readFileSync(path.join(root,'backend/windows/scripts/Profile-Policy.ps1'),'utf8');
  assert.match(policy,/function Test-OigVpnProfile/);
  assert.match(build,/Test-OigVpnProfile -Text \$text -ExpectedIP \$ip/);
  assert.match(build,/Test-OigVpnProfile -Text \$text -ExpectedIP \(\[string\]\$o.IP\)/);
  assert.doesNotMatch(build,/\x08/);
});

test('Windows VPN Gate refresh is bounded, parallel, HTTPS-first and merges multiple snapshots',()=>{
  const refresh=fs.readFileSync(path.join(root,'backend/windows/scripts/Refresh-VpnGateCache.ps1'),'utf8');
  assert.match(refresh,/https:\/\/www\.vpngate\.net/);
  assert.match(refresh,/--connect-timeout','2'/);
  assert.match(refresh,/--max-time','8'/);
  assert.match(refresh,/Diagnostics\.ProcessStartInfo/);
  assert.match(refresh,/sourceCount/);
  assert.match(refresh,/usedMirrors/);
  assert.match(refresh,/mergedRows/);
  assert.match(refresh,/cachedMergedRows/);
  assert.match(refresh,/liveMergedRows/);
  assert.match(refresh,/cachedSnapshotExisted/);
  assert.match(refresh,/liveMergedRows -ge 8/);
  assert.match(refresh,/MaxSources=3/);
});

test('VPN Gate source provenance never mistakes HTTP transport for authenticated HTTPS',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/config_factory.py'),'utf8');
  const refresh=fs.readFileSync(path.join(root,'backend/windows/scripts/Refresh-VpnGateCache.ps1'),'utf8');
  const status=fs.readFileSync(path.join(root,'backend/windows/scripts/Config-Factory.ps1'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  for(const text of [linux,refresh]){
    assert.match(text,/https:\/\/download\.vpngate\.jp/);
    assert.match(text,/sourceSecurity/);
    assert.match(text,/https-only/);
    assert.match(text,/http-fallback/);
    assert.match(text,/--proto-redir/);
  }
  assert.match(linux,/candidates\.sort\(key=lambda item:/);
  assert.match(refresh,/Prefer authenticated HTTPS transport/);
  assert.match(status,/sourceSecurity=\$sourceSecurity/);
  assert.match(renderer,/HTTP directory data is unauthenticated/);
  assert.match(renderer,/relay identity unverified/);
});

test('Windows source provenance downgrades mixed historical-cache snapshots to unknown',()=>{
  const src=fs.readFileSync(path.join(root,'backend/windows/scripts/Refresh-VpnGateCache.ps1'),'utf8');
  const f=src.slice(src.indexOf('function Get-DirectorySourceSecurity'),src.indexOf('$cachedSnapshotExisted'));
  assert.match(f,/CachedRows -gt 0/);
  assert.match(f,/return 'unknown'/);
  assert.match(f,/return 'http-fallback'/);
  assert.match(f,/return 'https-only'/);
  assert.match(src,/\$sourceSecurity=Get-DirectorySourceSecurity -Sources @\(\$used\) -CachedRows \$cachedAdded/);
});

test('Windows headless OpenVPN ranking consumes benchmark history and recent failure evidence',()=>{
  const headless=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8');
  const start=headless.indexOf('function Get-QualityScore');
  const end=headless.indexOf('function Resolve-ProfilePath',start);
  const block=headless.slice(start,end);
  assert.match(headless,/connection-benchmarks\.json/);
  for(const token of ['fastPingMs','downloadMbps','uploadMbps','httpsLatencyMs']) assert.ok(block.includes(token));
  assert.match(block,/Test-Fresh \$Failures\[\$Key\]\.last 6/);
  assert.match(block,/score-=320/);
  assert.match(block,/score\+=45/);
  assert.match(block,/\$limit=if\(\$OnlySha\)\{1\}else\{8\}/);
  assert.match(block,/Select-Object -First \$limit/);
  assert.match(headless,/first=\$first;count=\$count/);
});

test('Windows foreground connect qualifies before connector mutation while refresh preserves connect semantics',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const start=backend.indexOf('async action(action, options = {})');
  const end=backend.indexOf('\n  async diagnostics()',start);
  const block=backend.slice(start,end);
  assert.match(block,/this\.platform === 'win32' && action === 'connect'[\s\S]*benchmarkAllFast\(\)[\s\S]*_windows\('connect'\)/);
  assert.match(block,/this\.platform === 'win32' && \(action === 'refresh' \|\| action === 'factory-refresh'\)[\s\S]*_windows\(action\)[\s\S]*benchmarkAllFast\(\)/);
  assert.doesNotMatch(block,/this\.platform === 'win32'[\s\S]{0,220}action === 'refresh'[\s\S]{0,220}_windows\('connect'\)/);
});
test('Windows native handover keeps a physical shadow until isolated TAP data-plane readiness',()=>{
  const headless=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8').replace(/\r\n/g,'\n');
  assert.match(headless,/windows-physical-shadow\.json/);
  assert.match(headless,/shadow-handover-last\.json/);
  const physical=headless.slice(headless.indexOf('function Get-PhysicalDefaultPath'),headless.indexOf('function Add-PhysicalShadows'));
  assert.match(physical,/Refusing shadow path on tunnel-like default interface/);
  const add=headless.slice(headless.indexOf('function Add-PhysicalShadows'),headless.indexOf('function Get-ShadowState'));
  assert.match(add,/0\.0\.0\.0\/1/);
  assert.match(add,/128\.0\.0\.0\/1/);
  assert.match(add,/RouteMetric 1 -PolicyStore ActiveStore/);
  assert.match(add,/Refusing to add physical shadows while \/1 routes already exist/);
  const ready=headless.slice(headless.indexOf('function Wait-NativeReady'),headless.indexOf('function Stop-Connector'));
  assert.match(ready,/EVENT: CONNECTED/);
  assert.match(ready,/allow IPv4 traffic from TAP/);
  assert.match(ready,/NativeRoutes=\$native\.Count/);
  const data=headless.slice(headless.indexOf('function Wait-NativeDataPlane'),headless.indexOf('function Remove-PhysicalShadows'));
  assert.match(data,/1\.0\.0\.1\/32/);
  assert.match(data,/PolicyStore ActiveStore/);
  assert.match(data,/Test-TcpDataPlane '1\.0\.0\.1' 443 900/);
  assert.match(data,/finally/);
  assert.match(data,/Remove-NetRoute/);
});

test('Windows shadow takeover preserves native profile bytes and fails closed under physical cover',()=>{
  const headless=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8').replace(/\r\n/g,'\n');
  const ts=headless.indexOf('function Try-Candidate');
  const te=headless.indexOf('\n$mutex=',ts);
  const block=headless.slice(ts,te);
  assert.match(block,/Copy-Item -LiteralPath \$profile -Destination \$serviceProfile -Force/);
  assert.match(block,/ProgramData profile copy hash mismatch/);
  assert.doesNotMatch(block,/route-nopull|route-delay/);
  const addAt=block.indexOf('$shadow=Add-PhysicalShadows');
  const startAt=block.indexOf("Invoke-Connector @('start')");
  const nativeAt=block.indexOf('Wait-NativeReady');
  const dataAt=block.indexOf('Wait-NativeDataPlane');
  const removeAt=block.indexOf('Remove-PhysicalShadows');
  assert.ok(addAt >= 0 && addAt < startAt && startAt < nativeAt && nativeAt < dataAt && dataAt < removeAt);
  assert.match(block,/DATAPLANE_READY_FAIL.*Stop-Connector/);
  assert.match(block,/NATIVE_READY_FAIL.*Stop-Connector/);
  assert.match(block,/POST_TAKEOVER_HEALTH_FAIL/);
  const stop=headless.slice(headless.indexOf('function Stop-Connector'),headless.indexOf('function Stop-ServiceForConfig'));
  assert.match(stop,/Get-ShadowState/);
  assert.ok(stop.indexOf("Invoke-Connector @('stop')") < stop.indexOf('Remove-PhysicalShadows'));
});

test('Tray dashboard lifecycle never dereferences a destroyed or null BrowserWindow',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8').replace(/\r\n/g,'\n');
  const show=main.slice(main.indexOf('function showDashboard'),main.indexOf('function renderTray'));
  assert.match(show,/quitInProgress \|\| allowQuit \|\| app\.isQuitting/);
  assert.match(show,/!isLiveWindow\(mainWindow\)[\s\S]*createWindow\(\{ showWhenReady: true \}\)/);
  assert.match(show,/mainWindow\.isMinimized\(\)[\s\S]*mainWindow\.show\(\)[\s\S]*mainWindow\.focus\(\)/);
  assert.match(main,/Open Dashboard', click: showDashboard/);
  assert.match(main,/tray\.on\('double-click', showDashboard\)/);
  assert.doesNotMatch(main,/click: \(\) => \{ mainWindow\.show\(\)/);
  assert.doesNotMatch(main,/double-click', \(\) => \{ mainWindow\.show\(\)/);
  assert.match(main,/win\.on\('closed',[\s\S]*if \(mainWindow === win\) mainWindow = null/);
});

test('Windows clean-machine disconnect treats missing connector service as already off and does not require recovery task',()=>{
  const disconnect=fs.readFileSync(path.join(root,'backend/windows/scripts/Disconnect-OpenInternet.ps1'),'utf8').replace(/\r\n/g,'\n');
  const routeAt=disconnect.indexOf("$routes=@(Get-NetRoute");
  const alreadyAt=disconnect.indexOf("if($routes.Count -eq 0 -and (-not $svc -or $svc.Status -eq 'Stopped'))",routeAt);
  const taskAt=disconnect.indexOf("Get-ScheduledTask -TaskName 'OpenInternetGateway-AutoRecovery'",alreadyAt);
  const runAt=disconnect.indexOf('schtasks.exe /Run',taskAt);
  assert.ok(routeAt >= 0 && alreadyAt > routeAt && taskAt > alreadyAt && runAt > taskAt);
  assert.match(disconnect.slice(alreadyAt,taskAt),/DISCONNECTED - ALREADY OFF[\s\S]*exit 0/);
  assert.match(disconnect,/recovery task is missing while a managed tunnel may still be active/);
});

test('Windows first Connect bootstraps verified prerequisites before desired-state mutation',()=>{
  const connect=fs.readFileSync(path.join(root,'backend/windows/scripts/Connect-OpenInternet.ps1'),'utf8').replace(/\r\n/g,'\n');
  const connectorAt=connect.indexOf("$connector='C:\\Program Files\\OpenVPN Connect\\ovpnconnector.exe'");
  const taskAt=connect.indexOf("$taskName='OpenInternetGateway-AutoRecovery'");
  const installAt=connect.indexOf("Install-AutoRecovery.ps1",taskAt);
  const desiredAt=connect.indexOf("desired='on'");
  assert.ok(connectorAt >= 0 && taskAt > connectorAt && installAt > taskAt && desiredAt > installAt);
  assert.match(connect,/Administrator approval is required once for first-time setup/);
  const installer=fs.readFileSync(path.join(root,'backend/windows/scripts/Install-AutoRecovery.ps1'),'utf8');
  assert.match(installer,/Join-Path \$PSHOME 'pwsh\.exe'/);
  assert.match(installer,/Start-Process -FilePath \$pwsh -Verb RunAs -Wait -PassThru/);
  assert.match(installer,/Elevated Auto-Recovery setup returned without creating the recovery task/);
});

test('Windows backend installer has no dead Install-Launcher reference',()=>{
  const install=fs.readFileSync(path.join(root,'backend/windows/Install.ps1'),'utf8');
  assert.doesNotMatch(install,/Install-Launcher\.ps1/);
  assert.match(install,/Install-AutoRecovery\.ps1/);
  assert.ok(fs.existsSync(path.join(root,'backend/windows/scripts/Install-AutoRecovery.ps1')));
});

test('Windows package bundles verified portable PowerShell 7',()=>{
  const pkg=JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8'));
  assert.match(pkg.scripts['dist:win'],/prepareWindowsPwsh\.js/);
  assert.ok(pkg.build.win.extraResources.some(x=>x.from==='vendor/pwsh'&&x.to==='pwsh'));
  const prep=fs.readFileSync(path.join(root,'tools/prepareWindowsPwsh.js'),'utf8');
  assert.match(prep,/const VERSION = '7\.5\.4'/);
  assert.match(prep,/PowerShell-\$\{VERSION\}-win-x64\.zip/);
  assert.match(prep,/b40d192ae95ba6ccc4cc362ff4e1b18ca6fb5055bebbcd3920684e12701fa8f6/);
  assert.match(prep,/const PWSH_URL = `https:\/\/github\.com\/PowerShell\/PowerShell\/releases\/download\/v\$\{VERSION\}/);
  assert.doesNotMatch(prep,/const URL =/);
  assert.match(prep,/SHA-256 mismatch/);
  assert.match(prep,/pwsh\.exe/);
});

test('Windows first-connect OpenVPN prerequisite is pinned, verified and installed through Windows Installer',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8').replace(/\r\n/g,'\n');
  assert.match(backend,/openvpn-connect-3\.9\.0\.5008_signed\.msi/);
  assert.match(backend,/31347812dd37dbbb69bc47de842eb179827266e9dfb45e7f6ce10c5d71a5bad6/);
  assert.match(backend,/https:\/\/swupdate\.openvpn\.net\/downloads\/connect\/openvpn-connect-3\.9\.0\.5008_signed\.msi/);
  const ensure=backend.slice(backend.indexOf('async _ensureWindowsConnector'),backend.indexOf('async _ensureWindowsRuntimePrerequisites'));
  assert.match(ensure,/downloaded\.sha256/);
  assert.match(ensure,/WINDOWS_OPENVPN_CONNECT\.sha256/);
  assert.match(ensure,/Start-Process -FilePath 'msiexec\.exe' -Verb RunAs -Wait -PassThru/);
  assert.match(ensure,/\$msi='" \+ escapedMsi \+ "'/);
  assert.match(ensure,/\$msiArgs='\/i \\"' \+ \$msi \+ '\\" \/passive \/norestart'/);
  assert.match(ensure,/ArgumentList \$msiArgs/);
  assert.match(ensure,/run\(pwsh, \['-NoProfile','-Command',elevate\]/);
  assert.match(ensure,/administrator approval was cancelled/);
  assert.match(ensure,/ovpnconnector\.exe is still missing/);
  const actionStart=backend.indexOf('async action(action, options = {})');
  const action=backend.slice(actionStart,backend.indexOf('\n  async diagnostics()',actionStart));
  const pre=action.indexOf('await this._ensureWindowsRuntimePrerequisites()');
  const bench=action.indexOf('await this.benchmarkAllFast()');
  assert.ok(pre >= 0 && bench > pre);
  assert.match(action,/action === 'connect' \|\| action === 'connect-profile'/);
});

test('Windows update helper uses an isolated copy of bundled PowerShell instead of PATH lookup',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8').replace(/\r\n/g,'\n');
  const start=backend.indexOf('async launchDownloadedUpdate');
  const end=backend.indexOf("if (this.platform === 'linux')",start);
  const block=backend.slice(start,end);
  assert.match(block,/const bundledPwshRoot = path\.join\(this\.resourcesPath \|\| '', 'pwsh'\)/);
  assert.match(block,/copyDir\(bundledPwshRoot, helperRuntime\)/);
  assert.match(block,/updatePwsh = path\.join\(helperRuntime, 'pwsh\.exe'\)/);
  assert.match(block,/spawn\(updatePwsh, pwshArgs/);
  assert.doesNotMatch(block,/where\.exe pwsh\.exe|process\.env\.ComSpec|apply-update\.cmd/);
});


test('real VPN throughput rejects physical ISP routes and binds Linux transfers to the tunnel', async()=>{
  const Backend = require('../src/main/platform-backend');
  const b = new Backend({
    version: '2.5.20', appPath: root, resourcesPath: root,
    userData: root, emit: () => {}
  });
  b.platform = 'linux';
  b.profiles = async () => { throw new Error('Must not read inventory before tunnel guard'); };
  b.status = async () => ({ connected: true, fullRoutes: 0, interface: 'enp1s0' });
  await assert.rejects(b.benchmarkActive(), /active full-route VPN/);
  b.status = async () => ({ connected: true, fullRoutes: 2, interface: 'enp1s0' });
  await assert.rejects(b.benchmarkActive(), /VPN tunnel interface cannot be verified/);
  assert.deepEqual(
    await b._activeTunnelCurlArgs({ connected: true, fullRoutes: 2, interface: 'tun0' }),
    ['-4','--noproxy','*','--interface','if!tun0']
  );
  for (const suspicious of ['enp1s0', 'wg0', 'tun0;id', '--option', '']) {
    await assert.rejects(
      () => b._activeTunnelCurlArgs({ connected: true, fullRoutes: 2, interface: suspicious }),
      /VPN tunnel interface cannot be verified/
    );
  }
  b.platform = 'win32';
  await assert.rejects(() => b._activeTunnelCurlArgs({ connected: true, fullRoutes: 0 }),
    /active full-route VPN/);
  await assert.rejects(() => b._activeTunnelCurlArgs({ connected: true, fullRoutes: 2 }),
    /Windows managed VPN interface is missing/);
  const source = fs.readFileSync(path.join(root, 'src/main/platform-backend.js'), 'utf8');
  const active = source.slice(source.indexOf('  async benchmarkActive()'),
    source.indexOf('  _githubHeaders()', source.indexOf('  async benchmarkActive()')));
  assert.ok((active.match(/\.\.\.tunnelCurlArgs/g) || []).length >= 2,
    'VPN download and upload both require the verified tunnel args');
  assert.match(active, /this\._httpsLatencyMs\(sink, tunnelCurlArgs\)/);
  assert.match(active, /const endStatus = await this\.status\(\)/);
  assert.match(active, /result discarded/);
  assert.ok(active.indexOf('const endStatus = await this.status()') <
            active.indexOf('this._writeJson('),
    'Do not persist a throughput claim after the VPN route changed');
});

test('Windows tunnel speed is bound to a uniquely verified VPN IPv4 source, never an unbound physical connection',async()=>{
  const vm = require('node:vm');
  const {EventEmitter} = require('node:events');
  const source = fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const calls = [];
  let output = '10.19.0.8';
  // Intercept only the child process API in this isolated VM. No PowerShell,
  // Windows network, OpenVPN connector, or actual Internet request is invoked.
  const fakeSpawn = (program,argv,options)=>{
    const child = new EventEmitter();
    child.stdin = new EventEmitter();
    child.stdin.end = ()=>{};
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    calls.push({program,argv,options});
    process.nextTick(()=>{
      child.stdout.emit('data',Buffer.from(output));
      child.emit('close',0);
    });
    return child;
  };
  const moduleObj = {exports:{}};
  vm.runInNewContext(source,{
    module:moduleObj,exports:moduleObj.exports,process,Buffer,setTimeout,clearTimeout,
    require:n=>n==='child_process'?{spawn:fakeSpawn}:require(n)
  },{filename:'platform-backend-test-vm.js'});
  const b=new moduleObj.exports({version:'2.5.20',appPath:root,resourcesPath:root,userData:root});
  b.platform='win32';
  b._requireWindowsPwsh=()=> 'qa-fake-pwsh.exe';
  const route = {connected:true,fullRoutes:2,interface:'OIG OpenVPN QA Device'};
  const args = await b._activeTunnelCurlArgs(route);
  assert.deepEqual(Array.from(args),['-4','--noproxy','*','--interface','host!10.19.0.8']);
  assert.equal(calls.length,1);
  assert.equal(calls[0].program,'qa-fake-pwsh.exe');
  assert.equal(calls[0].options.env.OIG_SPEED_TUNNEL_IFACE,route.interface);
  const ps=calls[0].argv.at(-1);
  assert.match(ps,/Get-NetRoute -AddressFamily IPv4/);
  assert.match(ps,/0\.0\.0\.0\/1/);
  assert.match(ps,/128\.0\.0\.0\/1/);
  assert.match(ps,/\$routes\.Count -ne 2/);
  assert.match(ps,/\$indexes\.Count -ne 1/);
  assert.match(ps,/Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex/);
  assert.doesNotMatch(ps,/OIG OpenVPN QA Device/,'VPN alias must never be shell-interpolated');
  for(const invalid of ['127.0.0.1','169.254.1.2','bad-response','10.19.0.8\n10.19.0.9']){
    output=invalid;
    await assert.rejects(b._activeTunnelCurlArgs(route),/no trustworthy IPv4 source/);
  }
  assert.equal(calls.length,5);
  await assert.rejects(
    b._activeTunnelCurlArgs({...route,interface:'VPN\nmalicious'}),
    /Windows managed VPN interface is missing or invalid/
  );
  const active=source.slice(source.indexOf('  async benchmarkActive()'),
    source.indexOf('  _githubHeaders()',source.indexOf('  async benchmarkActive()')));
  assert.match(active,/await this\._activeTunnelCurlArgs\(status\)/);
  assert.match(active,/endStatus\.interface !== status\.interface/);
  assert.match(active,/vpn-source-ip-bound/);
});

test('real throughput never persists measurements when VPN source or active relay changes mid-transfer',async()=>{
  const vm = require('node:vm');
  const os = require('node:os');
  const {EventEmitter} = require('node:events');
  const source = fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const fakeSpawn = (file,args)=>{
    assert.equal(file,'curl','Only inert mocked curl transfers may execute');
    const child=new EventEmitter();
    child.stdin=new EventEmitter();child.stdin.end=()=>{};
    child.stdout=new EventEmitter();child.stderr=new EventEmitter();
    process.nextTick(()=>{
      const upload=args.includes('-X');
      child.stdout.emit('data',Buffer.from(upload?'200|1|62500':'200|1|1250000'));
      child.emit('close',0);
    });
    return child;
  };
  const mod={exports:{}};
  vm.runInNewContext(source,{module:mod,exports:mod.exports,process,Buffer,setTimeout,clearTimeout,
    require:n=>n==='child_process'?{spawn:fakeSpawn}:require(n)},{filename:'backend-no-real-traffic-test.js'});
  const profileSha='a'.repeat(64);
  async function exercise(mode){
    const temp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-throughput-route-guard-'));
    try{
      const b=new mod.exports({version:'2.5.20',appPath:root,resourcesPath:root,userData:temp});
      b.platform='win32';b.backendRoot=temp;
      let statusReads=0;let profileReads=0;let tunnelIp='10.19.0.2';
      b.status=async()=>{
        statusReads++;
        if(mode==='source-change' && statusReads===2)tunnelIp='10.19.0.3';
        return {connected:mode!=='disconnect'||statusReads===1,fullRoutes:2,interface:'OIG VPN Alias'};
      };
      b._activeTunnelCurlArgs=async()=>['-4','--noproxy','*','--interface','host!'+tunnelIp];
      b.profiles=async()=>{
        profileReads++;
        const moved=mode==='relay-change'&&profileReads>1;
        return {activeSha:moved?'b'.repeat(64):profileSha,
          profiles:[{active:true,sha256:moved?'b'.repeat(64):profileSha,ip:'198.51.100.1',
            host:'synthetic.test',country:'US',benchmark:null}]};
      };
      b._httpsLatencyMs=async()=>55;
      b._icmpPing=async()=>77;
      const persisted=path.join(temp,'state','connection-benchmarks.json');
      if(mode==='stable'){
        const x=await b.benchmarkActive();
        assert.equal(x.ok,true);
        assert.equal(x.benchmark.throughputPath,'vpn-source-ip-bound');
        assert.ok(x.benchmark.downloadMbps>0&&x.benchmark.uploadMbps>0);
        assert.equal(x.benchmark.tunnelRouteVerifiedAfterTransfer,true);
        assert.equal(JSON.parse(fs.readFileSync(persisted,'utf8'))[profileSha].sha256,profileSha);
        assert.equal(statusReads,2);
        assert.equal(profileReads,2);
      }else{
        const error=mode==='source-change'?/tunnel source changed/:
          mode==='relay-change'?/Active VPN relay rotated/:/route or active connection changed/;
        await assert.rejects(b.benchmarkActive(),error);
        assert.equal(fs.existsSync(persisted),false,
          'Never persist stale speed values after tunnel change '+mode);
      }
    }finally{fs.rmSync(temp,{recursive:true,force:true})}
  }
  for(const mode of ['stable','source-change','relay-change','disconnect'])await exercise(mode);
});

test('Windows packaged capture QA is fail-closed and never writes the real installed backend or registers autostart', async()=>{
  const Backend=require('../src/main/platform-backend');
  const os=require('node:os');
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-passive-win-capture-'));
  const vars=['OIG_CAPTURE_ONLY','OIG_CAPTURE_ROOT','LOCALAPPDATA'];
  const previous=Object.fromEntries(vars.map(name=>[name,process.env[name]]));
  try {
    const fakeResource=path.join(tmp,'app','backend','windows');
    fs.mkdirSync(fakeResource,{recursive:true});
    fs.writeFileSync(path.join(fakeResource,'OpenInternetGateway.ps1'),'# harmless fixture');
    const realUserLocal=path.join(tmp,'real-user-local');
    const installed=path.join(realUserLocal,'OpenInternetGateway');
    fs.mkdirSync(installed,{recursive:true});
    const sentinel=path.join(installed,'OpenInternetGateway.ps1');
    fs.writeFileSync(sentinel,'USER_BACKEND_MUST_NOT_BE_REPLACED');
    process.env.LOCALAPPDATA=realUserLocal;
    process.env.OIG_CAPTURE_ONLY='1';
    delete process.env.OIG_CAPTURE_ROOT;
    const makeBackend=()=>{
      const b=new Backend({version:'2.5.20',appPath:path.join(tmp,'app'),
        resourcesPath:path.join(tmp,'app'),userData:path.join(tmp,'user-data')});
      b.platform='win32';
      return b;
    };
    await assert.rejects(makeBackend().initialize(),/isolated absolute OIG_CAPTURE_ROOT/);
    process.env.OIG_CAPTURE_ROOT='relative-scratch';
    await assert.rejects(makeBackend().initialize(),/isolated absolute OIG_CAPTURE_ROOT/);
    const privateRoot=path.join(tmp,'capture-only-qa');
    process.env.OIG_CAPTURE_ROOT=privateRoot;
    const b=makeBackend();
    await b.initialize();
    assert.equal(b.backendRoot,path.join(privateRoot,'backend-windows'));
    assert.equal(fs.readFileSync(path.join(b.backendRoot,'OpenInternetGateway.ps1'),'utf8'),
      '# harmless fixture');
    assert.equal(fs.readFileSync(sentinel,'utf8'),'USER_BACKEND_MUST_NOT_BE_REPLACED');
    const entry=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
    assert.match(entry,/app\.isPackaged && process\.env\.OIG_CAPTURE_ONLY !== '1'/,
      "QA must not register the user's Windows login autostart");
    assert.match(entry,/process\.platform !== 'win32' \|\| process\.env\.OIG_CAPTURE_ONLY !== '1'\) createTray\(\)/,
      'QA must not create a notification icon in the real Windows tray');
    const frame=entry.slice(entry.indexOf("win.once('ready-to-show'"),
      entry.indexOf("win.on('close'"));
    assert.ok(frame.indexOf('fs.writeFileSync(process.env.OIG_CAPTURE_PATH') >= 0,
      'Capture frame must be stored before quitting');
    assert.ok(frame.indexOf('app.exit(0)') >
      frame.indexOf('fs.writeFileSync(process.env.OIG_CAPTURE_PATH'),
      'Capture must exit the Electron process unconditionally after writing the frame');
  } finally {
    for(const name of vars){
      if(previous[name]===undefined)delete process.env[name];else process.env[name]=previous[name];
    }
    fs.rmSync(tmp,{recursive:true,force:true});
  }
});

test('Windows direct ISP requires the winning physical route before claiming physical speed',async()=>{
  const vm=require('node:vm');
  const os=require('node:os');
  const {EventEmitter}=require('node:events');
  const source=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const calls=[];
  let redirectedDestination='';
  const spawnMock=(program,args,options)=>{
    const cmd=args.at(-1);
    let response='';
    if(program==='qa-pwsh.exe'){
      const to=options.env.OIG_DIRECT_REMOTE_IPV4;
      assert.match(cmd,/Find-NetRoute -RemoteIPAddress/);
      assert.equal(options.env.OIG_DIRECT_LOCAL_IPV4,'192.0.2.10');
      assert.equal(options.env.OIG_DIRECT_IFINDEX,'17');
      calls.push(to);
      response=to===redirectedDestination?'REJECTED_FAKE_VPN_ROUTE':'VERIFIED_DIRECT_ROUTE';
    }else if(program==='curl'){
      if(args.includes('--data-binary'))response='200|1|900000|203.0.113.21';
      else if(args.some(a=>String(a).includes('__down')))response='200|1|1800000|203.0.113.20';
      else response='ip=203.0.113.50\\nloc=US';
    }else throw Error('Unexpected external process in QA route fixtures '+program);
    const child=new EventEmitter();child.stdin=new EventEmitter();child.stdin.end=()=>{};
    child.stdout=new EventEmitter();child.stderr=new EventEmitter();
    process.nextTick(()=>{child.stdout.emit('data',Buffer.from(response));child.emit('close',0)});
    return child;
  };
  const mod={exports:{}};
  vm.runInNewContext(source,{
    module:mod,exports:mod.exports,process,Buffer,setTimeout,clearTimeout,
    require:n=>n==='child_process'?{spawn:spawnMock}:require(n)
  },{filename:'windows-direct-route-no-real-network-fixture.js'});
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-win-direct-winning-route-'));
  try {
    const b=new mod.exports({version:'2.5.20',appPath:root,resourcesPath:root,userData:temp});
    b.platform='win32';b.backendRoot=temp;b._requireWindowsPwsh=()=> 'qa-pwsh.exe';
    const routeSelection = source.slice(source.indexOf("  async _directInternetPath()"),
      source.indexOf("  async _assertWindowsDirectEgress("));
    assert.match(routeSelection,/\.HardwareInterface/,
      'Only a physical hardware adapter can qualify as ISP');
    assert.doesNotMatch(routeSelection,/if\(-not \$r\)\{\$r=\$routes/,
      'Do not fall back to a virtual Windows route when no hardware adapter exists');
    const physical={interface:'Ethernet QA',index:17,localIP:'192.0.2.10',gateway:'192.0.2.1',
      curlInterface:'host!192.0.2.10',bindMode:'physical-ip'};
    for(const invalid of ['', 'not-an-ip', '::1','127.0.0.1/8']){
      await assert.rejects(b._assertWindowsDirectEgress(physical,invalid),/invalid remote\/source/);
    }
    await b._assertWindowsDirectEgress(physical,'1.1.1.1');
    assert.equal(calls.at(-1),'1.1.1.1');
    redirectedDestination='203.0.113.21';
    await assert.rejects(b._assertWindowsDirectEgress(physical,'203.0.113.21'),
      /refused rather than attributing VPN traffic/);
    assert.equal(calls.at(-1),'203.0.113.21');
    const tempJson=path.join(temp,'state','direct-internet-benchmark.json');
    b._directInternetPath=async()=>physical;
    b._directTrace=async()=>({publicIP:'203.0.113.50',country:'US',colo:'QA',
      httpsLatencyMs:20,remoteIP:'203.0.113.19'});
    b._icmpPing=async()=>42;
    await assert.rejects(b.benchmarkDirectInternet(),
      /refused rather than attributing VPN traffic/);
    assert.equal(fs.existsSync(tempJson),false,
      'Windows direct ISP result must not be persisted after winning route changed');
    assert.equal(fs.existsSync(path.join(temp,'state','direct-benchmark-upload.bin')),false,
      'QA upload payload must be removed on refusal');
    redirectedDestination='';
    const ok=await b.benchmarkDirectInternet();
    assert.equal(ok.ok,true);
    assert.equal(ok.benchmark.effectiveRouteVerified,true);
    assert.equal(ok.benchmark.interface,'Ethernet QA');
    assert.equal(ok.benchmark.downloadMbps,14.4);
    assert.equal(ok.benchmark.uploadMbps,7.2);
    assert.deepEqual(calls.slice(-3),['203.0.113.19','203.0.113.20','203.0.113.21']);
    assert.equal(JSON.parse(fs.readFileSync(tempJson,'utf8')).effectiveRouteVerified,true);
  }finally{fs.rmSync(temp,{recursive:true,force:true})}
});
