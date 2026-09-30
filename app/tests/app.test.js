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
  assert.match(main,/mainWindow\.show\(\)/);
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
  const serviceConfigBlock=headless.slice(headless.indexOf('function Ensure-ServiceInstalled'),headless.indexOf('function Stop-Connector'));
  assert.match(serviceConfigBlock,/Stop-ServiceForConfig[\s\S]*set-config','profile'/);
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
  assert.match(main,/mainWindow\.on\('close'/);
  assert.match(main,/mainWindow\.hide\(\)/);
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
  assert.match(main,/mainWindow\.on\('closed'/);
  assert.match(main,/mainWindow = null/);
  assert.match(main,/mainWindow && !mainWindow\.isDestroyed\(\)/);
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
  assert.match(winFactory,/PerCountry=4/);
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
  assert.match(block,/No fallback relay was accepted[\s\S]*savePreferred\(\);[\s\S]*return \{ ok: true/);
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
  await assert.rejects(backend.connectProfile(target.sha256),/previous working relay could not be restored automatically/i);
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

test('GitHub workflows use current hosted-runner actions and Node LTS',()=>{
  const build=fs.readFileSync(path.resolve(root,'..','.github','workflows','build.yml'),'utf8');
  const release=fs.readFileSync(path.resolve(root,'..','.github','workflows','release.yml'),'utf8');
  for(const wf of [build,release]) {
    assert.doesNotMatch(wf,/actions\/checkout@v4/);
    assert.doesNotMatch(wf,/actions\/setup-node@v4/);
    assert.doesNotMatch(wf,/node-version:\s*['"]22['"]/);
    assert.match(wf,/actions\/checkout@v7/);
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
