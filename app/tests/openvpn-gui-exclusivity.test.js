const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.join(__dirname,'..');
const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8').replace(/\r\n/g,'\n');
const ensure=fs.readFileSync(path.join(root,'backend/windows/scripts/Ensure-OpenInternet.ps1'),'utf8').replace(/\r\n/g,'\n');
const daemon=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8').replace(/\r\n/g,'\n');
const hostedHarness=fs.readFileSync(path.join(root,'tests/hosted-first-connect.cjs'),'utf8').replace(/\r\n/g,'\n');
const hostedWrapper=fs.readFileSync(path.join(root,'tests/hosted-first-connect.ps1'),'utf8').replace(/\r\n/g,'\n');

test('first-time OpenVPN MSI suppresses the package-verified post-install GUI launch',()=>{
  const install=backend.slice(backend.indexOf('async _ensureWindowsConnector()'),backend.indexOf('async _ensureWindowsRuntimePrerequisites()'));
  assert.match(install,/\/quiet \/norestart/);
  assert.match(install,/\/quiet \/norestart AUTOSTART=no/);
  assert.doesNotMatch(install,/Start-Process[^\r\n]*OpenVPNConnect|OpenVPNConnect\.exe/i);
  assert.match(install,/sha256 !== WINDOWS_OPENVPN_CONNECT\.sha256/);
  assert.match(install,/Start-Process -FilePath 'msiexec\.exe' -Verb RunAs/);
});

test('Connect refuses an existing independent GUI before MSI download/install and never terminates it',()=>{
  const begin=backend.indexOf('async _ensureWindowsRuntimePrerequisites()');
  const end=backend.indexOf('async _windows(action',begin);
  const block=backend.slice(begin,end);
  const first=block.indexOf('await assertGuiClosed()');
  const setup=block.indexOf('await this._ensureWindowsConnector()');
  const second=block.lastIndexOf('await assertGuiClosed()');
  assert.ok(first>=0 && setup>first && second>setup);
  assert.equal((block.match(/await assertGuiClosed\(\)/g)||[]).length,2);
  assert.match(block,/Get-Process -Name 'OpenVPNConnect' -ErrorAction Stop/);
  assert.match(block,/NoProcessFoundForGivenName/);
  assert.match(block,/interactive\.code === 17/);
  assert.match(block,/No OpenVPN process was closed/);
  assert.doesNotMatch(block,/Stop-Process|taskkill|Kill\(/);
});

test('Ensure refuses GUI before bootstrapping the headless connector and cancels queued exact intent',()=>{
  const guard=ensure.indexOf('function Assert-OigOpenVpnGuiClosed');
  const exact=ensure.indexOf('if(Test-Path $exactRequest)');
  const exactCall=ensure.indexOf('Assert-OigOpenVpnGuiClosed',exact);
  const exactBootstrap=ensure.indexOf('Bootstrap-HeadlessConnector.ps1',exact);
  const generic=ensure.indexOf("if(-not $svc -or -not $ready){",exactBootstrap+1);
  const genericCall=ensure.indexOf('Assert-OigOpenVpnGuiClosed',generic);
  const genericBootstrap=ensure.indexOf('Bootstrap-HeadlessConnector.ps1',generic);
  assert.ok(guard>=0 && exact>=0 && exactCall>exact && exactBootstrap>exactCall);
  assert.ok(generic>exactBootstrap && genericCall>generic && genericBootstrap>genericCall);
  assert.match(ensure,/Get-Process -Name 'OpenVPNConnect' -ErrorAction Stop/);
  assert.match(ensure,/NoProcessFoundForGivenName/);
  assert.match(ensure,/desired='off'/);
  assert.match(ensure,/exact-profile\.request/);
});

test('elevated action checks GUI before Config Factory, service install, and route mutation',()=>{
  const actionStart=daemon.indexOf("if($Action -eq 'Connect'){Assert-OigNoIndependentVpn;Save-Desired 'on'}");
  const config=daemon.indexOf("Config-Factory.ps1') -Action Ensure",actionStart);
  const service=daemon.indexOf('Ensure-ServiceInstalled',actionStart);
  const firstGuard=daemon.indexOf('Assert-OpenVpnGuiClosed',actionStart);
  const lastGuard=daemon.lastIndexOf('Assert-OpenVpnGuiClosed',service);
  assert.ok(actionStart>=0 && firstGuard>actionStart && config>firstGuard);
  assert.ok(lastGuard>config && service>lastGuard);
  assert.match(daemon,/function Assert-OpenVpnGuiClosed/);
  assert.match(daemon,/Get-Process -Name 'OpenVPNConnect' -ErrorAction Stop/);
  assert.match(daemon,/NoProcessFoundForGivenName/);
  assert.match(daemon,/Save-Desired 'off'/);
  assert.doesNotMatch(daemon,/Stop-Process|taskkill/);
});

test('hosted first-connect requires real VPN-source-bound download/upload and records identity trust state',()=>{
  assert.match(hostedHarness,/schema:'oig-hosted-first-connect-v2'/);
  assert.match(hostedHarness,/await b\.benchmarkActive\(\)/);
  assert.match(hostedHarness,/throughputPath==='vpn-source-ip-bound'/);
  assert.match(hostedHarness,/tunnelRouteVerifiedAfterTransfer===true/);
  assert.match(hostedHarness,/downloadMbps/);
  assert.match(hostedHarness,/uploadMbps/);
  assert.match(hostedHarness,/serverIdentityVerified/);
  assert.match(hostedHarness,/FIRST_CONNECT_DATA_PLANE_VALIDATION/);
  assert.match(hostedWrapper,/report\.schema -ne 'oig-hosted-first-connect-v2'/);
  assert.match(hostedWrapper,/report\.checks\.throughput/);
  assert.match(hostedWrapper,/report\.serverIdentityVerified -isnot \[bool\]/);
  assert.match(hostedWrapper,/HOSTED_FIRST_CONNECT_DATA_PLANE_PASS/);
});

test('candidate rechecks GUI immediately before stopping/configuring the service',()=>{
  const begin=daemon.indexOf('function Try-Candidate($c)');
  const end=daemon.indexOf(' $native=Wait-NativeReady',begin);
  const block=daemon.slice(begin,end);
  const inspect=block.indexOf('Assert-OpenVpnGuiClosed');
  const teardown=block.indexOf('Stop-Connector');
  const shadows=block.indexOf('Add-PhysicalShadows');
  assert.ok(inspect>=0 && teardown>inspect && shadows>teardown);
});
