const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.join(__dirname,'..');
const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8').replace(/\r\n/g,'\n');
const daemon=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8').replace(/\r\n/g,'\n');

test('first-time OpenVPN MSI is silent and does not request GUI autostart',()=>{
  const install=backend.slice(backend.indexOf('async _ensureWindowsConnector()'),backend.indexOf('async _ensureWindowsRuntimePrerequisites()'));
  assert.match(install,/\/quiet \/norestart AUTOSTART=no/);
  assert.doesNotMatch(install,/\/passive/);
  assert.match(install,/sha256 !== WINDOWS_OPENVPN_CONNECT\.sha256/);
  assert.match(install,/Start-Process -FilePath 'msiexec\.exe' -Verb RunAs/);
});
test('Connect refuses existing independent GUI rather than terminating it',()=>{
  const begin=backend.indexOf('async _ensureWindowsRuntimePrerequisites()');
  const end=backend.indexOf('async _windows(action',begin);
  const block=backend.slice(begin,end);
  assert.match(block,/Get-Process -Name 'OpenVPNConnect'/);
  assert.match(block,/interactive\.code === 17/);
  assert.match(block,/No OpenVPN process was closed/);
  assert.doesNotMatch(block,/Stop-Process|taskkill|Kill\(/);
  assert.ok(block.indexOf("Get-Process")<block.indexOf('return { powerShell7'));
});
test('elevated connector refuses GUI before touching service, profile or routes',()=>{
  const begin=daemon.indexOf('function Try-Candidate($c)');
  const end=daemon.indexOf(' $native=Wait-NativeReady',begin);
  const block=daemon.slice(begin,end);
  const inspect=block.indexOf("Get-Process -Name 'OpenVPNConnect'");
  const teardown=block.indexOf('Stop-Connector');
  const shadows=block.indexOf('Add-PhysicalShadows');
  assert.ok(inspect>=0 && teardown>inspect && shadows>teardown);
  assert.match(block,/throw 'OpenVPN Connect GUI is already running/);
  assert.doesNotMatch(block,/Stop-Process|taskkill/);
});
