'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const Backend = require('../src/main/platform-backend');

const root = path.join(__dirname, '..');
const guard = path.join(root, 'backend/windows/scripts/Guard-IndependentVpn.ps1');
const backendSource = fs.readFileSync(path.join(root, 'src/main/platform-backend.js'), 'utf8');

test('Windows prerequisite safety guard is read-only and inspects native VPN, tunnel adapters and split routes', () => {
  const script = fs.readFileSync(guard, 'utf8');
  assert.match(script, /Get-VpnConnection -ErrorAction Stop/);
  assert.match(script, /Get-NetAdapter -ErrorAction Stop/);
  assert.match(script, /Get-NetRoute -ErrorAction Stop/);
  assert.match(script, /ConnectionStatus -eq 'Connected'/);
  assert.match(script, /'0\.0\.0\.0\/1','128\.0\.0\.0\/1','::\/1','8000::\/1'/);
  assert.match(script, /exit 17/);
  assert.match(script, /exit 18/);
  assert.doesNotMatch(script,
    /\b(?:Stop|Start|Restart|Set|Remove|New|Disable|Enable)-(?:Service|NetRoute|NetAdapter|VpnConnection|DnsClientServerAddress)|Invoke-Expression|Start-Process|schtasks|msiexec/i);
  const installStart = backendSource.indexOf('async _ensureWindowsConnector()');
  const firstGuard = backendSource.indexOf('await this._assertWindowsIndependentVpnInactive()', installStart);
  const download = backendSource.indexOf('this._downloadHttpsFile(WINDOWS_OPENVPN_CONNECT.url, msi)', installStart);
  const secondGuard = backendSource.indexOf('await this._assertWindowsIndependentVpnInactive()', firstGuard + 1);
  const elevatedMsi = backendSource.indexOf('const install = await run(pwsh', download);
  assert.ok(installStart >= 0 && installStart < firstGuard && firstGuard < download);
  assert.ok(download < secondGuard && secondGuard < elevatedMsi, 'guard must recheck before UAC/MSI');
  assert.match(backendSource, /Guard-IndependentVpn\.ps1/);
  assert.match(backendSource, /Another Windows VPN or tunnel is active/);
});

test('Windows native dependency installer cannot download or request UAC when guard refuses active VPN', async () => {
  const b = new Backend({version: '2.5.20', appPath: root, resourcesPath: root});
  b.platform = 'win32';
  b.backendRoot = path.join(__dirname, 'no-system-installs');
  b._windowsConnectorPath = () => path.join(b.backendRoot, 'absent-connector.exe');
  let guardChecks = 0;
  let startedDownloads = 0;
  b._assertWindowsIndependentVpnInactive = async () => {
    guardChecks++;
    throw new Error('Another Windows VPN or tunnel is active.');
  };
  b._downloadHttpsFile = async () => { startedDownloads++; throw new Error('UNEXPECTED_DOWNLOAD'); };
  await assert.rejects(b._ensureWindowsConnector(), /Another Windows VPN or tunnel is active/);
  assert.equal(guardChecks, 1);
  assert.equal(startedDownloads, 0);
});

test('native Windows independent VPN observation succeeds or explicitly refuses without modifying routes', {
  skip: process.platform !== 'win32'
}, () => {
  const p = spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-File', guard], {
    encoding: 'utf8', timeout: 16000, windowsHide: true
  });
  if (p.error) throw p.error;
  assert.ok(p.status === 0 || p.status === 17,
    'The read-only guard must detect absence or presence of independent VPN, not return unknown: ' + p.status);
  assert.equal((p.stdout || '').trim(), '');
  assert.equal((p.stderr || '').trim(), '');
});
