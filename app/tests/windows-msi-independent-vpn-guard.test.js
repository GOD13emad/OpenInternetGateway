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


test('Windows first-Connect and exact-profile connect refuse competing VPN before prerequisite or route mutation', async () => {
  const b = new Backend({version: '2.5.20', appPath: root, resourcesPath: root});
  b.platform = 'win32';
  b.backendRoot = path.join(__dirname, 'no-network-operations');
  let guards = 0, preparations = 0, attempts = 0;
  b._windows = async action => {
    if (action === 'status') return {connected: false, engine: 'HeadlessConnector'};
    attempts++;
    throw new Error('UNEXPECTED_NETWORK_MUTATION:' + action);
  };
  b._assertWindowsIndependentVpnInactive = async () => {
    guards++;
    throw new Error('Independent Windows VPN is already active.');
  };
  b.prepareWindowsInstallerPrerequisites = async () => {preparations++;};
  for (const action of ['connect', 'connect-profile']) {
    await assert.rejects(b.action(action, {sha256: 'a'.repeat(64)}),
      /Independent Windows VPN is already active/);
  }
  assert.equal(guards, 2);
  assert.equal(preparations, 0);
  assert.equal(attempts, 0);
  assert.equal(b.gatewayActionCount, 0);
});

test('Windows unknown status fails closed and an already verified OIG-managed tunnel avoids false takeover refusal', async () => {
  const b = new Backend({version: '2.5.20', appPath: root, resourcesPath: root});
  b.platform = 'win32';
  b.backendRoot = path.join(__dirname, 'no-network-operations');
  let mode = 'unknown', guards = 0, mutations = 0;
  const healthy = {connected: true, engine: 'HeadlessConnector', managedInterfaceIndex: 42};
  b._windows = async action => {
    if (action === 'status') {
      if (mode === 'unknown') throw new Error('STATUS_NOT_AVAILABLE');
      return healthy;
    }
    if (action !== 'connect') throw new Error('Unexpected action');
    mutations++;
    return {ok: true, status: healthy};
  };
  b._assertWindowsIndependentVpnInactive = async ownedIndex => {
    guards++;
    if (mode === 'unknown') {
      assert.equal(ownedIndex, 0);
      throw new Error('Independent VPN state unknown');
    }
    assert.equal(ownedIndex, 42, 'Only the OIG-managed interface may be excluded');
  };
  b.prepareWindowsInstallerPrerequisites = async () => ({openVpnConnect:{ready:true}});
  b.benchmarkAllFast = async () => ({});
  await assert.rejects(b.action('connect'), /Independent VPN state unknown/);
  assert.equal(mutations, 0);
  mode = 'own-verified';
  const result = await b.action('connect');
  assert.equal(result.status.connected, true);
  assert.equal(guards, 2);
  assert.equal(mutations, 1);
  assert.equal(b.gatewayActionCount, 0);
});


test('privileged Windows scheduled recovery and bootstrap check independent VPN before mutating connector', () => {
  const headless = fs.readFileSync(path.join(root, 'backend/windows/scripts/Headless-Control.ps1'), 'utf8');
  const ensure = fs.readFileSync(path.join(root, 'backend/windows/scripts/Ensure-OpenInternet.ps1'), 'utf8');
  const src = fs.readFileSync(guard, 'utf8');
  assert.match(src, /Get-VpnConnection -AllUserConnection -ErrorAction Stop/);
  assert.match(src, /OwnedInterfaceIndex/);
  assert.match(headless, /function Assert-OigNoIndependentVpn/);
  assert.match(headless, /function Get-OigOwnedInterfaceIndex/);
  assert.match(headless, /Guard-IndependentVpn\.ps1/);
  const firstConnect = headless.indexOf("if($Action -eq 'Connect'){Assert-OigNoIndependentVpn");
  const savedDesired = headless.indexOf("Save-Desired 'on'", firstConnect);
  const afterDesired = headless.indexOf(' Assert-OigNoIndependentVpn\n Assert-OpenVpnGuiClosed');
  const serviceChange = headless.indexOf(' Ensure-ServiceInstalled', afterDesired);
  assert.ok(firstConnect >= 0 && firstConnect < savedDesired && savedDesired < afterDesired &&
    afterDesired < serviceChange);
  assert.match(ensure, /function Assert-OigSafeToBootstrap/);
  assert.equal((ensure.match(/Assert-OigSafeToBootstrap\n/g) || []).length, 2);
  const firstBoot = ensure.indexOf("Bootstrap-HeadlessConnector.ps1')");
  assert.ok(ensure.indexOf('Assert-OigSafeToBootstrap', ensure.indexOf('if(Test-Path $exactRequest)')) < firstBoot);
  assert.match(backendSource, /managedInterfaceIndex=/);
  assert.match(backendSource, /_assertWindowsIndependentVpnInactive\(ownedInterfaceIndex\)/);
});

test('native Windows synthetic VPN coexistence guard respects own index but never hides foreign VPNs', {
  skip: process.platform !== 'win32'
}, () => {
  for (const [mode, expected] of [
    ['clean', 0], ['own', 0], ['native', 17], ['global', 17],
    ['other', 17], ['split', 17], ['unknown', 18]
  ]) {
    const script = [
      '$ErrorActionPreference="Stop"',
      '$env:OIG_NATIVE_GUARD_CASE=' + "'" + mode + "'",
      'function Get-VpnConnection {',
      ' param([switch]$AllUserConnection,$ErrorAction)',
      ' if($env:OIG_NATIVE_GUARD_CASE -eq "native" -and -not $AllUserConnection){return [pscustomobject]@{ConnectionStatus="Connected"}}',
      ' if($env:OIG_NATIVE_GUARD_CASE -eq "global" -and $AllUserConnection){return [pscustomobject]@{ConnectionStatus="Connected"}}',
      '}',
      'function Get-NetAdapter {',
      ' param($ErrorAction)',
      ' $case=$env:OIG_NATIVE_GUARD_CASE',
      ' if($case -in @("own","other","split")){',
      '  [pscustomobject]@{Status="Up";Name="OIG OpenVPN";InterfaceDescription="TAP";ifIndex=42}',
      ' }',
      ' if($case -eq "other"){[pscustomobject]@{Status="Up";Name="foreign OpenVPN";InterfaceDescription="TAP";ifIndex=99}}',
      '}',
      'function Get-NetRoute {',
      ' param($ErrorAction)',
      ' $case=$env:OIG_NATIVE_GUARD_CASE',
      ' if($case -eq "unknown"){throw "SYNTHETIC_UNKNOWN_NETWORK"}',
      ' if($case -in @("own","other","split")){',
      '  [pscustomobject]@{DestinationPrefix="0.0.0.0/1";InterfaceIndex=42}',
      '  [pscustomobject]@{DestinationPrefix="128.0.0.0/1";InterfaceIndex=42}',
      ' }',
      ' if($case -eq "split"){[pscustomobject]@{DestinationPrefix="::/1";InterfaceIndex=99}}',
      '}',
      '& ' + "'" + guard.replace(/'/g, "''") + "'" + ' -OwnedInterfaceIndex 42'
    ].join('\n');
    const out = spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-Command', script],
      {encoding: 'utf8', timeout: 12000, windowsHide: true});
    if (out.error) throw out.error;
    assert.equal(out.status, expected, mode + ': ' + (out.stderr || ''));
    assert.equal((out.stdout || '').trim(), '', mode);
  }
});
