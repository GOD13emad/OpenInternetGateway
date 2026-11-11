'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const tests = __dirname;
const script = fs.readFileSync(path.join(tests, 'windows-community-dco-driver-smoke.ps1'), 'utf8');
const workflow = fs.readFileSync(path.join(tests, '..', '..', '.github', 'workflows', 'hosted-windows-community-dco.yml'), 'utf8');

test('ovpn-dco installation stays in disposable Windows QA, outside the package', () => {
  for (const marker of [
    'GITHUB_ACTIONS','RUNNER_OS','RUNNER_ENVIRONMENT','GITHUB_REPOSITORY',
    'GITHUB_HEAD_REF','DOMAIN_JOINED_HOST_REFUSED',
    'PREEXISTING_VPN_INSTALL_REFUSED','DISPOSABLE_RUNNER_ADMIN_REQUIRED',
    'RECEIPT_NOT_PRIVATE_OR_EXISTS'
  ]) assert.ok(script.includes(marker), 'missing environment guard: '+marker);
  assert.match(workflow, /runs-on: windows-2025/);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /github\.event\.pull_request\.head\.repo\.full_name == github\.repository/);
  assert.match(workflow, /if: always\(\)/);
  assert.match(workflow, /windows-community-dco-driver-smoke\.ps1/);
  const pkg = require('../package.json');
  assert.deepEqual(pkg.build.files, ['src/**/*', 'assets/**/*', 'package.json']);
  assert.equal(pkg.build.win.extraResources.some(resource => resource.from === 'tests'), false);
  assert.doesNotMatch(fs.readFileSync(path.join(tests, '..','src','main','platform-backend.js'),'utf8'),/dco-driver-smoke/);
});

test('ovpn-dco test pins signed vendor source and uninstalls only its own adapter', () => {
  for (const marker of [
    '47abc38a15c217b848fe099332a8523500fcbf2ebf8a1eaa7d5648c6e75079aa',
    '0b9b5ad60279b912ae826da5e13a57750fdc918d9ec28b73f031aaffef8dd485',
    'OpenVPN-2.7.9-I001-amd64.msi', 'ovpn-dco','tapctl create',
    'TAPCTL_CREATE_FAILED','Get-CimInstance Win32_PnPSignedDriver',
    'IsSigned','PNPDeviceID','delete $rollbackGuid',"Run-Msi '/x' $msi",
    'hostRoutesAndDnsRestored','vendorServicesRemoved',
    'fullDeviceVpnTested=$false','externalVpnConnected=$false'
  ]) assert.ok(script.includes(marker), 'missing bounded lifecycle: '+marker);
  assert.doesNotMatch(script, /Remove-NetRoute|Set-DnsClientServerAddress|Add-NetRoute/);
  assert.match(script, /tapctl list --hwid ovpn-dco/);
  assert.match(script, /signed\[0\]\.IsSigned/);
  assert.doesNotMatch(script, /DCO_PNP_HARDWARE_ID_MISMATCH/);
});

test('scoped DCO tunneled HTTPS is opt-in, runner-only, and owns just a /32 probe route', () => {
  const probe = fs.readFileSync(path.join(tests, 'windows-community-dco-tunnel-qa.py'), 'utf8');
  for (const marker of [
    'HOSTED_WINDOWS_TUN_ONLY', 'RUNNER_ENVIRONMENT', 'GITHUB_HEAD_REF',
    'OIG_HOSTED_DCO_DATA_QA', 'TUN_SCRATCH_NOT_PRIVATE_RUNNER_TEMP',
    'OPENVPN_PE_PIN_MISMATCH', 'route-nopull', 'route-noexec',
    'remote-cert-tls server', 'verify-x509-name ', 'api.ipify.org',
    'New-NetRoute', 'Remove-NetRoute', 'sourceBoundHttpsOverVpn',
    'vpnProcessStopped', 'fullDeviceOrKillSwitchProven'
  ]) assert.ok(probe.includes(marker), 'missing bounded DCO probe: ' + marker);
  assert.match(workflow, /dco-tunnel:/);
  assert.match(workflow, /needs: dco-driver/);
  assert.match(script, /\[switch\]\$ProbeTun/);
  assert.match(script, /scopedDcoTunHttpsVerified/);
  assert.match(script, /OIG_HOSTED_DCO_DATA_QA/);
  assert.doesNotMatch(probe, /redirect-gateway def1/);
  assert.doesNotMatch(probe, /Set-DnsClientServerAddress|0\.0\.0\.0\/0.*New-NetRoute/);
});
