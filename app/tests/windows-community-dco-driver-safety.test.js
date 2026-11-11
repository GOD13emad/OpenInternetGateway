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
    'IsSigned','delete $rollbackGuid',"Run-Msi '/x' $msi",
    'hostRoutesAndDnsRestored','vendorServicesRemoved',
    'fullDeviceVpnTested=$false','externalVpnConnected=$false'
  ]) assert.ok(script.includes(marker), 'missing bounded lifecycle: '+marker);
  assert.doesNotMatch(script, /Remove-NetRoute|Set-DnsClientServerAddress|Add-NetRoute/);
});
