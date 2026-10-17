'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const script = fs.readFileSync(path.join(root, 'tests/hosted-desktop-screenshot.ps1'), 'utf8');

test('installed Windows screenshot smoke is limited to a disposable runner and an offline tunnel', () => {
  for (const guard of ['GITHUB_ACTIONS', 'RUNNER_OS', 'RUNNER_ENVIRONMENT',
      'GITHUB_REPOSITORY', 'DOMAIN_JOINED_MACHINE_REFUSED',
      'DESKTOP_CAPTURE_REQUIRES_VERIFIED_DISCONNECTED_BASELINE']) {
    assert.ok(script.includes(guard), guard);
  }
  assert.match(script, /Get-NetRoute -AddressFamily IPv4/);
  assert.match(script, /Get-Service -Name OVPNConnectorService/);
  assert.match(script, /\$intent -ne 'off'/);
  assert.equal((script.match(/Assert-Offline/g) || []).length, 3);
  assert.match(script, /OIG_CAPTURE_ONLY/);
  assert.match(script, /Start-Process -FilePath \$exe/);
  assert.match(script, /WaitForExit\(65000\)/);
  assert.match(script, /INSTALLED_DASHBOARD_INVALID_PNG/);
  assert.match(script, /endUserWindows10Or11GuiAcceptance=\$false/);
  assert.doesNotMatch(script, /Invoke-Connector|Connect-OpenInternet|\/Run \/TN|Start-Service|Set-NetRoute/);
});

test('standard Windows build validates installed GUI independently of the live VPN runner', () => {
  const workflow = fs.readFileSync(path.resolve(root, '../.github/workflows/build.yml'), 'utf8');
  const native = fs.readFileSync(path.resolve(root, '../.github/workflows/hosted-first-connect-acceptance.yml'), 'utf8');
  const packaged = workflow.indexOf('npm run dist:win');
  const desktopAt = workflow.indexOf('Installed desktop GUI render and safe exit on disposable Windows, no VPN');
  assert.ok(packaged >= 0 && desktopAt > packaged, 'installed GUI smoke must use the built installer');
  assert.match(workflow, /tests\/hosted-desktop-screenshot\.ps1 -Installer/);
  assert.match(workflow, /github\.event\.pull_request\.head\.repo\.full_name == github\.repository/);
  assert.match(workflow, /name: windows-desktop-smoke-evidence/);
  assert.doesNotMatch(native, /Installed Windows desktop dashboard screenshot after verified rollback/);
});

test('desktop screenshot fresh installer is checked by hash and its desired state stays off', () => {
  assert.match(script, /DESKTOP_INSTALLER_DIGEST_MISMATCH/);
  assert.match(script, /Start-Process -FilePath \(Resolve-Path \$Installer\)\.Path/);
  assert.match(script, /\[ordered\]@\{desired='off'/);
  assert.match(script, /DESKTOP_INSTALL_REQUIRES_CLEAN_NO_TUNNEL_RUNNER/);
  assert.match(script, /verifiedInstallerSha256=\$installerHash/);
});

test('Windows dashboard capture uses a single-pass safe quit instead of recursive before-quit retry', () => {
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  const capture=main.slice(main.indexOf("if (process.env.OIG_CAPTURE_ONLY === '1') {"),main.indexOf("  win.on('close'"));
  assert.match(capture, /if \(process\.platform === 'win32'\) requestProcessExitPreservingTunnel\(\);/);
  assert.match(main, /function requestProcessExitPreservingTunnel\(\)/);
  assert.match(main, /allowQuit = true;\s*app\.quit\(\)/);
});