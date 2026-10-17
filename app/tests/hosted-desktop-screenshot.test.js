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
  assert.match(workflow, /evidence\.verifiedInstallerSha256 -ne \$sha/);
  assert.match(workflow, /evidence\.disconnectedBeforeAndAfter -ne \$true/);
  assert.doesNotMatch(workflow, /if\(\$LASTEXITCODE -ne 0\)\{throw 'INSTALLED_WINDOWS_DESKTOP_SMOKE_FAILED'\}/);

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
test('hosted first-connect supports explicit opt-in from canonical main without automatic main network changes', () => {
  const yaml = require('js-yaml');
  const raw = fs.readFileSync(path.resolve(root,'../.github/workflows/hosted-first-connect-acceptance.yml'),'utf8');
  const parsed = yaml.load(raw);
  assert.equal(parsed.on.workflow_dispatch.inputs.confirm_disposable_runner.type, 'boolean');
  assert.equal(parsed.on.workflow_dispatch.inputs.confirm_disposable_runner.default, false);
  assert.equal(parsed.on.pull_request.paths.length, 21);
  assert.equal(parsed.on.push, undefined, 'no automatic main push VPN runs');
  assert.equal(parsed.on.pull_request_target, undefined, 'never check out a PR head under privileged target context');
  for (const job of [parsed.jobs.seed, parsed.jobs['first-connect']]) {
    assert.match(job.if, /github\.event_name == 'workflow_dispatch'/);
    assert.match(job.if, /github\.ref == 'refs\/heads\/main'/);
    assert.match(job.if, /inputs\.confirm_disposable_runner == true/);
    assert.match(job.if, /github\.event\.pull_request\.head\.repo\.full_name == github\.repository/);
    assert.match(job.if, /github\.head_ref == 'review\/firstconnect-security-20261017'/);
    const checkout = job.steps.find(step => String(step.uses).startsWith('actions/checkout@'));
    assert.match(checkout.with.ref, /github\.event\.pull_request\.head\.sha \|\| github\.sha/);
    assert.equal(checkout.with['persist-credentials'], false);
  }
  const native = parsed.jobs['first-connect'];
  assert.equal(native['runs-on'], 'windows-2025');
  const boundary = native.steps.find(x => x.name === 'Confirm disposable Windows scope and fixed source').run;
  assert.match(boundary, /MANUAL_MAIN_ONLY/);
  assert.match(boundary, /MANUAL_SOURCE_SHA_MISMATCH/);
  assert.match(boundary, /UNTRUSTED_PR_SOURCE/);
  assert.match(boundary, /WORKFLOW_EVENT_NOT_ALLOWED/);
  assert.match(boundary, /UNEXPECTED_PRODUCT_SCOPE/);
  assert.match(boundary, /RUNNER_ENVIRONMENT/);
  assert.match(boundary, /GITHUB_REPOSITORY/);
});
test('offline installed GUI probe exercises Settings and Overview navigation, then closes to tray', () => {
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  const probe=fs.readFileSync(path.join(root,'src/main/dashboard-navigation-probe.js'),'utf8');
  const workflow=fs.readFileSync(path.join(root,'../.github/workflows/build.yml'),'utf8');
  assert.match(probe, /settings\.click\(\)/);
  assert.match(probe, /find\('overview'\)\.click\(\)/);
  assert.match(probe, /executeJavaScript\(navigationScript, true\)/);
  assert.match(probe, /navigationClicked: true, powerControlInvoked: false/);
  assert.doesNotMatch(probe.slice(probe.indexOf('const navigationScript')), /gateway\.action|powerButton\.click|connect-profile|update-download/);
  assert.match(main, /await probeReadOnlyNavigation\(win\.webContents\)/);
  assert.match(main, /win\.close\(\);\s*if \(!isLiveWindow\(win\) \|\| win\.isVisible\(\)\)/);
  assert.match(main, /app\.exit\(41\)/);
  assert.match(main, /OIG_DESKTOP_PROBE_RECEIPT/);
  assert.match(script, /INSTALLED_DESKTOP_NAVIGATION_TRAY_PROBE_FAILED/);
  assert.match(script, /navigationAndTrayProbe=\$probe/);
  assert.match(script, /Assert-Offline\s+\$evidence=/);
  assert.match(workflow, /evidence\.navigationAndTrayProbe\.pass -ne \$true/);
  assert.match(workflow, /evidence\.navigationAndTrayProbe\.closeToTray -ne \$true/);
  assert.match(workflow, /oig-desktop-navigation-probe\.json/);
});
