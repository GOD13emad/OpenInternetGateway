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

test('review-only hosted acceptance runs desktop smoke after native Connect + Disconnect', () => {
  const workflow = fs.readFileSync(path.resolve(root, '../.github/workflows/hosted-first-connect-acceptance.yml'), 'utf8');
  const connectedAt = workflow.indexOf('First live Connect, diagnostics, and bounded rollback on disposable runner');
  const desktopAt = workflow.indexOf('Installed Windows desktop dashboard screenshot after verified rollback');
  assert.ok(connectedAt >= 0 && desktopAt > connectedAt);
  assert.match(workflow, /app\/tests\/hosted-desktop-screenshot\.ps1/);
  assert.match(workflow, /github\.head_ref == 'review\/firstconnect-security-20261017'/);
  assert.match(workflow, /runs-on: windows-2025/);
});
