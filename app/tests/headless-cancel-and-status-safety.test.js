const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..');
const headless = fs.readFileSync(path.join(root, 'backend/windows/scripts/Headless-Control.ps1'), 'utf8').replace(/\r\n/g, '\n');
const disconnect = fs.readFileSync(path.join(root, 'backend/windows/scripts/Disconnect-OpenInternet.ps1'), 'utf8').replace(/\r\n/g, '\n');
const backend = fs.readFileSync(path.join(root, 'src/main/platform-backend.js'), 'utf8').replace(/\r\n/g, '\n');

test('Disconnect persists off before scheduling privileged cleanup', () => {
  const setOff = disconnect.indexOf("desired='off'");
  const trigger = disconnect.indexOf('schtasks.exe /Run /TN OpenInternetGateway-AutoRecovery');
  assert.ok(setOff >= 0 && trigger > setOff);
});

test('headless connector scan obeys desired off before trying, between attempts and before recording success', () => {
  const helper = headless.slice(headless.indexOf('function Test-DesiredOn'), headless.indexOf('function Save-Desired'));
  assert.match(helper, /-LiteralPath \$desiredFile/);
  assert.match(helper, /catch\s*\{return \$false\}/);

  const candidate = headless.slice(headless.indexOf('function Try-Candidate'), headless.indexOf('$mutex='));
  assert.ok((candidate.match(/Test-DesiredOn/g) || []).length >= 6);
  assert.match(candidate, /if\(-not\(Test-DesiredOn\)\)\{Stop-Connector;return \$null\}/);
  assert.ok(candidate.indexOf('if(-not(Test-DesiredOn)){return $null}') < candidate.indexOf('Stop-Connector'));

  const loop = headless.slice(headless.indexOf(' for($cycle=0;'), headless.indexOf(" & (Join-Path $PSScriptRoot 'Config-Factory.ps1') -Action Status"));
  assert.match(loop, /if\(-not\(Test-DesiredOn\)\)\{break\}/);
  assert.match(loop, /CONNECT CANCELLED - DESIRED OFF/);
  assert.ok(loop.indexOf('CONNECT CANCELLED - DESIRED OFF') < loop.indexOf('if(-not $connected)'));
});

test('Windows status cannot label physical shadow routes a VPN without committed relay profile', () => {
  const start = backend.indexOf("if (action === 'status') {");
  const end = backend.indexOf('const mapped = map[action]', start);
  const status = backend.slice(start, end);
  assert.match(status, /\$profileSha=\[string\]\$s\.sha256/);
  assert.match(status, /connected=\(\$desired -eq 'on'/);
  assert.match(status, /\$profileSha -match '\^\[a-fA-F0-9\]\{64\}\$'/);
  assert.match(status, /\$relay -and \$relay -ne ':'/);
  assert.match(status, /\$profileCountry -and \$loc -eq \$profileCountry/);
});
