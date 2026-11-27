const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');

test('Headless OpenVPN health rejects mixed half routes, stopped service and poisoned DNS', {
  skip: process.platform !== 'win32'
}, () => {
  const result = spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-File',
    path.join(__dirname, 'windows-connection-health-smoke.ps1')], {
    encoding: 'utf8', timeout: 12000
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /PASS: Windows headless health refuses effective foreign IPv4\/IPv6 routes/);
});

test('Windows connection and recovery cannot credit two arbitrary routes as OIG transport', () => {
  const headless = fs.readFileSync(path.join(root, 'backend/windows/scripts/Headless-Control.ps1'), 'utf8');
  const connect = fs.readFileSync(path.join(root, 'backend/windows/scripts/Connect-OpenInternet.ps1'), 'utf8');
  for (const text of [headless, connect]) {
    assert.match(text, /\. \(Join-Path \$PSScriptRoot 'Route-Pair\.ps1'\)/);
    assert.match(text, /\$routePairValid=Test-OigFullRoutePair -Routes \$routes/);
  }
  const health = headless.slice(headless.indexOf('function Get-Health('), headless.indexOf('function Wait-Health('));
  assert.match(health, /\$managedActive=\(\$managedService -and \$managedService\.Status -eq 'Running'\)/);
  assert.match(health, /Healthy=\(\$routePairValid -and \$ipv6Safe -and \$managedActive/);
  assert.match(health, /FullRoutes=\$\(if\(\$routePairValid\)\{2\}else\{0\}\)/);
  assert.match(connect, /if\(\$routePairValid -and \$ipv6Safe -and \$loc/);
  assert.match(connect, /-or -not \$routePairValid -or -not \$ipv6Safe\)\{/);
  assert.doesNotMatch(connect, /if\(\$routes\.Count -ge 2 -and \$loc/);
});
