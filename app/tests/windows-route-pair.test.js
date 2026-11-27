const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');

test('Windows route-pair validator rejects mixed interfaces and physical shadow routes', {
  skip: process.platform !== 'win32'
}, () => {
  const r = spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-File',
    path.join(__dirname, 'windows-route-pair-smoke.ps1')], {
    encoding: 'utf8', timeout: 10000
  });
  assert.equal(r.status, 0, r.stderr || r.stdout);
  assert.match(r.stdout, /PASS: Windows OpenVPN IPv4 and IPv6 winning routes/);
});

test('both Windows status paths use the same fail-closed OpenVPN route-pair validator', () => {
  const backend = fs.readFileSync(path.join(root, 'src/main/platform-backend.js'), 'utf8');
  const native = fs.readFileSync(path.join(root, 'backend/windows/scripts/Status-OpenInternet.ps1'), 'utf8');
  const helper = fs.readFileSync(path.join(root, 'backend/windows/scripts/Route-Pair.ps1'), 'utf8');
  assert.match(backend, /Route-Pair\.ps1/);
  assert.match(native, /Route-Pair\.ps1/);
  for (const status of [backend, native]) {
    assert.match(status, /Test-OigFullRoutePair -Routes \$routes/);
    assert.match(status, /Test-OigIpv6EgressSafe -InterfaceIndex/);
    assert.match(status, /connected=\(\$routes\.Count -ge 2 -and \$routePairValid/i);
    assert.match(status, /FullRoutes=\$\(if\(\$routePairValid\)\{2\}else\{0\}\)/i);
  }
  assert.match(helper, /Get-NetAdapter -InterfaceIndex/);
  assert.match(helper, /Find-NetRoute -RemoteIPAddress \$destination/);
  assert.match(helper, /OpenVPN\|TAP-Windows/);
});
