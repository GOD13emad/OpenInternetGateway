const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

test('Linux status attributes full routes only to the OIG-owned VPN source, not another tunnel',
  { skip: process.platform !== 'linux' }, () => {
    const r = spawnSync('python3', ['-B', path.join(__dirname, 'linux-managed-route-ownership-smoke.py')], {
      encoding: 'utf8', timeout: 12000,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }
    });
    assert.equal(r.status, 0, r.stderr || r.stdout);
    assert.match(r.stdout, /PASS: only managed VPN source/);
  });
