const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

test('Linux AF_UNIX SO_PEERCRED: real kernel UID, strict read-only broker protocol, fail-closed rejection',
  { skip: process.platform !== 'linux' }, () => {
    const result = spawnSync('python3', ['-B', path.join(__dirname, 'killswitch-broker-protocol-smoke.py')], {
      encoding: 'utf8', timeout: 8000,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.match(result.stdout, /KERNEL_SO_PEERCRED_PROTOCOL_PASS/);
  });
