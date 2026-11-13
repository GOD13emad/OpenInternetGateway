const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

test('Linux root-owned kill-switch lifecycle contract fails closed and cannot change the owner host',
  { skip: process.platform !== 'linux' }, () => {
    const result = spawnSync('python3', ['-B', path.join(__dirname, 'killswitch-lifecycle-contract-smoke.py')], {
      encoding: 'utf8', timeout: 8000,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.match(result.stdout, /OIG_ROOT_BROKER_OFFLINE_CONTRACT_PASS/);
  });
