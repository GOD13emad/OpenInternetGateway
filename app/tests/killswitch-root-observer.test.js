const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

test('Linux independent NM and kernel evidence parser: strict fixed commands and never unlock from partial facts',
  { skip: process.platform !== 'linux' }, () => {
    const res = spawnSync('python3', ['-B', path.join(__dirname, 'killswitch-root-observer-smoke.py')], {
      encoding: 'utf8', timeout: 8000, env: {
        ...process.env, PYTHONDONTWRITEBYTECODE: '1'
      }
    });
    assert.equal(res.status, 0, res.stderr || res.stdout);
    assert.match(res.stdout, /NM_KERNEL_INDEPENDENT_PARTIAL_OBSERVER_FIXTURES_PASS/);
  });
