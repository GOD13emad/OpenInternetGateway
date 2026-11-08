const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

test('stable Linux VPN Gate prefers genuine HTTPS over faster HTTP and rejects insecure redirects',
  { skip: process.platform !== 'linux' }, () => {
    const run = spawnSync('python3', ['-B', path.join(__dirname, 'https-source-preference-smoke.py')], {
      timeout: 8000, encoding: 'utf8',
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }
    });
    assert.equal(run.status, 0, run.stderr || run.stdout);
    assert.match(run.stdout, /PASS: stable HTTPS priority/);
  });
