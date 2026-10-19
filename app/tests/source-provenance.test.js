const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

test('Linux VPN Gate source ranking and provenance use deterministic offline fixtures',
  { skip: process.platform !== 'linux' }, () => {
    const result = spawnSync('python3', [path.join(__dirname, 'source-provenance-smoke.py')], {
      timeout: 8000,
      encoding: 'utf8',
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.match(result.stdout, /PASS: HTTPS-first/);
  });
