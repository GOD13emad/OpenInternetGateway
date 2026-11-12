const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

test('Linux nft lockdown engine: isolated execution guard and fail-closed state machine',
  { skip: process.platform !== 'linux' }, () => {
    const res = spawnSync('python3', ['-B', path.join(__dirname, 'killswitch-nft-executor-smoke.py')], {
      encoding:'utf8', timeout:8000, env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'}
    });
    assert.equal(res.status,0,res.stderr||res.stdout);
    assert.match(res.stdout,/OIG_DISPOSABLE_NFT_ENGINE_OFFLINE_PASS/);
  });
