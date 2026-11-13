const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

test('Linux broker: real child-process AF_UNIX SO_PEERCRED and bounded one-shot framed read-only IPC',
  { skip: process.platform !== 'linux' }, () => {
    const result=spawnSync('python3', ['-B', path.join(__dirname, 'killswitch-broker-ipc-smoke.py')], {
      encoding:'utf8', timeout:20000,
      env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'}
    });
    assert.equal(result.status,0,result.stderr||result.stdout);
    assert.match(result.stdout,/OIG_INTERPROCESS_SO_PEERCRED_TRANSPORT_PASS/);
  });
