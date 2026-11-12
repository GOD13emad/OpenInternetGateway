const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { existsSync } = require('node:fs');

test('Linux systemd-style inherited AF_UNIX listener: strict FD validation and read-only service lifecycle',
  { skip: process.platform !== 'linux' }, () => {
    const result=spawnSync('python3',['-B',path.join(__dirname,'killswitch-broker-service-smoke.py')],{
      encoding:'utf8',timeout:15000,env:{
        ...process.env,PYTHONDONTWRITEBYTECODE:'1'
      }
    });
    assert.equal(result.status,0,result.stderr||result.stdout);
    assert.match(result.stdout,/SYSTEMD_FD3_READONLY_SERVICE_HANDOFF_PASS/);
  });

test('Linux real systemd-socket-activate passes a private AF_UNIX fd 3 to the read-only broker',
  { skip: process.platform !== 'linux' || !existsSync('/usr/bin/systemd-socket-activate') }, () => {
    const result=spawnSync('python3',['-B',path.join(__dirname,'killswitch-systemd-socket-activation-smoke.py')], {
      encoding:'utf8',timeout:12000,env:{
        ...process.env,PYTHONDONTWRITEBYTECODE:'1'
      }
    });
    assert.equal(result.status,0,result.stderr||result.stdout);
    assert.match(result.stdout,/REAL_SYSTEMD_SOCKET_ACTIVATION_FD3_PASS/);
  });
