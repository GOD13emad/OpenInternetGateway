const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const childProcess = require('node:child_process');

// A dedicated Node test file/process permits isolated spawn interception without
// invoking actual host networking tools, changing routes, or starting a VPN.
const originalSpawn = childProcess.spawn;
let mockedRoute = '';
let mockedAddress = '';
const calls = [];

childProcess.spawn = (file, args, options = {}) => {
  calls.push({ file, args, shell: options.shell });
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = () => true;
  process.nextTick(() => {
    let output = '';
    if (file === '/bin/bash' && args[0] === '-lc') output = mockedRoute;
    else if (file === 'ip') output = mockedAddress;
    else {
      child.emit('error', new Error('Unexpected executable in isolated regression: ' + file));
      return;
    }
    child.stdout.end(output);
    child.stderr.end();
    child.emit('close', 0);
  });
  return child;
};

const Backend = require('../src/main/platform-backend.js');
childProcess.spawn = originalSpawn;

function backend() {
  return { platform: 'linux' };
}

test('physical interface IP lookup uses direct argv, not interpolated bash', async () => {
  calls.length = 0;
  mockedRoute = 'default via 192.0.2.1 dev enp0s31f6 proto dhcp metric 100\n';
  mockedAddress = '2: enp0s31f6 inet 192.0.2.42/24 brd 192.0.2.255 scope global enp0s31f6\n';
  const result = await Backend.prototype._directInternetPath.call(backend());
  assert.equal(result.interface, 'enp0s31f6');
  assert.equal(result.localIP, '192.0.2.42');
  assert.equal(result.gateway, '192.0.2.1');
  assert.equal(result.bindMode, 'physical-interface');
  assert.equal(result.curlInterface, 'if!enp0s31f6');
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1].args, ['-4','-o','addr','show','dev','enp0s31f6']);
  assert.equal(calls[1].file, 'ip');
  assert.equal(calls[1].shell, false);
});

test('rejects a route device name containing shell metacharacters before lookup', async () => {
  calls.length = 0;
  mockedRoute = 'default via 192.0.2.1 dev eth0$(echo-payload) metric 100\n';
  mockedAddress = '2: eth0 inet 192.0.2.42/24\n';
  await assert.rejects(() => Backend.prototype._directInternetPath.call(backend()), /No safe physical IPv4 Internet route/);
  assert.equal(calls.length, 1);
});

test('rejects tunnel routes rather than binding a VPN interface', async () => {
  calls.length = 0;
  mockedRoute = 'default via 192.0.2.1 dev tun0 metric 1\n';
  await assert.rejects(() => Backend.prototype._directInternetPath.call(backend()), /No safe physical IPv4 Internet route/);
  assert.equal(calls.length, 1);
});

test('requires a real IPv4 address record from the selected physical NIC', async () => {
  calls.length = 0;
  mockedRoute = 'default via 192.0.2.1 dev wlp3s0 metric 600\n';
  mockedAddress = '2: wlp3s0 inet6 2001:db8::7/64 scope global\n';
  await assert.rejects(() => Backend.prototype._directInternetPath.call(backend()), /no IPv4 address/i);
  assert.equal(calls.length, 2);
  assert.equal(calls[1].file, 'ip');
});
