const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const childProcess = require('node:child_process');

// Isolated mock: no real host routing, networking or VPN calls.
const originalSpawn = childProcess.spawn;
let mockedDevices = '';
let mockedRouteJson = '[]';
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
    if (file === 'nmcli' && args.join(' ') === '-t -f DEVICE,TYPE,STATE device status') {
      output = mockedDevices;
    } else if (file === 'ip' && args.join(' ') === '-j -4 route show default') {
      output = mockedRouteJson;
    } else if (file === 'ip' && args.slice(0,5).join(' ') === '-4 -o addr show dev') {
      output = mockedAddress;
    } else {
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
  return {
    platform: 'linux',
    _isLinuxPhysicalNic: () => true,
    _selectLinuxPhysicalDefaultRoute: Backend.prototype._selectLinuxPhysicalDefaultRoute
  };
}
function setup(devices, routes, address = '') {
  calls.length = 0;
  mockedDevices = devices;
  mockedRouteJson = JSON.stringify(routes);
  mockedAddress = address;
}

test('physical interface lookup uses JSON routes, direct argv, not bash', async () => {
  setup('enp0s31f6:ethernet:connected\n',
    [{dst:'default',gateway:'192.0.2.1',dev:'enp0s31f6',metric:100}],
    '2: enp0s31f6 inet 192.0.2.42/24 brd 192.0.2.255 scope global enp0s31f6\n');
  const result = await Backend.prototype._directInternetPath.call(backend());
  assert.equal(result.interface,'enp0s31f6');
  assert.equal(result.localIP,'192.0.2.42');
  assert.equal(result.gateway,'192.0.2.1');
  assert.equal(result.bindMode,'physical-interface');
  assert.equal(result.curlInterface,'if!enp0s31f6');
  assert.equal(calls.length,3);
  assert.deepEqual(calls[0].args,['-t','-f','DEVICE,TYPE,STATE','device','status']);
  assert.deepEqual(calls[1].args,['-j','-4','route','show','default']);
  assert.deepEqual(calls[2].args,['-4','-o','addr','show','dev','enp0s31f6']);
  assert.ok(calls.every(c=>c.shell === false));
});

test('rejects route name with shell metacharacters before address lookup', async () => {
  setup('enp0s31f6:ethernet:connected\n',
    [{dst:'default',gateway:'192.0.2.1',dev:'eth0$(echo-payload)',metric:0}]);
  await assert.rejects(()=>Backend.prototype._directInternetPath.call(backend()),/physical IPv4 default route/);
  assert.equal(calls.length,2);
});

test('rejects VPN tunnel default', async () => {
  setup('tun0:tun:connected\n',
    [{dst:'default',gateway:'100.64.0.1',dev:'tun0',metric:1}]);
  await assert.rejects(()=>Backend.prototype._directInternetPath.call(backend()),/physical IPv4 default route/);
  assert.equal(calls.length,2);
});

test('rejects physical NIC lacking an IPv4 address', async () => {
  setup('wlp3s0:wifi:connected\n',
    [{dst:'default',gateway:'192.0.2.1',dev:'wlp3s0',metric:600}],
    '2: wlp3s0 inet6 2001:db8::7/64 scope global\n');
  await assert.rejects(()=>Backend.prototype._directInternetPath.call(backend()),/no usable IPv4 address/i);
  assert.equal(calls.length,3);
});

test('selects secondary physical Wi-Fi route when Ethernet lacks default', async () => {
  setup('enp0s31f6:ethernet:connected\nwlp3s0:wifi:connected\n',
    [{dst:'default',gateway:'100.64.0.1',dev:'tun0',metric:0},
     {dst:'default',gateway:'192.0.2.1',dev:'wlp3s0',metric:600}],
    '2: wlp3s0 inet 192.0.2.42/24 scope global\n');
  const result = await Backend.prototype._directInternetPath.call(backend());
  assert.equal(result.interface,'wlp3s0');
  assert.equal(result.gateway,'192.0.2.1');
  assert.deepEqual(calls[2].args,['-4','-o','addr','show','dev','wlp3s0']);
});