const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const native = process.platform === 'linux' && ['openvpn', 'openssl', 'python3']
  .every(cmd => spawnSync('which', [cmd], { encoding: 'utf8', timeout: 2000 }).status === 0);

test('real OpenVPN TLS loopback accepts pinned local CA/CN and rejects wrong CN without TUN', {
  skip: !native && 'OpenVPN native Linux integration dependencies unavailable'
}, () => {
  const script = path.join(__dirname, 'openvpn-loopback-tls-smoke.py');
  const result = spawnSync('python3', ['-B', script], {
    encoding: 'utf8', timeout: 35000, maxBuffer: 256 * 1024
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message || result.stdout);
  assert.match(result.stdout, /PASS: real OpenVPN TLS loopback authenticated peer/);
});
