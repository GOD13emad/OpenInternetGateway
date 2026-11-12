const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const helper = path.join(__dirname, '../backend/linux/nft_killswitch_plan.py');
function plan(tun, base, peer, port, transport) {
  return spawnSync('python3', ['-B', helper, '--tunnel', tun, '--underlay', base,
    '--peer', peer, '--port', String(port), '--transport', transport], {
    encoding: 'utf8', timeout: 4000, env: {
      ...process.env, PYTHONDONTWRITEBYTECODE: '1'
    }
  });
}

test('Linux render-only nft output policy permits only owned TUN, loopback, exact pinned VPN peer and DHCP',
  { skip: process.platform !== 'linux' }, () => {
    const res = plan('tun7', 'eth0', '1.1.1.1', 443, 'tcp');
    assert.equal(res.status, 0, res.stderr);
    assert.equal(res.stderr, '');
    assert.match(res.stdout, /^add table inet oig_qa_killswitch\n/);
    assert.match(res.stdout, /policy drop;/);
    assert.match(res.stdout, /oifname "lo" accept/);
    assert.match(res.stdout, /oifname "tun7" accept/);
    assert.match(res.stdout, /meta nfproto ipv4 oifname "eth0" ip daddr 1\.1\.1\.1 tcp dport 443 accept/);
    assert.match(res.stdout, /meta nfproto ipv4 oifname "eth0" udp sport 68 udp dport 67 accept/);
    assert.match(res.stdout, /counter drop\n$/);
    assert.doesNotMatch(res.stdout, /(?:flush ruleset|delete table|hook input|policy accept|accept.*meta nfproto ipv6)/);
    assert.equal(res.stdout.match(/\baccept\b/g).length, 4);
    assert.equal(plan('tap5', 'enp1s0', '8.8.8.8', 1194, 'udp').status, 0);
  });

test('Linux nft plan fails closed for unpinned endpoints, device injection, DNS hostnames and non-public peers',
  { skip: process.platform !== 'linux' }, () => {
    const cases = [
      ['eth0', 'eth1', '1.1.1.1', 443, 'tcp'],
      ['tun0', 'tun0', '1.1.1.1', 443, 'tcp'],
      ['tun0', 'lo', '1.1.1.1', 443, 'tcp'],
      ['tun0', 'wg0', '1.1.1.1', 443, 'tcp'],
      ['tun0"; flush ruleset', 'eth0', '1.1.1.1', 443, 'tcp'],
      ['tun0', 'eth0', 'vpn.example.net', 443, 'tcp'],
      ['tun0', 'eth0', '192.168.1.1', 443, 'tcp'],
      ['tun0', 'eth0', '2001:4860:4860::8888', 443, 'tcp'],
      ['tun0', 'eth0', '1.1.1.1', 0, 'tcp'],
      ['tun0', 'eth0', '1.1.1.1', 65536, 'udp'],
      ['tun0', 'eth0; flush ruleset', '1.1.1.1', 443, 'tcp'],
    ];
    for (const args of cases) {
      const res = plan(...args);
      assert.equal(res.status, 2, JSON.stringify(args) + res.stderr);
      assert.equal(res.stdout, '', JSON.stringify(args));
    }
  });
