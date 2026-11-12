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
    assert.match(res.stdout, /hook forward priority -150; policy drop;/);
    assert.match(res.stdout, /add rule inet oig_qa_killswitch forward counter drop/);
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

test('Linux nft staged lockdown/tunnel/relock updates preserve default drop and never flush unrelated tables',
  { skip: process.platform !== 'linux' }, () => {
    const source = [
      'import pathlib,sys',
      'sys.path.insert(0, sys.argv[1])',
      'import nft_killswitch_plan as p',
      'a=("tun7","eth0","1.1.1.1",443,"tcp")',
      'locked=p.render_lockdown(*a)',
      'active=p.render(*a)',
      'unlock=p.render_transition(*a,tunnel_allowed=True)',
      'relock=p.render_transition(*a,tunnel_allowed=False)',
      'assert locked.count("hook output priority -150; policy drop") == 1',
      'assert locked.count("hook forward priority -150; policy drop") == 1',
      'assert \'oifname "tun7" accept\' not in locked',
      'assert \'oifname "tun7" accept\' in active',
      'assert \'oifname "tun7" accept\' in unlock',
      'assert \'oifname "tun7" accept\' not in relock',
      'assert all(x.startswith("flush chain inet oig_qa_killswitch output") for x in (unlock,relock))',
      'assert all("flush ruleset" not in x and "delete table" not in x for x in (locked,active,unlock,relock))',
      'assert all("forward counter drop" in x for x in (locked,active))',
      'assert all("hook forward" not in x for x in (unlock,relock))',
      'try: p.render_transition(*a,tunnel_allowed="yes")',
      'except p.UnsafePlan: pass',
      'else: raise AssertionError("fail-open transition")',
      'print("NFT_LOCKED_ACTIVE_RELOCK_POLICY_PASS")',
    ].join('\n');
    const res = spawnSync('python3', ['-B', '-c', source, path.join(__dirname, '../backend/linux')], {
      encoding: 'utf8', timeout: 4000, env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }
    });
    assert.equal(res.status, 0, res.stderr || res.stdout);
    assert.match(res.stdout, /NFT_LOCKED_ACTIVE_RELOCK_POLICY_PASS/);
  });
