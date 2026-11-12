const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

test('Linux real-kernel netns smoke refuses owner-host execution without native isolation',
  { skip: process.platform !== 'linux' }, () => {
    const result = spawnSync(
      'python3', ['-B', '-I',
        path.join(__dirname, 'local-linux-nft-kernel-netns-smoke.py'),
        '--disposable-root-netns'],
      { encoding: 'utf8', timeout: 8000,
        env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } }
    );
    assert.notEqual(result.status, 0, result.stderr || result.stdout);
    const prefix = 'OIG_NATIVE_ISOLATED_NETNS_KERNEL_RECEIPT=';
    const line = result.stdout.split('\n').find((part) => part.startsWith(prefix));
    assert.ok(line, result.stderr || result.stdout);
    const receipt = JSON.parse(line.slice(prefix.length));
    assert.equal(receipt.schema, 'oig-isolated-netns-kernel-v1');
    assert.equal(receipt.pass, false);
    assert.equal(receipt.isolatedNetnsVerified, false);
    assert.equal(receipt.ownerHostFirewallChanged, false);
    assert.equal(receipt.ownerHostVpnChanged, false);
    assert.equal(receipt.productionKillSwitchVerified, false);
    assert.match(receipt.failureDetail, /REFUSED: native OS-approved isolated namespace required|REFUSED: host network namespace|REFUSED: nonempty network namespace/);
  });
