const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const python = path.join(__dirname, '../backend/linux/killswitch_bootstrap.py');

test('Linux root boot lockdown refuses owner checkout and passes offline fail-closed collisions',
  { skip: process.platform !== 'linux' }, () => {
    const denied = spawnSync('python3', ['-B', '-I', python, '--bootstrap-lockdown'], {
      encoding: 'utf8', timeout: 5000
    });
    assert.notEqual(denied.status, 0, denied.stdout);
    assert.match(denied.stderr, /OIG_ROOT_BOOTSTRAP_REFUSED:BootRefused/);
    const qa = spawnSync('python3', ['-B', path.join(__dirname, 'killswitch-bootstrap-smoke.py')], {
      encoding: 'utf8', timeout: 9000
    });
    assert.equal(qa.status, 0, qa.stderr || qa.stdout);
    assert.match(qa.stdout, /OIG_ROOT_BOOT_LOCKED_ONLY_OFFLINE_PASS/);
    assert.match(qa.stdout, /OIG_BOOT_NFT_JSON_STRICT_FAIL_CLOSED_PASS/);
    assert.match(qa.stdout, /OIG_ROOT_BOOT_MOCKED_NFT_0600_CHECK_THEN_COMMIT_PASS/);
  });

test('Linux optional root systemd unit parses but is deliberately not installable',
  { skip: process.platform !== 'linux' }, () => {
    const unit = spawnSync('python3', ['-B', '-I', python, '--print-noninstallable-unit-preview'], {
      encoding: 'utf8', timeout: 5000
    });
    assert.equal(unit.status, 0, unit.stderr);
    assert.ok(unit.stdout.startsWith('# REVIEW PREVIEW ONLY.'));
    assert.doesNotMatch(unit.stdout, /^\[Install\]$/m);
    assert.match(unit.stdout, /Before=network-pre.target NetworkManager.service/);
    assert.match(unit.stdout, /CapabilityBoundingSet=CAP_NET_ADMIN/);
    assert.match(unit.stdout, /UMask=0077/);
    assert.match(unit.stdout, /RestrictAddressFamilies=AF_UNIX AF_NETLINK/);
    assert.match(unit.stdout, /PrivateDevices=true/);
    assert.match(unit.stdout, /ProtectKernelTunables=true/);
    assert.match(unit.stdout, /RestrictNamespaces=true/);
    assert.doesNotMatch(unit.stdout, /^PrivateNetwork=true$/m);
    const gate = spawnSync('python3', [
      '-B', '-I', python, '--print-noninstallable-nm-gate-preview'
    ], { encoding: 'utf8', timeout: 5000 });
    assert.equal(gate.status, 0, gate.stderr);
    assert.match(gate.stdout, /Requires=openinternetgateway-lockdown\.service/);
    assert.match(gate.stdout, /After=openinternetgateway-lockdown\.service/);
    assert.match(gate.stdout, /# REVIEW PREVIEW ONLY/);
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8'));
    assert.equal(pkg.name, 'open-internet-gateway');
    assert.match(unit.stdout, /ExecStart=\/usr\/bin\/python3 -I \/opt\/open-internet-gateway\/resources\/backend\/linux\/killswitch_bootstrap\.py --bootstrap-lockdown/);
    const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-boot-unit-qa-'));
    try {
      const file = path.join(folder, 'oig-lockdown-preview.service');
      fs.writeFileSync(file, unit.stdout, { mode: 0o600 });
      const checked = spawnSync('/usr/bin/systemd-analyze', ['verify', file], {
        encoding: 'utf8', timeout: 8000
      });
      assert.equal(checked.status, 0, checked.stderr || checked.stdout);
    } finally {
      fs.rmSync(folder, { recursive: true, force: true });
    }
  });
