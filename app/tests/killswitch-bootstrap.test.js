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
    assert.match(qa.stdout, /OIG_HOSTED_BOOT_KERNEL_RECEIPT_FAIL_CLOSED_PASS 39/);
    assert.match(qa.stdout, /OIG_ROOT_BOOT_SYSTEMD_DEPENDENCY_REVIEW_PASS 17/);
    assert.match(qa.stdout, /OIG_BOOT_NFT_JSON_STRICT_FAIL_CLOSED_PASS/);
    assert.match(qa.stdout, /OIG_ROOT_BOOT_MOCKED_NFT_0600_CHECK_THEN_COMMIT_PASS/);
  });

test('Hosted real root-boot nft Kernel acceptance refuses ordinary Linux host',
  { skip: process.platform !== 'linux' }, () => {
    const script = path.join(__dirname, 'hosted-linux-root-boot-kernel-smoke.py');
    const env = { ...process.env };
    for (const key of [
      'OIG_HOSTED_CONTAINER', 'GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT',
      'GITHUB_REPOSITORY', 'GITHUB_EVENT_NAME', 'GITHUB_RUN_ID'
    ]) delete env[key];
    const refused = spawnSync('python3', ['-B', script, '--isolated-docker-only'], {
      encoding: 'utf8', timeout: 6000, env
    });
    assert.notEqual(refused.status, 0, refused.stdout);
    assert.equal(
      refused.stderr.trim(),
      'REFUSED: owner host or non-disposable runner'
    );
    const unknown = spawnSync('python3', ['-B', script, '--untrusted'], {
      encoding: 'utf8', timeout: 6000, env
    });
    assert.notEqual(unknown.status, 0, unknown.stdout);
    assert.equal(
      unknown.stderr.trim(),
      'REFUSED: owner host or non-disposable runner'
    );
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
    assert.match(gate.stdout, /BindsTo=openinternetgateway-lockdown\.service/);
    assert.doesNotMatch(gate.stdout, /^Requires=/m);
    assert.match(gate.stdout, /After=openinternetgateway-lockdown\.service/);
    assert.match(gate.stdout, /# REVIEW PREVIEW ONLY/);
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8'));
    assert.equal(pkg.name, 'open-internet-gateway');
    assert.match(unit.stdout, /ExecStart=\/usr\/bin\/python3 -I \/opt\/open-internet-gateway\/resources\/backend\/linux\/killswitch_bootstrap\.py --bootstrap-lockdown/);
    const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-boot-unit-qa-'));
    try {
      const file = path.join(folder, 'openinternetgateway-lockdown.service');
      fs.writeFileSync(file, unit.stdout, { mode: 0o600 });
      const gateDir = path.join(folder, 'NetworkManager.service.d');
      fs.mkdirSync(gateDir, { mode: 0o700 });
      fs.writeFileSync(path.join(gateDir, '90-oig-lockdown.conf'),
        gate.stdout, { mode: 0o600 });
      // Stand-in unit is NEVER started. Its executable is /usr/bin/true.
      // This exercises the real systemd parser and drop-in resolution
      // while leaving the owner's NetworkManager entirely untouched.
      const nmStub = path.join(folder, 'NetworkManager.service');
      fs.writeFileSync(nmStub, [
        '[Unit]',
        'Description=Offline NetworkManager dependency-parser stub',
        '[Service]',
        'Type=oneshot',
        'ExecStart=/usr/bin/true',
        'RemainAfterExit=yes',
        ''
      ].join('\n'), { mode: 0o600 });
      const checked = spawnSync('/usr/bin/systemd-analyze', [
        'verify', file, nmStub
      ], {
        encoding: 'utf8', timeout: 8000,
        env: { ...process.env, SYSTEMD_UNIT_PATH: folder + ':' }
      });
      assert.equal(checked.status, 0, checked.stderr || checked.stdout);
    } finally {
      fs.rmSync(folder, { recursive: true, force: true });
    }
  });
