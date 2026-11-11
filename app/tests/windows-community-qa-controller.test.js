'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');

const root = path.resolve(__dirname, '..');
const file = path.join(__dirname, 'qa-community-cli-controller.cjs');
const mod = require('./qa-community-cli-controller.cjs');

test('QA Community controller rejects all owner-host and non-disposable invocations', () => {
  const env = {
    ...process.env, GITHUB_ACTIONS: 'false', RUNNER_ENVIRONMENT: '',
    OIG_LOOPBACK_LOCAL_QA: ''
  };
  const result = spawnSync(process.execPath, [file], {
    env, input: JSON.stringify({}), encoding: 'utf8',
    windowsHide: true, timeout: 8000
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /DISPOSABLE_QA_RUNNER_ONLY/);
  assert.doesNotMatch(result.stderr + result.stdout, /oig_pass/);
});

test('QA Community controller is excluded from Windows installer and production backend', () => {
  const pkg = require('../package.json');
  assert.deepEqual(pkg.build.files, ['src/**/*', 'assets/**/*', 'package.json']);
  assert.ok(pkg.build.win.extraResources.every(item => item.from !== 'tests'));
  assert.ok(!fs.existsSync(path.join(root, 'backend', 'windows', 'qa-community-cli-controller.cjs')));
  const backend = fs.readFileSync(path.join(root, 'src', 'main', 'platform-backend.js'), 'utf8');
  const shipped = fs.readFileSync(path.join(root, 'backend', 'windows', 'scripts', 'Connect-OpenInternet.ps1'), 'utf8');
  assert.doesNotMatch(backend + shipped, /qa-community-cli-controller/);
  assert.match(shipped, /OVPNConnectorService|ovpnconnector\.exe/);
  const qa = fs.readFileSync(file, 'utf8');
  assert.doesNotMatch(qa, /'--management-client'/);
  assert.match(qa, /--management-query-passwords/);
  assert.match(qa, /managementTokenFile/);
  assert.match(qa, /managementPasswordProtected/);
  assert.match(qa, /PUBLIC_PROVIDER_CA_PIN_MISMATCH/);
  assert.match(qa, /pinnedPeerVerified/);
  assert.match(qa, /--pull-filter/);
  assert.doesNotMatch(qa, /--auth-nocache/);
  assert.doesNotMatch(qa, /'--management-forget-disconnect'/);
  assert.match(qa, /--dev', 'null'/);
  assert.match(qa, /--ifconfig-noexec/);
  assert.match(qa, /--route-noexec/);
});

test('local QA input checker permits only bounded synthetic credentials and same-scratch certs', {
  skip: process.platform !== 'linux'
}, () => {
  const previous = process.env.OIG_LOOPBACK_LOCAL_QA;
  process.env.OIG_LOOPBACK_LOCAL_QA = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-community-loopback-'));
  try {
    const filenames = ['ca.pem', 'client.pem', 'client.key'];
    for (const f of filenames) fs.writeFileSync(path.join(tmp, f), 'synthetic');
    const a = {
      root: tmp, exe: process.execPath, ca: path.join(tmp, filenames[0]),
      cert: path.join(tmp, filenames[1]), key: path.join(tmp, filenames[2]),
      mode: 'valid', port: 12000, username: 'oig_user', password: 'oig_pass'
    };
    const verified = mod.boundedInput(a);
    assert.equal(verified.port, 12000);
    assert.equal(verified.mode, 'valid');
    assert.throws(() => mod.boundedInput({...a, port: 0}), /INVALID_LOCAL_PORT/);
    assert.throws(() => mod.boundedInput({...a, port: 70000}), /INVALID_LOCAL_PORT/);
    assert.throws(() => mod.boundedInput({...a, mode: 'unknown'}), /INVALID_QA_MODE/);
    assert.throws(() => mod.boundedInput({...a, mode: 'live-provider',
      port: 443, username: 'vpnbook', password: 'not-a-real-password'}),
      /HOSTED_WINDOWS_LIVE_PROVIDER_ONLY/);
    assert.throws(() => mod.boundedInput({...a, mode: 'live-wrong-cn',
      port: 443, username: 'vpnbook', password: 'not-a-real-password'}),
      /HOSTED_WINDOWS_LIVE_PROVIDER_ONLY/);

    assert.throws(() => mod.boundedInput({...a, username: 'real_user'}),
      /NOT_SYNTHETIC_CREDENTIALS/);
    assert.throws(() => mod.boundedInput({...a, password: 'real_secret'}),
      /NOT_SYNTHETIC_CREDENTIALS/);
    assert.throws(() => mod.boundedInput({...a, password: 'wrong-pass'}),
      /TEST_MODE_CREDENTIAL_MISMATCH/);
    assert.throws(() => mod.boundedInput({...a, ca: process.execPath}),
      /QA_FILE_OUTSIDE_SCRATCH/);
    assert.throws(() => mod.boundedInput({...a, root: os.tmpdir()}),
      /NONPRIVATE_QA_ROOT/);
    const link = path.join(tmp, 'ca-symlink.pem');
    fs.symlinkSync(process.execPath, link);
    assert.throws(() => mod.boundedInput({...a, ca: link}),
      /QA_FILE_OUTSIDE_SCRATCH/);
  } finally {
    fs.rmSync(tmp, {recursive: true, force: true});
    if (previous === undefined) delete process.env.OIG_LOOPBACK_LOCAL_QA;
    else process.env.OIG_LOOPBACK_LOCAL_QA = previous;
  }
});
