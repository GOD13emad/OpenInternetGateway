'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Backend = require('../src/main/platform-backend');

test('Windows setup shares one prerequisite operation with Connect and never starts a VPN', async () => {
  const backend = new Backend({ version: '2.5.20', appPath: __dirname, resourcesPath: __dirname });
  backend.platform = 'win32';
  backend.backendRoot = path.join(__dirname, '..');
  let starts = 0;
  let release;
  backend._ensureWindowsRuntimePrerequisites = () => {
    starts++;
    return new Promise(resolve => { release = resolve; });
  };
  const one = backend.prepareWindowsInstallerPrerequisites();
  const two = backend.prepareWindowsInstallerPrerequisites();
  assert.equal(starts, 1, 'Concurrent installer and Connect operations must not race');
  release({ openVpnConnect: { ready: true } });
  const [first, second] = await Promise.all([one, two]);
  assert.equal(first.openVpnConnect.ready, true);
  assert.deepEqual(first, second);
  const three = backend.prepareWindowsInstallerPrerequisites();
  assert.equal(starts, 2, 'Failure/retry does not retain a stale installer promise');
  release({ openVpnConnect: { ready: true } });
  await three;
  assert.equal(backend.windowsPrerequisiteTask, null);
});

test('Windows first-launch setup is interactive and explicitly excluded from passive CI and login autostart', () => {
  const main = fs.readFileSync(path.join(__dirname, '..', 'src/main/main.js'), 'utf8');
  const backend = fs.readFileSync(path.join(__dirname, '..', 'src/main/platform-backend.js'), 'utf8');
  for (const pattern of [
    /process\.platform === 'win32' && app\.isPackaged/,
    /process\.env\.OIG_CAPTURE_ONLY !== '1'/,
    /process\.env\.RUNNER_ENVIRONMENT !== 'github-hosted'/,
    /!startInBackground/,
    /!backend\._windowsPrerequisiteStatus\(\)\?\.openVpnConnect\?\.ready/,
    /backend\.prepareWindowsInstallerPrerequisites\(\)\.catch/,
    /OpenVPN Connect prerequisite setup was not completed/
  ]) assert.match(main, pattern);
  assert.match(backend, /WINDOWS_OPENVPN_CONNECT\.sha256/);
  assert.match(backend, /AUTOSTART=no/);
  assert.match(backend, /Start-Process -FilePath 'msiexec\.exe' -Verb RunAs/);
  assert.match(backend, /async prepareWindowsInstallerPrerequisites\(\)/);
  assert.match(backend, /if \(this\.windowsPrerequisiteTask\) return this\.windowsPrerequisiteTask/);
  assert.match(backend, /skipped: 'disposable-qa-capture'/);
  assert.doesNotMatch(main.slice(main.indexOf('The NSIS per-user installer'), main.indexOf("app.on('activate'")),
    /backend\.action\('connect'\)|Stop-Process|taskkill/);
});

test('Linux Debian packaging keeps Electron dependencies and adds native OpenVPN prerequisites', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  const deps = pkg.build.deb.depends;
  assert.ok(deps.includes('default'), 'Do not remove Chromium/Electron dependencies');
  for (const name of ['network-manager','network-manager-openvpn','openvpn (>= 2.6)',
    'python3','curl','iproute2','systemd','ca-certificates']) {
    assert.ok(deps.includes(name), name + ' must be an apt dependency');
  }
  const launcher = fs.readFileSync(path.join(__dirname, '..', 'build/linux-oneclick-installer.sh'), 'utf8');
  assert.match(launcher, /OIG_PAYLOAD_SHA256/);
  assert.match(launcher, /--verify-only/);
  assert.match(launcher, /apt-get install --yes --no-install-recommends/);
  assert.match(launcher, /sudo apt-get update/);
  assert.match(launcher, /pkexec/);
  assert.match(launcher, /OIG_LINUX_ONECLICK_INSTALL_AND_LAUNCH_SUBMITTED/);
  assert.match(launcher, /nmcli -t -f TYPE connection show --active/);
  assert.match(launcher, /ip -4 route get 1\.1\.1\.1/);
  assert.match(launcher, /Refusing to change system packages during the session/);
  assert.doesNotMatch(launcher, /nmcli connection (up|down|modify)|systemctl (stop|restart)|--no-sandbox/);
});
