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
  assert.ok(!deps.includes('default'), 'Literal default is not a Debian package dependency');
  for (const name of ['libgtk-3-0', 'libnotify4', 'libnss3', 'libxss1',
    'libxtst6', 'xdg-utils', 'libatspi2.0-0', 'libuuid1', 'libsecret-1-0']) {
    assert.ok(deps.includes(name), 'Missing Chromium/Electron dependency: ' + name);
  }
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


test('Linux one-file builder verifies real embedded DEB and refuses tampering or active VPN without apt', {
  skip: process.platform !== 'linux' || process.arch !== 'x64' ||
    typeof process.getuid !== 'function' || process.getuid() === 0
}, async (t) => {
  const os = require('node:os');
  const { spawnSync } = require('node:child_process');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-oneclick-offline-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const call = (cmd, args, options = {}) => spawnSync(cmd, args, {
    encoding: 'utf8', timeout: 20000, ...options
  });
  const tool = call('dpkg-deb', ['--version']);
  if (tool.error?.code === 'ENOENT') {
    t.skip('dpkg-deb is unavailable on this non-Debian Linux host');
    return;
  }
  assert.equal(tool.status, 0, tool.stderr);
  const packageVersion = require('../package.json').version;
  const source = path.join(root, 'source');
  const control = path.join(source, 'DEBIAN');
  const desktop = path.join(source, 'usr/share/applications/OpenInternetGateway.desktop');
  const icon = path.join(source, 'usr/share/icons/hicolor/512x512/apps/open-internet-gateway.png');
  const postrm = path.join(control, 'postrm');
  for (const directory of [control, path.dirname(desktop), path.dirname(icon)]) {
    fs.mkdirSync(directory, { recursive: true });
  }
  fs.chmodSync(source, 0o755);
  fs.chmodSync(control, 0o755);
  fs.writeFileSync(path.join(control, 'control'),
    'Package: open-internet-gateway\nVersion: ' + packageVersion +
    '\nArchitecture: amd64\nMaintainer: Offline QA <qa@example.invalid>' +
    '\nDescription: Disposable Debian build-hook fixture\n');
  fs.writeFileSync(postrm,
    "#!/bin/sh\nupdate-alternatives --remove 'open-internet-gateway' " +
    "'/opt/Open Internet Gateway/open-internet-gateway'\n");
  fs.chmodSync(postrm, 0o755);
  fs.writeFileSync(desktop, '[Desktop Entry]\nType=Application\nName=Open Internet Gateway\n');
  fs.writeFileSync(icon, require('node:crypto').randomBytes(12 * 1024));
  const deb = path.join(root, 'OpenInternetGateway-' + packageVersion + '-amd64.deb');
  const built = call('dpkg-deb',
    ['--root-owner-group', '-Zgzip', '-z1', '--build', source, deb]);
  assert.equal(built.status, 0, built.stderr);
  const outputs = await require('../tools/afterAllArtifactBuild')({ artifactPaths: [deb] });
  assert.equal(outputs.length, 1);
  const setup = outputs[0];
  assert.equal(fs.statSync(setup).mode & 0o111, 0o111);
  const verified = call('bash', [setup, '--verify-only']);
  assert.equal(verified.status, 0, verified.stderr);
  assert.match(verified.stdout, /OIG_LINUX_ONECLICK_EMBEDDED_DEB_VERIFIED/);
  const metadata = call('dpkg-deb', ['-f', deb, 'Package', 'Version', 'Architecture']);
  assert.equal(metadata.status, 0, metadata.stderr);
  assert.match(metadata.stdout, /open-internet-gateway/);
  assert.match(metadata.stdout, new RegExp(packageVersion.replace(/\./g, '\\.')));
  const extracted = path.join(root, 'control-verified');
  assert.equal(call('dpkg-deb', ['--control', deb, extracted]).status, 0);
  const finalPostrm = fs.readFileSync(path.join(extracted, 'postrm'), 'utf8');
  assert.match(finalPostrm, /'\/opt\/open-internet-gateway\/open-internet-gateway'/);
  assert.doesNotMatch(finalPostrm, /'\/opt\/Open Internet Gateway\/open-internet-gateway'/);

  // One-byte corruption: a valid installer header must NOT bless modified payload bytes.
  const tampered = path.join(root, 'tampered.run');
  fs.copyFileSync(setup, tampered);
  const fd = fs.openSync(tampered, 'r+');
  try {
    const offset = fs.statSync(tampered).size - 1;
    const byte = Buffer.alloc(1);
    assert.equal(fs.readSync(fd, byte, 0, 1, offset), 1);
    byte[0] ^= 0xff;
    assert.equal(fs.writeSync(fd, byte, 0, 1, offset), 1);
  } finally { fs.closeSync(fd); }
  const rejected = call('bash', [tampered, '--verify-only']);
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /Embedded Debian package SHA-256 mismatch/);

  // Only the test's private PATH contains fake executables. No real sudo/apt
  // request may occur even if a guard regresses.
  const mock = path.join(root, 'mock-bin');
  fs.mkdirSync(mock);
  const sentinel = path.join(root, 'privileged-invocation');
  for (const name of ['sudo', 'pkexec', 'apt-get']) {
    const script = path.join(mock, name);
    fs.writeFileSync(script, '#!/bin/sh\nprintf invoked > "' + sentinel + '"\nexit 91\n');
    fs.chmodSync(script, 0o700);
  }
  const nmcli = path.join(mock, 'nmcli');
  fs.writeFileSync(nmcli, '#!/bin/sh\nprintf "vpn\\n"\n');
  fs.chmodSync(nmcli, 0o700);
  const refused = call('bash', [setup], {
    env: { ...process.env, PATH: mock + path.delimiter + process.env.PATH,
      DISPLAY: '', WAYLAND_DISPLAY: '', TMPDIR: root }
  });
  assert.notEqual(refused.status, 0);
  assert.match(refused.stderr, /An active NetworkManager VPN exists/);
  assert.equal(fs.existsSync(sentinel), false, 'Never invoke apt/elevation during active VPN');
});


test('Linux single-file installer acceptance launches the same packaged dashboard source as Windows', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  const workflow = fs.readFileSync(path.join(__dirname, '../../.github/workflows/build.yml'), 'utf8');
  const lifecycle = fs.readFileSync(path.join(__dirname, '../tools/qaLinuxHostedWindowLifecycle.sh'), 'utf8');
  assert.ok(pkg.build.files.includes('src/**/*'), 'One UI source tree must package on both OS targets');
  assert.ok(pkg.build.win.extraResources.some(x => x.from === 'common'));
  assert.ok(pkg.build.linux.extraResources.some(x => x.from === 'common'));
  assert.match(workflow, /OIG_QA_EXPECTED_VERSION="\$version" bash tools\/qaLinuxHostedWindowLifecycle\.sh --installed/);
  assert.match(workflow, /HOSTED_LINUX_ONEFILE_REAL_INSTALLED_DASHBOARD_LIFECYCLE_PASS/);
  assert.match(workflow, /oig-linux-onefile-installed-lifecycle-receipt\.json/);
  assert.match(lifecycle, /OIG_QA_X11_INSTALLED=1/);
  assert.match(lifecycle, /dpkg-query -W -f='\$\{Version\}' open-internet-gateway/);
  assert.match(lifecycle, /Exec=\/opt\/open-internet-gateway\/open-internet-gateway %U/);
  assert.match(lifecycle, /oneFileAptInstalled/);
  assert.match(lifecycle, /NATIVE_QUIT_NO_ACTIVE_VPN_WITH_READONLY_EMPTY_NM_PASS/);
  assert.doesNotMatch(lifecycle, /nmcli connection (up|down|modify|delete)/);
});
