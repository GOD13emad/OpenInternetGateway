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
    'python3','curl','iproute2','nftables','systemd','systemd-resolved','ca-certificates']) {
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


test('Linux hosted package gate requires nftables and exact root-owned backend modules', () => {
  const layout = fs.readFileSync(
    path.join(__dirname, '../tools/qaLinuxOfflineDebLayout.sh'), 'utf8'
  );
  const build = fs.readFileSync(
    path.join(__dirname, '../../.github/workflows/build.yml'), 'utf8'
  );
  const dependencyCheck = build.match(/for package in ([^\n]+); do/);
  assert.ok(dependencyCheck, 'Hosted Linux apt prerequisites gate missing');
  const required = dependencyCheck[1].trim().split(/\s+/);
  for (const dep of [
    'nftables', 'systemd-resolved', 'network-manager',
    'network-manager-openvpn', 'openvpn', 'python3'
  ]) {
    assert.ok(required.includes(dep), 'Hosted apt gate must enforce ' + dep);
  }
  assert.match(layout, /OIG_DEB_ROOT_BACKEND_EXACT_SOURCE_ROOT_0644_NOT_ACTIVATED_PASS/);
  assert.match(layout, /cmp -s -- "\$original" "\$packaged"/);
  assert.match(layout, /-rw-r--r--.*root\/root/);
  assert.match(layout, /UNAPPROVED_ROOT_SERVICE_INSTALLED/);
  for (const module of [
    'killswitch_bootstrap.py', 'killswitch_nft_executor.py',
    'nft_killswitch_plan.py', 'killswitch_lifecycle_contract.py',
    'killswitch_broker_service.py', 'killswitch_root_observer.py',
    'killswitch_broker_ipc.py', 'operator_full_device.py'
  ]) {
    assert.ok(layout.includes(module), 'Missing packaged root backend proof: ' + module);
  }
  assert.match(build, /qaLinuxOfflineDebLayout\.sh/);
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

  // Split-tunnel VPNs keep the default route on eth0. The installer must
  // refuse both IPv4 and IPv6 protected routes BEFORE any sudo/pkexec/apt.
  fs.writeFileSync(nmcli, '#!/bin/sh\nprintf "802-3-ethernet\\n"\n');
  const ipMock = path.join(mock, 'ip');
  fs.writeFileSync(ipMock, String.raw`#!/bin/sh
if [ "$1" = "-4" ] && [ "$2" = "route" ] && [ "$3" = "get" ]; then
  printf '1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.20\n'
  exit 0
fi
if [ "$2" = "route" ] && [ "$3" = "show" ] &&
   [ "$4" = "table" ] && [ "$5" = "all" ]; then
  if [ "$1" = "-4" ] && [ "$OIG_TEST_TUN_ROUTE" = "v4" ]; then
    printf '198.51.100.0/24 dev tun7 proto static\n'
  fi
  if [ "$1" = "-6" ] && [ "$OIG_TEST_TUN_ROUTE" = "v6" ]; then
    printf '2001:db8:7::/64 dev wg0 proto static\n'
  fi
  if [ "$1" = "-4" ] && [ "$OIG_TEST_TUN_ROUTE" = "unknown" ]; then
    exit 91
  fi
  exit 0
fi
exit 91
`);
  fs.chmodSync(ipMock, 0o700);
  for (const [variant, pattern] of [
    ['v4', /An active -4 tunnel route exists/],
    ['v6', /An active -6 tunnel route exists/],
    ['unknown', /Cannot verify -4 routes before package changes/]
  ]) {
    const result = call('bash', [setup], {
      env: {
        ...process.env,
        PATH: mock + path.delimiter + process.env.PATH,
        DISPLAY: '', WAYLAND_DISPLAY: '', TMPDIR: root,
        OIG_TEST_TUN_ROUTE: variant
      }
    });
    assert.notEqual(result.status, 0, variant + ': installer must refuse');
    assert.match(result.stderr, pattern, variant);
    assert.equal(fs.existsSync(sentinel), false,
      'Never invoke apt or elevation for split VPN route: ' + variant);
  }
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


test('Linux system-DEB online update selects the same one-file installer and hands off without running apt in Electron', async () => {
  const vm=require('node:vm');
  const {EventEmitter}=require('node:events');
  const os=require('node:os');
  const source=fs.readFileSync(path.join(__dirname,'../src/main/platform-backend.js'),'utf8');
  const scratch=fs.mkdtempSync(path.join(os.tmpdir(),'oig-deb-onefile-update-mock-'));
  const calls=[];
  let verification='valid';
  const fakeSpawn=(program,args)=>{
    calls.push({program,args:[...args]});
    const child=new EventEmitter();
    child.stdin=new EventEmitter();child.stdin.end=()=>{};
    child.stdout=new EventEmitter();child.stderr=new EventEmitter();
    child.unref=()=>{};
    process.nextTick(()=>{
      child.emit('spawn');
      if(program==='bash'){
        const output=verification==='valid'
          ? 'OIG_LINUX_ONECLICK_EMBEDDED_DEB_VERIFIED version=2.5.21 sha256='+'b'.repeat(64)
          : 'UNVERIFIED_PAYLOAD';
        child.stdout.emit('data',Buffer.from(output));
        child.emit('close',0);
      }
    });
    return child;
  };
  const mod={exports:{}};
  vm.runInNewContext(source,{module:mod,exports:mod.exports,process,Buffer,setTimeout,clearTimeout,
    require:name=>name==='child_process'?{spawn:fakeSpawn}:require(name)
  },{filename:'oig-synthetic-system-deb-updater.js'});
  const Backend=mod.exports;
  const b=new Backend({version:'2.5.20',resourcesPath:scratch,appPath:scratch,userData:scratch});
  b.platform='linux';b.backendRoot=scratch;
  const debExe='/opt/open-internet-gateway/open-internet-gateway';
  assert.equal(b._linuxInstallFlavor(debExe),'system-deb');
  assert.equal(b._linuxInstallFlavor(String.raw`\opt\open-internet-gateway\open-internet-gateway`),
    'system-deb','Linux executable identity is invariant in cross-host synthetic Windows tests');
  assert.equal(b._linuxInstallFlavor('/home/test/AppImageRoot/open-internet-gateway'),'user-appimage');
  const name='OpenInternetGateway-Linux-Setup-2.5.21-amd64.run';
  const asset={name,browser_download_url:'https://example.invalid/never-fetch',
    digest:'sha256:'+'a'.repeat(64)};
  const appImage={name:'OpenInternetGateway-2.5.21-x86_64.AppImage',
    browser_download_url:'https://example.invalid/never-fetch',digest:'sha256:'+'c'.repeat(64)};
  assert.equal(b._selectUpdateAsset([appImage,asset],'2.5.21')?.name,appImage.name);
  b._linuxInstallFlavor=()=> 'system-deb';
  assert.equal(b._selectUpdateAsset([appImage,asset],'2.5.21')?.name,name);
  assert.equal(b._selectUpdateAsset([appImage],'2.5.21'),undefined,
    'Debian installs must refuse an AppImage-only update rather than duplicate the application');
  const file=path.join(scratch,name);
  fs.writeFileSync(file,'SYNTHETIC_FILE_NEVER_EXECUTE');
  fs.mkdirSync(path.join(scratch,'linux'));
  fs.copyFileSync(path.join(__dirname,'../backend/linux/apply-oneclick-update.sh'),
    path.join(scratch,'linux','apply-oneclick-update.sh'));
  b._githubJson=async()=>({tag_name:'v2.5.21',assets:[appImage,asset]});
  try{
    const info=await b.updateInfo(true);
    assert.equal(info.installScope,'system-deb');
    assert.equal(info.requiresOsAuthorization,true);
    assert.equal(info.asset.name,name);
    const handoff=await b.launchDownloadedUpdate({
      path:file,sha256:'a'.repeat(64),info:{latestVersion:'2.5.21'}
    },{appPid:123456789,currentExecutable:debExe});
    assert.equal(handoff.applying,true);
    assert.equal(handoff.installScope,'system-deb');
    assert.equal(handoff.requiresOsAuthorization,true);
    assert.equal(calls.length,2);
    assert.equal(calls[0].program,'bash');
    assert.deepEqual(Array.from(calls[0].args),[file,'--verify-only']);
    assert.equal(calls[1].program,'/bin/bash');
    assert.equal(calls[1].args[0],path.join(scratch,'linux','apply-oneclick-update.sh'));
    assert.equal(calls[1].args[1],file);
    assert.equal(calls[1].args.at(-1),debExe);
    assert.equal(calls.every(x=>!['apt','apt-get','sudo','pkexec'].includes(x.program)),true,
      'Only the OS-approved one-file installer may touch apt, never Electron');
    verification='invalid';
    await assert.rejects(b.launchDownloadedUpdate({
      path:file,sha256:'a'.repeat(64),info:{latestVersion:'2.5.21'}
    },{appPid:123456789,currentExecutable:debExe}),/embedded Debian package could not be verified/);
    assert.equal(calls.length,3,'Failed verification must not start a handoff');
    const alternate=path.join(scratch,'alternate');
    fs.mkdirSync(alternate);
    fs.symlinkSync(file,path.join(alternate,name));
    await assert.rejects(b.launchDownloadedUpdate({
      path:path.join(alternate,name),sha256:'a'.repeat(64),
      info:{latestVersion:'2.5.21'}
    },{appPid:123456789,currentExecutable:debExe}),/regular non-symlink/);
    assert.equal(calls.length,3);
  }finally{
    fs.rmSync(scratch,{recursive:true,force:true});
  }
});

test('Linux native update helper only performs a one-file OS-authorized upgrade after app exit', () => {
  const script=fs.readFileSync(path.join(__dirname,'../backend/linux/apply-oneclick-update.sh'),'utf8');
  assert.match(script,/while kill -0 "\$wait_pid"/);
  assert.match(script,/sha256sum -- "\$installer"/);
  assert.match(script,/bash "\$installer" --verify-only/);
  assert.match(script,/timeout 600s bash "\$installer"/);
  assert.match(script,/NATIVE_INSTALLER_REFUSED_OR_FAILED/);
  assert.match(script,/EMBEDDED_DEB_DIGEST_INVALID/);
  const workflow=fs.readFileSync(path.join(__dirname,'../../.github/workflows/build.yml'),'utf8');
  const sentinelLine=workflow.split(/\r?\n/).find(s=>s.includes("printf 'FAKE_HELPER_NO_APT"));
  const verifiedLine=workflow.split(/\r?\n/).find(s=>s.includes("printf 'OIG_LINUX_ONECLICK_EMBEDDED_DEB_VERIFIED version=%s"));
  assert.ok(sentinelLine && verifiedLine,'Isolated CI update fixture must exist');
  for(const line of [sentinelLine,verifiedLine]){
    const slashRun=line.match(/\\+n/);
    assert.equal(slashRun?.[0],String.fromCharCode(92)+'n',
      'Synthetic CI sentinel must print an actual newline, not a literal backslash-n');
  }
  assert.match(script,/dpkg-query -W -f='\$\{Version\}' open-internet-gateway/);
  assert.match(script,/installScope':'system-deb'/);
  assert.doesNotMatch(script,/apt-get|nmcli connection (up|down|modify)|--no-sandbox/);
  const {spawnSync}=require('node:child_process');
  const syntax=spawnSync('bash',['-n',path.join(__dirname,'../backend/linux/apply-oneclick-update.sh')],
    {encoding:'utf8',timeout:5000});
  assert.equal(syntax.status,0,syntax.stderr);
});
