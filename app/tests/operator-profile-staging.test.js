const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

test('offline operator-pinned VPNBook profile staging is private, repeatable and fail-closed',
  { skip: process.platform !== 'linux' }, async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-operator-policy-'));
    try {
      const cert = path.join(root, 'test-ca.crt');
      const key = path.join(root, 'test-private.key');
      const made = spawnSync('openssl', [
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=synthetic-test-only', '-keyout', key, '-out', cert
      ], { encoding: 'utf8', timeout: 8000 });
      assert.equal(made.status, 0, made.stderr);
      const ca = fs.readFileSync(cert, 'utf8').trim();
      const privateKey = fs.readFileSync(key, 'utf8').trim();
      const caSha = crypto.createHash('sha256')
        .update(new crypto.X509Certificate(ca).raw).digest('hex');
      const profile = path.join(root, 'test.ovpn');
      const common = path.join(root, 'common');
      const script = path.join(__dirname, '..', 'backend', 'linux', 'operator_profile.py');
      const peer = 'server.vpnbook.com';
      const sample = [
        'client', 'dev tun', 'proto tcp-client', 'remote uk205.vpnbook.com 443',
        'nobind', 'persist-key', 'persist-tun', 'resolv-retry infinite',
        'auth-user-pass', 'verb 3',
        '<ca>', ca, '</ca>', '<cert>', ca, '</cert>', '<key>', privateKey, '</key>', ''
      ].join('\n');
      function invoke(action, text, sha = caSha, name = peer, file = profile) {
        if (text !== null) fs.writeFileSync(profile, text, { mode: 0o600 });
        return spawnSync('python3', [
          script, action, '--profile', file, '--ca-sha256', sha,
          '--peer-cn', name, '--common', common
        ], { encoding: 'utf8', timeout: 5000, env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
      }
      const result = invoke('stage', sample);
      assert.equal(result.status, 0, result.stderr);
      const output = JSON.parse(result.stdout);
      assert.equal(output.profilePolicyValidated, true);
      assert.equal(output.liveTlsVerified, false);
      assert.equal(output.readyForAutomaticConnection, false);
      assert.doesNotMatch(result.stdout, /PRIVATE KEY/);
      const directory = path.join(common, 'operator-profiles');
      const index = path.join(directory, 'current.json');
      const meta = JSON.parse(fs.readFileSync(index, 'utf8'));
      const staged = path.join(directory, meta.profile);
      assert.equal(meta.expectedPeerCN, peer);
      assert.equal(meta.caDerSha256, caSha);
      assert.equal(fs.statSync(directory).mode & 0o077, 0);
      assert.equal(fs.statSync(staged).mode & 0o077, 0);
      assert.equal(fs.statSync(index).mode & 0o077, 0);
      assert.match(fs.readFileSync(staged, 'utf8'), /verify-x509-name server\.vpnbook\.com name/);
      assert.match(fs.readFileSync(staged, 'utf8'), /remote-cert-tls server/);
      const metadataOriginal = fs.readFileSync(index);
      const repeated = invoke('stage', sample);
      assert.equal(repeated.status, 0, repeated.stderr);
      assert.ok(metadataOriginal.equals(fs.readFileSync(index)));

      const providerSafe = sample.replace('dev tun', 'dev tun1')
        .replace('verb 3', 'fast-io\npull\nroute-delay 5\nverb 3');
      assert.equal(invoke('check', providerSafe).status, 0,
        'Observed non-executable provider directives are accepted');
      assert.equal(invoke('check', providerSafe.replace('route-delay 5',
        'route-delay 999')).status, 2);
      for (const gw of ['redirect-gateway', 'redirect-gateway def1']) {
        assert.equal(invoke('check', providerSafe.replace('verb 3',
          gw + '\nverb 3')).status, 0, 'Default-route options are accepted only for removal');
      }
      assert.equal(invoke('check', providerSafe.replace('verb 3',
        'redirect-gateway bypass-dhcp\nverb 3')).status, 2);
      // Validate safe, reproducible normalization of a stock provider
      // default-route directive, retaining the original source digest.
      const providerCommon = path.join(root, 'official-style-common');
      const providerRaw = providerSafe.replace('verb 3',
        'redirect-gateway\nverb 3');
      fs.writeFileSync(profile, providerRaw, {mode: 0o600});
      const sanitized = spawnSync('python3', [script, 'stage',
        '--profile', profile, '--ca-sha256', caSha,
        '--peer-cn', peer, '--common', providerCommon],
      {encoding: 'utf8', timeout: 5000});
      assert.equal(sanitized.status, 0, sanitized.stderr);
      const metadata = JSON.parse(fs.readFileSync(
        path.join(providerCommon, 'operator-profiles', 'current.json'), 'utf8'));
      assert.equal(metadata.providerDefaultRouteDirectiveRemoved, true);
      assert.equal(metadata.sourceProfileSha256,
        crypto.createHash('sha256').update(providerRaw).digest('hex'));
      const normalizedContent = fs.readFileSync(path.join(providerCommon,
        'operator-profiles', metadata.profile), 'utf8');
      assert.doesNotMatch(normalizedContent, /^\s*redirect-gateway\b/m);
      assert.match(normalizedContent, /remote-cert-tls server/);
      assert.match(normalizedContent,
        /verify-x509-name server\.vpnbook\.com name/);
      const attacks = [
        sample.replace('auth-user-pass', 'auth-user-pass /tmp/credentials'),
        sample.replace('verb 3', 'up /tmp/exploit.sh\nverb 3'),
        sample.replace('verb 3', 'script-security 2\nverb 3'),
        sample.replace('verb 3', 'plugin /tmp/module.so\nverb 3'),
        sample.replace('remote uk205.vpnbook.com 443', 'remote attacker.example 443'),
        sample.replace('remote uk205.vpnbook.com 443', 'remote uk205.vpnbook.com 443\nremote uk205.vpnbook.com 443'),
        sample.replace('verb 3', 'verify-x509-name attacker.example name\nverb 3'),
        sample.replace('verb 3', 'remote-cert-tls client\nverb 3'),
        sample.replace('<ca>', '<auth-user-pass>\nsecret\n</auth-user-pass>\n<ca>')
      ];
      for (const attack of attacks) {
        const rejected = invoke('stage', attack);
        assert.equal(rejected.status, 2, rejected.stdout + rejected.stderr);
        assert.ok(metadataOriginal.equals(fs.readFileSync(index)));
      }
      assert.equal(invoke('stage', sample, '0'.repeat(64)).status, 2);
      assert.equal(invoke('stage', sample, caSha, '../server').status, 2);
      assert.equal(invoke('stage', sample.replace('-----BEGIN PRIVATE KEY-----',
        '-----BEGIN RSA PRIVATE KEY-----')).status, 2);
      assert.equal(invoke('stage', sample.replace('-----BEGIN CERTIFICATE-----',
        '-----BEGIN INVALID CERTIFICATE-----')).status, 2);
      const linkedDir = path.join(root, 'linked-directory');
      fs.symlinkSync(common, linkedDir);
      const dirAttack = spawnSync('python3', [
        script, 'stage', '--profile', profile, '--ca-sha256', caSha,
        '--peer-cn', peer, '--common', linkedDir
      ], { encoding: 'utf8', timeout: 5000 });
      assert.equal(dirAttack.status, 2);
      const gitRoot = path.join(root, 'source-checkout');
      fs.mkdirSync(path.join(gitRoot, '.git'), { recursive: true });
      const gitAttack = spawnSync('python3', [
        script, 'stage', '--profile', profile, '--ca-sha256', caSha,
        '--peer-cn', peer, '--common', path.join(gitRoot, 'secrets')
      ], { encoding: 'utf8', timeout: 5000 });
      assert.equal(gitAttack.status, 2);
      const hardlinked = path.join(root, 'link-outside.ovpn');
      fs.linkSync(staged, hardlinked);
      assert.equal(invoke('stage', sample).status, 2);
      fs.unlinkSync(hardlinked);

      // Full backend bridge: check that the native GUI target delegates to
      // exactly the same offline validator, without involving live connection.
      const Backend = require('../src/main/platform-backend');
      const backend = new Backend({ version: '2.5.20', appPath: root,
        resourcesPath: root, userData: root });
      backend.platform = 'linux';
      backend.backendRoot = root;
      fs.mkdirSync(path.join(root, 'linux'));
      fs.copyFileSync(script, path.join(root, 'linux', 'operator_profile.py'));
      fs.writeFileSync(profile, sample, { mode: 0o600 });
      assert.equal(backend.operatorProfileStatus().staged, true);
      const pendingImport = backend.stageOperatorProfile(profile, caSha, peer);
      assert.equal(backend.operatorProfileTaskBusy, true,
        'Import must hold its lease before any asynchronous file write');
      await assert.rejects(backend.checkOperatorNativeCompatibility(),
        /Another operator-profile task is still running/);
      const bridged = await pendingImport;
      assert.equal(backend.operatorProfileTaskBusy, false,
        'Import releases its lease after successful staging');
      assert.equal(bridged.staged, true);
      assert.equal(bridged.imported, true);
      assert.equal(bridged.liveTlsVerified, false);
      assert.equal(bridged.connected, false);
      assert.equal(bridged.readyForAutomaticConnection, false);
      assert.equal(bridged.remoteHost, 'uk205.vpnbook.com');
      fs.appendFileSync(staged, '\n# malicious local change');
      assert.equal(backend.operatorProfileStatus().staged, false,
        'A tampered local .ovpn cannot retain the staged status');
      await backend.stageOperatorProfile(profile, caSha, peer);
      assert.equal(backend.operatorProfileStatus().staged, true);

      await assert.rejects(backend.stageOperatorProfile(profile, '0'.repeat(64), peer));
      assert.equal(backend.operatorProfileTaskBusy, false,
        'Rejected invalid import must not acquire a lasting task lease');
      backend.platform = 'win32';
      await assert.rejects(backend.stageOperatorProfile(profile, caSha, peer),
        /only on Linux/);
      assert.equal(backend.operatorProfileStatus().staged, false);
      backend.platform = 'linux';
      assert.ok(metadataOriginal.equals(fs.readFileSync(index)));
      const main = fs.readFileSync(path.join(__dirname, '../src/main/main.js'), 'utf8');
      const preload = fs.readFileSync(path.join(__dirname, '../src/preload/preload.js'), 'utf8');
      const renderer = fs.readFileSync(path.join(__dirname, '../src/renderer/app.js'), 'utf8');
      assert.match(main, /dialog\.showOpenDialog\(mainWindow/);
      assert.match(main, /backend\.stageOperatorProfile\(chosen\.filePaths\[0\]/);
      assert.match(preload, /gateway:stageOperatorProfile/);
      assert.match(renderer, /readyForAutomaticConnection !== false/);

      // Simulate NM's real command lifecycle without opening a VPN or
      // registering an actual NetworkManager profile on the developer host.
      const fakeDir = path.join(root, 'stub-bin');
      const fakeState = path.join(root, 'stub-uuid');
      const fakeLog = path.join(root, 'stub-commands');
      fs.mkdirSync(fakeDir);
      fs.writeFileSync(path.join(fakeDir, 'nmcli'), `#!/usr/bin/env python3
import os,sys,pathlib
args=sys.argv[1:]
state=pathlib.Path(os.environ["OIG_NATIVE_STUB_STATE"])
with open(os.environ["OIG_NATIVE_STUB_LOG"],"a") as log:
    log.write(" ".join(args)+"\\n")
assert args[:2]==["--wait","5"],args
a=args[2:]
u="a1234567-1234-4234-8234-123456789abc"
if a==["-t","-f","UUID","connection","show"]:
    print(u if state.exists() else "bbbbbbbb-1234-4234-8234-123456789abc")
elif a[:3]==["connection","import","--temporary"] and a[3:6]==["type","openvpn","file"]:
    assert pathlib.Path(a[6]).is_file()
    state.write_text(u)
    if os.environ.get("OIG_NATIVE_STUB_IMPORT_FAIL_AFTER")=="1":
        sys.exit(8)
    if os.environ.get("OIG_NATIVE_STUB_NO_UUID")=="1":
        print("Imported connection successfully.")
    else:
        print("Connection 'validated' ("+u+") successfully added.")
elif a==["-g","connection.type","connection","show","uuid",u]:
    print("vpn")
elif a==["connection","delete","uuid",u]:
    if os.environ.get("OIG_NATIVE_STUB_DELETE_FAIL")=="1":
        sys.exit(7)
    state.unlink()
else:
    sys.exit(9)
`, { mode: 0o700 });
      const fakeEnv = { ...process.env, PATH: fakeDir + path.delimiter + process.env.PATH,
        OIG_NATIVE_STUB_STATE: fakeState, OIG_NATIVE_STUB_LOG: fakeLog,
        PYTHONDONTWRITEBYTECODE: '1' };
      const checkNative = (env) => spawnSync('python3', [
        script, 'native-check', '--profile', profile,
        '--ca-sha256', caSha, '--peer-cn', peer
      ], { env, encoding: 'utf8', timeout: 6000 });
      const native = checkNative(fakeEnv);
      assert.equal(native.status, 0, native.stderr);
      assert.equal(JSON.parse(native.stdout).nativeImportCompatible, true);
      assert.equal(JSON.parse(native.stdout).temporaryProfileRemoved, true);
      assert.equal(JSON.parse(native.stdout).connectionActivated, false);
      assert.equal(fs.existsSync(fakeState), false);
      assert.doesNotMatch(fs.readFileSync(fakeLog, 'utf8'), /connection up|nmcli .*show-secrets/);
      const envKeys = ['PATH', 'OIG_NATIVE_STUB_STATE', 'OIG_NATIVE_STUB_LOG'];
      const priorEnv = Object.fromEntries(envKeys.map(k => [k, process.env[k]]));
      try {
        for (const k of envKeys) process.env[k] = fakeEnv[k];
        const pendingNative = backend.checkOperatorNativeCompatibility();
        assert.equal(backend.operatorProfileTaskBusy, true,
          'Native compatibility import holds its lease until cleanup');
        await assert.rejects(backend.stageOperatorProfile(profile, caSha, peer),
          /Another operator-profile task is still running/);
        const nativeBridge = await pendingNative;
        assert.equal(backend.operatorProfileTaskBusy, false);
        assert.equal(nativeBridge.nativeImportCompatible, true);
        assert.equal(nativeBridge.temporaryProfileRemoved, true);
        assert.equal(nativeBridge.readyForAutomaticConnection, false);
        assert.equal(fs.existsSync(fakeState), false);
      } finally {
        for (const k of envKeys) {
          if (priorEnv[k] === undefined) delete process.env[k];
          else process.env[k] = priorEnv[k];
        }
      }
      const envBeforeFail = {
        PATH: process.env.PATH,
        OIG_NATIVE_STUB_STATE: process.env.OIG_NATIVE_STUB_STATE,
        OIG_NATIVE_STUB_LOG: process.env.OIG_NATIVE_STUB_LOG,
        OIG_NATIVE_STUB_DELETE_FAIL: process.env.OIG_NATIVE_STUB_DELETE_FAIL
      };
      try {
        Object.assign(process.env, fakeEnv, { OIG_NATIVE_STUB_DELETE_FAIL: '1' });
        await assert.rejects(backend.checkOperatorNativeCompatibility());
        assert.equal(backend.operatorProfileTaskBusy, false,
          'Failed native import must release the process-local profile task lease');
      } finally {
        for (const [key, value] of Object.entries(envBeforeFail)) {
          if (value === undefined) delete process.env[key];
          else process.env[key] = value;
        }
        fs.rmSync(fakeState, { force: true });
      }
      backend.platform = 'win32';
      await assert.rejects(backend.checkOperatorNativeCompatibility(), /Linux-only/);
      backend.platform = 'linux';
      const main2 = fs.readFileSync(path.join(__dirname, '../src/main/main.js'), 'utf8');
      assert.match(main2, /gateway:operatorNativeCheck/);
      assert.match(main2, /backend.checkOperatorNativeCompatibility/);
      const pre2 = fs.readFileSync(path.join(__dirname, '../src/preload/preload.js'), 'utf8');
      assert.match(pre2, /operatorNativeCheck/);
      const noUUID = checkNative({ ...fakeEnv, OIG_NATIVE_STUB_NO_UUID: '1' });
      assert.equal(noUUID.status, 0, noUUID.stderr);
      assert.equal(JSON.parse(noUUID.stdout).temporaryProfileRemoved, true);
      assert.equal(fs.existsSync(fakeState), false,
        'An import with missing UUID output must still be reconciled and deleted');
      const postImportFail = checkNative({
        ...fakeEnv, OIG_NATIVE_STUB_IMPORT_FAIL_AFTER: '1'
      });
      assert.equal(postImportFail.status, 2);
      assert.equal(fs.existsSync(fakeState), false,
        'An import with nonzero exit after profile creation must be cleaned');
      const failedDelete = checkNative({ ...fakeEnv, OIG_NATIVE_STUB_DELETE_FAIL: '1' });
      assert.equal(failedDelete.status, 2, 'Deletion failure must block success');
      assert.doesNotMatch(failedDelete.stdout, /nativeImportCompatible/);
      // Test-only stub residue is discarded with the root temp directory.

      const link = path.join(root, 'untrusted-link.ovpn');
      fs.symlinkSync(profile, link);
      assert.equal(invoke('check', sample, caSha, peer, link).status, 2);
      assert.ok(metadataOriginal.equals(fs.readFileSync(index)));
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
