const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const appRoot = path.resolve(__dirname, '..');

function writeExecutable(file, content) {
  fs.writeFileSync(file, content, { mode: 0o755 });
  fs.chmodSync(file, 0o755);
}

test('Linux AppImage launcher prepares the local SUID helper, uses userns safely, and fails closed', {
  skip: process.platform !== 'linux'
}, () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-apprun-test-'));
  try {
    const appDir = path.join(temp, 'AppDir');
    const binDir = path.join(temp, 'bin');
    const launcher = path.join(appDir, 'AppRun');
    const binary = path.join(appDir, 'open-internet-gateway');
    const localSandbox = path.join(appDir, 'chrome-sandbox');
    const helper = path.join(temp, 'chrome-sandbox-helper');
    const record = path.join(temp, 'launch-record');
    fs.mkdirSync(appDir);
    fs.mkdirSync(binDir);
    fs.copyFileSync(path.join(appRoot, 'build/linux/AppRun'), launcher);
    fs.chmodSync(launcher, 0o755);

    writeExecutable(binary, [
      '#!/usr/bin/env bash',
      '{',
      '  printf "sandbox=%s\\n" "${CHROME_DEVEL_SANDBOX:-}"',
      '  printf "args="',
      '  printf "%s|" "$@"',
      '  printf "\\n"',
      '} > "$OIG_TEST_LAUNCH_RECORD"',
      ''
    ].join('\n'));

    writeExecutable(path.join(binDir, 'stat'), [
      '#!/usr/bin/env bash',
      'if [[ -n "${OIG_TEST_HELPER:-}" ]]; then',
      '  for arg in "$@"; do',
      '    resolved="$(readlink -f "$arg" 2>/dev/null || true)"',
      '    if [[ "$arg" == "$OIG_TEST_HELPER" || "$resolved" == "$OIG_TEST_HELPER" ]]; then',
      '      printf "0:0:4755\\n"',
      '      exit 0',
      '    fi',
      '  done',
      'fi',
      'exec /usr/bin/stat "$@"',
      ''
    ].join('\n'));
    writeExecutable(path.join(binDir, 'unshare'), [
      '#!/usr/bin/env bash',
      '[[ "${OIG_TEST_USERNS:-0}" == "1" ]] && exit 0',
      'exit 1',
      ''
    ].join('\n'));
    writeExecutable(path.join(binDir, 'kdialog'), '#!/usr/bin/env bash\nexit 0\n');
    writeExecutable(path.join(binDir, 'zenity'), '#!/usr/bin/env bash\nexit 0\n');

    const env = {
      ...process.env,
      APPDIR: appDir,
      PATH: binDir + ':' + (process.env.PATH || '/usr/bin:/bin'),
      OIG_TEST_LAUNCH_RECORD: record
    };
    const run = (args, extra = {}) => spawnSync('/bin/bash', [launcher, ...args], {
      encoding: 'utf8',
      env: { ...env, ...extra }
    });

    fs.writeFileSync(localSandbox, 'same-helper-fixture');
    writeExecutable(helper, 'same-helper-fixture');
    const helperRun = run(['--background'], {
      OIG_CHROME_SANDBOX: helper,
      OIG_TEST_HELPER: helper,
      OIG_TEST_USERNS: '0',
      CHROME_DEVEL_SANDBOX: '/untrusted/inherited/value'
    });
    assert.equal(helperRun.status, 0, helperRun.stderr);
    let launched = fs.readFileSync(record, 'utf8');
    assert.ok(launched.includes('sandbox=' + helper), launched);
    assert.ok(launched.includes('args=--background|'), launched);
    assert.equal(fs.lstatSync(localSandbox).isSymbolicLink(), true);
    assert.equal(fs.realpathSync(localSandbox), helper);

    fs.rmSync(record, { force: true });
    fs.rmSync(localSandbox);
    fs.writeFileSync(localSandbox, 'no-matching-helper-fixture');
    const usernsRun = run(['--background'], {
      OIG_CHROME_SANDBOX: '',
      OIG_TEST_HELPER: '',
      OIG_TEST_USERNS: '1'
    });
    assert.equal(usernsRun.status, 0, usernsRun.stderr);
    launched = fs.readFileSync(record, 'utf8');
    assert.ok(launched.includes('sandbox=\n'), launched);
    assert.ok(launched.includes('args=--background|'), launched);
    assert.equal(fs.existsSync(localSandbox), false);

    fs.rmSync(record, { force: true });
    fs.writeFileSync(localSandbox, 'no-matching-helper-fixture');
    const blockedRun = run(['--background'], {
      OIG_CHROME_SANDBOX: '',
      OIG_TEST_HELPER: '',
      OIG_TEST_USERNS: '0'
    });
    assert.equal(blockedRun.status, 78, blockedRun.stderr);
    assert.match(blockedRun.stderr, /will not run with --no-sandbox/i);
    assert.equal(fs.existsSync(record), false);
    assert.equal(fs.existsSync(localSandbox), true);

    fs.rmSync(localSandbox);
    fs.writeFileSync(localSandbox, 'same-helper-fixture');
    fs.rmSync(record, { force: true });
    const explicitNoSandbox = run(['--no-sandbox'], {
      OIG_CHROME_SANDBOX: helper,
      OIG_TEST_HELPER: helper,
      OIG_TEST_USERNS: '0'
    });
    assert.equal(explicitNoSandbox.status, 78, explicitNoSandbox.stderr);
    assert.match(explicitNoSandbox.stderr, /refuses the --no-sandbox option/i);
    assert.equal(fs.existsSync(record), false);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('Linux AppImage read-only launcher extracts to unique per-invocation directories and cleans them', {
  skip: process.platform !== 'linux'
}, async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-apprun-isolated-test-'));
  const readOnlyDir = path.join(temp, 'ReadOnlyAppDir');
  const runtimeBase = path.join(temp, 'runtime');
  const binDir = path.join(temp, 'bin');
  const readOnlyLauncher = path.join(readOnlyDir, 'AppRun');
  const readOnlyBinary = path.join(readOnlyDir, 'open-internet-gateway');
  const readOnlySandbox = path.join(readOnlyDir, 'chrome-sandbox');
  const fakeAppImage = path.join(temp, 'fake-appimage');
  const extractRecord = path.join(temp, 'extract-record');
  const launchRecord = path.join(temp, 'launch-record');

  try {
    fs.mkdirSync(readOnlyDir);
    fs.mkdirSync(runtimeBase, { mode: 0o700 });
    fs.mkdirSync(binDir);
    fs.copyFileSync(path.join(appRoot, 'build/linux/AppRun'), readOnlyLauncher);
    fs.chmodSync(readOnlyLauncher, 0o755);
    fs.writeFileSync(readOnlySandbox, 'no-matching-helper-fixture');

    writeExecutable(readOnlyBinary, [
      '#!/usr/bin/env bash',
      'printf "%s|%s|%s\\n" "$APPDIR" "$TMPDIR" "$*" >> "$OIG_TEST_LAUNCH_RECORD"',
      'sleep 0.2',
      ''
    ].join('\n'));

    writeExecutable(fakeAppImage, [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      '[[ "$1" == "--appimage-extract" ]]',
      'printf "%s|%s\\n" "$1" "$PWD" >> "$OIG_TEST_EXTRACT_RECORD"',
      'mkdir -p "$PWD/squashfs-root"',
      'cp "$OIG_TEST_APPDIR_SOURCE/AppRun" "$PWD/squashfs-root/AppRun"',
      'cp "$OIG_TEST_APPDIR_SOURCE/open-internet-gateway" "$PWD/squashfs-root/open-internet-gateway"',
      'cp "$OIG_TEST_APPDIR_SOURCE/chrome-sandbox" "$PWD/squashfs-root/chrome-sandbox"',
      'chmod 755 "$PWD/squashfs-root/AppRun" "$PWD/squashfs-root/open-internet-gateway" "$PWD/squashfs-root/chrome-sandbox"',
      ''
    ].join('\n'));

    writeExecutable(path.join(binDir, 'unshare'), [
      '#!/usr/bin/env bash',
      '[[ "${OIG_TEST_USERNS:-0}" == "1" ]] && exit 0',
      'exit 1',
      ''
    ].join('\n'));

    const baseEnv = {
      ...process.env,
      APPDIR: readOnlyDir,
      APPIMAGE: fakeAppImage,
      OIG_TEST_APPDIR_SOURCE: readOnlyDir,
      OIG_TEST_EXTRACT_RECORD: extractRecord,
      OIG_TEST_LAUNCH_RECORD: launchRecord,
      OIG_TEST_USERNS: '1',
      OIG_CHROME_SANDBOX: '',
      OIG_TEST_HELPER: '',
      PATH: binDir + ':' + (process.env.PATH || '/usr/bin:/bin'),
      XDG_RUNTIME_DIR: runtimeBase,
      TMPDIR: runtimeBase
    };

    fs.chmodSync(readOnlyDir, 0o555);
    const runAsync = args => new Promise(resolve => {
      const child = spawn('/bin/bash', [readOnlyLauncher, ...args], {
        encoding: 'utf8',
        env: baseEnv
      });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', chunk => { stdout += chunk.toString(); });
      child.stderr.on('data', chunk => { stderr += chunk.toString(); });
      child.on('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
    });

    const [first, second] = await Promise.all([
      runAsync(['--background', '--run-id=1']),
      runAsync(['--background', '--run-id=2'])
    ]);
    fs.chmodSync(readOnlyDir, 0o755);

    assert.equal(first.code, 0, first.stderr);
    assert.equal(second.code, 0, second.stderr);
    const extracts = fs.readFileSync(extractRecord, 'utf8').trim().split('\n');
    assert.equal(extracts.length, 2, extracts.join('\n'));
    assert.ok(extracts.every(line => line.startsWith('--appimage-extract|')), extracts.join('\n'));
    const extractDirs = extracts.map(line => line.split('|')[1]);
    assert.equal(new Set(extractDirs).size, 2, extracts.join('\n'));

    const launches = fs.readFileSync(launchRecord, 'utf8').trim().split('\n');
    assert.equal(launches.length, 2, launches.join('\n'));
    const appDirs = launches.map(line => line.split('|')[0]);
    assert.equal(new Set(appDirs).size, 2, launches.join('\n'));
    assert.ok(launches.some(line => line.includes('--run-id=1')), launches.join('\n'));
    assert.ok(launches.some(line => line.includes('--run-id=2')), launches.join('\n'));
    assert.deepEqual(fs.readdirSync(runtimeBase), []);
    assert.equal(fs.existsSync(path.join(runtimeBase, 'squashfs-root')), false);
  } finally {
    try { fs.chmodSync(readOnlyDir, 0o755); } catch {}
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('Linux packaged sandbox verifier requires the prepared helper symlink or a removed helper with userns', {
  skip: process.platform !== 'linux'
}, () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-sandbox-verifier-test-'));
  try {
    const runtime = path.join(temp, 'runtime');
    const binDir = path.join(temp, 'bin');
    const appRun = path.join(runtime, 'AppRun');
    const localSandbox = path.join(runtime, 'chrome-sandbox');
    const helperScript = path.join(appRoot, 'backend/linux/harden_sandbox.py');
    fs.mkdirSync(runtime);
    fs.mkdirSync(binDir);
    fs.writeFileSync(appRun, '#!/usr/bin/env bash\nexit 0\n');
    fs.writeFileSync(localSandbox, 'nonmatching-sandbox-fixture');
    const appRunBefore = fs.readFileSync(appRun);
    const sandboxBefore = fs.readFileSync(localSandbox);

    writeExecutable(path.join(binDir, 'unshare'), [
      '#!/usr/bin/env bash',
      '[[ "${OIG_TEST_USERNS:-0}" == "1" ]] && exit 0',
      'exit 1',
      ''
    ].join('\n'));

    const runVerifier = userns => spawnSync('python3', [helperScript, runtime], {
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: binDir + ':' + (process.env.PATH || '/usr/bin:/bin'),
        OIG_TEST_USERNS: userns ? '1' : '0',
        CHROME_DEVEL_SANDBOX: ''
      }
    });

    const invalidHelper = runVerifier(true);
    assert.equal(invalidHelper.status, 0, invalidHelper.stderr);
    const invalidResult = JSON.parse(invalidHelper.stdout.trim());
    assert.equal(invalidResult.supported, true);
    assert.equal(invalidResult.hardened, false);

    fs.rmSync(localSandbox);
    const userns = runVerifier(true);
    assert.equal(userns.status, 0, userns.stderr);
    const usernsResult = JSON.parse(userns.stdout.trim());
    assert.equal(usernsResult.supported, true);
    assert.equal(usernsResult.hardened, true);
    assert.equal(usernsResult.method, 'user-namespaces');

    const blocked = runVerifier(false);
    assert.equal(blocked.status, 0, blocked.stderr);
    const blockedResult = JSON.parse(blocked.stdout.trim());
    assert.equal(blockedResult.supported, true);
    assert.equal(blockedResult.hardened, false);
    assert.match(blockedResult.reason, /did not install a verified root-owned helper/i);

    assert.deepEqual(fs.readFileSync(appRun), appRunBefore);
    assert.equal(fs.existsSync(localSandbox), false);
    assert.deepEqual(sandboxBefore, Buffer.from('nonmatching-sandbox-fixture'));
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
