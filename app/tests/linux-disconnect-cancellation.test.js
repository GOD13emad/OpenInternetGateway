'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const source = path.join(__dirname, '../backend/linux/oig-linux.sh');
const onLinux = process.platform === 'linux';

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-cancel-user-qa-'));
  const bin = path.join(root, 'bin');
  const state = path.join(root, 'state');
  fs.mkdirSync(bin, { mode: 0o700 });
  fs.mkdirSync(state, { mode: 0o700 });
  const factoryReady = path.join(root, 'factory-ready');
  const nmLog = path.join(root, 'nmcli-call-log');
  const mk = (name, contents) => {
    const file = path.join(bin, name);
    fs.writeFileSync(file, contents, { mode: 0o700 });
    return file;
  };
  mk('python3', `#!/bin/sh
# This private test intentionally never executes Python or touches a VPN.
if [ "$1" = "-c" ]; then exit 1; fi
if [ "$1" = "-B" ]; then exit 0; fi
case "$1" in
  */config_factory.py)
    if [ "$2" = "ensure" ]; then
      printf 'ready' > "$OIG_MOCK_FACTORY_READY"
      sleep 1.2
    fi
    exit 0;;
esac
exit 0
`);
  mk('nmcli', `#!/bin/sh
printf '%s\\n' "$*" >> "$OIG_MOCK_NM_LOG"
case " $* " in
  *" connection up "*) exit 93;;
esac
# No saved or active VPN profile is ever reported by the fake NM.
exit 0
`);
  const env = {
    ...process.env,
    PATH: bin + path.delimiter + process.env.PATH,
    OIG_HOME: root, OIG_COMMON: path.join(root, 'common'),
    OIG_MOCK_FACTORY_READY: factoryReady,
    OIG_MOCK_NM_LOG: nmLog,
    DISPLAY: '', WAYLAND_DISPLAY: ''
  };
  const children = new Set();
  function start(cmd, args, extraEnv = {}) {
    const child = spawn(cmd, args, {
      env: { ...env, ...extraEnv }, stdio: ['ignore', 'pipe', 'pipe']
    });
    children.add(child);
    let stdout = '', stderr = '';
    child.stdout.on('data', b => { stdout += b.toString(); });
    child.stderr.on('data', b => { stderr += b.toString(); });
    child.completed = new Promise((resolve, reject) => {
      child.on('error', reject);
      child.on('close', (code, signal) => {
        children.delete(child);
        resolve({ code, signal, stdout, stderr });
      });
    });
    return child;
  }
  t.after(() => {
    for (const child of children) {
      try { child.kill('SIGKILL'); } catch {}
    }
    fs.rmSync(root, { recursive: true, force: true });
  });
  return { root, state, factoryReady, nmLog, start, env };
}
async function until(check, label) {
  for (let i = 0; i < 180; i++) {
    if (check()) return;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error('Mocked cancellation barrier did not occur: ' + label);
}
async function settled(child) {
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error('Mocked gateway action did not exit'));
    }, 6500);
    child.completed.then(
      result => { clearTimeout(timer); resolve(result); },
      error => { clearTimeout(timer); reject(error); }
    );
  });
}

test('Linux disconnect cancels an in-flight Connect before any NM VPN activation', {
  skip: !onLinux
}, async (t) => {
  const f = fixture(t);
  const connect = f.start('/bin/bash', [source, 'connect']);
  await until(() => fs.existsSync(f.factoryReady), 'factory in flight');
  const disconnect = f.start('/bin/bash', [source, 'disconnect']);
  const [c, d] = await Promise.all([settled(connect), settled(disconnect)]);
  assert.equal(c.code, 76, c.stderr || c.stdout);
  assert.equal(d.code, 0, d.stderr || d.stdout);
  assert.equal(fs.readFileSync(path.join(f.state, 'desired-state'), 'utf8').trim(), 'off');
  assert.ok(fs.readFileSync(path.join(f.state, 'disconnect-generation'), 'utf8').trim());
  assert.doesNotMatch(fs.existsSync(f.nmLog) ? fs.readFileSync(f.nmLog, 'utf8') : '',
    /connection (up|import|modify)/);
  assert.equal(fs.existsSync(path.join(f.state, 'linux.keep')), false);
});

test('Linux queued Connect cannot overtake newer Disconnect despite flock scheduling', {
  skip: !onLinux
}, async (t) => {
  const f = fixture(t);
  const lock = path.join(f.state, 'gateway.lock');
  const holderReady = path.join(f.root, 'holder-ready');
  const holder = f.start('/usr/bin/flock', [
    '-x', lock, '/bin/sh', '-c',
    'printf ready > "$OIG_MOCK_HOLDER_READY"; sleep 1.5'
  ], { OIG_MOCK_HOLDER_READY: holderReady });
  await until(() => fs.existsSync(holderReady), 'holder has flock');
  const queued = f.start('/bin/bash', [source, 'connect']);
  await until(() => {
    try {
      return fs.readlinkSync('/proc/' + queued.pid + '/fd/9') === lock;
    } catch { return false; }
  }, 'queued Connect blocked on fd9 flock');
  const disconnect = f.start('/bin/bash', [source, 'disconnect']);
  await until(() => fs.existsSync(path.join(f.state, 'disconnect-generation')),
    'immediate disconnect cancellation marker');
  const [h, c, d] = await Promise.all([
    settled(holder), settled(queued), settled(disconnect)
  ]);
  assert.equal(h.code, 0, h.stderr || h.stdout);
  assert.equal(c.code, 76, c.stderr || c.stdout);
  assert.match(c.stderr, /Queued operation canceled by a newer Disconnect/);
  assert.equal(d.code, 0, d.stderr || d.stdout);
  assert.equal(fs.readFileSync(path.join(f.state, 'desired-state'), 'utf8').trim(), 'off');
  assert.doesNotMatch(fs.existsSync(f.nmLog) ? fs.readFileSync(f.nmLog, 'utf8') : '',
    /connection (up|import|modify)/);
});

test('Stale exact-profile recovery epoch is refused at shell entry before any VPN command', {
  skip: !onLinux
}, async (t) => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.state, 'disconnect-generation'), '444.555.666\n');
  fs.writeFileSync(path.join(f.state, 'desired-state'), 'off\n');
  const pending = f.start('/bin/bash', [source, 'connect'], {
    OIG_EXPECT_DISCONNECT_GENERATION: '111.222.333'
  });
  const result = await settled(pending);
  assert.equal(result.code, 76, result.stderr || result.stdout);
  assert.match(result.stderr, /Obsolete Linux gateway request canceled by Disconnect/);
  assert.equal(fs.readFileSync(path.join(f.state, 'desired-state'), 'utf8').trim(), 'off');
  assert.equal(fs.existsSync(f.nmLog), false,
    'A stale recovery must not even inspect NetworkManager');
});
