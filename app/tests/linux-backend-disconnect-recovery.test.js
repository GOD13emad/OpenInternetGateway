'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Backend = require('../src/main/platform-backend');

const selected = 'a'.repeat(64);
const previous = 'b'.repeat(64);
const recovered = 'c'.repeat(64);
const initialEpoch = '111.222.333';
const laterEpoch = '444.555.666';

function setup(t, { desired = 'on', withPrevious = true } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-exact-cancel-qa-'));
  const state = path.join(root, 'state');
  fs.mkdirSync(state);
  fs.writeFileSync(path.join(state, 'desired-state'), desired + '\n');
  fs.writeFileSync(path.join(state, 'disconnect-generation'), initialEpoch + '\n');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const backend = new Backend({
    version: '2.5.20', resourcesPath: root,
    appPath: root, userData: root, emit: () => {}
  });
  backend.platform = 'linux';
  backend.backendRoot = root;
  backend.profiles = async () => ({
    profiles: [
      { sha256: selected, country: 'US', host: 'us.invalid', active: false },
      ...(withPrevious ? [
        { sha256: previous, country: 'DE', host: 'de.invalid', active: true }
      ] : [])
    ],
    preferredSha: withPrevious ? previous : ''
  });
  backend.status = async () => ({ connected: true, country: 'US', fullRoutes: 2 });
  const setProfile = (sha) => fs.writeFileSync(
    path.join(state, 'current-linux-profile.json'),
    JSON.stringify({ sha256: sha, host: sha === previous ? 'de.invalid' : 'us.invalid' })
  );
  const disconnect = () => {
    fs.writeFileSync(path.join(state, 'desired-state'), 'off\n');
    fs.writeFileSync(path.join(state, 'disconnect-generation'), laterEpoch + '\n');
  };
  return { backend, root, state, setProfile, disconnect };
}

test('Linux exact-profile failure after user Disconnect never restarts previous or general VPN', async (t) => {
  const f = setup(t);
  const calls = [];
  f.backend._linux = async (action, args, options) => {
    calls.push({ action, args, options });
    f.disconnect();
    throw new Error('Simulated canceled connection');
  };
  await assert.rejects(
    f.backend.connectProfile(selected),
    /canceled by Disconnect; automatic recovery was suppressed/
  );
  assert.equal(calls.length, 1, 'No new OpenVPN recovery after explicit Disconnect');
  assert.equal(calls[0].action, 'connect-profile');
  assert.deepEqual(calls[0].options, { expectedCancelEpoch: initialEpoch });
  assert.equal(fs.readFileSync(path.join(f.state, 'desired-state'), 'utf8').trim(), 'off');
});

test('Linux exact-profile failure still restores former healthy relay without Disconnect', async (t) => {
  const f = setup(t);
  const calls = [];
  f.backend._linux = async (action, args, options) => {
    calls.push({ action, args, options });
    if (calls.length === 1) throw new Error('Simulated profile failure');
    f.setProfile(previous);
    return { ok: true };
  };
  const result = await f.backend.connectProfile(selected);
  assert.equal(result.code, 'SELECTED_RELAY_FAILED_RESTORED');
  assert.equal(result.recovered, true);
  assert.deepEqual(calls.map(v => v.action), ['connect-profile', 'connect-profile']);
  assert.deepEqual(calls.map(v => v.args[0]), [selected, previous]);
  for (const v of calls) assert.equal(v.options.expectedCancelEpoch, initialEpoch);
});

test('Linux normal fallback recovery retains expected cancellation epoch', async (t) => {
  const f = setup(t, { withPrevious: false });
  const calls = [];
  f.backend._linux = async (action, args, options) => {
    calls.push({ action, args, options });
    if (action === 'connect-profile') throw new Error('Simulated profile failure');
    assert.equal(action, 'connect');
    f.setProfile(recovered);
    return { ok: true };
  };
  const result = await f.backend.connectProfile(selected);
  assert.equal(result.code, 'SELECTED_RELAY_FAILED_GENERAL_RECOVERY');
  assert.equal(result.recovered, true);
  assert.deepEqual(calls.map(v => v.action), ['connect-profile', 'connect']);
  for (const v of calls) assert.equal(v.options.expectedCancelEpoch, initialEpoch);
});

test('Linux user-selected profile while initially disconnected is not falsely canceled', async (t) => {
  const f = setup(t, { desired: 'off', withPrevious: false });
  const calls = [];
  f.backend._linux = async (action, args, options) => {
    calls.push({ action, args, options });
    fs.writeFileSync(path.join(f.state, 'desired-state'), 'on\n');
    f.setProfile(selected);
    return { ok: true };
  };
  const result = await f.backend.connectProfile(selected);
  assert.equal(result.ok, true);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].options, { expectedCancelEpoch: initialEpoch });
});
