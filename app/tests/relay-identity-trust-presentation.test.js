const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');

test('disconnected, unverified connected, and verified connected states never conflate protection', () => {
  const ui = fs.readFileSync(path.join(root, 'src/renderer/app.js'), 'utf8');
  const m = ui.match(/function protectionStatusLabel\(connected, identityVerified, score\) \{[\s\S]*?\n\}/);
  assert.ok(m, 'pure security display policy exists');
  const policy = vm.runInNewContext('(' + m[0] + ')');
  assert.equal(policy(false, false, 4), '0%');
  assert.equal(policy(false, true, 4), '0%');
  assert.equal(policy(true, false, 4), 'Unverified');
  assert.equal(policy(true, false, 0), 'Unverified');
  assert.equal(policy(true, true, 4), '100%');
  assert.equal(policy(true, true, 3), '75%');
  assert.match(ui, /const identityVerified = s\.serverIdentityVerified === true/);
  assert.match(ui, /Server certificate identity not independently verified/);
  assert.match(ui, /Tunnel active · relay unverified/);
  assert.match(ui, /IPv4 uses VPN; relay identity unverified/);
  assert.match(ui, /setText\('healthScore', protectionStatusLabel\(connected, identityVerified, score\)\)/);
});
test('backend cannot infer public relay identity from transport, geography or cached data', () => {
  const backend = fs.readFileSync(path.join(root, 'src/main/platform-backend.js'), 'utf8');
  assert.match(backend, /return \{ \.\.\.base, activeSha, configPool, serverIdentityVerified: false \}/);
  assert.match(backend, /serverIdentityVerified: false,\s*error: error\.message/);
  assert.doesNotMatch(backend, /serverIdentityVerified:\s*!!base\./);
});
