'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { OFFICIAL_URL, MAX_BYTES, parsePublicLogin, fetchPublicLogin } =
  require('../src/main/vpnbook-public-credentials');

const now = Date.parse('2026-11-09T12:00:00Z');
function fixture(password = 'fake0abc', update = 'Nov 8, 2026') {
  return '<html><script>Username vpnbook Copy Password injected123 Copy Last updated: Nov 8, 2026</script>' +
    '<main><h2>VPN Credentials</h2><p>Use these credentials for all VPN servers</p>' +
    '<div>Username</div><code>vpnbook</code><span>Copy</span>' +
    '<div>Password</div><code>' + password + '</code><span>Copy</span>' +
    '<p>Last updated: ' + update + '</p></main></html>';
}
function response(body, opts = {}) {
  const r = new Response(body, {
    status: opts.status || 200, headers: { 'content-type': opts.type || 'text/html' }
  });
  Object.defineProperty(r, 'url', { value: opts.url || OFFICIAL_URL });
  return r;
}

test('parse official free login, reject script injection, and keep source provenance', () => {
  const result = parsePublicLogin(fixture(), now);
  assert.deepEqual(result, {
    username: 'vpnbook', password: 'fake0abc',
    lastUpdated: '2026-11-08', source: OFFICIAL_URL
  });
});
test('fail closed on stale, future, malformed, ambiguous and oversized HTML', () => {
  assert.throws(() => parsePublicLogin(fixture('fake0abc','Sep 14, 2026'), now), /stale/);
  assert.throws(() => parsePublicLogin(fixture('fake0abc','Nov 15, 2026'), now), /stale/);
  assert.throws(() => parsePublicLogin(fixture('bad secret'), now), /ambiguous/);
  assert.throws(() => parsePublicLogin(fixture() + ' '.repeat(MAX_BYTES), now), /large/);
  assert.throws(() => parsePublicLogin('<div>Username vpnbook Copy Password fake0abc</div>', now), /section/);
});
test('HTTPS fetch is bounded, does not follow redirects and never logs credentials', async () => {
  let called = 0;
  const login = await fetchPublicLogin({ now: () => now, request: async (url, init) => {
    called++;
    assert.equal(url, OFFICIAL_URL);
    assert.equal(init.redirect, 'error');
    assert.equal(init.cache, 'no-store');
    assert.equal(init.headers.Accept, 'text/html');
    return response(fixture());
  }});
  assert.equal(called, 1);
  assert.equal(login.username, 'vpnbook');
  assert.equal(login.password, 'fake0abc');
  for (const bad of [
    response(fixture(), { url: 'https://other.example/freevpn/openvpn' }),
    response(fixture(), { type: 'text/plain' }),
    response('a'.repeat(MAX_BYTES + 1))
  ]) {
    await assert.rejects(fetchPublicLogin({ now: () => now, request: async () => bad }),
      /Cannot securely retrieve current free VPNBook credentials/);
  }
});
test('Linux UI requires distinct owner consent, credential fetch is read-only and password remains transient', () => {
  const dir = path.join(__dirname, '../src');
  const main = fs.readFileSync(path.join(dir,'main/main.js'),'utf8');
  const preload = fs.readFileSync(path.join(dir,'preload/preload.js'),'utf8');
  const renderer = fs.readFileSync(path.join(dir,'renderer/app.js'),'utf8');
  const markup = fs.readFileSync(path.join(dir,'renderer/index.html'),'utf8');
  const backend = fs.readFileSync(path.join(dir,'main/platform-backend.js'),'utf8');
  assert.match(main,/gateway:freeVpnBookCredentials/);
  assert.match(preload,/gateway:freeVpnBookCredentials/);
  assert.match(renderer,/loadFreeVpnBookCredentials/);
  assert.match(renderer,/operatorPassword'\)\.value = ''/);
  assert.match(renderer,/operatorTrialConsent/);
  assert.match(backend,/fetchPublicLogin/);
  assert.match(markup,/id="operatorFreeCredentialsButton"/);
  assert.match(markup,/id="operatorCredentialsStatus"/);
});

test('reject conflicting free shared logins and provider name substitution', () => {
  const extra = '<p>Username vpnbook Copy Password fake1234 Copy Last updated: Nov 8, 2026</p>';
  assert.throws(() => parsePublicLogin(fixture().replace('</main>', extra + '</main>'), now), /ambiguous/);
  assert.throws(() => parsePublicLogin(fixture().replace('<code>vpnbook</code>', '<code>attacker</code>'), now), /ambiguous/);
});
test('backend never retrieves free login on Windows or while a gateway task is active', async () => {
  const Backend = require('../src/main/platform-backend');
  const backend = new Backend({ version: '2.5.20', resourcesPath: '', appPath: '', userData: '' });
  backend.platform = 'win32';
  await assert.rejects(backend.freeVpnBookCredentials(), /Linux QA-only/);
  backend.platform = 'linux';
  backend.operatorTrialBusy = true;
  await assert.rejects(backend.freeVpnBookCredentials(), /Wait for the active gateway task/);
  backend.operatorTrialBusy = false;
  backend.gatewayActionCount = 1;
  await assert.rejects(backend.freeVpnBookCredentials(), /Wait for the active gateway task/);
});
