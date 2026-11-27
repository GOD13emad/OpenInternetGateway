'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { DEFAULT_RELEASE_URL, trustedReleaseUrl } = require('../src/main/release-url');

test('trusted GitHub release links remain usable', () => {
  assert.equal(trustedReleaseUrl(DEFAULT_RELEASE_URL), DEFAULT_RELEASE_URL);
  assert.equal(
    trustedReleaseUrl('https://github.com/GOD13emad/OpenInternetGateway/releases/tag/v2.5.19'),
    'https://github.com/GOD13emad/OpenInternetGateway/releases/tag/v2.5.19'
  );
});

test('reject protocols, redirects, lookalikes, encoded paths and credentials', () => {
  for (const value of [
    'javascript:alert(1)',
    'file:///etc/passwd',
    'https://example.invalid/GOD13emad/OpenInternetGateway/releases/latest',
    'https://github.com.evil.invalid/GOD13emad/OpenInternetGateway/releases/latest',
    'https://github.com@evil.invalid/GOD13emad/OpenInternetGateway/releases/latest',
    'https://evil.invalid@github.com/GOD13emad/OpenInternetGateway/releases/latest',
    'http://github.com/GOD13emad/OpenInternetGateway/releases/latest',
    'https://github.com:444/GOD13emad/OpenInternetGateway/releases/latest',
    'https://github.com/GOD13emad/OpenInternetGateway/releases/latest?next=evil',
    'https://github.com/GOD13emad/OpenInternetGateway/releases/latest#fragment',
    'https://github.com/GOD13emad/OpenInternetGateway/releases/tag/..',
    'https://github.com/GOD13emad/OpenInternetGateway/releases/tag/%2fattack',
    'https://github.com/GOD13emad/OpenInternetGateway/releases/tag/v1/extra',
    'https://github.com/GOD13emad/other-repository/releases/latest',
    'https://github.com/GOD13emad/OpenInternetGateway/issues',
    ' https://github.com/GOD13emad/OpenInternetGateway/releases/latest',
    'https:\\\\github.com\\GOD13emad\\OpenInternetGateway\\releases\\latest',
    null,
    undefined,
    {},
    'x'.repeat(513)
  ]) {
    assert.equal(trustedReleaseUrl(value), DEFAULT_RELEASE_URL, String(value));
  }
});

test('gateway openRelease always passes an allowlisted link to Electron', () => {
  const main = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'main.js'), 'utf8');
  assert.match(main, /require\(['"]\.\/release-url['"]\)/);
  assert.match(main, /url = trustedReleaseUrl\(url\);\s*await shell\.openExternal\(url\);\s*return \{ ok: true, url \}/);
});
