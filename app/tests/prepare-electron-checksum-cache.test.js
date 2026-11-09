const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  sha256,
  electronArtifactName,
  electronCacheRoot,
  validateChecksumManifest,
  seedElectronChecksumCache
} = require('../tools/prepareElectronChecksumCache');

function manifest(artifactName = 'electron-v44.10.2-linux-x64.zip') {
  return Buffer.from(
    'd2f9319dc81d6786c684a80f63d728421761f55a27a3ae3bd373250f0f40fdca *' + artifactName + '\n' +
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa *electron-v44.10.2-win32-x64.zip\n',
    'utf8'
  );
}

function tempRoot(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-electron-checksums-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

test('Electron checksum manifest is pinned by digest and contains the exact requested platform artifact', () => {
  const data = manifest();
  assert.equal(
    validateChecksumManifest(data, sha256(data), 'electron-v44.10.2-linux-x64.zip'),
    'd2f9319dc81d6786c684a80f63d728421761f55a27a3ae3bd373250f0f40fdca'
  );
  assert.throws(
    () => validateChecksumManifest(data, '0'.repeat(64), 'electron-v44.10.2-linux-x64.zip'),
    /SHA-256 mismatch/
  );
  assert.throws(
    () => validateChecksumManifest(data, sha256(data), 'electron-v44.10.2-win32-arm64.zip'),
    /does not contain/
  );
});

test('Electron artifact names and cache roots follow app-builder platform conventions', () => {
  assert.equal(electronArtifactName('44.10.2', 'linux', 'x64'), 'electron-v44.10.2-linux-x64.zip');
  assert.equal(electronArtifactName('44.10.2', 'win32', 'x64'), 'electron-v44.10.2-win32-x64.zip');
  assert.equal(
    electronCacheRoot('linux', { XDG_CACHE_HOME: '/cache' }, '/home/test'),
    path.join('/cache', 'electron')
  );
  assert.equal(
    electronCacheRoot('win32', { LOCALAPPDATA: 'C:\\Users\\test\\AppData\\Local' }, 'C:\\Users\\test'),
    path.win32.join('C:\\Users\\test\\AppData\\Local', 'electron', 'Cache')
  );
});

test('Electron checksum seeding retries HTTP 504, verifies the manifest, and writes the versioned cache file', async t => {
  const root = tempRoot(t);
  const data = manifest();
  const waits = [];
  let attempts = 0;
  const result = await seedElectronChecksumCache({
    version: '44.10.2',
    packageJson: { devDependencies: { electron: '44.10.2' } },
    platform: 'linux',
    arch: 'x64',
    cacheRoot: root,
    expectedAssetSha256: sha256(data),
    attempts: 3,
    baseDelayMs: 20,
    wait: async ms => waits.push(ms),
    fetchImpl: async () => {
      attempts += 1;
      if (attempts === 1) return { ok: false, status: 504 };
      return { ok: true, status: 200, arrayBuffer: async () => data };
    }
  });
  assert.equal(attempts, 2);
  assert.deepEqual(waits, [20]);
  assert.equal(result.artifactName, 'electron-v44.10.2-linux-x64.zip');
  assert.equal(result.artifactSha256, 'd2f9319dc81d6786c684a80f63d728421761f55a27a3ae3bd373250f0f40fdca');
  assert.equal(result.manifestSha256, sha256(data));
  assert.equal(fs.readFileSync(result.cacheFile).equals(data), true);
  assert.equal(fs.statSync(result.cacheFile).mode & 0o777, 0o600);
});

test('Electron checksum seeding refuses permanent HTTP errors and mismatched Electron versions', async t => {
  const root = tempRoot(t);
  let attempts = 0;
  await assert.rejects(seedElectronChecksumCache({
    version: '44.10.2',
    packageJson: { devDependencies: { electron: '44.10.2' } },
    platform: 'linux',
    arch: 'x64',
    cacheRoot: root,
    fetchImpl: async () => {
      attempts += 1;
      return { ok: false, status: 404 };
    },
    wait: async () => assert.fail('HTTP 404 must not be retried')
  }), /HTTP 404/);
  assert.equal(attempts, 1);
  await assert.rejects(seedElectronChecksumCache({
    version: '44.10.2',
    packageJson: { devDependencies: { electron: '45.0.0' } },
    platform: 'linux',
    arch: 'x64',
    cacheRoot: root,
    fetchImpl: async () => assert.fail('version mismatch must fail before network')
  }), /package.json requests 45.0.0/);
});
