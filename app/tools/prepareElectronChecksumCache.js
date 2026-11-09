const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const VERSION = '44.10.2';
const RELEASE_ASSET_URL = 'https://api.github.com/repos/electron/electron/releases/assets/706723361';
const RELEASE_ASSET_SHA256 = '75346aa3e2499b9ababcefc9d2acae5b2fcf8c036966b3f7045ce2be89d62cf3';
const TRANSIENT_HTTP_STATUS_CODES = new Set([408, 425, 429, 500, 502, 503, 504]);
const TRANSIENT_NETWORK_ERROR_CODES = new Set([
  'ECONNRESET', 'ETIMEDOUT', 'EAI_AGAIN', 'ECONNREFUSED',
  'EHOSTUNREACH', 'ENETUNREACH'
]);

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex').toLowerCase();
}

function isTransientDownloadError(error) {
  return TRANSIENT_HTTP_STATUS_CODES.has(Number(error?.statusCode)) ||
    TRANSIENT_NETWORK_ERROR_CODES.has(String(error?.code || error?.cause?.code || ''));
}

function electronArtifactName(version, platform, arch) {
  const platformName = { win32: 'win32', linux: 'linux', darwin: 'darwin' }[platform];
  const archName = { x64: 'x64', arm64: 'arm64', ia32: 'ia32' }[arch];
  if (!platformName || !archName) {
    throw new Error('Unsupported Electron artifact platform/architecture: ' + platform + '/' + arch);
  }
  return 'electron-v' + version + '-' + platformName + '-' + archName + '.zip';
}

function electronCacheRoot(platform, env, home) {
  const pathApi = platform === 'win32' ? path.win32 : path;
  if (platform === 'win32') {
    return pathApi.join(env.LOCALAPPDATA || pathApi.join(home, 'AppData', 'Local'), 'electron', 'Cache');
  }
  if (platform === 'darwin') {
    return pathApi.join(home, 'Library', 'Caches', 'electron');
  }
  return pathApi.join(env.XDG_CACHE_HOME || pathApi.join(home, '.cache'), 'electron');
}

function validateChecksumManifest(buffer, expectedSha256, artifactName) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    throw new Error('Electron SHASUMS256 manifest is empty');
  }
  const actual = sha256(buffer);
  if (actual !== String(expectedSha256).toLowerCase()) {
    throw new Error('Electron SHASUMS256 manifest SHA-256 mismatch: ' + actual);
  }
  const lines = buffer.toString('utf8').split(/\r?\n/);
  const match = lines
    .map(line => /^([a-fA-F0-9]{64})\s+\*?(.+)$/.exec(line.trim()))
    .find(entry => entry && entry[2] === artifactName);
  if (!match) {
    throw new Error('Pinned Electron SHASUMS256 manifest does not contain ' + artifactName);
  }
  return match[1].toLowerCase();
}

async function fetchManifestWithRetry(options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const attempts = options.attempts ?? 4;
  const baseDelayMs = options.baseDelayMs ?? 1500;
  const wait = options.wait || (ms => new Promise(resolve => setTimeout(resolve, ms)));
  if (typeof fetchImpl !== 'function') throw new Error('Node.js fetch API is unavailable');
  if (!Number.isInteger(attempts) || attempts < 1) {
    throw new TypeError('Electron checksum fetch attempts must be a positive integer');
  }
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetchImpl(RELEASE_ASSET_URL, {
        headers: {
          Accept: 'application/octet-stream',
          'X-GitHub-Api-Version': '2022-11-28',
          'User-Agent': 'OpenInternetGateway-build'
        }
      });
      if (!response.ok) {
        const error = new Error('Electron SHASUMS256 download failed with HTTP ' + response.status);
        error.statusCode = response.status;
        throw error;
      }
      return Buffer.from(await response.arrayBuffer());
    } catch (error) {
      if (attempt === attempts || !isTransientDownloadError(error)) throw error;
      const delay = baseDelayMs * (2 ** (attempt - 1));
      console.warn(
        'Electron SHASUMS256 attempt ' + attempt + '/' + attempts +
        ' failed transiently; retrying in ' + delay + 'ms: ' + error.message
      );
      await wait(delay);
    }
  }
  throw new Error('Electron SHASUMS256 download attempts exhausted');
}

async function seedElectronChecksumCache(options = {}) {
  const version = options.version || VERSION;
  const packageJson = options.packageJson || require('../package.json');
  if (packageJson.devDependencies?.electron !== version) {
    throw new Error(
      'Electron checksum pin is for ' + VERSION +
      ' but package.json requests ' + String(packageJson.devDependencies?.electron)
    );
  }
  const platform = options.platform || process.platform;
  const arch = options.arch || process.arch;
  const artifactName = options.artifactName || electronArtifactName(version, platform, arch);
  const expectedSha256 = options.expectedAssetSha256 || RELEASE_ASSET_SHA256;
  const buffer = options.buffer || await fetchManifestWithRetry(options);
  const artifactSha256 = validateChecksumManifest(buffer, expectedSha256, artifactName);
  const cacheRoot = options.cacheRoot || electronCacheRoot(
    platform, options.env || process.env, options.home || os.homedir()
  );
  fs.mkdirSync(cacheRoot, { recursive: true, mode: 0o700 });
  const target = path.join(cacheRoot, 'SHASUMS256.txt-' + version);
  const temporary = target + '.' + process.pid + '.tmp';
  try {
    fs.writeFileSync(temporary, buffer, { mode: 0o600 });
    try { fs.rmSync(target, { force: true }); } catch {}
    fs.renameSync(temporary, target);
  } finally {
    try { fs.rmSync(temporary, { force: true }); } catch {}
  }
  return {
    version,
    artifactName,
    artifactSha256,
    manifestSha256: sha256(buffer),
    cacheFile: target
  };
}

async function main() {
  const result = await seedElectronChecksumCache();
  console.log(
    'Seeded official Electron ' + result.version + ' checksums for ' +
    result.artifactName + ' (' + result.artifactSha256 + ') at ' + result.cacheFile
  );
}

if (require.main === module) {
  main().catch(error => {
    console.error(error?.stack || error);
    process.exit(1);
  });
}

module.exports = {
  VERSION,
  RELEASE_ASSET_URL,
  RELEASE_ASSET_SHA256,
  sha256,
  isTransientDownloadError,
  electronArtifactName,
  electronCacheRoot,
  validateChecksumManifest,
  fetchManifestWithRetry,
  seedElectronChecksumCache
};
