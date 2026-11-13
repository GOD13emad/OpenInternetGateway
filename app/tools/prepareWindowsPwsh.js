const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const VERSION = '7.5.4';
const PWSH_URL = `https://github.com/PowerShell/PowerShell/releases/download/v${VERSION}/PowerShell-${VERSION}-win-x64.zip`;
const SHA256 = 'b40d192ae95ba6ccc4cc362ff4e1b18ca6fb5055bebbcd3920684e12701fa8f6';
const appRoot = path.resolve(__dirname, '..');
const target = path.join(appRoot, 'vendor', 'pwsh');
const marker = path.join(target, '.oig-pwsh.json');

function download(url, file, redirects = 5) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'OpenInternetGateway-build' } }, res => {
      const code = Number(res.statusCode || 0);
      if ([301,302,303,307,308].includes(code) && res.headers.location && redirects > 0) {
        res.resume();
        download(new URL(res.headers.location, url).toString(), file, redirects - 1).then(resolve, reject);
        return;
      }
      if (code < 200 || code >= 300) {
        res.resume();
        const error = new Error('PowerShell archive download failed with HTTP ' + code);
        error.statusCode = code;
        reject(error);
        return;
      }
      const out = fs.createWriteStream(file, { flags: 'w' });
      res.pipe(out);
      out.on('finish', () => out.close(resolve));
      out.on('error', reject);
      res.on('error', reject);
    });
    req.setTimeout(60000, () => {
      const error = new Error('PowerShell archive download timed out');
      error.code = 'ETIMEDOUT';
      req.destroy(error);
    });
    req.on('error', reject);
  });
}

const TRANSIENT_HTTP_STATUS_CODES = new Set([408, 425, 429, 500, 502, 503, 504]);
const TRANSIENT_NETWORK_ERROR_CODES = new Set([
  'ECONNRESET', 'ETIMEDOUT', 'EAI_AGAIN', 'ECONNREFUSED',
  'EHOSTUNREACH', 'ENETUNREACH'
]);

function isTransientDownloadError(error) {
  return TRANSIENT_HTTP_STATUS_CODES.has(Number(error?.statusCode)) ||
    TRANSIENT_NETWORK_ERROR_CODES.has(String(error?.code || ''));
}

async function downloadWithRetry(url, file, options = {}) {
  const attempts = options.attempts ?? 4;
  const baseDelayMs = options.baseDelayMs ?? 1500;
  const downloader = options.downloader ?? download;
  const wait = options.wait ?? (ms => new Promise(resolve => setTimeout(resolve, ms)));
  const logger = options.logger ?? console;
  if (!Number.isInteger(attempts) || attempts < 1) {
    throw new TypeError('PowerShell download attempts must be a positive integer');
  }
  if (!Number.isFinite(baseDelayMs) || baseDelayMs < 0) {
    throw new TypeError('PowerShell download retry delay must be a non-negative number');
  }

  try { fs.rmSync(file, { force: true }); } catch {}
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const attemptFile = file + '.attempt-' + attempt;
    try {
      fs.rmSync(attemptFile, { force: true });
      await downloader(url, attemptFile);
      fs.renameSync(attemptFile, file);
      return;
    } catch (error) {
      try { fs.rmSync(attemptFile, { force: true }); } catch {}
      if (attempt === attempts || !isTransientDownloadError(error)) throw error;
      const delay = baseDelayMs * (2 ** (attempt - 1));
      logger.warn?.(
        'PowerShell archive attempt ' + attempt + '/' + attempts +
        ' failed transiently; retrying in ' + delay + 'ms: ' + error.message
      );
      await wait(delay);
    }
  }
}

function sha256(file) {
  const hash = crypto.createHash('sha256');
  const fd = fs.openSync(file, 'r');
  try {
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let read = 0;
    do {
      read = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (read) hash.update(buffer.subarray(0, read));
    } while (read);
  } finally { fs.closeSync(fd); }
  return hash.digest('hex').toLowerCase();
}

async function main() {
  if (process.platform !== 'win32') throw new Error('Windows PowerShell payload preparation must run on Windows.');
  try {
    const current = JSON.parse(fs.readFileSync(marker, 'utf8'));
    if (current.version === VERSION && current.sha256 === SHA256 && fs.existsSync(path.join(target, 'pwsh.exe'))) {
      console.log(`Bundled PowerShell ${VERSION} already prepared.`);
      return;
    }
  } catch {}

  const archive = path.join(os.tmpdir(), `oig-powershell-${VERSION}-${process.pid}.zip`);
  try {
    try { fs.unlinkSync(archive); } catch {}
    console.log(`Downloading verified PowerShell ${VERSION} portable runtime…`);
    await downloadWithRetry(PWSH_URL, archive);
    const actual = sha256(archive);
    if (actual !== SHA256) throw new Error(`PowerShell archive SHA-256 mismatch: ${actual}`);
    fs.rmSync(target, { recursive: true, force: true });
    fs.mkdirSync(target, { recursive: true });
    const extract = spawnSync('tar.exe', ['-xf', archive, '-C', target], { stdio: 'inherit', windowsHide: true });
    if (extract.status !== 0) throw new Error(`tar.exe failed to extract PowerShell archive (${extract.status})`);
    if (!fs.existsSync(path.join(target, 'pwsh.exe'))) throw new Error('PowerShell extraction completed without pwsh.exe');
    fs.writeFileSync(marker, JSON.stringify({ version: VERSION, sha256: SHA256, source: PWSH_URL }, null, 2) + '\n');
    console.log(`Prepared PowerShell ${VERSION}; SHA-256 ${SHA256}`);
  } finally {
    try { fs.unlinkSync(archive); } catch {}
  }
}

if (require.main === module) {
  main().catch(error => {
    console.error(error?.stack || error);
    process.exit(1);
  });
}

module.exports = {
  VERSION,
  PWSH_URL,
  SHA256,
  download,
  downloadWithRetry,
  isTransientDownloadError,
  sha256
};
