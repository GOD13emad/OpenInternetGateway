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
        reject(new Error(`PowerShell archive download failed with HTTP ${code}`));
        return;
      }
      const out = fs.createWriteStream(file, { flags: 'w' });
      res.pipe(out);
      out.on('finish', () => out.close(resolve));
      out.on('error', reject);
      res.on('error', reject);
    });
    req.setTimeout(60000, () => req.destroy(new Error('PowerShell archive download timed out')));
    req.on('error', reject);
  });
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
    await download(PWSH_URL, archive);
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

main().catch(error => {
  console.error(error?.stack || error);
  process.exit(1);
});
