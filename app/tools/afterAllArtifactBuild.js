const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

function run(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(command + ' ' + args.join(' ') + ' failed: ' + (result.stderr || result.stdout || '').trim());
  }
  return String(result.stdout || '');
}

function fixDebDesktopMode(debPath) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-deb-mode-'));
  const root = path.join(temp, 'root');
  const rebuilt = path.join(temp, path.basename(debPath));
  try {
    run('dpkg-deb', ['--raw-extract', debPath, root]);
    fs.chmodSync(root, 0o755);
    const controlDir = path.join(root, 'DEBIAN');
    if (!fs.existsSync(controlDir)) throw new Error('Debian control directory missing after raw extract');
    fs.chmodSync(controlDir, 0o755);
    const desktop = path.join(root, 'usr', 'share', 'applications', 'OpenInternetGateway.desktop');
    if (!fs.existsSync(desktop)) throw new Error('Linux desktop entry missing from Debian artifact');
    fs.chmodSync(desktop, 0o644);
    run('dpkg-deb', ['--root-owner-group', '-Zxz', '--build', root, rebuilt]);
    const listing = run('dpkg-deb', ['--contents', rebuilt]);
    const desktopLine = listing.split(/\r?\n/).find(line => line.includes('./usr/share/applications/OpenInternetGateway.desktop'));
    if (!desktopLine || !desktopLine.startsWith('-rw-r--r--')) {
      throw new Error('Debian desktop entry mode is not 0644 after repack');
    }
    fs.copyFileSync(rebuilt, debPath);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

module.exports = async function afterAllArtifactBuild(result) {
  if (process.platform !== 'linux') return [];
  const debs = (result.artifactPaths || []).filter(file => /\.deb$/i.test(file));
  for (const deb of debs) fixDebDesktopMode(deb);
  return [];
};
