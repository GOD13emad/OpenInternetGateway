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
    const icon = path.join(root, 'usr', 'share', 'icons', 'hicolor', '512x512', 'apps', 'open-internet-gateway.png');
    if (!fs.existsSync(desktop)) throw new Error('Linux desktop entry missing from Debian artifact');
    if (!fs.existsSync(icon)) throw new Error('Linux application icon missing from Debian artifact');
    fs.chmodSync(desktop, 0o644);
    fs.chmodSync(icon, 0o644);
    run('dpkg-deb', ['--root-owner-group', '-Zxz', '--build', root, rebuilt]);
    const listing = run('dpkg-deb', ['--contents', rebuilt]);
    const lines = listing.split(/\r?\n/);
    const desktopLine = lines.find(line => line.includes('./usr/share/applications/OpenInternetGateway.desktop'));
    const iconLine = lines.find(line => line.includes('./usr/share/icons/hicolor/512x512/apps/open-internet-gateway.png'));
    if (!desktopLine || !desktopLine.startsWith('-rw-r--r--')) {
      throw new Error('Debian desktop entry mode is not 0644 after repack');
    }
    if (!iconLine || !iconLine.startsWith('-rw-r--r--')) {
      throw new Error('Debian application icon mode is not 0644 after repack');
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
