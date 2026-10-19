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
    // electron-builder's generated postrm still targets the product-name
    // directory with spaces, whereas our Debian payload installs under the
    // canonical lowercase executable directory.  A stale alternatives path
    // cannot unregister the installed launcher on package removal.
    const postRemove = path.join(controlDir, 'postrm');
    const legacyAlternative = "update-alternatives --remove 'open-internet-gateway' '/opt/Open Internet Gateway/open-internet-gateway'";
    const correctAlternative = "update-alternatives --remove 'open-internet-gateway' '/opt/open-internet-gateway/open-internet-gateway'";
    if (fs.existsSync(postRemove)) {
      const source = fs.readFileSync(postRemove, 'utf8');
      if (source.includes(legacyAlternative)) {
        fs.writeFileSync(postRemove, source.replace(legacyAlternative, correctAlternative));
      } else if (source.includes("update-alternatives --remove 'open-internet-gateway'") &&
                 !source.includes(correctAlternative)) {
        throw new Error('Debian postrm contains an unexpected alternatives target');
      }
    }
    const desktop = path.join(root, 'usr', 'share', 'applications', 'OpenInternetGateway.desktop');
    const icon = path.join(root, 'usr', 'share', 'icons', 'hicolor', '512x512', 'apps', 'open-internet-gateway.png');
    if (!fs.existsSync(desktop)) throw new Error('Linux desktop entry missing from Debian artifact');
    if (!fs.existsSync(icon)) throw new Error('Linux application icon missing from Debian artifact');
    fs.chmodSync(desktop, 0o644);
    fs.chmodSync(icon, 0o644);
    // The original xz repack can exceed the automated packaging watchdog on
    // large Electron payloads. gzip level 1 is broadly supported by dpkg and
    // restores correct desktop/icon permissions within a bounded build time.
    run('dpkg-deb', ['--root-owner-group', '-Zgzip', '-z1', '--build', root, rebuilt]);
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
    if (fs.existsSync(postRemove)) {
      const checkControl = path.join(temp, 'verified-control');
      run('dpkg-deb', ['--control', rebuilt, checkControl]);
      const postrm = fs.readFileSync(path.join(checkControl, 'postrm'), 'utf8');
      if (postrm.includes(legacyAlternative) ||
          (postrm.includes("update-alternatives --remove 'open-internet-gateway'") &&
           !postrm.includes(correctAlternative))) {
        throw new Error('Debian postrm alternatives target was not corrected');
      }
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
