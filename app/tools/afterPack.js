const fs = require('fs');
const path = require('path');

function normalizeLinuxPayload(root) {
  fs.chmodSync(root, 0o755);
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) {
      normalizeLinuxPayload(full);
      continue;
    }
    if (entry.isFile()) {
      const mode = fs.statSync(full).mode & 0o7777;
      fs.chmodSync(full, mode | 0o044);
    }
  }
}

module.exports = async function afterPack(context) {
  if (context.electronPlatformName !== 'linux') return;

  // FPM uses appInfo.sanitizedProductName as the /opt install directory. Chromium's Linux
  // setuid sandbox cannot safely launch when that path contains spaces, so keep the public
  // product name but force only the Linux package install directory to a no-space name.
  context.packager.appInfo.sanitizedProductName = 'open-internet-gateway';

  // electron-builder can inherit a restrictive umask into /opt payload directories.
  // Keep application directories traversable by normal desktop users.
  normalizeLinuxPayload(context.appOutDir);

  const mainExe = path.join(context.appOutDir, 'open-internet-gateway');
  const crashpad = path.join(context.appOutDir, 'chrome_crashpad_handler');
  const sandbox = path.join(context.appOutDir, 'chrome-sandbox');

  if (!fs.existsSync(mainExe)) throw new Error('Linux main executable missing from package');
  if (!fs.existsSync(sandbox)) throw new Error('chrome-sandbox missing from Linux package');

  fs.chmodSync(mainExe, 0o755);
  if (fs.existsSync(crashpad)) fs.chmodSync(crashpad, 0o755);
  fs.chmodSync(sandbox, 0o4755);
};
