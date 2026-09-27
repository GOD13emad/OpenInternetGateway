const fs = require('fs');
const path = require('path');

function chmodDirs(root) {
  fs.chmodSync(root, 0o755);
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    chmodDirs(path.join(root, entry.name));
  }
}

module.exports = async function afterPack(context) {
  if (context.electronPlatformName !== 'linux') return;

  // electron-builder can inherit a restrictive umask into /opt payload directories.
  // Keep application directories traversable by normal desktop users.
  chmodDirs(context.appOutDir);

  const mainExe = path.join(context.appOutDir, 'open-internet-gateway');
  const crashpad = path.join(context.appOutDir, 'chrome_crashpad_handler');
  const sandbox = path.join(context.appOutDir, 'chrome-sandbox');

  if (!fs.existsSync(mainExe)) throw new Error('Linux main executable missing from package');
  if (!fs.existsSync(sandbox)) throw new Error('chrome-sandbox missing from Linux package');

  fs.chmodSync(mainExe, 0o755);
  if (fs.existsSync(crashpad)) fs.chmodSync(crashpad, 0o755);
  fs.chmodSync(sandbox, 0o4755);
};
