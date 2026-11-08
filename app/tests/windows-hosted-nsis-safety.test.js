const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..');

test('hosted NSIS install, GUI, tray and uninstall smoke is limited to disposable runner', () => {
  const workflow = fs.readFileSync(path.join(root, '../.github/workflows/build.yml'), 'utf8');
  const smoke = fs.readFileSync(path.join(root, 'tools/qaWindowsInstalledTray.ps1'), 'utf8');
  assert.match(workflow, /Smoke-test silent NSIS install on disposable runner/);
  assert.match(workflow, /OIG_CAPTURE_ONLY.*1/);
  assert.match(workflow, /NSIS-installed Dashboard Electron render PASS/);
  assert.match(workflow, /qaWindowsInstalledTray\.ps1/);
  assert.match(workflow, /NSIS silent uninstall PASS/);
  assert.match(smoke, /\$env:GITHUB_ACTIONS -ne 'true'/);
  assert.match(smoke, /\$env:RUNNER_TEMP/);
  assert.match(smoke, /\$testRoot\.StartsWith\(\$runnerRoot/);
  assert.match(smoke, /WM_CLOSE -> hidden tray-lifetime PASS/);
  assert.match(smoke, /Hosted explicit Quit -> installed app exit PASS/);
  assert.doesNotMatch(smoke, /Set-NetRoute|New-NetRoute|Remove-NetRoute|OVPNConnectorService|nmcli/);
});

test('stable Windows capture-only exits without autostart registration or tray', () => {
  const main = fs.readFileSync(path.join(root, 'src/main/main.js'), 'utf8');
  const capture = main.slice(main.indexOf('fs.writeFileSync(process.env.OIG_CAPTURE_PATH'),
    main.indexOf('fs.writeFileSync(process.env.OIG_CAPTURE_PATH') + 420);
  assert.match(capture, /if \(process\.env\.OIG_CAPTURE_ONLY === '1'\)/);
  assert.match(capture, /app\.exit\(0\)/);
  assert.doesNotMatch(capture, /app\.quit\(\)/);
  assert.match(main, /app\.isPackaged && process\.env\.OIG_CAPTURE_ONLY !== '1'/);
  assert.match(main, /process\.platform !== 'win32' \|\| process\.env\.OIG_CAPTURE_ONLY !== '1'\) createTray\(\)/);
});
