const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Backend = require('../src/main/platform-backend');
const appRoot = path.resolve(__dirname, '..');

test('Windows status resolves route guard from deployed backendRoot/scripts, not backendRoot/windows/scripts', () => {
  const code = fs.readFileSync(path.join(appRoot, 'src/main/platform-backend.js'), 'utf8');
  const start = code.indexOf("if (action === 'status')");
  const end = code.indexOf('const mapped = map[action]', start);
  assert.ok(start >= 0 && end > start);
  const status = code.slice(start, end);
  assert.match(status, /path\.join\(this\.backendRoot, 'scripts', 'Route-Pair\.ps1'\)/);
  assert.doesNotMatch(status, /path\.join\(this\.backendRoot, 'windows', 'scripts'/);
  assert.match(status, /Test-OigFullRoutePair -Routes \$routes/);
});

test('Windows packaged-backend copy puts route guard at the status import path', {
  skip: process.platform !== 'win32'
}, async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-status-guard-install-'));
  const previousCapture = process.env.OIG_CAPTURE_ONLY;
  const previousRoot = process.env.OIG_CAPTURE_ROOT;
  try {
    process.env.OIG_CAPTURE_ONLY = '1';
    process.env.OIG_CAPTURE_ROOT = tmp;
    const backend = new Backend({
      version: '2.5.20',
      resourcesPath: path.join(tmp, 'nonexistent-resources'),
      appPath: appRoot,
      userData: tmp,
      emit: () => {}
    });
    await backend.initialize();
    const expectedRoot = path.join(tmp, 'backend-windows');
    assert.equal(backend.backendRoot, expectedRoot);
    const imported = path.join(expectedRoot, 'scripts', 'Route-Pair.ps1');
    assert.equal(fs.existsSync(imported), true);
    const supplied = path.join(appRoot, 'backend/windows/scripts/Route-Pair.ps1');
    assert.deepEqual(fs.readFileSync(imported), fs.readFileSync(supplied));
    assert.equal(fs.existsSync(path.join(expectedRoot, 'windows', 'scripts', 'Route-Pair.ps1')), false);
  } finally {
    if (previousCapture === undefined) delete process.env.OIG_CAPTURE_ONLY;
    else process.env.OIG_CAPTURE_ONLY = previousCapture;
    if (previousRoot === undefined) delete process.env.OIG_CAPTURE_ROOT;
    else process.env.OIG_CAPTURE_ROOT = previousRoot;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
