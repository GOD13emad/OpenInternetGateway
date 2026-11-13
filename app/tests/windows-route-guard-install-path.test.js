const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Backend = require('../src/main/platform-backend');
const { spawnSync } = require('node:child_process');
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

// Also verify the legacy stable mode while keeping the child LOCALAPPDATA private.
test('Windows stable installed backend copies route guard under sandboxed LOCALAPPDATA', {
  skip: process.platform !== 'win32'
}, () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-stable-status-path-'));
  assert.notEqual(path.resolve(tmp), path.resolve(process.env.LOCALAPPDATA || ''));
  const installed = path.join(tmp, 'OpenInternetGateway');
  try {
    // v2.5.19 has no OIG_CAPTURE_ONLY. Force the child process's actual
    // installed-backend parent to a freshly created temporary LOCALAPPDATA.
    // Do not modify the parent process environment or the owner's backend.
    const childScript = [
      "const Backend=require(process.env.OIG_TEST_BACKEND_MODULE)",
      "const path=require('path')",
      "const root=process.env.OIG_TEST_APP_ROOT",
      "const b=new Backend({version:'2.5.19',resourcesPath:path.join(process.env.LOCALAPPDATA,'no-resources'),appPath:root,userData:process.env.LOCALAPPDATA,emit:()=>{}})",
      "b.initialize().then(()=>process.stdout.write(b.backendRoot)).catch(e=>{process.stderr.write(e.stack);process.exitCode=1})"
    ].join(';');
    const child = spawnSync(process.execPath, ['-e', childScript], {
      encoding: 'utf8', timeout: 15000,
      env: {
        ...process.env,
        LOCALAPPDATA: tmp,
        OIG_CAPTURE_ONLY: '0',
        OIG_CAPTURE_ROOT: '',
        OIG_TEST_BACKEND_MODULE: path.join(appRoot, 'src/main/platform-backend.js'),
        OIG_TEST_APP_ROOT: appRoot
      }
    });
    assert.equal(child.status, 0, child.stderr || child.stdout);
    assert.equal(path.resolve(child.stdout.trim()), path.resolve(installed));
    const copied = path.join(installed, 'scripts', 'Route-Pair.ps1');
    const source = path.join(appRoot, 'backend/windows/scripts/Route-Pair.ps1');
    assert.equal(fs.existsSync(copied), true);
    assert.deepEqual(fs.readFileSync(copied), fs.readFileSync(source));
    assert.equal(fs.existsSync(path.join(installed, 'windows', 'scripts', 'Route-Pair.ps1')), false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
