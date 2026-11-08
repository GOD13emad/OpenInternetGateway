const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
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
