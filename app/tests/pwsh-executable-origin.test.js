// Isolated executable-resolution guard. No PowerShell, VPN, updater or network execution.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Backend = require('../src/main/platform-backend.js');

function withFakeExePaths(testCase) {
  const originalExists = fs.existsSync;
  const tracked = ['PATH', 'ProgramFiles', 'ProgramFiles(x86)'];
  const originalEnv = new Map(tracked.map(key => [key, process.env[key]]));
  try { testCase((present) => { fs.existsSync = candidate => present.has(String(candidate)); }); }
  finally {
    fs.existsSync = originalExists;
    for (const [key, value] of originalEnv) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

test('Windows PowerShell lookup rejects PATH-only executable even if it exists', () => {
  withFakeExePaths(setExists => {
    const untrusted = path.join(os.tmpdir(), 'untrusted-path-only');
    const fake = path.join(untrusted, 'pwsh.exe');
    process.env.PATH = untrusted;
    setExists(new Set([fake]));
    const backend = Object.create(Backend.prototype);
    backend.platform = 'win32'; backend.resourcesPath = '';
    assert.equal(backend._windowsPwshPath(), '', 'must fail closed instead of accepting PATH-resolved pwsh');
  });
});

test('Windows PowerShell lookup still prefers packaged runtime over PATH', () => {
  withFakeExePaths(setExists => {
    const root = path.join(os.tmpdir(), 'trusted-app-resources');
    const bundled = path.join(root, 'pwsh', 'pwsh.exe');
    const injected = path.join(os.tmpdir(), 'untrusted-path-only', 'pwsh.exe');
    process.env.PATH = path.dirname(injected);
    setExists(new Set([injected, bundled]));
    const backend = Object.create(Backend.prototype);
    backend.platform = 'win32'; backend.resourcesPath = root;
    assert.equal(backend._windowsPwshPath(), bundled);
  });
});

test('non-Windows PowerShell lookup never returns a binary', () => {
  const backend = Object.create(Backend.prototype);
  backend.platform = 'linux'; backend.resourcesPath = '/does/not/matter';
  assert.equal(backend._windowsPwshPath(), '');
});


test('Windows PowerShell lookup rejects forged ProgramFiles and ProgramFiles(x86) executables', () => {
  withFakeExePaths(setExists => {
    const fake64 = path.join(os.tmpdir(), 'untrusted-programfiles');
    const fake32 = path.join(os.tmpdir(), 'untrusted-programfiles-x86');
    process.env.ProgramFiles = fake64;
    process.env['ProgramFiles(x86)'] = fake32;
    const malicious64 = path.join(fake64, 'PowerShell', '7', 'pwsh.exe');
    const malicious32 = path.join(fake32, 'PowerShell', '7', 'pwsh.exe');
    setExists(new Set([malicious64, malicious32]));
    const backend = Object.create(Backend.prototype);
    backend.platform = 'win32'; backend.resourcesPath = ''; backend.appPath = '';
    assert.equal(backend._windowsPwshPath(), '', 'never accept environment-derived privileged executables');
  });
});

test('Windows source checkout accepts only app-vendored PowerShell after preparation', () => {
  withFakeExePaths(setExists => {
    const appRoot = path.join(os.tmpdir(), 'trusted-source-checkout');
    const vendor = path.join(appRoot, 'vendor', 'pwsh', 'pwsh.exe');
    const fake = path.join(os.tmpdir(), 'untrusted-programfiles', 'PowerShell', '7', 'pwsh.exe');
    process.env.ProgramFiles = path.join(os.tmpdir(), 'untrusted-programfiles');
    setExists(new Set([vendor, fake]));
    const backend = Object.create(Backend.prototype);
    backend.platform = 'win32'; backend.resourcesPath = ''; backend.appPath = appRoot;
    assert.equal(backend._windowsPwshPath(), vendor, 'development requires prepared app-vendored runtime');
  });
});
