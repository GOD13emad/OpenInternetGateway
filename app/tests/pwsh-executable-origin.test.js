// Isolated executable-resolution guard. No PowerShell, VPN, updater or network execution.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Backend = require('../src/main/platform-backend.js');

function withFakeExePaths(testCase) {
  const originalExists = fs.existsSync;
  const originalPath = process.env.PATH;
  try { testCase((present) => { fs.existsSync = candidate => present.has(String(candidate)); }); }
  finally { fs.existsSync = originalExists; if (originalPath === undefined) delete process.env.PATH; else process.env.PATH = originalPath; }
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
