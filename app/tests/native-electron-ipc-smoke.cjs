'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { app, BrowserWindow, ipcMain } = require('electron');
if (process.argv.includes('--no-sandbox') || app.commandLine.hasSwitch('no-sandbox') ||
    process.argv.includes('--disable-setuid-sandbox') || app.commandLine.hasSwitch('disable-setuid-sandbox')) {
  throw new Error('SANDBOX_FLAG_FORBIDDEN_IN_NATIVE_ACCEPTANCE');
}
const { protectDashboardNavigation, assertDashboardIpcSender } =
  require('../src/main/dashboard-security');

const testRoot = path.resolve(__dirname, '../../native-electron-smoke');
fs.mkdirSync(testRoot, { recursive: true });
app.setPath('userData', path.join(testRoot, 'userdata'));
const originalPage = path.resolve(__dirname, '../src/renderer/index.html');
const originalUrl = pathToFileURL(originalPage).href;
const preload = path.resolve(__dirname, '../src/preload/preload.js');
let trustedWindow = null;
let foreignWindow = null;
let navAttempts = 0;
let createdWindows = 0;
let statusCalls = 0;
let forbiddenCalls = 0;
let terminated = false;

const watchdog = setTimeout(() => {
  if (!terminated) {
    console.error('NATIVE_ELECTRON_IPC_SMOKE_TIMEOUT');
    app.exit(124);
  }
}, 17000);

function createIsolatedWindow() {
  return new BrowserWindow({
    show: false,
    width: 1000,
    height: 700,
    webPreferences: {
      preload,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      partition: 'temp:native-oig-guard'
    }
  });
}

function reply(event, name) {
  try {
    assertDashboardIpcSender(event, trustedWindow, originalUrl);
    if (name === 'gateway:status') {
      statusCalls++;
      return { ok: true, nativeSmoke: 'trusted-main-frame' };
    }
    return { ok: true, nativeSmoke: 'mock-no-operating-system-action' };
  } catch (e) {
    forbiddenCalls++;
    throw e;
  }
}
const names = [
  'status', 'profiles', 'action', 'diagnostics', 'activity', 'platform',
  'openLogs', 'updateInfo', 'installUpdate', 'openRelease', 'setTheme'
];
for (const name of names) {
  ipcMain.handle('gateway:' + name, (event) => reply(event, 'gateway:' + name));
}

(async () => {
  await app.whenReady();
  trustedWindow = createIsolatedWindow();
  protectDashboardNavigation(trustedWindow.webContents);
  trustedWindow.webContents.on('will-navigate', () => { navAttempts++; });
  trustedWindow.webContents.on('did-create-window', () => { createdWindows++; });
  await trustedWindow.loadFile(originalPage);
  const trustedResult = await trustedWindow.webContents.executeJavaScript(
    "window.gateway.status().then(x => x.nativeSmoke).catch(e => 'FAIL:' + e.message)"
  );
  assert.equal(trustedResult, 'trusted-main-frame');

  foreignWindow = createIsolatedWindow();
  const foreignFile = path.join(testRoot, 'untrusted.html');
  fs.writeFileSync(foreignFile, '<!doctype html><title>Untrusted test page</title>');
  await foreignWindow.loadFile(foreignFile);
  const rejected = await foreignWindow.webContents.executeJavaScript(
    "window.gateway.status().then(x => 'UNEXPECTED_ACCEPT').catch(e => e.message)"
  );
  assert.match(rejected, /GATEWAY_IPC_SENDER_DENIED/);

  const popupWasNull = await trustedWindow.webContents.executeJavaScript(
    "window.open('https://example.invalid/untrusted') === null"
  );
  assert.equal(popupWasNull, true);
  await trustedWindow.webContents.executeJavaScript(
    "window.location.href='https://example.invalid/redirect'; true"
  ).catch(() => {});
  await new Promise(resolve => setTimeout(resolve, 300));
  assert.equal(trustedWindow.webContents.getURL(), originalUrl);
  assert.ok(navAttempts >= 1, 'navigation attempted but no will-navigate event observed');
  assert.equal(createdWindows, 0);
  assert.ok(statusCalls >= 1);
  assert.ok(forbiddenCalls >= 1);
  console.log('NATIVE_ELECTRON_IPC_SMOKE_PASS ' + JSON.stringify({
    electron: process.versions.electron,
    trustedMainFrameIPC: true,
    foreignWindowIPCRejected: true,
    popupDenied: popupWasNull,
    navigationDenied: true,
    navAttempts, createdWindows,
    backend: 'mocked-no-network-or-VPN-operation'
  }));
  terminated = true;
  clearTimeout(watchdog);
  trustedWindow.destroy();
  foreignWindow.destroy();
  app.exit(0);
})().catch(error => {
  terminated = true;
  clearTimeout(watchdog);
  console.error('NATIVE_ELECTRON_IPC_SMOKE_FAIL', error.stack || String(error));
  app.exit(1);
});
