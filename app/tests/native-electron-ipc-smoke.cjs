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
const { probeReadOnlyNavigation } = require('../src/main/dashboard-navigation-probe');

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
let privilegedActions = 0;
let updateInfoCalls = 0;
let forcedChecks = 0;
let mockInstallCalls = 0;
const updateFixture = {
  currentVersion:'2.5.18', latestVersion:'2.5.19', updateAvailable:true, upToDate:false,
  asset: {name:'MOCK-NO-INSTALL.exe',sha256:'b'.repeat(64)},
  publishedAt:'2026-10-01T12:00:00Z'
};
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

function reply(event, name, ...args) {
  try {
    assertDashboardIpcSender(event, trustedWindow, originalUrl);
    if (name.startsWith('gateway:update') || name === 'gateway:installUpdate') console.log('UPDATE_IPC_MOCK_ROUTE', name, JSON.stringify(args));
    if (name === 'gateway:action') privilegedActions++;
    if (name === 'gateway:updateInfo') {
      updateInfoCalls++;
      if (args[0] === true) forcedChecks++;
      const safeFixture = JSON.parse(JSON.stringify(updateFixture));
      structuredClone(safeFixture); // Explicitly require IPC-safe metadata, never functions.
      return safeFixture;
    }
    if (name === 'gateway:installUpdate') {
      mockInstallCalls++;
      return {ok:true,applying:true,info:updateFixture};
    }
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
  ipcMain.handle('gateway:' + name, (event, ...args) => reply(event, 'gateway:' + name, ...args));
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
  // Exercise real dashboard DOM handlers without touching a VPN or updater.
  const navigation = await probeReadOnlyNavigation(trustedWindow.webContents);
  assert.deepEqual(navigation.pagesVisited, ['settings', 'overview']);
  assert.equal(navigation.powerControlInvoked, false);
  // Real Electron DOM handlers and trusted IPC; responses are mocked and have no OS side effects.
  console.log('MOCK_UPDATE_UI_BEGIN');
  const updateUi = await trustedWindow.webContents.executeJavaScript(`(async () => {
    const until = async p => { for (let i=0;i<100;i++) { if(p())return; await new Promise(r=>setTimeout(r,20)); } throw new Error('UPDATE_UI_TIMEOUT'); };
    document.querySelector('.nav-item[data-page="updates"]').click();
    await until(() => document.getElementById('page-updates').classList.contains('active'));
    const install = document.getElementById('installUpdate');
    await until(() => !install.disabled);
    if (document.getElementById('updateCurrent').textContent !== '2.5.18' ||
      document.getElementById('updateLatest').textContent !== '2.5.19' ||
      document.getElementById('updateChecksum').textContent !== 'b'.repeat(64)) throw new Error('UPDATE_DOM_INVALID');
    document.getElementById('checkUpdates').click();
    await until(() => document.getElementById('updateState').textContent === 'Update available');
    install.click();
    await until(() => document.getElementById('toast').textContent.includes('Verified update is installing.'));
    await until(() => !document.getElementById('busyOverlay').classList.contains('show'));
    const r={visible:!install.disabled,shaVisible:document.getElementById('updateChecksum').textContent==='b'.repeat(64),toast:document.getElementById('toast').textContent.includes('will restart automatically')};
    document.querySelector('.nav-item[data-page="overview"]').click();
    return r;
  })`, true);
  console.log('MOCK_UPDATE_UI_RENDERER_RETURN', JSON.stringify(updateUi));
  assert.equal(updateUi.visible, true);
  assert.equal(updateUi.shaVisible, true);
  assert.equal(updateUi.toast, true);
  assert.ok(updateInfoCalls >= 1);
  assert.ok(forcedChecks >= 1);
  assert.equal(mockInstallCalls, 1);
  console.log('UPDATE_UI_MOCKED_PROBE_PASS '+JSON.stringify({ ...updateUi, forcedChecks, mockInstallCalls }));

  foreignWindow = createIsolatedWindow();
  const foreignFile = path.join(testRoot, 'untrusted.html');
  fs.writeFileSync(foreignFile, '<!doctype html><title>Untrusted test page</title>');
  await foreignWindow.loadFile(foreignFile);
  const rejected = await foreignWindow.webContents.executeJavaScript(
    "window.gateway.status().then(x => 'UNEXPECTED_ACCEPT').catch(e => e.message)"
  );
  assert.match(rejected, /GATEWAY_IPC_SENDER_DENIED/);
  console.log('MOCK_FOREIGN_UPDATE_DENIAL_BEGIN');
  const deniedInstall = await foreignWindow.webContents.executeJavaScript(
    "window.gateway.installUpdate().then(() => 'UNEXPECTED_ACCEPT').catch(e => e.message)"
  );
  assert.match(deniedInstall, /GATEWAY_IPC_SENDER_DENIED/);
  assert.equal(mockInstallCalls, 1, 'Untrusted IPC cannot invoke even mock install');

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
  assert.equal(privilegedActions, 0, 'native offline probe must not invoke connect/disconnect/update');
  console.log('NATIVE_ELECTRON_IPC_SMOKE_PASS ' + JSON.stringify({
    electron: process.versions.electron,
    trustedMainFrameIPC: true,
    foreignWindowIPCRejected: true,
    popupDenied: popupWasNull,
    navigationDenied: true,
    navAttempts, createdWindows,
    dashboardNavigation: navigation.pagesVisited, privilegedActions,
    updateUiMocked: { ...updateUi, forcedChecks, mockInstallCalls, foreignInstallDenied: true },
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
