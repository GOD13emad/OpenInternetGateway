const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { protectDashboardNavigation, assertDashboardIpcSender } = require('../src/main/dashboard-security');

function fixture() {
  let navigationHandler;
  let newWindowHandler;
  const trustedUrl = pathToFileURL(path.resolve(__dirname, '../src/renderer/index.html')).href;
  const mainFrame = { url: trustedUrl };
  const webContents = {
    mainFrame,
    isDestroyed: () => false,
    on(name, handler) {
      if (name === 'will-navigate') navigationHandler = handler;
    },
    setWindowOpenHandler(handler) { newWindowHandler = handler; }
  };
  return {
    webContents,
    trustedUrl,
    navigation: () => navigationHandler,
    popup: () => newWindowHandler,
    window: { webContents }
  };
}

test('dashboard disallows top-level navigation and window creation', () => {
  const x = fixture();
  protectDashboardNavigation(x.webContents);
  for (const url of ['https://example.test', 'file:///tmp/untrusted.html', 'javascript:alert(1)']) {
    let stopped = false;
    x.navigation()({ preventDefault() { stopped = true; } }, url);
    assert.equal(stopped, true, url);
    assert.deepEqual(x.popup()({ url }), { action: 'deny' });
  }
});

test('dashboard IPC only accepts the original main frame and exact local page', () => {
  const x = fixture();
  const valid = { sender: x.webContents, senderFrame: x.webContents.mainFrame };
  assert.doesNotThrow(() => assertDashboardIpcSender(valid, x.window, x.trustedUrl));
  const untrusted = [
    { sender: {}, senderFrame: x.webContents.mainFrame },
    { sender: x.webContents, senderFrame: { url: x.trustedUrl } },
    { sender: x.webContents, senderFrame: { url: 'https://example.test' } },
    { sender: x.webContents, senderFrame: null },
    null
  ];
  for (const event of untrusted) assert.throws(
    () => assertDashboardIpcSender(event, x.window, x.trustedUrl),
    /GATEWAY_IPC_SENDER_DENIED/
  );
  x.webContents.mainFrame.url = 'https://example.test';
  assert.throws(() => assertDashboardIpcSender(valid, x.window, x.trustedUrl), /GATEWAY_IPC_SENDER_DENIED/);
  x.webContents.mainFrame.url = x.trustedUrl;
  assert.throws(() => assertDashboardIpcSender(valid, null, x.trustedUrl), /GATEWAY_IPC_SENDER_DENIED/);
});

test('every gateway IPC route uses trusted binder', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../src/main/main.js'), 'utf8');
  assert.match(source, /protectDashboardNavigation\(win\.webContents\)/);
  assert.match(source, /assertDashboardIpcSender\(event,\s*mainWindow,\s*dashboardFileUrl\)/);
  const lines = source.split('\n').filter(line => /['"]gateway:[^'"]+['"]/.test(line) && /ipcMain\.handle|handleDashboardIpc/.test(line));
  assert.ok(lines.length >= 10);
  assert.ok(lines.every(line => /handleDashboardIpc\(/.test(line)), lines.join('\n'));
});
