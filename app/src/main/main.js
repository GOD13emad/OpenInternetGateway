const { app, BrowserWindow, ipcMain, Menu, Tray, nativeImage, shell, nativeTheme } = require('electron');
const path = require('path');
const fs = require('fs');
const Backend = require('./platform-backend');

let mainWindow;
let tray;
let backend;
let trayPoll;
let trayRefreshing = false;
let lastStatus = null;
const startInBackground = process.argv.includes('--background');

const gotSingleInstanceLock = app.requestSingleInstanceLock();
if (!gotSingleInstanceLock) app.quit();

function asset(name) {
  return path.join(__dirname, '..', '..', 'assets', name);
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 760,
    minWidth: 980,
    minHeight: 680,
    show: false,
    backgroundColor: '#09111f',
    title: 'Open Internet Gateway',
    icon: asset(process.platform === 'win32' ? 'icon.ico' : 'icon.png'),
    webPreferences: {
      preload: path.join(__dirname, '..', 'preload', 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });
  mainWindow.removeMenu();
  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  mainWindow.once('ready-to-show', async () => {
    if (!startInBackground) mainWindow.show();
    if (process.env.OIG_CAPTURE_PATH) {
      setTimeout(async () => {
        try {
          const image = await mainWindow.webContents.capturePage();
          fs.writeFileSync(process.env.OIG_CAPTURE_PATH, image.toPNG());
        } finally {
          if (process.env.OIG_CAPTURE_ONLY === '1') {
            app.isQuitting = true;
            app.quit();
          }
        }
      }, 1800);
    }
  });
  mainWindow.on('close', (event) => {
    if (!app.isQuitting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });
}

function renderTray(status = lastStatus) {
  if (!tray) return;
  const connected = !!status?.connected;
  const country = status?.country || '';
  const ip = status?.ip || '';
  const stateText = connected ? ('Connected' + (country ? ' • ' + country : '')) : 'Disconnected';
  tray.setToolTip('OpenInternetGateway — ' + stateText);
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Open Dashboard', click: () => { mainWindow.show(); mainWindow.focus(); } },
    { label: stateText + (ip ? ' • ' + ip : ''), enabled: false },
    { type: 'separator' },
    { label: 'Connect', enabled: !connected, click: async () => { try { await backend.action('connect'); } finally { refreshTrayStatus(); } } },
    { label: 'Disconnect', enabled: connected, click: async () => { try { await backend.action('disconnect'); } finally { refreshTrayStatus(); } } },
    { type: 'separator' },
    { label: 'Quit OpenInternetGateway', click: () => { app.isQuitting = true; app.quit(); } }
  ]));
}

async function refreshTrayStatus() {
  if (!tray || trayRefreshing || !backend) return;
  trayRefreshing = true;
  try {
    lastStatus = await backend.status();
    renderTray(lastStatus);
  } catch {
    renderTray({ connected: false });
  } finally {
    trayRefreshing = false;
  }
}

function createTray() {
  const img = nativeImage.createFromPath(asset(process.platform === 'win32' ? 'icon.ico' : 'icon.png'));
  tray = new Tray(img.resize({ width: 20, height: 20 }));
  renderTray({ connected: false });
  tray.on('double-click', () => { mainWindow.show(); mainWindow.focus(); });
  refreshTrayStatus();
  trayPoll = setInterval(refreshTrayStatus, 15000);
}

function registerIpc() {
  ipcMain.handle('gateway:status', () => backend.status());
  ipcMain.handle('gateway:action', (_e, action, options) => backend.action(action, options));
  ipcMain.handle('gateway:diagnostics', () => backend.diagnostics());
  ipcMain.handle('gateway:activity', () => backend.activity());
  ipcMain.handle('gateway:platform', () => backend.platformInfo());
  ipcMain.handle('gateway:openLogs', async () => shell.openPath(await backend.logsPath()));
  ipcMain.handle('gateway:setTheme', (_e, theme) => {
    nativeTheme.themeSource = ['light', 'dark', 'system'].includes(theme) ? theme : 'system';
    return { ok: true, theme: nativeTheme.themeSource };
  });
}

app.on('second-instance', () => {
  if (!mainWindow) return;
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
});

app.whenReady().then(async () => {
  backend = new Backend({
    resourcesPath: process.resourcesPath,
    appPath: app.getAppPath(),
    userData: app.getPath('userData'),
    emit: (payload) => {
      mainWindow?.webContents.send('gateway:event', payload);
      if (payload?.status) { lastStatus = payload.status; renderTray(lastStatus); }
    }
  });
  await backend.initialize();
  if (process.platform === 'win32' && app.isPackaged) {
    app.setLoginItemSettings({ openAtLogin: true, path: process.execPath, args: ['--background'] });
  }
  registerIpc();
  createWindow();
  createTray();
});

app.on('activate', () => {
  if (mainWindow) { mainWindow.show(); mainWindow.focus(); }
  else createWindow();
});

app.on('before-quit', () => { app.isQuitting = true; if (trayPoll) clearInterval(trayPoll); });
