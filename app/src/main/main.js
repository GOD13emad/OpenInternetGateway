const { app, BrowserWindow, ipcMain, Menu, Tray, nativeImage, shell, nativeTheme } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const Backend = require('./platform-backend');

let mainWindow;
let tray;
let backend;
let trayPoll;
let trayRefreshing = false;
let lastStatus = null;
let quitInProgress = false;
let allowQuit = false;
const startInBackground = process.argv.includes('--background');
const quitRequestedAtLaunch = process.argv.includes('--quit');

const launchIntent = quitRequestedAtLaunch ? 'quit' : 'show';
const gotSingleInstanceLock = app.requestSingleInstanceLock({ intent: launchIntent });
if (!gotSingleInstanceLock) app.quit();

function asset(name) {
  return path.join(__dirname, '..', '..', 'assets', name);
}

function isLiveWindow(win = mainWindow) {
  return !!win && !win.isDestroyed();
}

function createWindow({ showWhenReady = !startInBackground } = {}) {
  const win = new BrowserWindow({
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
  mainWindow = win;
  win.removeMenu();
  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  win.once('ready-to-show', () => {
    if (showWhenReady && !app.isQuitting && isLiveWindow(win)) win.show();
    if (process.env.OIG_CAPTURE_PATH && isLiveWindow(win)) {
      setTimeout(async () => {
        try {
          if (!isLiveWindow(win) || win.webContents.isDestroyed()) return;
          const image = await win.webContents.capturePage();
          fs.writeFileSync(process.env.OIG_CAPTURE_PATH, image.toPNG());
        } finally {
          if (process.env.OIG_CAPTURE_ONLY === '1') {
            app.isQuitting = true;
            app.quit();
          }
        }
      }, 350);
    }
  });
  win.on('close', event => {
    if (app.isQuitting) return;
    event.preventDefault();
    if (isLiveWindow(win)) win.hide();
  });
  win.on('closed', () => {
    if (mainWindow === win) mainWindow = null;
  });
  return win;
}

function showDashboard() {
  if (quitInProgress || allowQuit || app.isQuitting) return false;
  if (!isLiveWindow(mainWindow)) {
    createWindow({ showWhenReady: true });
    return true;
  }
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
  return true;
}

function renderTray(status = lastStatus) {
  if (!tray || (typeof tray.isDestroyed === 'function' && tray.isDestroyed())) return;
  const connected = !!status?.connected;
  const country = status?.country || '';
  const ip = status?.ip || '';
  const stateText = connected ? ('Connected' + (country ? ' • ' + country : '')) : 'Disconnected';
  tray.setToolTip('OpenInternetGateway — ' + stateText);
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Open Dashboard', click: showDashboard },
    { label: stateText + (ip ? ' • ' + ip : ''), enabled: false },
    { type: 'separator' },
    { label: 'Connect', enabled: !connected, click: async () => { try { await backend.action('connect'); } finally { refreshTrayStatus(); } } },
    { label: 'Disconnect', enabled: connected, click: async () => { try { await backend.action('disconnect'); } finally { refreshTrayStatus(); } } },
    { type: 'separator' },
    { label: 'Quit OpenInternetGateway', click: () => requestQuit() }
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
  tray.on('double-click', showDashboard);
  refreshTrayStatus();
  trayPoll = setInterval(refreshTrayStatus, 15000);
}

function registerIpc() {
  ipcMain.handle('gateway:status', () => backend.status());
  ipcMain.handle('gateway:profiles', () => backend.profiles());
  ipcMain.handle('gateway:action', (_e, action, options) => backend.action(action, options));
  ipcMain.handle('gateway:diagnostics', () => backend.diagnostics());
  ipcMain.handle('gateway:activity', () => backend.activity());
  ipcMain.handle('gateway:platform', () => backend.platformInfo());
  ipcMain.handle('gateway:openLogs', async () => shell.openPath(await backend.logsPath()));
  ipcMain.handle('gateway:updateInfo', (_e, force) => backend.updateInfo(!!force));
  ipcMain.handle('gateway:installUpdate', async () => {
    const result = await backend.downloadUpdate();
    if (result.alreadyCurrent || !result.path) return { ...result, applying: false };
    const launched = await backend.launchDownloadedUpdate(result, {
      appPid: process.pid,
      currentExecutable: process.execPath
    });
    if (launched?.applying) {
      if (process.platform === 'linux' && backend?.backendRoot) {
        // Disarm the old parent-exit watchdog. The new app writes its own lease
        // after restart; a failed updater helper relaunches the previous app.
        try {
          const lease = path.join(backend.backendRoot, 'state', 'app-process.lease');
          fs.mkdirSync(path.dirname(lease), { recursive: true });
          fs.writeFileSync(lease, 'update ' + process.pid + ' ' + Date.now() + '\n');
        } catch {}
      }
      setTimeout(requestProcessExitPreservingTunnel, 500);
    }
    return { ...result, ...launched };
  });
  ipcMain.handle('gateway:openRelease', async () => {
    let url = 'https://github.com/GOD13emad/OpenInternetGateway/releases/latest';
    try { url = (await backend.updateInfo(false)).releaseUrl || url; } catch {}
    await shell.openExternal(url);
    return { ok: true, url };
  });
  ipcMain.handle('gateway:setTheme', (_e, theme) => {
    nativeTheme.themeSource = ['light', 'dark', 'system'].includes(theme) ? theme : 'system';
    return { ok: true, theme: nativeTheme.themeSource };
  });
}

function linuxProcStartToken(pid) {
  try {
    const raw = fs.readFileSync('/proc/' + String(pid) + '/stat', 'utf8').trim();
    const end = raw.lastIndexOf(') ');
    if (end < 0) return '';
    const fieldsAfterComm = raw.slice(end + 2).split(/\s+/);
    return fieldsAfterComm[19] || '';
  } catch {
    return '';
  }
}

function startLinuxExitWatchdog() {
  if (process.platform !== 'linux' || !backend || process.env.OIG_CAPTURE_ONLY === '1') return;
  const root = backend.backendRoot;
  const watcher = path.join(root, 'linux', 'watch-parent.sh');
  const start = linuxProcStartToken(process.pid);
  if (!root || !start || !fs.existsSync(watcher)) return;
  const stateDir = path.join(root, 'state');
  fs.mkdirSync(stateDir, { recursive: true });
  fs.writeFileSync(path.join(stateDir, 'app-process.lease'), String(process.pid) + ' ' + start + '\n');
  try { fs.chmodSync(watcher, 0o755); } catch {}
  const child = spawn('/bin/bash', [watcher, String(process.pid), start, root], {
    detached: true,
    stdio: 'ignore',
    env: { ...process.env, OIG_HOME: root, OIG_COMMON: path.join(root, 'common') }
  });
  child.unref();
}

async function disconnectBeforeQuit() {
  if (!backend) return;
  // Explicit Quit is an intent change, not a health inference. A transient
  // geo/status probe must never leave a managed tunnel or desired=on behind.
  await backend.action('disconnect');
}

async function requestQuit() {
  if (quitInProgress || allowQuit) return;
  quitInProgress = true;
  app.isQuitting = true;
  if (trayPoll) clearInterval(trayPoll);
  try {
    await disconnectBeforeQuit();
    allowQuit = true;
    app.quit();
  } catch (error) {
    console.error('OpenInternetGateway refused to quit before tunnel disconnect:', error);
    quitInProgress = false;
    app.isQuitting = false;
    showDashboard();
  }
}

function requestProcessExitPreservingTunnel() {
  if (allowQuit) return;
  // Installer/update lifecycle exits are not the user's explicit Quit command.
  // Keep desired-state and the independent tunnel intact while the dashboard
  // is replaced and restarted.
  app.isQuitting = true;
  if (trayPoll) clearInterval(trayPoll);
  allowQuit = true;
  app.quit();
}

if (gotSingleInstanceLock) {
app.on('second-instance', (_event, argv, _workingDirectory, additionalData) => {
    const intent = additionalData?.intent || (argv.includes('--quit') ? 'quit' : 'show');
    if (intent === 'quit') { requestQuit(); return; }
    showDashboard();
  });
  
  app.whenReady().then(async () => {
    backend = new Backend({
      version: app.getVersion(),
      resourcesPath: process.resourcesPath,
      appPath: app.getAppPath(),
      userData: app.getPath('userData'),
      emit: (payload) => {
        if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents && !mainWindow.webContents.isDestroyed()) {
          mainWindow.webContents.send('gateway:event', payload);
        }
        if (payload?.status) { lastStatus = payload.status; renderTray(lastStatus); }
      }
    });
    const initialized = await backend.initialize();
    if (process.platform === 'linux'
        && process.env.OIG_CAPTURE_ONLY !== '1'
        && initialized?.sandboxHardening?.restartRequired) {
      const appRun = path.join(initialized.sandboxHardening.runtimeRoot || '', 'AppRun');
      if (fs.existsSync(appRun)) {
        const relaunchArgs = process.argv.slice(1).filter(arg => arg !== '--no-sandbox');
        try {
          const child = spawn(appRun, relaunchArgs, {
            detached: true,
            stdio: 'ignore',
            env: { ...process.env, OIG_SANDBOX_RESTARTED: '1' }
          });
          child.unref();
          allowQuit = true;
          app.isQuitting = true;
          app.quit();
          return;
        } catch (error) {
          console.error('OpenInternetGateway sandbox hardening restart failed:', error);
        }
      }
    }
    startLinuxExitWatchdog();
    if (quitRequestedAtLaunch) { requestQuit(); return; }
    if (process.platform === 'win32' && app.isPackaged) {
      app.setLoginItemSettings({ openAtLogin: true, path: process.execPath, args: ['--background'] });
    }
    registerIpc();
    createWindow();
    createTray();
  });
  
  app.on('activate', () => {
    showDashboard();
  });

  // Tray-style desktop apps must stay alive when the last BrowserWindow is
  // closed/destroyed. Explicit Quit remains the only app-termination path.
  app.on('window-all-closed', () => {});
  
  process.on('SIGTERM', () => {
    if (process.platform === 'win32') requestProcessExitPreservingTunnel();
    else requestQuit();
  });
  process.on('SIGINT', () => {
    if (process.platform === 'win32') requestProcessExitPreservingTunnel();
    else requestQuit();
  });
  
  app.on('before-quit', (event) => {
    if (allowQuit) {
      if (trayPoll) clearInterval(trayPoll);
      return;
    }
    event.preventDefault();
    if (process.platform === 'win32') requestProcessExitPreservingTunnel();
    else requestQuit();
  });
  
}
