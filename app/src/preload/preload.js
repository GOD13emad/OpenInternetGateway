const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('gateway', {
  status: () => ipcRenderer.invoke('gateway:status'),
  profiles: () => ipcRenderer.invoke('gateway:profiles'),
  action: (action, options = {}) => ipcRenderer.invoke('gateway:action', action, options),
  diagnostics: () => ipcRenderer.invoke('gateway:diagnostics'),
  activity: () => ipcRenderer.invoke('gateway:activity'),
  platform: () => ipcRenderer.invoke('gateway:platform'),
  openLogs: () => ipcRenderer.invoke('gateway:openLogs'),
  updateInfo: (force = false) => ipcRenderer.invoke('gateway:updateInfo', force),
  installUpdate: () => ipcRenderer.invoke('gateway:installUpdate'),
  openRelease: () => ipcRenderer.invoke('gateway:openRelease'),
  setTheme: (theme) => ipcRenderer.invoke('gateway:setTheme', theme),
  onBackendEvent: (callback) => ipcRenderer.on('gateway:event', (_event, payload) => callback(payload))
});
