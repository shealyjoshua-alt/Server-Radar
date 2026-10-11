// The only bridge between the dashboard page and the main process.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('radar', {
  getViewModel: () => ipcRenderer.invoke('radar:getViewModel'),
  markRead: (key) => ipcRenderer.invoke('radar:markRead', key),
  markAllRead: () => ipcRenderer.invoke('radar:markAllRead'),
  refresh: () => ipcRenderer.invoke('radar:refresh'),
  openUrl: (url) => ipcRenderer.invoke('radar:openUrl', url),
  onUpdate: (cb) => ipcRenderer.on('radar:update', (_e, vm) => cb(vm)),
  onFocusItem: (cb) => ipcRenderer.on('radar:focusItem', (_e, key) => cb(key)),
});
