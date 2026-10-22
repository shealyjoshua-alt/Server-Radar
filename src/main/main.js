// Electron shell: menu bar icon, dashboard window, hourly refresh, notifications.
const path = require('node:path');
const fs = require('node:fs');
const { app, BrowserWindow, Tray, Menu, Notification, nativeImage, ipcMain, shell, powerMonitor } = require('electron');

const { loadConfig } = require('../core/match');
const { createStore } = require('../core/store');
const { runRefresh } = require('../core/refresh');
const { buildViewModel } = require('../core/viewModel');
const { httpGet } = require('../sources/http');
const sources = require('../sources');
const { safeUrl } = require('../renderer/view');

const ASSETS = path.join(__dirname, '..', '..', 'assets');
const RESUME_DELAY_MS = 10000;

if (!app.requestSingleInstanceLock()) app.quit();

let tray = null;
let win = null;
let store = null;
let config = null;
let refreshing = null;
let quitting = false;

const viewModel = () => buildViewModel(store.snapshot(), config, new Date());

function prefsFile() { return path.join(app.getPath('userData'), 'prefs.json'); }
function readPrefs() { try { return JSON.parse(fs.readFileSync(prefsFile(), 'utf8')); } catch { return {}; } }
function writePrefs(p) { fs.writeFileSync(prefsFile(), JSON.stringify(p)); }

function updateTray() {
  const vm = viewModel();
  tray.setImage(nativeImage.createFromPath(path.join(ASSETS, `tray-${vm.icon.color}.png`)));
  tray.setTitle(vm.icon.count > 0 ? String(vm.icon.count) : '');
  tray.setToolTip(`Server Radar — ${vm.icon.tooltip}`);
  if (win && !win.isDestroyed()) win.webContents.send('radar:update', vm);
  return vm;
}

function showWindow(focusKey) {
  // Menu bar (no Dock icon) apps must take focus explicitly or the window opens behind others.
  app.focus({ steal: true });
  if (!win || win.isDestroyed()) {
    win = new BrowserWindow({
      width: 1200,
      height: 800,
      minWidth: 640,
      show: false,
      title: 'Server Radar',
      backgroundColor: '#12161f',
      webPreferences: {
        preload: path.join(__dirname, 'preload.js'),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
      },
    });
    win.on('close', (e) => {
      if (!quitting) { e.preventDefault(); win.hide(); }
    });
    // Never navigate the dashboard away or open new windows; links go to the browser.
    win.webContents.on('will-navigate', (e) => e.preventDefault());
    win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
    win.once('ready-to-show', () => {
      win.show();
      win.focus();
      if (focusKey) win.webContents.send('radar:focusItem', focusKey);
    });
    return;
  }
  win.show();
  win.focus();
  if (focusKey) win.webContents.send('radar:focusItem', focusKey);
}

function toggleWindow() {
  if (win && !win.isDestroyed() && win.isVisible() && win.isFocused()) win.hide();
  else showWindow();
}

function notify(item) {
  if (!Notification.isSupported()) return;
  const n = new Notification({
    title: item.kind === 'incident' ? 'Outage: Azure Gov / Entra / M365' : `Exploited: ${item.key}`,
    body: item.title,
  });
  n.on('click', () => showWindow(item.key));
  n.show();
}

async function refresh() {
  if (refreshing) return refreshing; // ignore overlapping requests
  refreshing = (async () => {
    try {
      const { toNotify } = await runRefresh({ sources, store, config, httpGet });
      toNotify.forEach(notify);
    } catch (e) {
      console.error('refresh failed', e);
    } finally {
      refreshing = null;
    }
    return updateTray();
  })();
  return refreshing;
}

function contextMenu() {
  return Menu.buildFromTemplate([
    { label: 'Open Dashboard', click: () => showWindow() },
    { label: 'Refresh Now', click: () => refresh() },
    { label: 'Mark All Read', click: () => { store.markAllRead(); store.save(); updateTray(); } },
    { type: 'separator' },
    {
      label: 'Open at Login',
      type: 'checkbox',
      checked: app.getLoginItemSettings().openAtLogin,
      click: (mi) => app.setLoginItemSettings({ openAtLogin: mi.checked }),
    },
    { label: 'Quit Server Radar', click: () => { quitting = true; app.quit(); } },
  ]);
}

function registerIpc() {
  ipcMain.handle('radar:getViewModel', () => viewModel());
  ipcMain.handle('radar:markRead', (_e, key) => { store.markRead(String(key)); store.save(); return updateTray(); });
  ipcMain.handle('radar:markAllRead', () => { store.markAllRead(); store.save(); return updateTray(); });
  ipcMain.handle('radar:refresh', () => refresh());
  ipcMain.handle('radar:openUrl', (_e, url) => {
    const safe = safeUrl(url);
    if (safe !== '#') shell.openExternal(safe);
  });
}

app.on('second-instance', () => showWindow());
// Double-clicking the app (or its shortcut) while it runs sends 'activate', not a second instance.
app.on('activate', () => { if (store) showWindow(); });
app.on('before-quit', () => { quitting = true; });
app.on('window-all-closed', () => { /* stay alive in the menu bar */ });

app.whenReady().then(() => {
  if (app.dock) app.dock.hide();
  config = loadConfig();
  store = createStore(path.join(app.getPath('userData'), 'radar-state.json'), config);

  // Only the installed app registers itself; a dev run must not add node_modules' Electron to login items.
  const prefs = readPrefs();
  if (app.isPackaged && !prefs.loginItemSet) {
    app.setLoginItemSettings({ openAtLogin: true });
    writePrefs({ ...prefs, loginItemSet: true });
  }

  tray = new Tray(nativeImage.createFromPath(path.join(ASSETS, 'tray-green.png')));
  tray.on('click', toggleWindow);
  tray.on('right-click', () => tray.popUpContextMenu(contextMenu()));
  registerIpc();
  updateTray();

  // Opening the app by hand shows the dashboard; a login launch stays in the menu bar.
  if (!app.getLoginItemSettings().wasOpenedAtLogin) showWindow();

  refresh();
  setInterval(refresh, (config.refreshMinutes || 60) * 60 * 1000);
  powerMonitor.on('resume', () => setTimeout(refresh, RESUME_DELAY_MS));
});
