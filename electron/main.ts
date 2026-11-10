// Главный процесс Electron для AegisMesh VPN: системный трей, мини-виджет, автозапуск ядра и очистка прокси
import { app, BrowserWindow, ipcMain, Menu, nativeImage, Tray } from 'electron';
import path from 'node:path';
import { LocalApiServer } from '../src/backend/apiServer';
import { VpnEngine } from '../src/backend/vpnEngine';

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let engine: VpnEngine | null = null;
let apiServer: LocalApiServer | null = null;
let isQuitting = false;

function createShieldIcon() {
  // Встроенная векторная иконка тактического щита 16x16 для системного трея
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 32 32">
    <path d="M16 2 L28 7 V16 C28 23.5 22.8 28.4 16 30 C9.2 28.4 4 23.5 4 16 V7 Z" fill="#0B0F17" stroke="#00F59B" stroke-width="2.5"/>
    <path d="M11 16.5 L14.5 20 L21.5 12.5" fill="none" stroke="#00F59B" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;
  const dataUrl = `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`;
  return nativeImage.createFromDataURL(dataUrl);
}

function updateTrayMenu() {
  if (!tray || !engine) return;
  const snap = engine.getSnapshot();
  const activeNode = snap.nodes.find((n) => n.id === snap.activeNodeId);
  const statusLabel =
    snap.connectionState === 'connected'
      ? `Щит активен: ${activeNode?.name || 'VPN'}`
      : snap.connectionState === 'killswitch_locked'
        ? 'Kill Switch: Трафик заблокирован'
        : 'Щит отключён';

  const contextMenu = Menu.buildFromTemplate([
    { label: `AegisMesh VPN — ${statusLabel}`, enabled: false },
    { type: 'separator' },
    {
      label:
        snap.connectionState === 'connected'
          ? 'Отключить VPN-щит'
          : 'Включить VPN-щит (Auto-Failover)',
      click: () => {
        if (!engine) return;
        if (snap.connectionState === 'connected') {
          void engine.disconnect();
        } else {
          void engine.connect();
        }
      },
    },
    {
      label: 'Развернуть Командный Центр',
      click: () => {
        mainWindow?.show();
        mainWindow?.focus();
      },
    },
    {
      label: 'Мобильный мини-виджет (390×760)',
      click: () => {
        if (!mainWindow) return;
        mainWindow.setSize(390, 760, true);
        mainWindow.show();
      },
    },
    { type: 'separator' },
    {
      label: 'Полный выход (сброс прокси)',
      click: () => {
        isQuitting = true;
        app.quit();
      },
    },
  ]);

  tray.setToolTip(`AegisMesh VPN — ${statusLabel}`);
  tray.setContextMenu(contextMenu);
}

async function createWindow() {
  const storageDir = path.join(app.getPath('userData'), 'aegismesh-vault');
  const distRendererDir = path.resolve(__dirname, '..', '..', 'renderer');

  engine = new VpnEngine(storageDir);
  apiServer = new LocalApiServer(engine, distRendererDir);
  const apiPort = await apiServer.start(18940);

  engine.on('state', () => updateTrayMenu());

  mainWindow = new BrowserWindow({
    width: 1320,
    height: 860,
    minWidth: 340,
    minHeight: 600,
    backgroundColor: '#070A0F',
    title: 'AegisMesh VPN — Tactical Auto-Failover & Cyber Shield',
    icon: createShieldIcon(),
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  ipcMain.handle('engine:get-api-url', () => `http://127.0.0.1:${apiPort}`);
  ipcMain.handle('window:toggle-mini-widget', (_evt, compact: boolean) => {
    if (!mainWindow) return false;
    if (compact) {
      mainWindow.setSize(392, 780, true);
      mainWindow.setAlwaysOnTop(true, 'floating');
    } else {
      mainWindow.setAlwaysOnTop(false);
      mainWindow.setSize(1320, 860, true);
    }
    return compact;
  });
  ipcMain.handle('window:minimize', () => {
    mainWindow?.minimize();
  });
  ipcMain.handle('window:close', () => {
    mainWindow?.hide();
  });

  mainWindow.on('close', (e) => {
    if (!isQuitting && tray) {
      e.preventDefault();
      mainWindow?.hide();
    }
  });

  if (process.env.NODE_ENV === 'development') {
    await mainWindow.loadURL(`http://127.0.0.1:5173/?apiPort=${apiPort}`);
  } else {
    const indexHtml = path.join(distRendererDir, 'index.html');
    await mainWindow.loadFile(indexHtml, {
      query: { apiPort: String(apiPort) },
    });
  }

  tray = new Tray(createShieldIcon());
  tray.on('double-click', () => {
    mainWindow?.show();
    mainWindow?.focus();
  });
  updateTrayMenu();
}

app.whenReady().then(() => {
  void createWindow();
});

app.on('before-quit', () => {
  isQuitting = true;
});

app.on('will-quit', (e) => {
  if (engine) {
    e.preventDefault();
    const eng = engine;
    const srv = apiServer;
    engine = null;
    apiServer = null;
    void (async () => {
      await srv?.stop();
      await eng.shutdown();
      app.exit(0);
    })();
  }
});
