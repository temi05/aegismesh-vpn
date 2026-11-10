// Безопасный мост contextBridge для взаимодействия React-интерфейса с главным процессом Electron
import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('aegisElectron', {
  isDesktopApp: true,
  toggleMiniWidget: (compact: boolean): Promise<boolean> =>
    ipcRenderer.invoke('window:toggle-mini-widget', compact),
  minimizeWindow: (): Promise<void> => ipcRenderer.invoke('window:minimize'),
  closeToTray: (): Promise<void> => ipcRenderer.invoke('window:close'),
  getApiBaseUrl: (): Promise<string> => ipcRenderer.invoke('engine:get-api-url'),
});
