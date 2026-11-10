// Клиент взаимодействия с движком AegisMesh VPN:
// 1) На Android / iOS (Capacitor) — напрямую вызывает нативный VpnService + sing-box контроллер (без ложных HTTP-запросов)
// 2) На Windows ПК (Electron) и в режиме Wi-Fi пульта — работает с локальным сервером VpnEngine
import { Capacitor } from '@capacitor/core';
import type {
  AppSettings,
  AppUpdateInfo,
  CyberAuditReport,
  MobileAccessInfo,
  ParseImportResult,
  VpnStateSnapshot,
} from '../shared/types';
import { handleMobileStandaloneCall } from './mobileStandaloneFallback';

export interface AegisElectronBridge {
  isDesktopApp: boolean;
  toggleMiniWidget: (compact: boolean) => Promise<boolean>;
  minimizeWindow: () => Promise<void>;
  closeToTray: () => Promise<void>;
  getApiBaseUrl: () => Promise<string>;
}

declare global {
  interface Window {
    aegisElectron?: AegisElectronBridge;
  }
}

let cachedBaseUrl: string | null = null;

function getSearchToken(): string {
  if (typeof window === 'undefined') return '';
  const params = new URLSearchParams(window.location.search);
  return params.get('token') || '';
}

export function isNativeMobileApp(): boolean {
  if (typeof window === 'undefined') return false;
  if (window.aegisElectron?.isDesktopApp) return false;
  const params = new URLSearchParams(window.location.search);
  if (params.get('apiPort')) return false;
  if (Capacitor.isNativePlatform()) return true;
  if (window.location.protocol === 'capacitor:' || window.location.protocol === 'file:') {
    return true;
  }
  return false;
}

export async function resolveApiBaseUrl(): Promise<string> {
  if (cachedBaseUrl !== null) return cachedBaseUrl;

  if (typeof window !== 'undefined') {
    const params = new URLSearchParams(window.location.search);
    const apiPort = params.get('apiPort');
    if (apiPort && /^\d+$/.test(apiPort)) {
      cachedBaseUrl = `${window.location.protocol}//${window.location.hostname}:${apiPort}`;
      return cachedBaseUrl;
    }

    if (window.aegisElectron?.getApiBaseUrl) {
      try {
        const electronUrl = await window.aegisElectron.getApiBaseUrl();
        if (electronUrl) {
          cachedBaseUrl = electronUrl.replace(/\/+$/, '');
          return cachedBaseUrl;
        }
      } catch {
        // Fallback к относительным маршрутам встроенного сервера
      }
    }
  }

  cachedBaseUrl = '';
  return cachedBaseUrl;
}

async function requestJson<T>(
  path: string,
  method: 'GET' | 'POST' = 'GET',
  body?: unknown
): Promise<T> {
  // На Android APK сразу вызываем встроенный нативный VPN-контроллер (исключает возврат index.html вместо JSON!)
  if (isNativeMobileApp()) {
    return (await handleMobileStandaloneCall(
      path,
      (body as Record<string, unknown>) || undefined
    )) as T;
  }

  const baseUrl = await resolveApiBaseUrl();
  const token = getSearchToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };
  if (token) {
    headers['X-Aegis-Token'] = token;
  }

  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    // Защита от SPA fallback (когда вместо /api/* сервер статики отдал index.html с 200 OK)
    return (await handleMobileStandaloneCall(
      path,
      (body as Record<string, unknown>) || undefined
    )) as T;
  }

  const data = (await response.json()) as T & { error?: string };
  if (!response.ok) {
    throw new Error(data.error || `Ошибка HTTP ${response.status}`);
  }
  return data;
}

export const aegisApi = {
  getState: (): Promise<VpnStateSnapshot> => requestJson<VpnStateSnapshot>('/api/state'),

  getMobileInfo: (): Promise<MobileAccessInfo> =>
    requestJson<MobileAccessInfo>('/api/mobile-info'),

  connect: (nodeId?: string): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/connect', 'POST', { nodeId }),

  disconnect: (): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/disconnect', 'POST'),

  switchNode: (nodeId: string): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/switch-node', 'POST', { nodeId }),

  pingAll: (): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/ping-all', 'POST'),

  recoverUnavailableNodes: (): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/recover-unavailable', 'POST'),

  rebindNetwork: (): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/network/rebind', 'POST'),

  probeNode: (nodeId: string): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/node/probe', 'POST', { nodeId }),

  smartOptimize: (): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/smart-optimize', 'POST'),

  scanAiNodes: (): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/ai/scan', 'POST'),

  switchAiNode: (nodeId?: string): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/ai/switch', 'POST', nodeId ? { nodeId } : {}),

  loadInstalledApps: (): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/installed-apps', 'POST'),

  importNodes: (
    text: string
  ): Promise<{ result: ParseImportResult; snapshot: VpnStateSnapshot }> =>
    requestJson('/api/import', 'POST', { text }),

  addSubscription: (name: string, url: string): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/subscription/add', 'POST', { name, url }),

  deleteSubscription: (id: string): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/subscription/delete', 'POST', { id }),

  refreshSubscription: (id: string): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/subscription/refresh', 'POST', { id }),

  toggleSubscriptionFailover: (id: string, enabled: boolean): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/subscription/toggle-failover', 'POST', {
      id,
      enabled,
    }),

  toggleManualGroupFailover: (enabled: boolean): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/manual-group/toggle-failover', 'POST', {
      enabled,
    }),

  scanExternalClients: (): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/external-clients/scan', 'POST'),

  toggleExternalClient: (id: string, enabled: boolean): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/external-clients/toggle', 'POST', {
      id,
      enabled,
    }),

  addCustomExternalClient: (
    clientName: string,
    protocol: 'socks' | 'http',
    port: number
  ): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/external-clients/add-custom', 'POST', {
      clientName,
      protocol,
      port,
    }),

  selectEmergencyApp: (packageName: string | null): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/emergency-app/select', 'POST', {
      packageName,
    }),

  launchEmergencyApp: (packageName?: string): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/emergency-app/launch', 'POST', {
      packageName,
    }),

  dismissFailoverBanner: (): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/failover-banner/dismiss', 'POST'),

  deleteNode: (nodeId: string): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/node/delete', 'POST', { nodeId }),

  toggleNode: (nodeId: string, enabled: boolean): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/node/toggle', 'POST', { nodeId, enabled }),

  moveNodePriority: (
    nodeId: string,
    direction: 'up' | 'down'
  ): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/node/priority', 'POST', { nodeId, direction }),

  updateSettings: (patch: Partial<AppSettings>): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/settings', 'POST', patch),

  unlockVault: (pin: string): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/vault/unlock', 'POST', { pin }),

  setVaultPin: (pin: string | null): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/vault/pin', 'POST', { pin }),

  startTestStand: (): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/test-stand/start', 'POST'),

  stopTestStand: (): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/test-stand/stop', 'POST'),

  setTestNodeOnline: (nodeId: string, online: boolean): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/test-stand/node-online', 'POST', {
      nodeId,
      online,
    }),

  setTestNodeDelay: (nodeId: string, delayMs: number): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/test-stand/node-delay', 'POST', {
      nodeId,
      delayMs,
    }),

  runAudit: (): Promise<{ report: CyberAuditReport; snapshot: VpnStateSnapshot }> =>
    requestJson('/api/audit', 'POST'),

  installSingboxCore: (): Promise<VpnStateSnapshot> =>
    requestJson<VpnStateSnapshot>('/api/core/install', 'POST'),

  checkAppUpdate: (
    mockReleasePayload?: unknown
  ): Promise<{ ok: boolean; update: AppUpdateInfo; snapshot: VpnStateSnapshot }> =>
    requestJson(
      '/api/update/check',
      'POST',
      mockReleasePayload ? { mockReleasePayload } : {}
    ),

  installAppUpdate: (
    url?: string
  ): Promise<{ ok: boolean; update: AppUpdateInfo; snapshot: VpnStateSnapshot }> =>
    requestJson('/api/update/install', 'POST', { url }),
};
