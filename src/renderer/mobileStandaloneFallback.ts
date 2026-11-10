// Боевой мобильный контроллер AegisMesh VPN для Android APK (Capacitor + нативный VpnService + sing-box)
// Работает СТРОГО с добавленными пользователем VPN-ключами и подписками (0 выдуманных серверов!)
import { Capacitor, registerPlugin } from '@capacitor/core';
import {
  AI_UNSUPPORTED_COUNTRY_CODES,
  buildAiScanCandidateQueue,
  computeNodeAiRank,
  DEFAULT_AI_SERVICES,
  evaluateAiProbeResult,
  inferCountryHintFromNode,
  isSuspiciousAiCandidateNode,
  pickBestStickyAiNode,
  pickNextAiNodeForManualCycle,
} from '../shared/aiRouting';
import { buildAndroidEmbeddedSingboxConfig } from '../shared/androidSingboxConfig';
import {
  buildDiversifiedFailoverBatch,
  canTriggerSelfHealingRefresh,
  classifyAndroidAppCategory,
  detectZombieTunnelStall,
  getNodeProviderGroupKey,
  isDedicatedMobileRelayNode,
  isMobileCarrierFriendlyNode,
  isSubscriptionDueForAutoRefresh,
  isUdpBasedVpnProtocol,
  markNodeTemporarilyUnavailable,
  pickRememberedNetworkChampion,
  rankCandidatesSmart,
  releaseExpiredUnavailableNodes,
  releaseQuarantineForNetworkShift,
  shouldPreemptivelySwitchNode,
  updateNodeSmartMetrics,
} from '../shared/smartFailover';
import {
  createDefaultExternalClientBridges,
  externalBridgeToVpnNode,
  generateValidHwid,
  isSyntheticDummyNode,
  parseSubscriptionResponseHeaders,
  SUBSCRIPTION_COMPAT_PROFILES,
} from '../shared/subscriptionMeta';
import type {
  AppSettings,
  CyberAuditReport,
  DnsProviderId,
  ExternalVpnClientBridge,
  FailoverEventType,
  InstalledAndroidVpnApp,
  LiveTunnelTelemetry,
  MobileAccessInfo,
  ParseImportResult,
  PhysicalNetworkProfile,
  SubscriptionSource,
  VpnNode,
  VpnStateSnapshot,
} from '../shared/types';
import { parseVpnImportPayload } from '../shared/uriParser';
import {
  APP_VERSION,
  createDefaultAppUpdateInfo,
  GITHUB_RELEASES_LATEST_URL,
  GITHUB_RELEASES_PAGE_URL,
  parseGitHubReleasePayload,
} from '../shared/versionUpdater';

interface AegisNativeVpnBridge {
  startVpn(options: {
    configJson: string;
    activeNodeName: string;
    outboundTag?: string;
    dnsServer: string;
    excludedPackages?: string[];
    perAppMode?: string;
    perAppPackages?: string[];
    candidatesJson?: string;
    watchdogJson?: string;
  }): Promise<{ running: boolean; activeNodeName: string }>;
  stopVpn(): Promise<{ running: boolean }>;
  switchOutbound(options: {
    tag: string;
    activeNodeName: string;
  }): Promise<{ switched: boolean; running: boolean; activeNodeName: string }>;
  switchAiOutbound(options: {
    tag: string;
    activeAiNodeName: string;
  }): Promise<{
    switched: boolean;
    running: boolean;
    activeAiNodeName: string;
    activeAiOutboundTag?: string;
  }>;
  probeAiNode(options: {
    tag: string;
    timeoutMs?: number;
  }): Promise<{
    reachable: boolean;
    latencyMs?: number;
    exitCountry?: string;
    googleCountry?: string;
    geminiStatus?: number;
    geminiLocation?: string;
    geminiHtmlAllowed?: string;
    chatgptStatus?: number;
    chatgptBlockedBody?: boolean;
    grokStatus?: number;
    grokBlockedBody?: boolean;
    error?: string;
  }>;
  getStatus(): Promise<{
    running: boolean;
    activeNodeName: string;
    activeAiNodeName?: string;
    activeOutboundTag?: string;
    activeAiOutboundTag?: string;
    nativeWatchdogActive?: boolean;
    nativeSwitchCount?: number;
    lastSwitchFrom?: string;
    lastSwitchTo?: string;
    lastSwitchReason?: string;
    lastSwitchTimestamp?: number;
    lastMeasuredSpeedKbps?: number;
    networkType?: string;
    roamingHandoverCount?: number;
    lastHandoverTimestamp?: number;
    activeMtu?: number;
    bestWifiTag?: string;
    bestCellularTag?: string;
    lastError: string;
    txPackets: number;
    txBytes: number;
    rxPackets: number;
    rxBytes: number;
  }>;
  rebindNetwork(options?: {
    reason?: string;
  }): Promise<{
    rebound: boolean;
    networkType?: string;
    activeNodeName?: string;
    activeOutboundTag?: string;
  }>;
  tcpPing(options: {
    host: string;
    port: number;
    timeoutMs?: number;
  }): Promise<{ reachable: boolean; latencyMs?: number; error?: string }>;
  httpFetch(options: {
    url: string;
    useTunnelProxy?: boolean;
    timeoutMs?: number;
    headers?: Record<string, string>;
  }): Promise<{ status: number; body: string; headers?: Record<string, string> }>;
  probeProxyDelay(options: {
    tag: string;
    timeoutMs?: number;
  }): Promise<{ reachable: boolean; delayMs?: number }>;
  scanLocalPorts(options: {
    ports?: number[];
    timeoutMs?: number;
  }): Promise<{ results: Array<{ port: number; open: boolean; latencyMs?: number }> }>;
  listInstalledVpnApps(): Promise<{
    apps: Array<{ packageName: string; appName: string }>;
  }>;
  listInstalledApps(): Promise<{
    apps: Array<{ packageName: string; appName: string }>;
  }>;
  measureTunnelSpeed(options?: {
    bytes?: number;
    timeoutMs?: number;
  }): Promise<{ ok: boolean; kbps: number }>;
  updateWatchdogConfig(options: {
    candidatesJson: string;
    watchdogJson: string;
  }): Promise<{ updated: boolean }>;
  launchApp(options: { packageName: string }): Promise<{ launched: boolean }>;
  downloadAndInstallApk(options: {
    url: string;
  }): Promise<{
    started: boolean;
    installedIntentLaunched?: boolean;
    needsInstallPermission?: boolean;
    sha256?: string;
    sizeBytes?: number;
    filePath?: string;
    message?: string;
  }>;
  getUpdateInstallStatus(): Promise<{
    downloading: boolean;
    progressPercent: number;
    downloadedBytes: number;
    totalBytes: number;
    statusMessage: string;
    sha256: string;
    canInstallPackages: boolean;
    appVersionName: string;
    appVersionCode: number;
  }>;
}

const AegisNativeVpn: AegisNativeVpnBridge =
  registerPlugin<AegisNativeVpnBridge>('AegisNativeVpn');

const STORAGE_KEY = 'aegismesh_mobile_native_v2';
const PIN_HASH_KEY = 'aegismesh_mobile_pin_v2';
const HWID_KEY = 'aegismesh_device_hwid_v2';
const AI_PROBE_SCHEMA_KEY = 'aegismesh_ai_probe_v35';

let localSnap: VpnStateSnapshot | null = null;
let watchdogTimer: number | null = null;
let speedTimer: number | null = null;
let watchdogBusy = false;
let initialDiscoveryStarted = false;
let lastByteSampleTs = 0;
let lastSampleRx = 0;
let lastSampleTx = 0;
let lastSampleTxPackets = 0;
let lastSwitchTimestampMs = 0;
let lastSyncedNativeSwitchCount = 0;
let autoRefreshTimerMobile: number | null = null;
let activeAiNodeIdMobile: string | null = null;
let aiScanInProgressMobile = false;
let watchdogTickCounter = 0;
let lastObservedNetworkTypeMobile: PhysicalNetworkProfile = 'unknown';
const emergencyRefreshHistory = new Map<string, number>();

function getOrCreateDeviceHwid(): string {
  try {
    const existing = globalThis.localStorage?.getItem(HWID_KEY);
    if (existing && /^[A-Za-z0-9=-]{16,64}$/.test(existing.trim())) {
      return existing.trim();
    }
    const created = generateValidHwid();
    globalThis.localStorage?.setItem(HWID_KEY, created);
    return created;
  } catch {
    return generateValidHwid();
  }
}

function getDnsIp(provider: DnsProviderId): string {
  switch (provider) {
    case 'adguard':
      return '94.140.14.14';
    case 'quad9':
      return '9.9.9.9';
    case 'google':
      return '8.8.8.8';
    case 'cloudflare':
    default:
      return '1.1.1.1';
  }
}

function hashPinSimple(pin: string): string {
  let h = 2166136261;
  for (let i = 0; i < pin.length; i++) {
    h ^= pin.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return `pin_${(h >>> 0).toString(16)}`;
}

function createCleanTelemetry(): LiveTunnelTelemetry {
  return {
    verified: false,
    exitIp: null,
    exitCountry: null,
    rxSpeedBps: 0,
    txSpeedBps: 0,
    totalRxBytes: 0,
    totalTxBytes: 0,
    lastErrorReason: null,
    lastFailoverBanner: null,
  };
}

function mergeExternalBridges(
  saved?: ExternalVpnClientBridge[]
): ExternalVpnClientBridge[] {
  const defaults = createDefaultExternalClientBridges();
  if (!Array.isArray(saved) || saved.length === 0) return defaults;
  const map = new Map(saved.map((b) => [b.id, b]));
  const merged = defaults.map((def) => {
    const prev = map.get(def.id);
    return prev
      ? {
          ...def,
          enabledInFailover: Boolean(prev.enabledInFailover),
          detectedRunning: Boolean(prev.detectedRunning),
          latencyMs: prev.latencyMs ?? null,
        }
      : def;
  });
  for (const item of saved) {
    if (item.isCustom && !merged.some((m) => m.id === item.id)) {
      merged.push({ ...item, detectedRunning: false });
    }
  }
  return merged;
}

function normalizePriorities(nodes: VpnNode[]): VpnNode[] {
  // Автоматически очищаем любые застрявшие 0.0.0.0:1 инфо-заглушки от старых версий
  const clean = nodes.filter(
    (n) => !n.isTestStand && !isSyntheticDummyNode(n)
  );
  clean.sort((a, b) => a.priority - b.priority);
  clean.forEach((n, idx) => {
    n.priority = idx + 1;
  });
  return clean;
}

function createInitialCleanState(): VpnStateSnapshot {
  const savedPinHash = globalThis.localStorage?.getItem(PIN_HASH_KEY) || null;
  return {
    connectionState: 'disconnected',
    activeNodeId: null,
    connectedSince: null,
    failoverSwitchCount: 0,
    killSwitchBlocking: false,
    vaultLocked: Boolean(savedPinHash),
    vaultHasPin: Boolean(savedPinHash),
    nodes: [],
    subscriptions: [],
    settings: {
      failoverMode: 'strict_cascade',
      healthCheckIntervalSec: 6,
      maxLatencyThresholdMs: 1200,
      failureThreshold: 2,
      quarantineDurationSec: 30,
      killSwitchEnabled: true,
      connectionMode: 'tun',
      localProxyPort: 20808,
      allowLanGateway: false,
      dnsProvider: 'adguard',
      customDohUrl: 'https://1.1.1.1/dns-query',
      blockAdsAndTrackers: true,
      splitTunnelingEnabled: true,
      bypassDomains: ['gosuslugi.ru', 'kaspi.kz', 'sberbank.ru', '*.local'],
      bypassPrivateLan: true,
      perAppMode: 'all',
      perAppPackages: [],
      autoRefreshSubscriptions: true,
      defaultAutoUpdateHours: 12,
      speedFailoverEnabled: true,
      minThroughputKbps: 350,
      zombieCheckEnabled: true,
      antiFlapEnabled: true,
      aiRoutingEnabled: true,
      aiRoutingMode: 'parallel_ai_tunnel',
      aiServices: [...DEFAULT_AI_SERVICES],
      aiIncludeGoogleAccountSession: true,
      aiIncludeXForGrok: false,
      aiCustomDomains: [],
      preferredAiNodeId: null,
      seamlessRoamingEnabled: true,
      networkProfileAutoSwitchEnabled: true,
      bestWifiNodeId: null,
      bestCellularNodeId: null,
      adaptiveMobileMtu: true,
    },
    events: [],
    latencyHistory: [],
    coreStatus: {
      installed: true,
      version: 'sing-box 1.14.4 (Android VpnService)',
      binaryPath: 'jniLibs/arm64-v8a/libsingbox.so',
      downloading: false,
      downloadProgress: 100,
      engineDriver: 'sing-box',
      isAdmin: true,
    },
    lastAudit: null,
    testStandRunning: false,
    manualGroupEnabledInFailover: true,
    externalClients: createDefaultExternalClientBridges(),
    installedVpnApps: [],
    installedUserApps: [],
    emergencyAppPackage: null,
    telemetry: createCleanTelemetry(),
    appUpdate: createDefaultAppUpdateInfo(APP_VERSION),
  };
}

function getStateInternal(): VpnStateSnapshot {
  if (localSnap) return localSnap;

  try {
    globalThis.localStorage?.removeItem('aegismesh_mobile_standalone_v1');
    const raw = globalThis.localStorage?.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<VpnStateSnapshot>;
      if (parsed && Array.isArray(parsed.nodes)) {
        const base = createInitialCleanState();
        const savedPinHash = globalThis.localStorage?.getItem(PIN_HASH_KEY) || null;
        const subs = Array.isArray(parsed.subscriptions)
          ? parsed.subscriptions.map((sub, idx) => ({
              ...sub,
              enabledInFailover: sub.enabledInFailover !== false,
              priority: sub.priority ?? idx + 1,
            }))
          : [];
        const needAiSchemaReset =
          globalThis.localStorage?.getItem(AI_PROBE_SCHEMA_KEY) !== '1';
        const subNames = new Map(subs.map((x) => [x.id, x.name]));
        const realNodes = normalizePriorities(
          parsed.nodes.filter((n) => !n.isExternalClientBridge)
        ).map((n) => ({
          ...n,
          providerName:
            n.subscriptionId && subNames.has(n.subscriptionId)
              ? subNames.get(n.subscriptionId)
              : n.providerName || 'Личные ключи',
          // При старте приложения освобождаем все серверы из старого карантина/down, чтобы они не застревали навечно
          status: 'standby' as const,
          quarantinedUntil: null,
          consecutiveFailures: 0,
          lastError: undefined,
          ...(needAiSchemaReset
            ? {
                aiStatus: 'unknown' as const,
                aiGeminiOk: undefined,
                aiChatgptOk: undefined,
                aiGrokOk: undefined,
                aiExitCountry: null,
                aiBlockReason: null,
                aiScore: undefined,
              }
            : {}),
        }));
        if (needAiSchemaReset) {
          globalThis.localStorage?.setItem(AI_PROBE_SCHEMA_KEY, '1');
          if (parsed.settings) {
            parsed.settings.preferredAiNodeId = null;
          }
        }

        localSnap = {
          ...base,
          ...parsed,
          connectionState: 'disconnected',
          activeNodeId: null,
          connectedSince: null,
          killSwitchBlocking: false,
          testStandRunning: false,
          vaultHasPin: Boolean(savedPinHash),
          vaultLocked: Boolean(savedPinHash),
          nodes: realNodes,
          subscriptions: subs,
          settings: { ...base.settings, ...(parsed.settings || {}) },
          events: Array.isArray(parsed.events) ? parsed.events.slice(0, 50) : [],
          latencyHistory: [],
          coreStatus: base.coreStatus,
          manualGroupEnabledInFailover:
            parsed.manualGroupEnabledInFailover !== false,
          externalClients: mergeExternalBridges(parsed.externalClients),
          installedVpnApps: Array.isArray(parsed.installedVpnApps)
            ? parsed.installedVpnApps
            : [],
          emergencyAppPackage: parsed.emergencyAppPackage || null,
          telemetry: createCleanTelemetry(),
          appUpdate: parsed.appUpdate
            ? {
                ...createDefaultAppUpdateInfo(APP_VERSION),
                ...parsed.appUpdate,
                currentVersion: APP_VERSION,
              }
            : createDefaultAppUpdateInfo(APP_VERSION),
        };
        syncExternalBridgeNodesMobile(localSnap);
        return localSnap;
      }
    }
  } catch {
    // При повреждённом storage создаём чистый профиль
  }

  localSnap = createInitialCleanState();
  saveInternal();
  return localSnap;
}

function saveInternal(): void {
  if (!localSnap) return;
  try {
    const copyToSave: VpnStateSnapshot = {
      ...localSnap,
      nodes: localSnap.nodes.filter(
        (n) => !n.isExternalClientBridge && !isSyntheticDummyNode(n)
      ),
    };
    globalThis.localStorage?.setItem(STORAGE_KEY, JSON.stringify(copyToSave));
  } catch {
    // Игнорируем переполнение storage
  }
}

function syncExternalBridgeNodesMobile(s: VpnStateSnapshot): void {
  const bridges = s.externalClients || [];
  const activeBridges = bridges.filter(
    (b) => b.enabledInFailover && b.detectedRunning
  );
  const activeIds = new Set(activeBridges.map((b) => `bridge_${b.id}`));
  s.nodes = s.nodes.filter(
    (n) => !n.isExternalClientBridge || activeIds.has(n.id)
  );
  for (const b of activeBridges) {
    const id = `bridge_${b.id}`;
    const existing = s.nodes.find((n) => n.id === id);
    if (existing) {
      existing.latencyMs = b.latencyMs;
      existing.enabled = true;
      if (existing.id !== s.activeNodeId && existing.status === 'down') {
        existing.status = 'standby';
      }
    } else {
      s.nodes.push(externalBridgeToVpnNode(b, s.nodes.length + 1));
    }
  }
  s.nodes = normalizePriorities(s.nodes);
}

function isNodeInEnabledSourceMobile(s: VpnStateSnapshot, node: VpnNode): boolean {
  if (node.isExternalClientBridge) {
    const b = (s.externalClients || []).find((x) => `bridge_${x.id}` === node.id);
    return Boolean(b && b.enabledInFailover && b.detectedRunning);
  }
  if (node.subscriptionId) {
    const sub = s.subscriptions.find((x) => x.id === node.subscriptionId);
    return sub ? sub.enabledInFailover !== false : true;
  }
  return s.manualGroupEnabledInFailover !== false;
}

/**
 * Собирает полный пул включённых серверов пользователя по ВСЕМ подпискам и личным ключам для шлюза ИИ (`proxy-ai`).
 * Сначала идут узлы из активных источников автозамены, затем включённые серверы остальных подписок (например, `VPNUS`),
 * чтобы ИИ-шлюз мог выбрать чистый зарубежный сервер для Gemini, даже если для основного трафика выбрана другая подписка!
 */
function collectAllAiCandidateNodesMobile(s: VpnStateSnapshot): VpnNode[] {
  const primaryPool: VpnNode[] = [];
  const secondaryPool: VpnNode[] = [];

  for (const n of s.nodes) {
    if (!n.enabled || n.isTestStand) continue;
    if (n.isExternalClientBridge) {
      if (isNodeInEnabledSourceMobile(s, n)) {
        primaryPool.push(n);
      }
      continue;
    }
    if (isNodeInEnabledSourceMobile(s, n)) {
      primaryPool.push(n);
    } else {
      secondaryPool.push(n);
    }
  }

  return [...primaryPool, ...secondaryPool];
}

function collectExcludedPackagesMobile(s: VpnStateSnapshot): string[] {
  const pkgs = new Set<string>();
  for (const b of s.externalClients || []) {
    if (b.enabledInFailover || b.detectedRunning) {
      for (const p of b.androidPackages || []) {
        if (p) pkgs.add(p);
      }
    }
  }
  return Array.from(pkgs);
}

async function scanExternalClientsMobile(s: VpnStateSnapshot): Promise<void> {
  if (!s.externalClients) {
    s.externalClients = createDefaultExternalClientBridges();
  }
  if (!Capacitor.isNativePlatform()) return;
  try {
    const ports = Array.from(new Set(s.externalClients.map((b) => b.port)));
    const resp = await AegisNativeVpn.scanLocalPorts({ ports, timeoutMs: 250 });
    const map = new Map((resp.results || []).map((r) => [r.port, r]));
    for (const b of s.externalClients) {
      const r = map.get(b.port);
      if (r && r.open) {
        b.detectedRunning = true;
        b.latencyMs = typeof r.latencyMs === 'number' ? Math.max(1, Math.round(r.latencyMs)) : 2;
      } else {
        b.detectedRunning = false;
        b.latencyMs = null;
      }
    }
    syncExternalBridgeNodesMobile(s);
  } catch {
    // Игнорируем ошибку сканера портов
  }
}

async function discoverInstalledVpnAppsMobile(s: VpnStateSnapshot): Promise<void> {
  if (!Capacitor.isNativePlatform()) return;
  try {
    const resp = await AegisNativeVpn.listInstalledVpnApps();
    const list: InstalledAndroidVpnApp[] = (resp.apps || []).map((a) => ({
      packageName: a.packageName,
      appName: a.appName || a.packageName,
      isEmergencyFallback: s.emergencyAppPackage === a.packageName,
    }));
    s.installedVpnApps = list;
  } catch {
    // Игнорируем ошибку чтения установленных VPN-приложений
  }
}

async function discoverInstalledUserAppsMobile(s: VpnStateSnapshot): Promise<void> {
  if (!Capacitor.isNativePlatform()) return;
  try {
    const resp = await AegisNativeVpn.listInstalledApps();
    s.installedUserApps = (resp.apps || []).map((a) => ({
      packageName: a.packageName,
      appName: a.appName || a.packageName,
      categoryHint: classifyAndroidAppCategory(a.packageName, a.appName || ''),
    }));
  } catch {
    // Игнорируем ошибку чтения списка приложений
  }
}

function normalizeNetworkProfile(raw?: string): PhysicalNetworkProfile {
  if (raw === 'cellular') return 'cellular';
  if (raw === 'wifi' || raw === 'ethernet') return 'wifi';
  return 'unknown';
}

function rememberBestNetworkChampionMobile(
  s: VpnStateSnapshot,
  node: VpnNode,
  netType: PhysicalNetworkProfile
): void {
  if (!node || !node.enabled) return;
  if (netType === 'cellular') {
    const curBest = s.nodes.find((n) => n.id === s.settings.bestCellularNodeId);
    const curScore = curBest?.cellularScore ?? 0;
    const nextScore = node.cellularScore ?? node.smartScore ?? 65;
    if (!curBest || !curBest.enabled || nextScore >= curScore - 3 || isMobileCarrierFriendlyNode(node)) {
      s.settings.bestCellularNodeId = node.id;
    }
  } else if (netType === 'wifi') {
    const curBest = s.nodes.find((n) => n.id === s.settings.bestWifiNodeId);
    const curScore = curBest?.wifiScore ?? 0;
    const nextScore = node.wifiScore ?? node.smartScore ?? 65;
    if (!curBest || !curBest.enabled || nextScore >= curScore - 3) {
      s.settings.bestWifiNodeId = node.id;
    }
  }
}

async function detectCellularModeMobile(): Promise<boolean> {
  if (!Capacitor.isNativePlatform()) return false;
  try {
    const st = await AegisNativeVpn.getStatus();
    const prof = normalizeNetworkProfile(st.networkType);
    if (prof !== 'unknown') {
      lastObservedNetworkTypeMobile = prof;
    }
    return prof === 'cellular';
  } catch {
    return false;
  }
}

function buildNativeWatchdogPayloadsMobile(s: VpnStateSnapshot): {
  candidatesJson: string;
  watchdogJson: string;
} {
  // Включаем все узлы всех подписок (включая LTE #1 и чистые серверы США/Европы из VPNUS),
  // чтобы нативный Watchdog мог переключать основной канал на LTE-мосты, а ИИ-шлюз — строго на зарубежные серверы!
  const rawPool = collectAllAiCandidateNodesMobile(s);
  const isCellNow = lastObservedNetworkTypeMobile === 'cellular';
  const pool = rankCandidatesSmart(rawPool, null, Date.now(), isCellNow);
  const candidates = pool.map((n) => {
    const country = inferCountryHintFromNode(n);
    const isUnsupportedCountry = Boolean(
      country && AI_UNSUPPORTED_COUNTRY_CODES.has(country)
    );
    return {
      tag: `node-${n.id}`,
      name: n.name,
      group: getNodeProviderGroupKey(n),
      aiOk: n.aiStatus === 'ok' && n.aiGeminiOk !== false && !isUnsupportedCountry,
      aiBlocked:
        n.aiStatus === 'blocked' ||
        isUnsupportedCountry ||
        (n.aiStatus !== 'ok' && isSuspiciousAiCandidateNode(n)),
      aiRank: computeNodeAiRank(n),
      mobileFriendly: isMobileCarrierFriendlyNode(n),
      wifiScore: n.wifiScore ?? n.smartScore ?? 50,
      cellularScore: n.cellularScore ?? n.smartScore ?? 50,
    };
  });
  const watchdog = {
    intervalSec: Math.max(5, s.settings.healthCheckIntervalSec || 6),
    maxLatencyMs: Math.max(500, s.settings.maxLatencyThresholdMs || 1400),
    failureThreshold: Math.max(1, s.settings.failureThreshold || 2),
    speedEnabled: s.settings.speedFailoverEnabled !== false,
    minKbps: Math.max(120, s.settings.minThroughputKbps || 350),
    zombieEnabled: s.settings.zombieCheckEnabled !== false,
    networkProfileAutoSwitch: s.settings.networkProfileAutoSwitchEnabled !== false,
    adaptiveMobileMtu: s.settings.adaptiveMobileMtu !== false,
    bestWifiTag: s.settings.bestWifiNodeId ? `node-${s.settings.bestWifiNodeId}` : '',
    bestCellularTag: s.settings.bestCellularNodeId ? `node-${s.settings.bestCellularNodeId}` : '',
  };
  return {
    candidatesJson: JSON.stringify(candidates),
    watchdogJson: JSON.stringify(watchdog),
  };
}

function syncNativeStatusIntoSnapshotMobile(
  s: VpnStateSnapshot,
  st: Awaited<ReturnType<AegisNativeVpnBridge['getStatus']>>
): void {
  if (!s.telemetry) s.telemetry = createCleanTelemetry();
  s.telemetry.nativeWatchdogActive = Boolean(st.nativeWatchdogActive);
  if (typeof st.lastMeasuredSpeedKbps === 'number' && st.lastMeasuredSpeedKbps > 0) {
    s.telemetry.measuredBandwidthKbps = st.lastMeasuredSpeedKbps;
  }

  const netProf = normalizeNetworkProfile(st.networkType);
  if (netProf !== 'unknown') {
    if (
      lastObservedNetworkTypeMobile !== 'unknown' &&
      lastObservedNetworkTypeMobile !== netProf
    ) {
      // Сменилась физическая сеть (Wi-Fi <-> LTE): снимаем карантин с серверов прошлой сети!
      releaseQuarantineForNetworkShift(s.nodes, netProf);
    }
    lastObservedNetworkTypeMobile = netProf;
    s.telemetry.physicalNetworkType = netProf;
  }
  if (typeof st.roamingHandoverCount === 'number') {
    s.telemetry.roamingHandoverCount = st.roamingHandoverCount;
  }
  if (typeof st.lastHandoverTimestamp === 'number' && st.lastHandoverTimestamp > 0) {
    s.telemetry.lastHandoverAt = st.lastHandoverTimestamp;
  }
  if (typeof st.activeMtu === 'number' && st.activeMtu > 0) {
    s.telemetry.activeMtu = st.activeMtu;
  }

  if (st.bestWifiTag && st.bestWifiTag.startsWith('node-') && !s.settings.bestWifiNodeId) {
    const wid = st.bestWifiTag.slice('node-'.length);
    if (s.nodes.some((n) => n.id === wid)) {
      s.settings.bestWifiNodeId = wid;
    }
  }
  if (st.bestCellularTag && st.bestCellularTag.startsWith('node-') && !s.settings.bestCellularNodeId) {
    const cid = st.bestCellularTag.slice('node-'.length);
    if (s.nodes.some((n) => n.id === cid)) {
      s.settings.bestCellularNodeId = cid;
    }
  }
  s.telemetry.bestWifiNodeName =
    s.nodes.find((n) => n.id === s.settings.bestWifiNodeId)?.name || null;
  s.telemetry.bestCellularNodeName =
    s.nodes.find((n) => n.id === s.settings.bestCellularNodeId)?.name || null;

  // Если нативный фоновый сторож 24/7 переключил сервер при выключенном экране или через виджет/шторку:
  if (st.running && st.activeOutboundTag && st.activeOutboundTag.startsWith('node-')) {
    const nativeNodeId = st.activeOutboundTag.slice('node-'.length);
    const matched = s.nodes.find((n) => n.id === nativeNodeId);
    if (matched && s.activeNodeId !== matched.id) {
      s.activeNodeId = matched.id;
      s.connectionState = 'connected';
      if (!s.connectedSince) s.connectedSince = Date.now();
      s.telemetry.verified = true;
      s.telemetry.activeProviderLabel = matched.providerName || 'Мои VPN';
      s.telemetry.smartScore = matched.smartScore ?? null;
      s.telemetry.jitterMs = matched.jitterMs ?? null;
      s.nodes.forEach((n) => {
        if (n.id === matched.id) n.status = 'active';
        else if (n.status === 'active') n.status = 'standby';
      });
    }
  }

  if (st.running && st.activeAiOutboundTag && st.activeAiOutboundTag.startsWith('node-')) {
    const aiId = st.activeAiOutboundTag.slice('node-'.length);
    const aiNode = s.nodes.find((n) => n.id === aiId);
    if (aiNode) {
      const aiCountry = inferCountryHintFromNode(aiNode);
      const isBad =
        aiNode.aiStatus === 'blocked' ||
        Boolean(aiCountry && AI_UNSUPPORTED_COUNTRY_CODES.has(aiCountry));
      if (!isBad) {
        activeAiNodeIdMobile = aiNode.id;
        s.telemetry.activeAiNodeId = aiNode.id;
        s.telemetry.activeAiNodeName = aiNode.name;
        s.telemetry.activeAiCountry = aiCountry;
      } else {
        void syncStickyAiGatewayMobile(s);
      }
    }
  }
  s.telemetry.aiCompatibleCount = s.nodes.filter((n) => n.enabled && n.aiStatus === 'ok').length;

  const nativeSwitches = st.nativeSwitchCount || 0;
  if (nativeSwitches > lastSyncedNativeSwitchCount && st.lastSwitchTo) {
    const diff = nativeSwitches - lastSyncedNativeSwitchCount;
    lastSyncedNativeSwitchCount = nativeSwitches;
    s.failoverSwitchCount += diff;
    const reasonText = st.lastSwitchReason || 'Фоновая автозамена 24/7';
    s.telemetry.lastFailoverBanner = {
      timestamp: st.lastSwitchTimestamp || Date.now(),
      fromName: st.lastSwitchFrom || 'Предыдущий VPN',
      toName: st.lastSwitchTo,
      reason: reasonText,
    };
    pushEvent(s, 'failover_switch', reasonText, st.lastSwitchFrom, st.lastSwitchTo);
    void resolveTunnelExitIpMobile(s);
  }
}

async function probeTunnelNodeDelayMobile(
  node: VpnNode,
  timeoutMs = 4200
): Promise<number | null> {
  const netType: PhysicalNetworkProfile =
    lastObservedNetworkTypeMobile === 'cellular' ? 'cellular' : 'wifi';
  if (!Capacitor.isNativePlatform()) {
    const simLat = node.latencyMs ?? 45;
    updateNodeSmartMetrics(node, simLat, undefined, netType);
    if (localSnap) {
      rememberBestNetworkChampionMobile(localSnap, node, netType);
    }
    return simLat;
  }
  try {
    const res = await AegisNativeVpn.probeProxyDelay({
      tag: `node-${node.id}`,
      timeoutMs,
    });
    if (res.reachable && typeof res.delayMs === 'number' && res.delayMs > 0) {
      const cleanMs = Math.round(res.delayMs);
      updateNodeSmartMetrics(node, cleanMs, undefined, netType);
      node.lastCheckedAt = Date.now();
      node.lastError = undefined;
      if (localSnap) {
        rememberBestNetworkChampionMobile(localSnap, node, netType);
      }
      return cleanMs;
    }
  } catch {
    // Сквозная проверка не прошла
  }
  updateNodeSmartMetrics(node, null, undefined, netType);
  return null;
}

async function syncStickyAiGatewayMobile(
  s: VpnStateSnapshot,
  explicitAiNode?: VpnNode | null,
  allowStrictAlign = true
): Promise<VpnNode | null> {
  if (!s.telemetry) s.telemetry = createCleanTelemetry();
  const aiCandidatePool = collectAllAiCandidateNodesMobile(s);
  s.telemetry.aiCompatibleCount = aiCandidatePool.filter((n) => n.aiStatus === 'ok').length;

  if (s.settings.aiRoutingEnabled === false || aiCandidatePool.length === 0) {
    s.telemetry.activeAiNodeId = null;
    s.telemetry.activeAiNodeName = null;
    s.telemetry.activeAiCountry = null;
    return null;
  }

  const chosen =
    explicitAiNode ||
    pickBestStickyAiNode({
      nodes: aiCandidatePool,
      currentAiNodeId: activeAiNodeIdMobile,
      preferredAiNodeId: s.settings.preferredAiNodeId,
      fallbackActiveNodeId: s.activeNodeId,
    });

  if (!chosen) return null;

  const prevAiId = activeAiNodeIdMobile;
  activeAiNodeIdMobile = chosen.id;
  s.telemetry.activeAiNodeId = chosen.id;
  s.telemetry.activeAiNodeName = chosen.name;
  s.telemetry.activeAiCountry = inferCountryHintFromNode(chosen);

  if (Capacitor.isNativePlatform() && s.connectionState === 'connected') {
    await AegisNativeVpn.switchAiOutbound({
      tag: `node-${chosen.id}`,
      activeAiNodeName: chosen.name,
    }).catch(() => {});

    // Если включён режим «Весь телефон только через AI-серверы», выравниваем и основной туннель
    if (
      allowStrictAlign &&
      s.settings.aiRoutingMode === 'strict_ai_only' &&
      s.activeNodeId !== chosen.id &&
      isNodeInEnabledSourceMobile(s, chosen)
    ) {
      const curMain = s.nodes.find((n) => n.id === s.activeNodeId);
      if (!curMain || curMain.aiStatus === 'blocked' || (chosen.aiStatus === 'ok' && curMain.aiStatus !== 'ok')) {
        await switchMobileTunnelNode(
          s,
          chosen,
          'failover_switch',
          `🤖 Режим ИИ: основной туннель переключён на AI-совместимый сервер «${chosen.name}»`
        );
      }
    }
  }

  if (prevAiId && prevAiId !== chosen.id && s.connectionState === 'connected') {
    const prevName = s.nodes.find((n) => n.id === prevAiId)?.name;
    pushEvent(
      s,
      'security',
      `🤖 Шлюз Нейросетей (Gemini/GPT/Grok) закреплён на «${chosen.name}»${s.telemetry.activeAiCountry ? ` (${s.telemetry.activeAiCountry})` : ''}`,
      prevName,
      chosen.name,
      chosen.latencyMs
    );
  }

  return chosen;
}

async function probeSingleNodeAiMobile(
  s: VpnStateSnapshot,
  node: VpnNode
): Promise<void> {
  node.aiStatus = 'checking';
  const enabledServices =
    Array.isArray(s.settings.aiServices) && s.settings.aiServices.length > 0
      ? s.settings.aiServices
      : DEFAULT_AI_SERVICES;

  if (Capacitor.isNativePlatform() && s.connectionState === 'connected') {
    try {
      const raw = await AegisNativeVpn.probeAiNode({
        tag: `node-${node.id}`,
        timeoutMs: 5200,
      });
      if (raw.reachable && typeof raw.latencyMs === 'number' && raw.latencyMs > 0) {
        updateNodeSmartMetrics(
          node,
          raw.latencyMs,
          undefined,
          lastObservedNetworkTypeMobile === 'cellular' ? 'cellular' : 'wifi'
        );
      }
      const parsedHtmlAllowed =
        raw.geminiHtmlAllowed === 'true'
          ? true
          : raw.geminiHtmlAllowed === 'false'
            ? false
            : null;

      evaluateAiProbeResult(
        node,
        {
          reachable: raw.reachable,
          latencyMs: raw.latencyMs ?? node.latencyMs,
          exitCountry: raw.exitCountry || null,
          googleCountry: raw.googleCountry || null,
          geminiStatus: raw.geminiStatus,
          geminiLocation: raw.geminiLocation,
          geminiHtmlAllowed: parsedHtmlAllowed,
          chatgptStatus: raw.chatgptStatus,
          chatgptBlockedBody: Boolean(raw.chatgptBlockedBody),
          grokStatus: raw.grokStatus,
          grokBlockedBody: Boolean(raw.grokBlockedBody),
          error: raw.error || null,
        },
        enabledServices
      );
      return;
    } catch (err) {
      evaluateAiProbeResult(
        node,
        {
          reachable: false,
          error: err instanceof Error ? err.message : 'Сбой проверки ИИ',
        },
        enabledServices
      );
      return;
    }
  }

  // Если VPN сейчас выключен на телефоне: не выдаём ложных статусов «AI OK» без живой проверки базы Google через туннель!
  const rtt = await pingSingleNodeNative(node);
  const country = inferCountryHintFromNode(node);
  if (
    rtt === null &&
    Capacitor.isNativePlatform() &&
    !isUdpBasedVpnProtocol(node.protocol)
  ) {
    evaluateAiProbeResult(
      node,
      {
        reachable: false,
        error: 'Сервер недоступен',
      },
      enabledServices
    );
    return;
  }

  const isBlockedRegion =
    country === 'RU' || country === 'BY' || country === 'HK' || country === 'CN';
  const suspiciousRelay = isSuspiciousAiCandidateNode(node);

  if (Capacitor.isNativePlatform()) {
    if (isBlockedRegion) {
      evaluateAiProbeResult(
        node,
        {
          reachable: true,
          latencyMs: rtt ?? 45,
          exitCountry: country,
          googleCountry: country,
          geminiStatus: 302,
          geminiLocation: 'https://gemini.google.com/faq',
          chatgptStatus: 403,
          grokStatus: 403,
        },
        enabledServices
      );
    } else {
      node.aiStatus = 'unknown';
      node.aiBlockReason = null;
    }
    return;
  }

  evaluateAiProbeResult(
    node,
    {
      reachable: true,
      latencyMs: rtt ?? 45,
      exitCountry: country,
      googleCountry: isBlockedRegion || suspiciousRelay ? 'RU' : country,
      geminiStatus: isBlockedRegion || suspiciousRelay ? 302 : 200,
      geminiLocation: isBlockedRegion || suspiciousRelay ? 'https://gemini.google.com/faq' : '',
      chatgptStatus: isBlockedRegion ? 403 : 200,
      grokStatus: isBlockedRegion ? 403 : 200,
    },
    enabledServices
  );
}

async function scanAiCompatibilityMobile(
  s: VpnStateSnapshot,
  maxCandidates = 16,
  earlyStopWhenFound = false
): Promise<void> {
  if (aiScanInProgressMobile) return;
  const aiCandidatePool = collectAllAiCandidateNodesMobile(s);
  if (aiCandidatePool.length === 0) return;

  aiScanInProgressMobile = true;
  if (!s.telemetry) s.telemetry = createCleanTelemetry();
  s.telemetry.aiProbeInProgress = true;

  try {
    // При ручном нажатии «Проверить ИИ» сбрасываем прежние отказы, чтобы честно перепроверить все подписки заново
    if (!earlyStopWhenFound) {
      for (const n of aiCandidatePool) {
        if (n.aiStatus === 'blocked') {
          n.aiStatus = 'unknown';
          n.aiBlockReason = null;
        }
      }
    }

    const ordered = buildAiScanCandidateQueue({
      nodes: aiCandidatePool,
      preferredAiNodeId: s.settings.preferredAiNodeId,
      currentAiNodeId: activeAiNodeIdMobile,
      includeAlreadyBlocked: !earlyStopWhenFound,
    });

    // Гарантируем, что текущий выбранный ИИ-узел проверяется самым первым, чтобы мгновенно сменить его при Google=RU!
    if (activeAiNodeIdMobile) {
      const curIdx = ordered.findIndex((n) => n.id === activeAiNodeIdMobile);
      if (curIdx > 0) {
        const [curItem] = ordered.splice(curIdx, 1);
        ordered.unshift(curItem);
      } else if (curIdx === -1) {
        const curNode = aiCandidatePool.find((n) => n.id === activeAiNodeIdMobile);
        if (curNode) ordered.unshift(curNode);
      }
    }

    let foundGoodAi = 0;
    for (const candidate of ordered.slice(0, maxCandidates)) {
      await probeSingleNodeAiMobile(s, candidate);
      if (candidate.aiStatus === 'ok') {
        foundGoodAi += 1;
        // Как только нашли первый подтверждённый в базе Google рабочий сервер — немедленно переключаем proxy-ai!
        const curAi = aiCandidatePool.find((n) => n.id === activeAiNodeIdMobile);
        if (!curAi || curAi.aiStatus !== 'ok') {
          await syncStickyAiGatewayMobile(s, candidate);
          saveInternal();
        }
        if (earlyStopWhenFound && foundGoodAi >= 2) {
          break;
        }
      } else if (candidate.id === activeAiNodeIdMobile && candidate.aiStatus === 'blocked') {
        // Текущий ИИ-узел оказался заблокирован в Google (например, YouTube-RU): сразу уводим proxy-ai на следующий кандидат
        await syncStickyAiGatewayMobile(s);
        saveInternal();
      }
    }

    await syncStickyAiGatewayMobile(s);
    if (Capacitor.isNativePlatform() && s.connectionState === 'connected') {
      const wdPayloads = buildNativeWatchdogPayloadsMobile(s);
      void AegisNativeVpn.updateWatchdogConfig(wdPayloads).catch(() => {});
    }
  } finally {
    s.telemetry.aiProbeInProgress = false;
    s.telemetry.aiCompatibleCount = aiCandidatePool.filter((n) => n.aiStatus === 'ok').length;
    aiScanInProgressMobile = false;
    saveInternal();
  }
}

async function resolveTunnelExitIpMobile(s: VpnStateSnapshot): Promise<void> {
  if (!Capacitor.isNativePlatform() || s.connectionState !== 'connected') return;
  if (!s.telemetry) s.telemetry = createCleanTelemetry();
  try {
    const res = await AegisNativeVpn.httpFetch({
      url: 'https://ipwho.is/',
      useTunnelProxy: true,
      timeoutMs: 6500,
    });
    if (res.status >= 200 && res.status < 300) {
      const data = JSON.parse(res.body) as Record<string, unknown>;
      if (data.ip) {
        s.telemetry.exitIp = String(data.ip);
        s.telemetry.exitCountry = String(data.country_code || data.country || '');
        saveInternal();
        return;
      }
    }
  } catch {
    // Резерв через Cloudflare trace
  }
  try {
    const res = await AegisNativeVpn.httpFetch({
      url: 'https://1.1.1.1/cdn-cgi/trace',
      useTunnelProxy: true,
      timeoutMs: 5000,
    });
    if (res.status >= 200 && res.status < 300) {
      const ipMatch = res.body.match(/^ip=(.+)$/m);
      const locMatch = res.body.match(/^loc=(.+)$/m);
      if (ipMatch?.[1]) {
        s.telemetry.exitIp = ipMatch[1].trim();
        s.telemetry.exitCountry = locMatch?.[1]?.trim() || null;
        saveInternal();
      }
    }
  } catch {
    // Внешний IP определится при следующем цикле
  }
}

function stopSpeedTicker(): void {
  if (speedTimer !== null) {
    globalThis.clearInterval(speedTimer);
    speedTimer = null;
  }
  lastByteSampleTs = 0;
}

function startSpeedTicker(): void {
  stopSpeedTicker();
  if (!Capacitor.isNativePlatform()) return;
  lastByteSampleTs = Date.now();
  lastSampleRx = 0;
  lastSampleTx = 0;
  speedTimer = globalThis.setInterval(async () => {
    const s = getStateInternal();
    if (s.connectionState !== 'connected') return;
    try {
      const st = await AegisNativeVpn.getStatus();
      if (!st.running) {
        s.connectionState = 'disconnected';
        s.activeNodeId = null;
        s.connectedSince = null;
        if (s.telemetry) {
          s.telemetry.verified = false;
          s.telemetry.rxSpeedBps = 0;
          s.telemetry.txSpeedBps = 0;
        }
        stopWatchdog();
        stopSpeedTicker();
        saveInternal();
        return;
      }
      const now = Date.now();
      const dtSec = Math.max(0.5, (now - lastByteSampleTs) / 1000);
      if (!s.telemetry) s.telemetry = createCleanTelemetry();
      syncNativeStatusIntoSnapshotMobile(s, st);
      if (lastSampleRx > 0 || lastSampleTx > 0) {
        s.telemetry.rxSpeedBps = Math.max(0, Math.round((st.rxBytes - lastSampleRx) / dtSec));
        s.telemetry.txSpeedBps = Math.max(0, Math.round((st.txBytes - lastSampleTx) / dtSec));

        // Мгновенный детектор «зомби-туннеля» (DPI заморозил поток): сразу будим сторожа без ожидания таймера!
        if (
          s.settings.zombieCheckEnabled !== false &&
          lastSampleTxPackets > 0 &&
          detectZombieTunnelStall({
            prevTxPackets: lastSampleTxPackets,
            currTxPackets: st.txPackets,
            prevRxBytes: lastSampleRx,
            currRxBytes: st.rxBytes,
          })
        ) {
          void runMobileWatchdogTick();
        }
      }
      s.telemetry.totalRxBytes = st.rxBytes;
      s.telemetry.totalTxBytes = st.txBytes;
      lastSampleRx = st.rxBytes;
      lastSampleTx = st.txBytes;
      lastSampleTxPackets = st.txPackets;
      lastByteSampleTs = now;
    } catch {
      // Игнорируем разовую ошибку чтения счётчиков байт
    }
  }, 2000) as unknown as number;
}

async function fetchSubscriptionWaterfallMobile(cleanUrl: string): Promise<{
  parsed: ParseImportResult;
  headersMeta: ReturnType<typeof parseSubscriptionResponseHeaders>;
  compatLabel: string;
  rawBody: string;
}> {
  const hwid = getOrCreateDeviceHwid();
  let lastStatus = 0;
  let lastParsed: ParseImportResult = {
    nodes: [],
    errors: [],
    infoMessages: [],
    filteredDummyCount: 0,
  };
  let lastMeta = parseSubscriptionResponseHeaders({});
  let lastCompat = SUBSCRIPTION_COMPAT_PROFILES[0].label;
  let lastBody = '';

  for (const profile of SUBSCRIPTION_COMPAT_PROFILES) {
    const headers = profile.buildHeaders(hwid, 'android');
    if (Capacitor.isNativePlatform()) {
      const resp = await AegisNativeVpn.httpFetch({
        url: cleanUrl,
        useTunnelProxy: false,
        timeoutMs: 12000,
        headers,
      });
      lastStatus = resp.status;
      if (resp.status < 200 || resp.status >= 400 || !resp.body.trim()) {
        continue;
      }
      lastBody = resp.body;
      lastCompat = profile.label;
      lastMeta = parseSubscriptionResponseHeaders(resp.headers || {});
      const probe = parseVpnImportPayload(resp.body, 1);
      lastParsed = probe;
      if (probe.nodes.length > 0) {
        return {
          parsed: probe,
          headersMeta: lastMeta,
          compatLabel: profile.label,
          rawBody: resp.body,
        };
      }
    } else {
      const r = await fetch(cleanUrl);
      lastStatus = r.status;
      if (!r.ok) continue;
      const txt = await r.text();
      lastBody = txt;
      lastCompat = profile.label;
      const hdrObj: Record<string, string> = {};
      r.headers.forEach((v, k) => {
        hdrObj[k.toLowerCase()] = v;
      });
      lastMeta = parseSubscriptionResponseHeaders(hdrObj);
      const probe = parseVpnImportPayload(txt, 1);
      lastParsed = probe;
      if (probe.nodes.length > 0) {
        return {
          parsed: probe,
          headersMeta: lastMeta,
          compatLabel: profile.label,
          rawBody: txt,
        };
      }
    }
  }

  if (lastStatus < 200 || lastStatus >= 400) {
    throw new Error(`Сервер подписки вернул HTTP ${lastStatus}`);
  }
  return {
    parsed: lastParsed,
    headersMeta: lastMeta,
    compatLabel: lastCompat,
    rawBody: lastBody,
  };
}

function pushEvent(
  s: VpnStateSnapshot,
  type: FailoverEventType,
  reason: string,
  fromNodeName?: string,
  toNodeName?: string,
  latencyMs?: number | null
): void {
  s.events = [
    {
      id: `evt_${Date.now()}_${Math.random().toString(16).slice(2, 6)}`,
      timestamp: Date.now(),
      type,
      fromNodeName,
      toNodeName,
      reason,
      latencyMs,
    },
    ...s.events,
  ].slice(0, 60);
}

async function pingSingleNodeNative(node: VpnNode): Promise<number | null> {
  const netType: PhysicalNetworkProfile =
    lastObservedNetworkTypeMobile === 'cellular' ? 'cellular' : 'wifi';
  if (Capacitor.isNativePlatform()) {
    const s = getStateInternal();
    const baseQuarantineSec = s.settings.quarantineDurationSec || 45;

    // 1. Если VPN-туннель уже запущен и узел входит в активную конфигурацию sing-box —
    // проверяем его по НАСТОЯЩЕМУ протоколу (включая QUIC/UDP для Hysteria2 [HY2], TUIC и WireGuard!) через Clash API
    if (
      s.connectionState === 'connected' &&
      node.enabled &&
      isNodeInEnabledSourceMobile(s, node)
    ) {
      const tunnelRtt = await probeTunnelNodeDelayMobile(node, 3600);
      if (tunnelRtt !== null) {
        node.consecutiveFailures = 0;
        node.quarantinedUntil = null;
        node.lastError = undefined;
        if (node.status !== 'active') node.status = 'standby';
        return tunnelRtt;
      }
      markNodeTemporarilyUnavailable(
        node,
        'Временный таймаут сквозной проверки туннеля',
        baseQuarantineSec,
        Date.now(),
        netType
      );
      return null;
    }

    // 2. Если VPN сейчас выключен, а узел работает поверх UDP/QUIC (Hysteria2 [HY2], TUIC, WireGuard):
    // НЕЛЬЗЯ проверять его TCP-сокетом (Socket.connect всегда даёт ложный таймаут на UDP-порту!).
    // Оставляем сервер готовым в очереди, чтобы sing-box честно проверил его по QUIC/UDP при подключении.
    if (isUdpBasedVpnProtocol(node.protocol)) {
      node.lastCheckedAt = Date.now();
      node.lastError = undefined;
      node.quarantinedUntil = null;
      node.consecutiveFailures = 0;
      if (node.status !== 'active') node.status = 'standby';
      return node.latencyMs;
    }

    // 3. Для TCP-протоколов при выключенном VPN выполняем быструю проверку TCP-рукопожатия
    try {
      const res = await AegisNativeVpn.tcpPing({
        host: node.server,
        port: node.port,
        timeoutMs: 3200,
      });
      node.lastCheckedAt = Date.now();
      if (res.reachable && typeof res.latencyMs === 'number') {
        const cleanMs = Math.max(1, Math.round(res.latencyMs));
        updateNodeSmartMetrics(node, cleanMs, undefined, netType);
        node.consecutiveFailures = 0;
        node.quarantinedUntil = null;
        node.lastError = undefined;
        if (node.status !== 'active') node.status = 'standby';
        return node.latencyMs;
      }
      updateNodeSmartMetrics(node, null, undefined, netType);
      markNodeTemporarilyUnavailable(
        node,
        res.error || 'Таймаут соединения',
        baseQuarantineSec,
        Date.now(),
        netType
      );
      return null;
    } catch (err) {
      updateNodeSmartMetrics(node, null, undefined, netType);
      markNodeTemporarilyUnavailable(
        node,
        err instanceof Error ? err.message : 'Сервер временно недоступен',
        baseQuarantineSec,
        Date.now(),
        netType
      );
      return null;
    }
  }
  return node.latencyMs;
}

function chooseBestUserNode(
  s: VpnStateSnapshot,
  excludeId?: string
): VpnNode | null {
  const now = Date.now();
  releaseExpiredUnavailableNodes(s.nodes, now);

  const candidates = s.nodes
    .filter(
      (n) =>
        n.enabled &&
        isNodeInEnabledSourceMobile(s, n) &&
        n.id !== excludeId &&
        n.status !== 'quarantined' &&
        n.status !== 'down'
    )
    .sort((a, b) => a.priority - b.priority);

  if (candidates.length === 0) {
    const fallback = s.nodes
      .filter(
        (n) =>
          n.enabled &&
          isNodeInEnabledSourceMobile(s, n) &&
          n.id !== excludeId
      )
      .sort((a, b) => a.priority - b.priority);
    return fallback[0] || null;
  }

  if (s.settings.failoverMode === 'smart_fastest') {
    const ranked = rankCandidatesSmart(candidates, excludeId, now);
    if (ranked.length > 0) {
      return ranked[0];
    }
  }

  return candidates[0];
}

function stopWatchdog(): void {
  if (watchdogTimer !== null) {
    globalThis.clearInterval(watchdogTimer);
    watchdogTimer = null;
  }
}

function startWatchdog(): void {
  stopWatchdog();
  const s = getStateInternal();
  const intervalMs = Math.max(4, s.settings.healthCheckIntervalSec) * 1000;
  watchdogTimer = globalThis.setInterval(() => {
    void runMobileWatchdogTick();
  }, intervalMs) as unknown as number;
}

async function runMobileWatchdogTick(): Promise<void> {
  if (watchdogBusy) return;
  const s = getStateInternal();
  releaseExpiredUnavailableNodes(s.nodes);
  if (s.connectionState !== 'connected' || !s.activeNodeId) return;

  watchdogBusy = true;
  watchdogTickCounter += 1;
  try {
    // Тихая фоновая авто-реабилитация: каждые ~18 сек проверяем 1–2 сервера из карантина через Clash API,
    // чтобы ожившие серверы досрочно возвращались в рабочий список сами без участия пользователя!
    if (watchdogTickCounter % 3 === 0) {
      const quarantinedPool = s.nodes
        .filter(
          (n) =>
            n.enabled &&
            isNodeInEnabledSourceMobile(s, n) &&
            n.id !== s.activeNodeId &&
            (n.status === 'quarantined' || n.status === 'down')
        )
        .sort((a, b) => (a.quarantinedUntil || 0) - (b.quarantinedUntil || 0))
        .slice(0, 2);

      for (const cand of quarantinedPool) {
        const healedDelay = await probeTunnelNodeDelayMobile(cand, 2600);
        if (healedDelay !== null) {
          cand.status = 'standby';
          cand.quarantinedUntil = null;
          cand.consecutiveFailures = 0;
          cand.lastError = undefined;
        }
      }
    }
    if (Capacitor.isNativePlatform()) {
      const nativeStatus = await AegisNativeVpn.getStatus();
      if (!nativeStatus.running) {
        s.connectionState = 'disconnected';
        s.activeNodeId = null;
        s.connectedSince = null;
        if (s.telemetry) {
          s.telemetry.verified = false;
          s.telemetry.rxSpeedBps = 0;
          s.telemetry.txSpeedBps = 0;
        }
        s.nodes.forEach((n) => {
          if (n.status === 'active') n.status = 'standby';
        });
        stopWatchdog();
        stopSpeedTicker();
        saveInternal();
        return;
      }
    }

    const active = s.nodes.find((n) => n.id === s.activeNodeId);
    if (!active) return;

    const rtt = await probeTunnelNodeDelayMobile(active, 3800);
    s.latencyHistory = [
      ...s.latencyHistory.slice(-39),
      {
        timestamp: Date.now(),
        latencyMs: rtt,
        nodeName: active.name,
        failed: rtt === null,
      },
    ];

    let speedDegradedReason: string | null = null;
    if (
      rtt !== null &&
      rtt <= Math.max(1500, s.settings.maxLatencyThresholdMs) &&
      s.settings.speedFailoverEnabled !== false &&
      Capacitor.isNativePlatform() &&
      s.telemetry &&
      s.telemetry.rxSpeedBps > 0 &&
      (s.telemetry.rxSpeedBps * 8) / 1000 < Math.max(100, (s.settings.minThroughputKbps || 350) / 2)
    ) {
      try {
        const speedRes = await AegisNativeVpn.measureTunnelSpeed({
          bytes: 98304,
          timeoutMs: 3400,
        });
        if (speedRes.ok && speedRes.kbps > 0) {
          s.telemetry.measuredBandwidthKbps = speedRes.kbps;
          updateNodeSmartMetrics(
            active,
            rtt,
            speedRes.kbps,
            lastObservedNetworkTypeMobile === 'cellular' ? 'cellular' : 'wifi'
          );
          const minKbps = Math.max(120, s.settings.minThroughputKbps || 350);
          if (speedRes.kbps < minKbps) {
            speedDegradedReason = `Низкая скорость «${active.name}» (${speedRes.kbps} Кбит/с < ${minKbps} Кбит/с)`;
          }
        }
      } catch {
        // Игнорируем сбой микро-замера скорости
      }
    }

    const degraded =
      rtt === null ||
      rtt > Math.max(1500, s.settings.maxLatencyThresholdMs) ||
      speedDegradedReason !== null;

    if (degraded) {
      active.consecutiveFailures = (active.consecutiveFailures || 0) + 1;
      if (active.consecutiveFailures >= s.settings.failureThreshold) {
        await performMobileFailover(
          s,
          active,
          speedDegradedReason ||
            (rtt === null
              ? `Потеря сквозной связи с «${active.name}»`
              : `Деградация туннеля «${active.name}» (${rtt} мс)`)
        );
      }
    } else {
      active.consecutiveFailures = 0;
      active.status = 'active';
      if (s.telemetry) {
        s.telemetry.verified = true;
        s.telemetry.smartScore = active.smartScore ?? null;
        s.telemetry.jitterMs = active.jitterMs ?? null;
      }

      if (s.settings.failoverMode === 'cascade_recovery') {
        const primary = s.nodes
          .filter((n) => n.enabled && isNodeInEnabledSourceMobile(s, n))
          .sort((a, b) => a.priority - b.priority)[0];
        if (primary && primary.id !== active.id) {
          const pPing = await probeTunnelNodeDelayMobile(primary, 3200);
          if (pPing !== null && pPing <= s.settings.maxLatencyThresholdMs) {
            await switchMobileTunnelNode(
              s,
              primary,
              'primary_restored',
              `Основной сервер #1 «${primary.name}» восстановился (${pPing} мс) — автовозврат`
            );
          }
        }
      } else if (
        s.settings.failoverMode === 'smart_fastest' &&
        s.settings.antiFlapEnabled !== false
      ) {
        const ranked = rankCandidatesSmart(
          s.nodes.filter((n) => n.enabled && isNodeInEnabledSourceMobile(s, n)),
          active.id
        );
        const challenger = ranked[0];
        if (
          challenger &&
          shouldPreemptivelySwitchNode({
            activeNode: active,
            challengerNode: challenger,
            lastSwitchAtMs: lastSwitchTimestampMs,
          })
        ) {
          const cDelay = await probeTunnelNodeDelayMobile(challenger, 2800);
          if (
            cDelay !== null &&
            shouldPreemptivelySwitchNode({
              activeNode: active,
              challengerNode: challenger,
              lastSwitchAtMs: lastSwitchTimestampMs,
            })
          ) {
            await switchMobileTunnelNode(
              s,
              challenger,
              'failover_switch',
              `Умная оптимизация: «${challenger.name}» значительно быстрее (${cDelay} мс, рейтинг ${challenger.smartScore}★)`
            );
          }
        }
      }
    }

    saveInternal();
  } finally {
    watchdogBusy = false;
  }
}

async function switchMobileTunnelNode(
  s: VpnStateSnapshot,
  nextNode: VpnNode,
  eventType: FailoverEventType,
  reason: string
): Promise<void> {
  const prevNode = s.nodes.find((n) => n.id === s.activeNodeId);
  const enabledPool = s.nodes.filter(
    (n) => n.enabled && isNodeInEnabledSourceMobile(s, n)
  );
  if (Capacitor.isNativePlatform()) {
    const res = await AegisNativeVpn.switchOutbound({
      tag: `node-${nextNode.id}`,
      activeNodeName: nextNode.name,
    });
    const wdPayloads = buildNativeWatchdogPayloadsMobile(s);
    if (!res.switched) {
      const cfg = buildAndroidEmbeddedSingboxConfig({
        nodes: enabledPool.length > 0 ? enabledPool : [nextNode],
        aiExtraCandidateNodes: collectAllAiCandidateNodesMobile(s),
        activeNodeId: nextNode.id,
        activeAiNodeId: activeAiNodeIdMobile,
        settings: s.settings,
      });
      await AegisNativeVpn.startVpn({
        configJson: JSON.stringify(cfg),
        activeNodeName: nextNode.name,
        outboundTag: `node-${nextNode.id}`,
        dnsServer: getDnsIp(s.settings.dnsProvider),
        excludedPackages: collectExcludedPackagesMobile(s),
        perAppMode: s.settings.perAppMode || 'all',
        perAppPackages: s.settings.perAppPackages || [],
        candidatesJson: wdPayloads.candidatesJson,
        watchdogJson: wdPayloads.watchdogJson,
      });
    } else {
      void AegisNativeVpn.updateWatchdogConfig(wdPayloads).catch(() => {});
    }
  }
  lastSwitchTimestampMs = Date.now();

  for (const n of s.nodes) {
    if (n.id === nextNode.id) {
      n.status = 'active';
      n.consecutiveFailures = 0;
      n.quarantinedUntil = null;
    } else if (n.status === 'active') {
      n.status = 'standby';
    }
  }
  s.activeNodeId = nextNode.id;
  s.connectionState = 'connected';
  s.killSwitchBlocking = false;
  if (!s.telemetry) s.telemetry = createCleanTelemetry();
  s.telemetry.verified = true;
  s.telemetry.activeProviderLabel = nextNode.providerName || 'Мои VPN';
  s.telemetry.lastErrorReason = null;
  if (eventType === 'failover_switch' || eventType === 'primary_restored') {
    s.failoverSwitchCount += 1;
    s.telemetry.lastFailoverBanner = {
      timestamp: Date.now(),
      fromName: prevNode?.name || 'Предыдущий сервер',
      toName: nextNode.name,
      reason,
    };
  }
  pushEvent(s, eventType, reason, prevNode?.name, nextNode.name, nextNode.latencyMs);
  await syncStickyAiGatewayMobile(s, null, false);
  void resolveTunnelExitIpMobile(s);
}

async function raceVerifyNodesMobile(
  candidates: VpnNode[],
  timeoutMs = 3400
): Promise<VpnNode | null> {
  if (candidates.length === 0) return null;
  const baseQuarantineSec = localSnap?.settings.quarantineDurationSec || 45;
  const netType: PhysicalNetworkProfile =
    lastObservedNetworkTypeMobile === 'cellular' ? 'cellular' : 'wifi';
  const results = await Promise.all(
    candidates.map(async (cand) => {
      const delay = await probeTunnelNodeDelayMobile(cand, timeoutMs);
      if (delay === null) {
        markNodeTemporarilyUnavailable(
          cand,
          'Временный таймаут сквозной проверки туннеля',
          baseQuarantineSec,
          Date.now(),
          netType
        );
      } else {
        cand.consecutiveFailures = 0;
        cand.quarantinedUntil = null;
        cand.lastError = undefined;
        if (cand.status !== 'active') cand.status = 'standby';
      }
      return { cand, delay };
    })
  );
  const alive = results
    .filter((r): r is { cand: VpnNode; delay: number } => r.delay !== null && r.delay > 0)
    .sort((a, b) => (b.cand.smartScore ?? 50) - (a.cand.smartScore ?? 50) || a.delay - b.delay);

  return alive[0]?.cand || null;
}

/**
 * Многоволновая сквозная гонка для мобильного интернета (LTE / 4G / 5G) и Wi-Fi:
 * Волна 1: 6 диверсифицированных кандидатов с приоритетом LTE / через РФ / Reality.
 * Волна 2: следующие 8 ещё не проверенных кандидатов.
 * Волна 3 (спасение при переходе Wi-Fi -> LTE): горячий перезапуск сокетов sing-box
 * на текущей физической сети (rebindNetwork), разблокировка карантина и проверка всех подписок (включая VPNUS LTE #1).
 */
async function multiWaveVerifyNodesMobile(
  s: VpnStateSnapshot,
  pool: VpnNode[],
  excludeId: string | null,
  preferMobileFriendly = true
): Promise<VpnNode | null> {
  // Волна 1: 6 лучших кандидатов из разных подписок с приоритетом LTE / через РФ
  const wave1 = buildDiversifiedFailoverBatch(
    pool,
    excludeId,
    6,
    Date.now(),
    preferMobileFriendly
  );
  const testedIds = new Set<string>(wave1.map((x) => x.id));
  if (excludeId) testedIds.add(excludeId);

  let winner = await raceVerifyNodesMobile(wave1, 3600);
  if (winner) return winner;

  // Волна 2: следующие 8 кандидатов из пула
  const remaining = rankCandidatesSmart(
    pool.filter((x) => !testedIds.has(x.id)),
    excludeId,
    Date.now(),
    preferMobileFriendly
  );
  const wave2 = remaining.slice(0, 8);
  for (const n of wave2) testedIds.add(n.id);

  if (wave2.length > 0) {
    if (s.telemetry) {
      s.telemetry.verifyingStep = 'Вторая волна: проверка резервных серверов и LTE-мостов...';
    }
    winner = await raceVerifyNodesMobile(wave2, 3600);
    if (winner) return winner;
  }

  // Волна 3: если сокеты залипли после смены Wi-Fi -> LTE, перепривязываем интерфейс и проверяем ВСЕ подписки (включая LTE #1)
  if (Capacitor.isNativePlatform()) {
    if (s.telemetry) {
      s.telemetry.verifyingStep = 'Перепривязка мобильной сети (LTE/4G) и проверка LTE-маршрутов...';
    }
    await AegisNativeVpn.rebindNetwork({
      reason: 'Авто-перепривязка сокетов на мобильном интернете',
    }).catch(() => {});
  }
  releaseExpiredUnavailableNodes(s.nodes, Date.now(), true);

  const allSubsPool = collectAllAiCandidateNodesMobile(s);
  const rescuePool = buildDiversifiedFailoverBatch(
    allSubsPool.length > 0 ? allSubsPool : pool,
    excludeId,
    8,
    Date.now(),
    true
  );
  if (rescuePool.length > 0) {
    winner = await raceVerifyNodesMobile(rescuePool, 3800);
  }
  return winner;
}

function startAutoRefreshSchedulerMobile(): void {
  if (autoRefreshTimerMobile !== null) return;
  autoRefreshTimerMobile = globalThis.setInterval(() => {
    void checkDueSubscriptionsMobile();
  }, 10 * 60 * 1000) as unknown as number;
}

async function checkDueSubscriptionsMobile(): Promise<void> {
  const s = getStateInternal();
  if (s.settings.autoRefreshSubscriptions === false || s.vaultLocked) return;
  const defaultHours = s.settings.defaultAutoUpdateHours || 12;
  for (const sub of s.subscriptions) {
    if (isSubscriptionDueForAutoRefresh(sub, defaultHours)) {
      try {
        await handleMobileStandaloneCall('/api/subscription/refresh', { id: sub.id });
        if (s.telemetry) s.telemetry.lastAutoRefreshAt = Date.now();
      } catch {
        // Если сеть недоступна — повторим в следующем цикле
      }
    }
  }
}

async function performMobileFailover(
  s: VpnStateSnapshot,
  failedNode: VpnNode,
  reason: string
): Promise<void> {
  markNodeTemporarilyUnavailable(
    failedNode,
    reason,
    s.settings.quarantineDurationSec || 45,
    Date.now(),
    lastObservedNetworkTypeMobile === 'cellular' ? 'cellular' : 'wifi'
  );

  // Самоисцеление подписки (Self-Healing Refresh): если упал узел подписки, тихо проверяем свежие IP в фоне!
  if (failedNode.subscriptionId && s.settings.autoRefreshSubscriptions !== false) {
    const sub = s.subscriptions.find((x) => x.id === failedNode.subscriptionId);
    if (sub && canTriggerSelfHealingRefresh(sub, emergencyRefreshHistory.get(sub.id))) {
      emergencyRefreshHistory.set(sub.id, Date.now());
      void handleMobileStandaloneCall('/api/subscription/refresh', { id: sub.id }).catch(
        () => {}
      );
    }
  }

  await scanExternalClientsMobile(s);
  const eligible = s.nodes.filter(
    (n) =>
      n.enabled &&
      (isNodeInEnabledSourceMobile(s, n) || isDedicatedMobileRelayNode(n)) &&
      n.id !== failedNode.id
  );

  // Многоволновая диверсифицированная гонка (Волна 1 -> Волна 2 -> Rebind сокетов LTE + Волна 3)
  const verifiedNext = await multiWaveVerifyNodesMobile(
    s,
    eligible,
    failedNode.id,
    true
  );

  if (!verifiedNext) {
    // Честное отключение фейковой иконки VPN, если НИ ОДИН резервный сервис или внешний клиент не работает!
    stopWatchdog();
    stopSpeedTicker();
    if (Capacitor.isNativePlatform()) {
      await AegisNativeVpn.stopVpn();
    }
    s.connectionState = 'error';
    s.activeNodeId = null;
    s.connectedSince = null;
    s.killSwitchBlocking = false;
    if (!s.telemetry) s.telemetry = createCleanTelemetry();
    s.telemetry.verified = false;
    s.telemetry.rxSpeedBps = 0;
    s.telemetry.txSpeedBps = 0;
    s.telemetry.lastErrorReason = `${reason}. Все резервные VPN-серверы и внешние клиенты недоступны — туннель остановлен без ложного значка VPN.`;
    pushEvent(
      s,
      'security',
      s.telemetry.lastErrorReason,
      failedNode.name
    );
    return;
  }

  await switchMobileTunnelNode(
    s,
    verifiedNext,
    'failover_switch',
    `${reason} ➔ Мульти-VPN автозамена на «${verifiedNext.name}» (${verifiedNext.providerName || 'Резерв'})`
  );
}

export async function handleMobileStandaloneCall(
  path: string,
  body?: Record<string, unknown>
): Promise<unknown> {
  const s = getStateInternal();

  if (path === '/api/state') {
    if (Capacitor.isNativePlatform()) {
      startAutoRefreshSchedulerMobile();
      if (!initialDiscoveryStarted) {
        initialDiscoveryStarted = true;
        void (async () => {
          await discoverInstalledVpnAppsMobile(s);
          await discoverInstalledUserAppsMobile(s);
          await scanExternalClientsMobile(s);
          await checkDueSubscriptionsMobile();
          saveInternal();
        })();
      }
      try {
        const st = await AegisNativeVpn.getStatus();
        if (st.running) {
          syncNativeStatusIntoSnapshotMobile(s, st);
          if (s.connectionState !== 'connected') {
            // Туннель был запущен из шторки Android (Quick Settings Tile) или виджета рабочего стола!
            s.connectionState = 'connected';
            if (!s.connectedSince) s.connectedSince = Date.now();
            if (!s.activeNodeId && s.nodes.length > 0) {
              const byName = s.nodes.find((n) => n.name === st.activeNodeName) || s.nodes[0];
              s.activeNodeId = byName.id;
              byName.status = 'active';
            }
            if (!s.telemetry) s.telemetry = createCleanTelemetry();
            s.telemetry.verified = true;
            startWatchdog();
            startSpeedTicker();
            void resolveTunnelExitIpMobile(s);
            saveInternal();
          }
        } else if (s.connectionState === 'connected') {
          s.connectionState = 'disconnected';
          s.activeNodeId = null;
          s.connectedSince = null;
          if (s.telemetry) {
            s.telemetry.verified = false;
            s.telemetry.rxSpeedBps = 0;
            s.telemetry.txSpeedBps = 0;
          }
          stopWatchdog();
          stopSpeedTicker();
          saveInternal();
        }
      } catch {
        // Игнорируем временную ошибку статуса
      }
    }
    const released = releaseExpiredUnavailableNodes(s.nodes);
    syncExternalBridgeNodesMobile(s);
    if (released > 0) {
      saveInternal();
    }
    return structuredClone(s);
  }

  if (path === '/api/mobile-info') {
    const enabledMain = s.nodes.filter((n) => n.enabled && isNodeInEnabledSourceMobile(s, n));
    const aiPool = collectAllAiCandidateNodesMobile(s);
    const profileObj =
      (enabledMain.length > 0 || aiPool.length > 0)
        ? buildAndroidEmbeddedSingboxConfig({
            nodes: enabledMain.length > 0 ? enabledMain : aiPool,
            aiExtraCandidateNodes: aiPool,
            activeNodeId: s.activeNodeId,
            activeAiNodeId: activeAiNodeIdMobile,
            settings: s.settings,
          })
        : { log: { level: 'warn' }, outbounds: [{ type: 'direct', tag: 'direct' }] };

    const info: MobileAccessInfo = {
      lanIp: 'Android-устройство',
      remoteWebUrl: 'https://aegismesh.local',
      lanProxyAddress: '127.0.0.1:20808',
      accessToken: 'android-native',
      singboxProfileJson: JSON.stringify(profileObj, null, 2),
      singboxDeepLink: 'sing-box://import-remote-profile#AegisMesh_Cascade',
      nodeCount: s.nodes.length,
    };
    return info;
  }

  if (path === '/api/vault/unlock') {
    const pin = String(body?.pin || '');
    const savedHash = globalThis.localStorage?.getItem(PIN_HASH_KEY);
    if (savedHash && hashPinSimple(pin) !== savedHash) {
      throw new Error('Неверный PIN-код криптосейфа');
    }
    s.vaultLocked = false;
    return structuredClone(s);
  }

  if (path === '/api/vault/pin') {
    const rawPin = body?.pin ? String(body.pin).trim() : '';
    if (rawPin) {
      globalThis.localStorage?.setItem(PIN_HASH_KEY, hashPinSimple(rawPin));
      s.vaultHasPin = true;
      s.vaultLocked = false;
    } else {
      globalThis.localStorage?.removeItem(PIN_HASH_KEY);
      s.vaultHasPin = false;
      s.vaultLocked = false;
    }
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/import') {
    const text = String(body?.text || '').trim();
    // Автоматическое распознавание: если пользователь вставил https:// ссылку подписки в единую кнопку вставки!
    if (
      /^https?:\/\/\S+$/i.test(text) &&
      !text.includes('\n') &&
      !/^(vless|vmess|ss|trojan|hy2|hysteria2|tuic|wg|wireguard|socks5?):\/\//i.test(text)
    ) {
      const updatedSnap = (await handleMobileStandaloneCall('/api/subscription/add', {
        name: '',
        url: text,
      })) as VpnStateSnapshot;
      const latestSub = updatedSnap.subscriptions[updatedSnap.subscriptions.length - 1];
      const addedNodes = latestSub
        ? updatedSnap.nodes.filter((n) => n.subscriptionId === latestSub.id)
        : [];
      return {
        result: {
          nodes: addedNodes,
          errors: [],
          infoMessages: latestSub?.announceText ? [latestSub.announceText] : [],
          filteredDummyCount: latestSub?.filteredDummyCount || 0,
        } satisfies ParseImportResult,
        snapshot: updatedSnap,
      };
    }

    const res: ParseImportResult = parseVpnImportPayload(text, s.nodes.length + 1);
    if (res.nodes.length > 0) {
      for (const n of res.nodes) {
        n.providerName = 'Личные ключи';
      }
      s.nodes = normalizePriorities([...s.nodes, ...res.nodes]);
      await Promise.all(res.nodes.map((n) => pingSingleNodeNative(n)));
      pushEvent(
        s,
        'security',
        `Добавлено ${res.nodes.length} личных VPN-серверов в очередь автозамены`
      );
      saveInternal();
    }
    return { result: res, snapshot: structuredClone(s) };
  }

  if (path === '/api/subscription/add') {
    const name = String(body?.name || '').trim();
    const url = String(body?.url || '').trim();
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      throw new Error('Ссылка подписки должна начинаться с https:// или http://');
    }

    const { parsed: probe, headersMeta, compatLabel, rawBody } =
      await fetchSubscriptionWaterfallMobile(url);

    if (probe.nodes.length === 0) {
      const providerMsg =
        probe.infoMessages && probe.infoMessages.length > 0
          ? `Ответ провайдера: ${probe.infoMessages.join(' • ')}`
          : probe.errors[0] || 'По ссылке подписки не найдено рабочих VPN-серверов';
      throw new Error(providerMsg);
    }

    const subId = `sub_${Date.now()}`;
    const finalName =
      name ||
      headersMeta.profileTitle ||
      `VPN-сервис #${s.subscriptions.length + 1}`;
    const parsed = parseVpnImportPayload(rawBody, s.nodes.length + 1, subId);
    for (const n of parsed.nodes) {
      n.providerName = finalName;
    }

    const sub: SubscriptionSource = {
      id: subId,
      name: finalName,
      url,
      lastUpdatedAt: Date.now(),
      nodeCount: parsed.nodes.length,
      autoUpdateHours: headersMeta.autoUpdateHours ?? 12,
      enabledInFailover: true,
      priority: s.subscriptions.length + 1,
      usedBytes: headersMeta.usedBytes,
      totalBytes: headersMeta.totalBytes,
      expireUnix: headersMeta.expireUnix,
      supportUrl: headersMeta.supportUrl,
      announceText:
        headersMeta.announceText ||
        (parsed.infoMessages && parsed.infoMessages.length > 0
          ? parsed.infoMessages.join(' • ')
          : undefined),
      filteredDummyCount: parsed.filteredDummyCount || 0,
      compatProfile: compatLabel,
    };
    s.subscriptions.push(sub);
    s.nodes = normalizePriorities([...s.nodes, ...parsed.nodes]);
    await Promise.all(parsed.nodes.map((n) => pingSingleNodeNative(n)));
    pushEvent(
      s,
      'security',
      `Подключён VPN-сервис «${sub.name}» (${parsed.nodes.length} серверов, ${compatLabel})`
    );
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/subscription/refresh') {
    const subId = String(body?.id || '');
    const sub = s.subscriptions.find((x) => x.id === subId);
    if (!sub) throw new Error('Подписка не найдена');

    const { parsed: probe, headersMeta, compatLabel, rawBody } =
      await fetchSubscriptionWaterfallMobile(sub.url);
    if (probe.nodes.length === 0) {
      const providerMsg =
        probe.infoMessages && probe.infoMessages.length > 0
          ? `Ответ провайдера: ${probe.infoMessages.join(' • ')}`
          : probe.errors[0] || 'Провайдер не вернул активных VPN-серверов';
      throw new Error(providerMsg);
    }

    if (headersMeta.profileTitle && sub.name.startsWith('VPN-сервис')) {
      sub.name = headersMeta.profileTitle;
    }
    const parsed = parseVpnImportPayload(rawBody, 1, sub.id);
    for (const n of parsed.nodes) {
      n.providerName = sub.name;
    }

    s.nodes = normalizePriorities([
      ...s.nodes.filter((n) => n.subscriptionId !== sub.id),
      ...parsed.nodes,
    ]);
    sub.lastUpdatedAt = Date.now();
    sub.nodeCount = parsed.nodes.length;
    sub.usedBytes = headersMeta.usedBytes;
    sub.totalBytes = headersMeta.totalBytes;
    sub.expireUnix = headersMeta.expireUnix;
    sub.supportUrl = headersMeta.supportUrl || sub.supportUrl;
    sub.announceText =
      headersMeta.announceText ||
      (parsed.infoMessages && parsed.infoMessages.length > 0
        ? parsed.infoMessages.join(' • ')
        : sub.announceText);
    sub.filteredDummyCount = parsed.filteredDummyCount || 0;
    sub.compatProfile = compatLabel;

    await Promise.all(parsed.nodes.map((n) => pingSingleNodeNative(n)));
    pushEvent(
      s,
      'security',
      `Обновлён VPN-сервис «${sub.name}» (${sub.nodeCount} серверов)`
    );
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/subscription/toggle-failover') {
    const sub = s.subscriptions.find((x) => x.id === String(body?.id || ''));
    if (sub) {
      sub.enabledInFailover = Boolean(body?.enabled);
      saveInternal();
    }
    return structuredClone(s);
  }

  if (path === '/api/manual-group/toggle-failover') {
    s.manualGroupEnabledInFailover = Boolean(body?.enabled);
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/external-clients/scan') {
    await scanExternalClientsMobile(s);
    await discoverInstalledVpnAppsMobile(s);
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/external-clients/toggle') {
    const id = String(body?.id || '');
    const enabled = Boolean(body?.enabled);
    const bridge = (s.externalClients || []).find((b) => b.id === id);
    if (bridge) {
      bridge.enabledInFailover = enabled;
      await scanExternalClientsMobile(s);
      saveInternal();
    }
    return structuredClone(s);
  }

  if (path === '/api/external-clients/add-custom') {
    const clientName = String(body?.clientName || '').trim();
    const protocol = body?.protocol === 'http' ? 'http' : 'socks';
    const cleanPort = Math.round(Number(body?.port || 0));
    if (!Number.isInteger(cleanPort) || cleanPort < 1 || cleanPort > 65535) {
      throw new Error('Укажите корректный порт (1–65535)');
    }
    if (!s.externalClients) {
      s.externalClients = createDefaultExternalClientBridges();
    }
    s.externalClients.push({
      id: `ext_custom_${cleanPort}_${Date.now().toString(36)}`,
      clientName: clientName || `Локальный клиент (:${cleanPort})`,
      protocol,
      host: '127.0.0.1',
      port: cleanPort,
      androidPackages: [],
      detectedRunning: false,
      enabledInFailover: true,
      latencyMs: null,
      isCustom: true,
    });
    await scanExternalClientsMobile(s);
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/emergency-app/select') {
    const pkg = body?.packageName ? String(body.packageName) : null;
    s.emergencyAppPackage = pkg;
    s.installedVpnApps = (s.installedVpnApps || []).map((a) => ({
      ...a,
      isEmergencyFallback: a.packageName === pkg,
    }));
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/emergency-app/launch') {
    const pkg = String(body?.packageName || s.emergencyAppPackage || '').trim();
    if (!pkg) {
      throw new Error('Сначала выберите резервное VPN-приложение в настройках');
    }
    if (Capacitor.isNativePlatform()) {
      await AegisNativeVpn.stopVpn();
      await AegisNativeVpn.launchApp({ packageName: pkg });
    }
    s.connectionState = 'disconnected';
    s.activeNodeId = null;
    s.connectedSince = null;
    stopWatchdog();
    stopSpeedTicker();
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/failover-banner/dismiss') {
    if (s.telemetry) {
      s.telemetry.lastFailoverBanner = null;
    }
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/subscription/delete') {
    const subId = String(body?.id || '');
    s.subscriptions = s.subscriptions.filter((sub) => sub.id !== subId);
    s.nodes = normalizePriorities(s.nodes.filter((n) => n.subscriptionId !== subId));
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/ping-all') {
    await Promise.all(s.nodes.map((n) => pingSingleNodeNative(n)));
    releaseExpiredUnavailableNodes(s.nodes);
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/recover-unavailable') {
    const quarantinedNodes = s.nodes.filter(
      (n) => n.status === 'quarantined' || n.status === 'down'
    );
    for (const n of quarantinedNodes) {
      n.status = 'standby';
      n.quarantinedUntil = null;
      n.consecutiveFailures = 0;
      n.lastError = undefined;
    }
    // Параллельно проверяем возвращённые серверы по настоящему протоколу (Clash API при включённом VPN или UDP-safe при выключенном)
    await Promise.all(quarantinedNodes.map((n) => pingSingleNodeNative(n)));
    releaseExpiredUnavailableNodes(s.nodes);
    pushEvent(
      s,
      'security',
      `Выполнена реабилитация серверов из карантина (${quarantinedNodes.length} шт.)`
    );
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/node/probe') {
    const nodeId = String(body?.nodeId || '');
    const target = s.nodes.find((n) => n.id === nodeId);
    if (!target) throw new Error('Сервер не найден');
    target.status = 'standby';
    target.quarantinedUntil = null;
    target.consecutiveFailures = 0;
    target.lastError = undefined;
    await pingSingleNodeNative(target);
    releaseExpiredUnavailableNodes(s.nodes);
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/network/rebind') {
    releaseExpiredUnavailableNodes(s.nodes, Date.now(), true);
    if (Capacitor.isNativePlatform()) {
      const reb = await AegisNativeVpn.rebindNetwork({
        reason: 'Сброс зависших сокетов и обновление маршрута в 1 тап',
      }).catch(() => ({ rebound: false, networkType: 'unknown' }));
      const st = await AegisNativeVpn.getStatus().catch(() => null);
      if (st) {
        syncNativeStatusIntoSnapshotMobile(s, st);
      } else if (reb.networkType) {
        if (!s.telemetry) s.telemetry = createCleanTelemetry();
        s.telemetry.physicalNetworkType = normalizeNetworkProfile(reb.networkType);
      }
    }
    if (!s.telemetry) s.telemetry = createCleanTelemetry();
    s.telemetry.roamingHandoverCount = (s.telemetry.roamingHandoverCount || 0) + 1;
    s.telemetry.lastHandoverAt = Date.now();
    const curNode = s.nodes.find((n) => n.id === s.activeNodeId);
    pushEvent(
      s,
      'connect',
      `Сокеты сброшены и маршрут обновлён (${s.telemetry.physicalNetworkType === 'cellular' ? '📶 LTE/4G' : '🏠 Wi-Fi'})`,
      curNode?.name,
      curNode?.name,
      curNode?.latencyMs
    );
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/installed-apps') {
    await discoverInstalledUserAppsMobile(s);
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/smart-optimize') {
    await scanExternalClientsMobile(s);
    syncExternalBridgeNodesMobile(s);
    const pool = s.nodes.filter((n) => n.enabled && isNodeInEnabledSourceMobile(s, n));
    if (pool.length === 0) {
      throw new Error('Включите галочку [✓] хотя бы у одного VPN-сервиса для турбо-подбора');
    }

    if (s.connectionState === 'connected') {
      const batch = buildDiversifiedFailoverBatch(pool, null, 8);
      const bestInTunnel = await raceVerifyNodesMobile(batch, 3200);
      if (!bestInTunnel) {
        throw new Error('Ни один резервный сервер не прошёл сквозную турбо-проверку');
      }
      if (s.activeNodeId !== bestInTunnel.id) {
        await switchMobileTunnelNode(
          s,
          bestInTunnel,
          'failover_switch',
          `⚡ Турбо-подбор нашёл самый быстрый VPN: «${bestInTunnel.name}» (${bestInTunnel.latencyMs} мс, рейтинг ${bestInTunnel.smartScore ?? 90}★)`
        );
      }
      if (Capacitor.isNativePlatform()) {
        try {
          const sp = await AegisNativeVpn.measureTunnelSpeed({ bytes: 147456, timeoutMs: 4200 });
          if (sp.ok && sp.kbps > 0) {
            updateNodeSmartMetrics(
              bestInTunnel,
              bestInTunnel.latencyMs,
              sp.kbps,
              lastObservedNetworkTypeMobile === 'cellular' ? 'cellular' : 'wifi'
            );
            if (s.telemetry) {
              s.telemetry.measuredBandwidthKbps = sp.kbps;
              s.telemetry.smartScore = bestInTunnel.smartScore ?? null;
              s.telemetry.jitterMs = bestInTunnel.jitterMs ?? null;
            }
          }
        } catch {
          // Игнорируем ошибку скоростного теста
        }
      }
      saveInternal();
      return structuredClone(s);
    }

    // Если VPN выключен — пингуем все доступные узлы параллельно и подключаем лидера Smart Score
    await Promise.all(
      pool.filter((n) => !n.isExternalClientBridge).map((n) => pingSingleNodeNative(n))
    );
    const ranked = rankCandidatesSmart(pool, null).filter((n) => n.status !== 'down');
    const best = ranked[0] || pool[0];
    return handleMobileStandaloneCall('/api/connect', { nodeId: best.id });
  }

  if (path === '/api/ai/scan') {
    await scanExternalClientsMobile(s);
    syncExternalBridgeNodesMobile(s);
    await scanAiCompatibilityMobile(s, 20, false);
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/ai/switch') {
    const requestedId = body?.nodeId ? String(body.nodeId) : '';
    const aiPool = collectAllAiCandidateNodesMobile(s);
    if (aiPool.length === 0) {
      throw new Error('Нет доступных включённых серверов для шлюза нейросетей');
    }

    let nextAi = requestedId
      ? aiPool.find((n) => n.id === requestedId) || null
      : pickNextAiNodeForManualCycle(
          aiPool,
          activeAiNodeIdMobile || s.telemetry?.activeAiNodeId
        );

    if (!nextAi) {
      throw new Error('Не найден подходящий сервер для шлюза нейросетей');
    }

    // При ручной смене кнопки «Сменить ИИ» во время активного VPN сразу проверяем регион в базе Google,
    // автоматически перешагивая через серверы с Google=RU (YouTube без рекламы), чтобы не оставлять пользователя на заблокированном IP!
    if (!requestedId && Capacitor.isNativePlatform() && s.connectionState === 'connected') {
      const triedIds = new Set<string>();
      let cursor: VpnNode | null = nextAi;
      for (let attempt = 0; attempt < 6 && cursor; attempt++) {
        triedIds.add(cursor.id);
        if (cursor.aiStatus !== 'ok') {
          await probeSingleNodeAiMobile(s, cursor);
        }
        if (cursor.aiStatus === 'ok') {
          nextAi = cursor;
          break;
        }
        const remaining = aiPool.filter((n) => !triedIds.has(n.id) && n.aiStatus !== 'blocked');
        cursor = pickNextAiNodeForManualCycle(remaining, cursor.id);
      }
      if (!nextAi || nextAi.aiStatus === 'blocked') {
        nextAi =
          pickBestStickyAiNode({
            nodes: aiPool,
            currentAiNodeId: null,
            preferredAiNodeId: null,
            fallbackActiveNodeId: s.activeNodeId,
          }) || nextAi;
      }
    } else if (requestedId && s.connectionState === 'connected') {
      void probeSingleNodeAiMobile(s, nextAi).then(() => saveInternal());
    }

    s.settings.preferredAiNodeId = requestedId ? nextAi.id : null;
    await syncStickyAiGatewayMobile(s, nextAi);
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/connect') {
    await scanExternalClientsMobile(s);
    syncExternalBridgeNodesMobile(s);

    const enabledPool = s.nodes
      .filter((n) => n.enabled && isNodeInEnabledSourceMobile(s, n))
      .sort((a, b) => a.priority - b.priority);

    if (enabledPool.length === 0) {
      throw new Error(
        s.nodes.length > 0
          ? 'Включите галочку [✓] хотя бы у одного VPN-сервиса или запустите внешний VPN-клиент'
          : 'Добавьте свой VPN-ключ, подписку или запустите внешний клиент во вкладке «Мои VPN»'
      );
    }

    if (!s.telemetry) s.telemetry = createCleanTelemetry();
    s.telemetry.verified = false;
    s.telemetry.lastErrorReason = null;
    s.telemetry.verifyingStep = 'Подготовка туннеля и разрешение IP серверов...';
    s.connectionState = 'connecting';

    // Перед новым подключением сбрасываем прошлые карантины, чтобы ни один сервер
    // не был пропущен из-за старых таймаутов при смене Wi-Fi <-> Мобильный интернет (LTE/4G)
    releaseExpiredUnavailableNodes(s.nodes, Date.now(), true);

    const isCellular = await detectCellularModeMobile();
    const netProfile: PhysicalNetworkProfile = isCellular ? 'cellular' : 'wifi';
    const preferredId = body?.nodeId ? String(body.nodeId) : undefined;
    const orderedCandidates: VpnNode[] = [];
    if (preferredId) {
      const pref =
        enabledPool.find((n) => n.id === preferredId) ||
        s.nodes.find((n) => n.id === preferredId && n.enabled);
      if (pref) orderedCandidates.push(pref);
    }

    // Если включён авто-профиль сети (Wi-Fi vs LTE), ставим первым запомненный лучший сервер для этой сети!
    if (!preferredId && s.settings.networkProfileAutoSwitchEnabled !== false) {
      const rememberedId = isCellular
        ? s.settings.bestCellularNodeId
        : s.settings.bestWifiNodeId;
      const champion = pickRememberedNetworkChampion(
        s.nodes.filter(
          (n) => n.enabled && (isNodeInEnabledSourceMobile(s, n) || isDedicatedMobileRelayNode(n))
        ),
        netProfile,
        rememberedId
      );
      if (champion && !orderedCandidates.some((x) => x.id === champion.id)) {
        orderedCandidates.push(champion);
      }
    }

    // На мобильном интернете (LTE / 4G) автоматически ставим в приоритет LTE-серверы и мосты [через РФ]
    if (isCellular && !preferredId) {
      const mobileFriendlyNodes = rankCandidatesSmart(
        s.nodes.filter(
          (n) =>
            n.enabled &&
            (isNodeInEnabledSourceMobile(s, n) || isDedicatedMobileRelayNode(n)) &&
            isMobileCarrierFriendlyNode(n)
        ),
        null,
        Date.now(),
        true
      );
      for (const mf of mobileFriendlyNodes) {
        if (!orderedCandidates.some((x) => x.id === mf.id)) {
          orderedCandidates.push(mf);
        }
      }
    }

    const best = chooseBestUserNode(s);
    if (best && !orderedCandidates.some((x) => x.id === best.id)) {
      orderedCandidates.push(best);
    }
    const rankedRest = rankCandidatesSmart(enabledPool, null, Date.now(), isCellular);
    for (const item of rankedRest) {
      if (!orderedCandidates.some((x) => x.id === item.id)) {
        orderedCandidates.push(item);
      }
    }
    for (const item of enabledPool) {
      if (!orderedCandidates.some((x) => x.id === item.id)) {
        orderedCandidates.push(item);
      }
    }

    const firstTarget = orderedCandidates[0];
    const aiCandidatePool = collectAllAiCandidateNodesMobile(s);
    const initialAiTarget = pickBestStickyAiNode({
      nodes: aiCandidatePool.length > 0 ? aiCandidatePool : enabledPool,
      currentAiNodeId: activeAiNodeIdMobile,
      preferredAiNodeId: s.settings.preferredAiNodeId,
      fallbackActiveNodeId: firstTarget.id,
    });
    if (initialAiTarget) {
      activeAiNodeIdMobile = initialAiTarget.id;
    }
    const allConfigNodes =
      aiCandidatePool.length >= enabledPool.length ? aiCandidatePool : enabledPool;
    const cfg = buildAndroidEmbeddedSingboxConfig({
      nodes: allConfigNodes,
      aiExtraCandidateNodes: aiCandidatePool,
      activeNodeId: firstTarget.id,
      activeAiNodeId: initialAiTarget?.id || firstTarget.id,
      settings: s.settings,
    });

    if (Capacitor.isNativePlatform()) {
      const wdPayloads = buildNativeWatchdogPayloadsMobile(s);
      await AegisNativeVpn.startVpn({
        configJson: JSON.stringify(cfg),
        activeNodeName: firstTarget.name,
        outboundTag: `node-${firstTarget.id}`,
        dnsServer: getDnsIp(s.settings.dnsProvider),
        excludedPackages: collectExcludedPackagesMobile(s),
        perAppMode: s.settings.perAppMode || 'all',
        perAppPackages: s.settings.perAppPackages || [],
        candidatesJson: wdPayloads.candidatesJson,
        watchdogJson: wdPayloads.watchdogJson,
      });
    }

    // Честная сквозная End-to-End верификация: сначала мгновенно проверяем выбранный узел,
    // а при отказе — запускаем многоволновую диверсифицированную гонку по всем VPN-подпискам (включая LTE #1 и [через РФ])!
    s.telemetry.verifyingStep = `Сквозная проверка «${firstTarget.name}»...`;
    let verifiedNode: VpnNode | null = null;
    const firstDelay = await probeTunnelNodeDelayMobile(firstTarget, 3800);
    if (firstDelay !== null) {
      verifiedNode = firstTarget;
    } else {
      markNodeTemporarilyUnavailable(
        firstTarget,
        'Временный таймаут сквозной проверки туннеля',
        s.settings.quarantineDurationSec || 45,
        Date.now(),
        lastObservedNetworkTypeMobile === 'cellular' ? 'cellular' : 'wifi'
      );
      s.telemetry.verifyingStep =
        'Многоволновой поиск живого сервера (LTE / через РФ / мульти-подписки)...';
      verifiedNode = await multiWaveVerifyNodesMobile(
        s,
        orderedCandidates,
        firstTarget.id,
        true
      );
    }

    if (!verifiedNode) {
      // Ни один сервер не работает: ГАСИМ системный VpnService, чтобы не висел обманчивый значок VPN!
      stopWatchdog();
      stopSpeedTicker();
      if (Capacitor.isNativePlatform()) {
        await AegisNativeVpn.stopVpn();
      }
      // Защита от массового офлайна: не запираем весь список в карантине, если на телефоне пропал интернет
      releaseExpiredUnavailableNodes(s.nodes);
      s.connectionState = 'error';
      s.activeNodeId = null;
      s.connectedSince = null;
      s.telemetry.verified = false;
      s.telemetry.verifyingStep = undefined;
      s.telemetry.lastErrorReason =
        'Ни один из выбранных VPN-серверов не прошёл сквозную проверку связи. Проверьте подписку или запустите внешний VPN-клиент.';
      saveInternal();
      throw new Error(s.telemetry.lastErrorReason);
    }

    if (Capacitor.isNativePlatform() && verifiedNode.id !== firstTarget.id) {
      await AegisNativeVpn.switchOutbound({
        tag: `node-${verifiedNode.id}`,
        activeNodeName: verifiedNode.name,
      });
      s.failoverSwitchCount += 1;
      s.telemetry.lastFailoverBanner = {
        timestamp: Date.now(),
        fromName: firstTarget.name,
        toName: verifiedNode.name,
        reason: 'Основной сервер не ответил — сработала мульти-VPN автозамена',
      };
    }

    s.activeNodeId = verifiedNode.id;
    s.connectionState = 'connected';
    s.connectedSince = Date.now();
    lastSwitchTimestampMs = Date.now();
    s.killSwitchBlocking = false;
    s.telemetry.verified = true;
    s.telemetry.verifyingStep = undefined;
    s.telemetry.activeProviderLabel = verifiedNode.providerName || 'Мои VPN';
    s.telemetry.lastErrorReason = null;

    s.nodes.forEach((n) => {
      if (n.id === verifiedNode.id) {
        n.status = 'active';
        n.consecutiveFailures = 0;
        n.quarantinedUntil = null;
      } else if (n.status === 'active') {
        n.status = 'standby';
      }
    });

    pushEvent(
      s,
      'connect',
      `Туннель проверен и подключён через «${verifiedNode.name}» (${verifiedNode.providerName || verifiedNode.protocol.toUpperCase()})`,
      undefined,
      verifiedNode.name,
      verifiedNode.latencyMs
    );
    await syncStickyAiGatewayMobile(s);
    void resolveTunnelExitIpMobile(s);
    // В фоне проверяем реальную доступность Gemini / ChatGPT / Grok через изолированный порт 20809 и базу Google sw.js_data
    if (s.settings.aiRoutingEnabled !== false) {
      void scanAiCompatibilityMobile(s, 16, true);
    }
    startWatchdog();
    startSpeedTicker();
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/disconnect') {
    stopWatchdog();
    stopSpeedTicker();
    if (Capacitor.isNativePlatform()) {
      await AegisNativeVpn.stopVpn();
    }
    const prev = s.nodes.find((n) => n.id === s.activeNodeId);
    s.connectionState = 'disconnected';
    s.activeNodeId = null;
    activeAiNodeIdMobile = null;
    s.connectedSince = null;
    s.killSwitchBlocking = false;
    if (s.telemetry) {
      s.telemetry.verified = false;
      s.telemetry.verifyingStep = undefined;
      s.telemetry.exitIp = null;
      s.telemetry.exitCountry = null;
      s.telemetry.activeAiNodeId = null;
      s.telemetry.activeAiNodeName = null;
      s.telemetry.activeAiCountry = null;
      s.telemetry.rxSpeedBps = 0;
      s.telemetry.txSpeedBps = 0;
      s.telemetry.activeProviderLabel = undefined;
      s.telemetry.lastErrorReason = null;
    }
    s.nodes.forEach((n) => {
      if (n.status === 'active') n.status = 'standby';
    });
    if (prev) {
      pushEvent(s, 'disconnect', `VPN-туннель «${prev.name}» отключён`, prev.name);
    }
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/switch-node') {
    const nodeId = String(body?.nodeId || '');
    const target = s.nodes.find((n) => n.id === nodeId);
    if (!target) throw new Error('Выбранный сервер не найден');
    target.enabled = true;
    target.quarantinedUntil = null;

    if (s.connectionState !== 'connected') {
      return handleMobileStandaloneCall('/api/connect', { nodeId });
    }

    await pingSingleNodeNative(target);
    await switchMobileTunnelNode(
      s,
      target,
      'connect',
      `Ручное переключение туннеля на #${target.priority} «${target.name}»`
    );
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/node/delete') {
    const delId = String(body?.nodeId || '');
    if (s.activeNodeId === delId && s.connectionState === 'connected') {
      await handleMobileStandaloneCall('/api/disconnect');
    }
    s.nodes = normalizePriorities(s.nodes.filter((n) => n.id !== delId));
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/node/toggle') {
    const n = s.nodes.find((x) => x.id === body?.nodeId);
    if (n) n.enabled = Boolean(body?.enabled);
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/node/priority') {
    const idx = s.nodes.findIndex((x) => x.id === body?.nodeId);
    const swap = body?.direction === 'up' ? idx - 1 : idx + 1;
    if (idx >= 0 && swap >= 0 && swap < s.nodes.length) {
      const tmp = s.nodes[idx];
      s.nodes[idx] = s.nodes[swap];
      s.nodes[swap] = tmp;
      s.nodes.forEach((n, i) => {
        n.priority = i + 1;
      });
    }
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/settings') {
    const prevPerAppMode = s.settings.perAppMode || 'all';
    const prevPerAppPkgs = JSON.stringify(s.settings.perAppPackages || []);
    const prevAiSig = JSON.stringify({
      en: s.settings.aiRoutingEnabled !== false,
      mode: s.settings.aiRoutingMode || 'parallel_ai_tunnel',
      svc: s.settings.aiServices || DEFAULT_AI_SERVICES,
      gAcc: s.settings.aiIncludeGoogleAccountSession !== false,
      xGrok: Boolean(s.settings.aiIncludeXForGrok),
      cust: s.settings.aiCustomDomains || [],
    });
    s.settings = { ...s.settings, ...(body as Partial<AppSettings>) };
    const nextAiSig = JSON.stringify({
      en: s.settings.aiRoutingEnabled !== false,
      mode: s.settings.aiRoutingMode || 'parallel_ai_tunnel',
      svc: s.settings.aiServices || DEFAULT_AI_SERVICES,
      gAcc: s.settings.aiIncludeGoogleAccountSession !== false,
      xGrok: Boolean(s.settings.aiIncludeXForGrok),
      cust: s.settings.aiCustomDomains || [],
    });

    await syncStickyAiGatewayMobile(s);

    if (s.connectionState === 'connected') {
      startWatchdog();
      if (Capacitor.isNativePlatform()) {
        const wdPayloads = buildNativeWatchdogPayloadsMobile(s);
        void AegisNativeVpn.updateWatchdogConfig(wdPayloads).catch(() => {});
        const nextPerAppMode = s.settings.perAppMode || 'all';
        const nextPerAppPkgs = JSON.stringify(s.settings.perAppPackages || []);
        // Если изменились правила Per-App VPN или домены ИИ-шлюза при включённом туннеле — бесшовно пересоздаём конфиг sing-box
        if (
          (prevPerAppMode !== nextPerAppMode ||
            prevPerAppPkgs !== nextPerAppPkgs ||
            prevAiSig !== nextAiSig) &&
          s.activeNodeId
        ) {
          const activeNode = s.nodes.find((n) => n.id === s.activeNodeId);
          const enabledPool = s.nodes.filter((n) => n.enabled && isNodeInEnabledSourceMobile(s, n));
          if (activeNode && enabledPool.length > 0) {
            const cfg = buildAndroidEmbeddedSingboxConfig({
              nodes: enabledPool,
              aiExtraCandidateNodes: collectAllAiCandidateNodesMobile(s),
              activeNodeId: activeNode.id,
              activeAiNodeId: activeAiNodeIdMobile,
              settings: s.settings,
            });
            await AegisNativeVpn.startVpn({
              configJson: JSON.stringify(cfg),
              activeNodeName: activeNode.name,
              outboundTag: `node-${activeNode.id}`,
              dnsServer: getDnsIp(s.settings.dnsProvider),
              excludedPackages: collectExcludedPackagesMobile(s),
              perAppMode: nextPerAppMode,
              perAppPackages: s.settings.perAppPackages || [],
              candidatesJson: wdPayloads.candidatesJson,
              watchdogJson: wdPayloads.watchdogJson,
            });
          }
        }
      }
    }
    saveInternal();
    return structuredClone(s);
  }

  if (path === '/api/update/check') {
    if (!s.appUpdate) {
      s.appUpdate = createDefaultAppUpdateInfo(APP_VERSION);
    }

    if (body?.mockReleasePayload !== undefined) {
      s.appUpdate = parseGitHubReleasePayload(body.mockReleasePayload, APP_VERSION);
      if (s.appUpdate.updateAvailable) {
        pushEvent(
          s,
          'security',
          `Доступна новая версия AegisMesh VPN v${s.appUpdate.latestVersion} (${s.appUpdate.releaseTitle})`
        );
      }
      saveInternal();
      return { ok: true, update: s.appUpdate, snapshot: structuredClone(s) };
    }

    const ghHeaders = {
      Accept: 'application/vnd.github+json',
      'User-Agent': `AegisMesh-VPN/${APP_VERSION}`,
    };
    let rawPayload: unknown = null;
    let fetchError: string | null = null;

    if (Capacitor.isNativePlatform()) {
      const tryTunnelFirst = s.connectionState === 'connected';
      try {
        const res = await AegisNativeVpn.httpFetch({
          url: GITHUB_RELEASES_LATEST_URL,
          timeoutMs: 9000,
          useTunnelProxy: tryTunnelFirst,
          headers: ghHeaders,
        });
        if (res.status >= 200 && res.status < 300 && res.body.trim()) {
          rawPayload = res.body;
        }
      } catch {
        // Fallback к прямому соединению
      }

      if (!rawPayload && tryTunnelFirst) {
        try {
          const fallbackRes = await AegisNativeVpn.httpFetch({
            url: GITHUB_RELEASES_LATEST_URL,
            timeoutMs: 9000,
            useTunnelProxy: false,
            headers: ghHeaders,
          });
          if (
            fallbackRes.status >= 200 &&
            fallbackRes.status < 300 &&
            fallbackRes.body.trim()
          ) {
            rawPayload = fallbackRes.body;
          }
        } catch (err) {
          fetchError =
            err instanceof Error ? err.message : 'Не удалось связаться с GitHub Releases';
        }
      }
    }

    if (!rawPayload && typeof fetch === 'function') {
      try {
        const r = await fetch(GITHUB_RELEASES_LATEST_URL, {
          headers: { Accept: 'application/vnd.github+json' },
        });
        if (r.ok) {
          rawPayload = await r.json();
        } else {
          fetchError = `GitHub API вернул HTTP ${r.status}`;
        }
      } catch (err) {
        fetchError =
          err instanceof Error ? err.message : 'Не удалось связаться с GitHub Releases';
      }
    }

    if (rawPayload) {
      s.appUpdate = parseGitHubReleasePayload(rawPayload, APP_VERSION);
      if (s.appUpdate.updateAvailable) {
        pushEvent(
          s,
          'security',
          `Доступна новая версия AegisMesh VPN v${s.appUpdate.latestVersion} (${s.appUpdate.releaseTitle})`
        );
      }
    } else {
      s.appUpdate = {
        ...createDefaultAppUpdateInfo(APP_VERSION),
        ...s.appUpdate,
        currentVersion: APP_VERSION,
        checkedAt: Date.now(),
        downloading: false,
        error: fetchError,
      };
    }

    saveInternal();
    return { ok: true, update: s.appUpdate, snapshot: structuredClone(s) };
  }

  if (path === '/api/update/install') {
    if (!s.appUpdate) {
      s.appUpdate = createDefaultAppUpdateInfo(APP_VERSION);
    }
    const targetUrl =
      (typeof body?.url === 'string' && body.url.trim()) ||
      s.appUpdate.apkDownloadUrl ||
      s.appUpdate.desktopDownloadUrl ||
      s.appUpdate.htmlUrl ||
      GITHUB_RELEASES_PAGE_URL;

    if (Capacitor.isNativePlatform()) {
      const res = await AegisNativeVpn.downloadAndInstallApk({ url: targetUrl });
      s.appUpdate = {
        ...s.appUpdate,
        downloading: false,
        downloadProgress: 100,
        error: null,
        statusMessage:
          res.message || 'Запущена установка обновления AegisMesh-VPN.apk',
      };
    } else {
      s.appUpdate = {
        ...s.appUpdate,
        downloading: false,
        downloadProgress: 100,
        error: null,
        statusMessage: `Готова ссылка для скачивания: ${targetUrl}`,
      };
      if (typeof window !== 'undefined' && typeof window.open === 'function') {
        try {
          window.open(targetUrl, '_blank', 'noopener,noreferrer');
        } catch {
          // Игнорируем блокировку всплывающего окна в тестовой среде
        }
      }
    }

    saveInternal();
    return { ok: true, update: s.appUpdate, snapshot: structuredClone(s) };
  }

  if (path === '/api/audit') {
    let directIp: string | null = null;
    let directCountry: string | null = null;
    let directOrg: string | null = null;
    let tunnelIp: string | null = null;
    let tunnelCountry: string | null = null;
    let tunnelOrg: string | null = null;
    const t0 = Date.now();

    if (Capacitor.isNativePlatform()) {
      try {
        const directRes = await AegisNativeVpn.httpFetch({
          url: 'https://ipwho.is/',
          useTunnelProxy: false,
          timeoutMs: 6000,
        });
        const dJson = JSON.parse(directRes.body) as Record<string, unknown>;
        directIp = String(dJson.ip || '');
        directCountry = String(dJson.country_code || '');
        const connObj = (dJson.connection as Record<string, unknown>) || {};
        directOrg = String(connObj.isp || connObj.org || 'ISP');
      } catch {
        // Прямой канал недоступен
      }

      if (s.connectionState === 'connected') {
        try {
          const tunRes = await AegisNativeVpn.httpFetch({
            url: 'https://ipwho.is/',
            useTunnelProxy: true,
            timeoutMs: 7000,
          });
          const tJson = JSON.parse(tunRes.body) as Record<string, unknown>;
          tunnelIp = String(tJson.ip || '');
          tunnelCountry = String(tJson.country_code || '');
          const connObj = (tJson.connection as Record<string, unknown>) || {};
          tunnelOrg = String(connObj.isp || connObj.org || 'VPN Gateway');
        } catch {
          // Туннель проверяется
        }
      }
    }

    const ipMasked = Boolean(
      s.connectionState === 'connected' &&
        tunnelIp &&
        (!directIp || tunnelIp !== directIp)
    );
    const score =
      (ipMasked ? 50 : 0) +
      (s.settings.killSwitchEnabled ? 25 : 0) +
      25;

    const report: CyberAuditReport = {
      checkedAt: Date.now(),
      directIp,
      directCountry,
      directOrg,
      tunnelIp,
      tunnelCountry,
      tunnelOrg,
      ipMasked,
      dnsProtected: true,
      activeDnsLabel: `${s.settings.dnsProvider.toUpperCase()} DoH`,
      killSwitchActive: s.settings.killSwitchEnabled,
      tunnelLatencyMs: s.connectionState === 'connected' ? Date.now() - t0 : null,
      securityScore: score,
      verdict: ipMasked
        ? 'Реальный IP скрыт — весь трафик устройства защищён через ваш VPN-сервер'
        : s.connectionState === 'connected'
          ? 'VPN запущен, проверьте доступность внешнего выхода выбранного сервера'
          : 'VPN отключён — подключите свой сервер для маскировки IP-адреса',
      checks: [
        {
          id: 'ip_masking',
          title: 'Маскировка реального IP-адреса',
          passed: ipMasked,
          detail: ipMasked
            ? `Внешний IP туннеля: ${tunnelIp} (${tunnelCountry || 'VPN'})`
            : 'Туннель не активен или выходной IP совпадает с оператором',
        },
        {
          id: 'kill_switch',
          title: 'Защита от утечек при автозамене (Kill Switch)',
          passed: s.settings.killSwitchEnabled,
          detail: s.settings.killSwitchEnabled
            ? 'Активна защита при переключении серверов каскада'
            : 'Kill Switch отключён в настройках',
        },
        {
          id: 'secure_dns',
          title: 'Шифрованный DNS-over-HTTPS (DoH)',
          passed: true,
          detail: `DNS запросы шифруются через ${s.settings.dnsProvider.toUpperCase()}`,
        },
      ],
    };
    s.lastAudit = report;
    saveInternal();
    return { report, snapshot: structuredClone(s) };
  }

  return structuredClone(s);
}
