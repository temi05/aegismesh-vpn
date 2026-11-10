// Общие типы и модели данных для AegisMesh VPN (Десктоп + Мобильный клиент)

export type VpnProtocol =
  | 'vless'
  | 'vmess'
  | 'shadowsocks'
  | 'trojan'
  | 'hysteria2'
  | 'tuic'
  | 'wireguard'
  | 'socks'
  | 'http';

export type TransportType = 'tcp' | 'ws' | 'grpc' | 'httpupgrade' | 'quic' | 'http';

export type TlsSecurity = 'none' | 'tls' | 'reality';

export type NodeHealthStatus =
  | 'idle'
  | 'active'
  | 'standby'
  | 'testing'
  | 'degraded'
  | 'down'
  | 'quarantined';

export interface VpnNode {
  id: string;
  name: string;
  protocol: VpnProtocol;
  server: string;
  port: number;
  enabled: boolean;
  priority: number; // Порядок приоритета для очереди автозамены (1, 2, 3...)
  subscriptionId?: string;
  providerName?: string; // Название VPN-сервиса / подписки / внешнего клиента
  isExternalClientBridge?: boolean; // Локальный мост к стороннему VPN-клиенту (Happ, v2rayNG, Clash, ByeDPI и др.)
  externalPackageNames?: string[]; // Android packageName стороннего клиента для исключения из петли TUN
  countryHint?: string;
  isTestStand?: boolean; // Флаг встроенного локального узла для тестирования автозамены
  rawUri?: string;

  // Криптографические и протокольные параметры
  uuid?: string;
  password?: string;
  username?: string;
  method?: string;
  alterId?: number;
  flow?: string;

  // Транспортный уровень
  transport?: TransportType;
  wsPath?: string;
  wsHost?: string;
  grpcServiceName?: string;

  // TLS / XTLS-Reality параметры
  tls?: TlsSecurity;
  sni?: string;
  alpn?: string[];
  fingerprint?: string;
  allowInsecure?: boolean;
  realityPublicKey?: string;
  realityShortId?: string;

  // Hysteria2 / TUIC параметры
  mport?: string;
  obfsType?: string;
  obfsPassword?: string;
  upMbps?: number;
  downMbps?: number;
  congestionControl?: string;
  udpRelayMode?: string;

  // WireGuard параметры
  wgPrivateKey?: string;
  wgPublicKey?: string;
  wgPreSharedKey?: string;
  wgLocalAddress?: string[];
  wgMtu?: number;
  wgReserved?: number[];

  // Живая телеметрия состояния
  status: NodeHealthStatus;
  latencyMs: number | null;
  lastCheckedAt: number | null;
  consecutiveFailures: number;
  quarantinedUntil: number | null;
  unavailableReason?: string | null;
  lastError?: string;
  // Метрики Умной Автозамены v3 (EMA-пинг, джиттер, стабильность, скорость, Smart Score 0-100)
  emaLatencyMs?: number | null;
  jitterMs?: number | null;
  successRate?: number;
  measuredSpeedKbps?: number | null;
  smartScore?: number | null;
  // Метрики Умного шлюза для Нейросетей v3.1 (Gemini, ChatGPT, Grok)
  aiStatus?: NodeAiCompatStatus;
  aiExitCountry?: string | null;
  aiScore?: number | null;
  aiGeminiOk?: boolean;
  aiChatgptOk?: boolean;
  aiGrokOk?: boolean;
  aiBlockReason?: string | null;
  aiCheckedAt?: number | null;
  // Раздельная сетевая память v3.4 (Wi-Fi vs Мобильный LTE/4G/5G)
  wifiScore?: number | null;
  cellularScore?: number | null;
  wifiEmaLatencyMs?: number | null;
  cellularEmaLatencyMs?: number | null;
  lastSuccessNetwork?: PhysicalNetworkProfile | null;
  quarantinedOnNetwork?: PhysicalNetworkProfile | null;
}

export type PhysicalNetworkProfile = 'wifi' | 'cellular' | 'ethernet' | 'unknown';

export type AiServicePresetId = 'gemini' | 'chatgpt' | 'grok' | 'claude_other';

export type AiRoutingMode = 'parallel_ai_tunnel' | 'strict_ai_only';

export type NodeAiCompatStatus = 'unknown' | 'checking' | 'ok' | 'blocked';

export type PerAppVpnMode = 'all' | 'exclude_selected' | 'only_selected';

export interface InstalledUserApp {
  packageName: string;
  appName: string;
  categoryHint?: 'bank_gov' | 'social_media' | 'video_music' | 'browser' | 'other';
}

export type FailoverMode = 'smart_fastest' | 'strict_cascade' | 'cascade_recovery';

export type DnsProviderId = 'cloudflare' | 'quad9' | 'adguard' | 'google' | 'custom';

export type ConnectionMode = 'system_proxy' | 'proxy_only' | 'tun';

export interface AppSettings {
  failoverMode: FailoverMode;
  healthCheckIntervalSec: number;
  maxLatencyThresholdMs: number;
  failureThreshold: number;
  quarantineDurationSec: number;
  killSwitchEnabled: boolean;
  connectionMode: ConnectionMode;
  localProxyPort: number;
  allowLanGateway: boolean;
  dnsProvider: DnsProviderId;
  customDohUrl: string;
  blockAdsAndTrackers: boolean;
  splitTunnelingEnabled: boolean;
  bypassDomains: string[];
  bypassPrivateLan: boolean;
  // Параметры AegisMesh VPN v3.0 (Per-App VPN, автообновление подписок, контроль скорости и умный гистерезис)
  perAppMode?: PerAppVpnMode;
  perAppPackages?: string[];
  autoRefreshSubscriptions?: boolean;
  defaultAutoUpdateHours?: number;
  speedFailoverEnabled?: boolean;
  minThroughputKbps?: number;
  zombieCheckEnabled?: boolean;
  antiFlapEnabled?: boolean;
  // Параметры AegisMesh VPN v3.1 (Умный шлюз для Нейросетей: Gemini, ChatGPT, Grok)
  aiRoutingEnabled?: boolean;
  aiRoutingMode?: AiRoutingMode;
  aiServices?: AiServicePresetId[];
  aiIncludeGoogleAccountSession?: boolean;
  aiIncludeXForGrok?: boolean;
  aiCustomDomains?: string[];
  preferredAiNodeId?: string | null;
  // Параметры AegisMesh VPN v3.4 (Бесшовный роуминг Wi-Fi ⇄ LTE, память лучших серверов по сетям и адаптивный MTU)
  seamlessRoamingEnabled?: boolean;
  networkProfileAutoSwitchEnabled?: boolean;
  bestWifiNodeId?: string | null;
  bestCellularNodeId?: string | null;
  adaptiveMobileMtu?: boolean;
}

export interface SubscriptionSource {
  id: string;
  name: string;
  url: string;
  lastUpdatedAt: number | null;
  nodeCount: number;
  autoUpdateHours: number;
  // Параметры Мульти-VPN Автозамены и метаданные провайдера (v2)
  enabledInFailover?: boolean; // Галочка [✓] Участвует в автозамене
  priority?: number; // Приоритет целого VPN-сервиса (1 -> 2 -> 3)
  usedBytes?: number | null;
  totalBytes?: number | null;
  expireUnix?: number | null;
  supportUrl?: string;
  announceText?: string;
  filteredDummyCount?: number;
  compatProfile?: string;
}

export interface ExternalVpnClientBridge {
  id: string;
  clientName: string; // Например: "Happ / v2rayNG", "Throne / NekoBox", "Clash / FlClash", "ByeDPI"
  protocol: 'socks' | 'http';
  host: string; // 127.0.0.1
  port: number; // 10808, 2080, 7890, 12334, 1080, 9050
  androidPackages: string[];
  detectedRunning: boolean;
  enabledInFailover: boolean; // Галочка [✓] Участвует в автозамене
  latencyMs: number | null;
  isCustom?: boolean;
}

export interface InstalledAndroidVpnApp {
  packageName: string;
  appName: string;
  isEmergencyFallback: boolean;
}

export interface LiveTunnelTelemetry {
  verified: boolean; // Прошёл ли реальный End-to-End запрос сквозь VPN-туннель
  verifyingStep?: string;
  exitIp: string | null;
  exitCountry: string | null;
  rxSpeedBps: number; // Входящая скорость (байт/сек)
  txSpeedBps: number; // Исходящая скорость (байт/сек)
  totalRxBytes: number;
  totalTxBytes: number;
  activeProviderLabel?: string;
  lastErrorReason?: string | null;
  lastFailoverBanner?: {
    timestamp: number;
    fromName: string;
    toName: string;
    reason: string;
  } | null;
  // Телеметрия AegisMesh VPN v3.0
  nativeWatchdogActive?: boolean;
  measuredBandwidthKbps?: number | null;
  smartScore?: number | null;
  jitterMs?: number | null;
  lastAutoRefreshAt?: number | null;
  // Телеметрия Умного шлюза для Нейросетей v3.1
  activeAiNodeId?: string | null;
  activeAiNodeName?: string | null;
  activeAiCountry?: string | null;
  aiProbeInProgress?: boolean;
  aiCompatibleCount?: number;
  // Телеметрия Бесшовного роуминга сетей v3.4 (Wi-Fi ⇄ LTE)
  physicalNetworkType?: PhysicalNetworkProfile;
  roamingHandoverCount?: number;
  lastHandoverAt?: number | null;
  activeMtu?: number;
  bestWifiNodeName?: string | null;
  bestCellularNodeName?: string | null;
}

export type FailoverEventType =
  | 'connect'
  | 'disconnect'
  | 'failover_switch'
  | 'killswitch_engaged'
  | 'node_recovered'
  | 'primary_restored'
  | 'health_warning'
  | 'security';

export interface FailoverEvent {
  id: string;
  timestamp: number;
  type: FailoverEventType;
  fromNodeName?: string;
  toNodeName?: string;
  reason: string;
  latencyMs?: number | null;
}

export interface AuditCheckItem {
  id: string;
  title: string;
  passed: boolean;
  detail: string;
}

export interface CyberAuditReport {
  checkedAt: number;
  directIp: string | null;
  directCountry: string | null;
  directOrg: string | null;
  tunnelIp: string | null;
  tunnelCountry: string | null;
  tunnelOrg: string | null;
  ipMasked: boolean;
  dnsProtected: boolean;
  activeDnsLabel: string;
  killSwitchActive: boolean;
  tunnelLatencyMs: number | null;
  securityScore: number;
  verdict: string;
  checks: AuditCheckItem[];
}

export interface LatencySample {
  timestamp: number;
  latencyMs: number | null;
  nodeName: string;
  failed: boolean;
}

export type EngineConnectionState =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'switching'
  | 'killswitch_locked'
  | 'error';

export interface MobileAccessInfo {
  lanIp: string;
  remoteWebUrl: string;
  lanProxyAddress: string;
  accessToken: string;
  singboxProfileJson: string;
  singboxDeepLink: string;
  nodeCount: number;
}

export interface CoreBinaryStatus {
  installed: boolean;
  version: string | null;
  binaryPath: string;
  downloading: boolean;
  downloadProgress: number;
  engineDriver: 'sing-box' | 'native-guard' | 'hybrid';
  isAdmin: boolean;
  error?: string;
}

export interface AppUpdateInfo {
  currentVersion: string;
  latestVersion: string;
  updateAvailable: boolean;
  releaseTag: string;
  releaseTitle: string;
  releaseNotes: string;
  publishedAt: string | null;
  htmlUrl: string;
  apkDownloadUrl: string | null;
  apkSizeBytes: number | null;
  desktopDownloadUrl: string | null;
  checkedAt: number;
  downloading?: boolean;
  downloadProgress?: number;
  statusMessage?: string | null;
  error?: string | null;
}

export interface VpnStateSnapshot {
  connectionState: EngineConnectionState;
  activeNodeId: string | null;
  connectedSince: number | null;
  failoverSwitchCount: number;
  killSwitchBlocking: boolean;
  vaultLocked: boolean;
  vaultHasPin: boolean;
  nodes: VpnNode[];
  subscriptions: SubscriptionSource[];
  settings: AppSettings;
  events: FailoverEvent[];
  latencyHistory: LatencySample[];
  coreStatus: CoreBinaryStatus;
  lastAudit: CyberAuditReport | null;
  testStandRunning: boolean;
  // Поля AegisMesh VPN v2 (Мульти-VPN источники, внешние клиенты и честная живая телеметрия)
  manualGroupEnabledInFailover?: boolean;
  externalClients?: ExternalVpnClientBridge[];
  installedVpnApps?: InstalledAndroidVpnApp[];
  installedUserApps?: InstalledUserApp[];
  emergencyAppPackage?: string | null;
  telemetry?: LiveTunnelTelemetry;
  appUpdate?: AppUpdateInfo | null;
}

export interface ParseImportResult {
  nodes: VpnNode[];
  errors: string[];
  infoMessages?: string[];
  filteredDummyCount?: number;
}
