// Главный движок AegisMesh VPN: объединение сейфа, GuardProxy, sing-box, Auto-Failover и диагностики
import crypto from 'node:crypto';
import EventEmitter from 'node:events';
import type {
  AppSettings,
  AppUpdateInfo,
  CyberAuditReport,
  EngineConnectionState,
  ExternalVpnClientBridge,
  FailoverEvent,
  FailoverEventType,
  LatencySample,
  LiveTunnelTelemetry,
  MobileAccessInfo,
  ParseImportResult,
  PhysicalNetworkProfile,
  SubscriptionSource,
  VpnNode,
  VpnStateSnapshot,
} from '../shared/types';
import {
  buildAiScanCandidateQueue,
  DEFAULT_AI_SERVICES,
  evaluateAiProbeResult,
  inferCountryHintFromNode,
  parseGoogleSwJsCountry,
  parseGoogleWizHtmlSignals,
  pickBestStickyAiNode,
  pickNextAiNodeForManualCycle,
} from '../shared/aiRouting';
import {
  buildDiversifiedFailoverBatch,
  canTriggerSelfHealingRefresh,
  isSubscriptionDueForAutoRefresh,
  isUdpBasedVpnProtocol,
  markNodeTemporarilyUnavailable,
  rankCandidatesSmart,
  releaseExpiredUnavailableNodes,
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
import { parseVpnImportPayload } from '../shared/uriParser';
import {
  APP_VERSION,
  createDefaultAppUpdateInfo,
  GITHUB_RELEASES_LATEST_URL,
  GITHUB_RELEASES_PAGE_URL,
  parseGitHubReleasePayload,
} from '../shared/versionUpdater';
import { BinaryManager } from './binaryManager';
import { runCyberSecurityAudit } from './cyberDiagnostics';
import {
  findRecoveredPrimaryNode,
  releaseExpiredQuarantines,
  selectNextFailoverNode,
} from './failoverWatchdog';
import { GuardProxy } from './guardProxy';
import { MobileBridgeManager } from './mobileBridge';
import {
  fetchDirectWithHeaders,
  fetchViaUpstream,
  measureTcpLatency,
  scanLocalLoopbackPorts,
  type UpstreamEndpoint,
} from './proxyConnector';
import { DEFAULT_APP_SETTINGS, SecureVault } from './secureVault';
import { SingboxProcessRunner } from './singboxRunner';
import { TestStandCluster } from './testStandCluster';
import { WindowsSystemProxy } from './windowsProxy';

export class VpnEngine extends EventEmitter {
  private readonly vault: SecureVault;
  private readonly binaryManager: BinaryManager;
  private readonly singboxRunner: SingboxProcessRunner;
  private readonly guardProxy: GuardProxy;
  private readonly winProxy: WindowsSystemProxy;
  private readonly testCluster: TestStandCluster;
  private readonly mobileBridge: MobileBridgeManager;

  private nodes: VpnNode[] = [];
  private subscriptions: SubscriptionSource[] = [];
  private settings: AppSettings = { ...DEFAULT_APP_SETTINGS };
  private connectionState: EngineConnectionState = 'disconnected';
  private activeNodeId: string | null = null;
  private activeAiNodeId: string | null = null;
  private aiScanBusy = false;
  private connectedSince: number | null = null;
  private failoverSwitchCount = 0;
  private killSwitchBlocking = false;
  private events: FailoverEvent[] = [];
  private latencyHistory: LatencySample[] = [];
  private lastAudit: CyberAuditReport | null = null;
  private watchdogTimer: NodeJS.Timeout | null = null;
  private healthCheckTickCounter = 0;
  private autoRefreshTimer: NodeJS.Timeout | null = null;
  private emergencyRefreshMap = new Map<string, number>();
  private switchingInProgress = false;
  private apiServerPort = 18940;
  private manualGroupEnabledInFailover = true;
  private externalClients: ExternalVpnClientBridge[] = createDefaultExternalClientBridges();
  private deviceHwid: string = generateValidHwid();
  private currentNetworkType: PhysicalNetworkProfile = 'wifi';
  private appUpdate: AppUpdateInfo | null = createDefaultAppUpdateInfo(APP_VERSION);
  private telemetry: LiveTunnelTelemetry = {
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

  constructor(storageRootDir: string) {
    super();
    this.vault = new SecureVault(storageRootDir);
    this.binaryManager = new BinaryManager(storageRootDir);
    this.singboxRunner = new SingboxProcessRunner(storageRootDir);
    this.winProxy = new WindowsSystemProxy();
    this.testCluster = new TestStandCluster();
    this.mobileBridge = new MobileBridgeManager();

    this.guardProxy = new GuardProxy({
      onUpstreamFailure: (errMsg) => {
        if (this.connectionState !== 'connected' || !this.activeNodeId || this.switchingInProgress) {
          return;
        }
        const active = this.nodes.find((n) => n.id === this.activeNodeId);
        if (!active) return;
        if (active.isTestStand && !this.testCluster.isNodeOnline(active.id)) {
          void this.handleActiveNodeFailure(`Сбой соединения на прокси-шлюзе: ${errMsg}`);
          return;
        }
        void this.probeSingleNode(active).then((rtt) => {
          if (rtt === null && this.connectionState === 'connected' && this.activeNodeId === active.id) {
            void this.handleActiveNodeFailure(`Сбой соединения на прокси-шлюзе: ${errMsg}`);
          }
        });
      },
    });

    this.loadFromVaultSafe();
    this.startAutoRefreshScheduler();
  }

  public setApiServerPort(port: number): void {
    this.apiServerPort = port;
  }

  public validateMobileToken(token?: string | null): boolean {
    return this.mobileBridge.validateToken(token);
  }

  private mergeExternalBridges(saved?: ExternalVpnClientBridge[]): ExternalVpnClientBridge[] {
    const defaults = createDefaultExternalClientBridges();
    if (!Array.isArray(saved) || saved.length === 0) return defaults;
    const savedMap = new Map(saved.map((b) => [b.id, b]));
    const merged = defaults.map((def) => {
      const prev = savedMap.get(def.id);
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

  private hydrateProviderNames(): void {
    const subMap = new Map(this.subscriptions.map((s) => [s.id, s.name]));
    for (const n of this.nodes) {
      if (n.isExternalClientBridge || n.isTestStand) continue;
      if (n.subscriptionId && subMap.has(n.subscriptionId)) {
        n.providerName = subMap.get(n.subscriptionId);
      } else if (!n.providerName) {
        n.providerName = 'Личные ключи';
      }
    }
  }

  private loadFromVaultSafe(): void {
    try {
      const data = this.vault.load();
      this.nodes = data.nodes
        .filter((n) => !n.isExternalClientBridge && !isSyntheticDummyNode(n))
        .map((n) => ({
          ...n,
          status: 'standby' as const,
          quarantinedUntil: null,
          consecutiveFailures: 0,
          lastError: undefined,
        }))
        .sort((a, b) => a.priority - b.priority);
      this.subscriptions = data.subscriptions.map((s, idx) => ({
        ...s,
        enabledInFailover: s.enabledInFailover !== false,
        priority: s.priority ?? idx + 1,
      }));
      this.settings = data.settings;
      this.manualGroupEnabledInFailover = data.manualGroupEnabledInFailover !== false;
      this.externalClients = this.mergeExternalBridges(data.externalClients);
      if (data.deviceHwid && data.deviceHwid.length >= 16) {
        this.deviceHwid = data.deviceHwid;
      } else {
        this.deviceHwid = generateValidHwid();
      }
      this.hydrateProviderNames();
    } catch {
      // Если сейф закрыт PIN-кодом, оставляем список пустым до ввода PIN
      this.nodes = [];
      this.subscriptions = [];
      this.settings = { ...DEFAULT_APP_SETTINGS };
    }
  }

  private saveToVaultSafe(): void {
    if (this.vault.isLocked()) return;
    this.normalizePriorities();
    this.vault.save({
      nodes: this.nodes.filter((n) => !n.isExternalClientBridge && !isSyntheticDummyNode(n)),
      subscriptions: this.subscriptions,
      settings: this.settings,
      manualGroupEnabledInFailover: this.manualGroupEnabledInFailover,
      externalClients: this.externalClients,
      deviceHwid: this.deviceHwid,
    });
  }

  private normalizePriorities(): void {
    const sorted = [...this.nodes].sort((a, b) => a.priority - b.priority);
    sorted.forEach((n, idx) => {
      n.priority = idx + 1;
    });
    this.nodes = sorted;
  }

  private emitState(): void {
    this.emit('state', this.getSnapshot());
  }

  private recordEvent(
    type: FailoverEventType,
    reason: string,
    fromNodeName?: string,
    toNodeName?: string,
    latencyMs?: number | null
  ): void {
    const evt: FailoverEvent = {
      id: `evt_${Date.now()}_${crypto.randomBytes(2).toString('hex')}`,
      timestamp: Date.now(),
      type,
      fromNodeName,
      toNodeName,
      reason,
      latencyMs,
    };
    this.events = [evt, ...this.events].slice(0, 80);
  }

  public getSnapshot(): VpnStateSnapshot {
    releaseExpiredUnavailableNodes(this.nodes);
    this.syncExternalBridgeNodes();
    return {
      connectionState: this.connectionState,
      activeNodeId: this.activeNodeId,
      connectedSince: this.connectedSince,
      failoverSwitchCount: this.failoverSwitchCount,
      killSwitchBlocking: this.killSwitchBlocking,
      vaultLocked: this.vault.isLocked(),
      vaultHasPin: this.vault.hasPin(),
      nodes: this.nodes.map((n) => ({ ...n })),
      subscriptions: this.subscriptions.map((s) => ({ ...s })),
      settings: {
        ...this.settings,
        bypassDomains: [...this.settings.bypassDomains],
      },
      events: this.events.slice(0, 50),
      latencyHistory: this.latencyHistory.slice(-40),
      coreStatus: this.binaryManager.getStatus(),
      lastAudit: this.lastAudit,
      testStandRunning: this.testCluster.isRunning(),
      manualGroupEnabledInFailover: this.manualGroupEnabledInFailover,
      externalClients: this.externalClients.map((b) => ({ ...b })),
      installedVpnApps: [],
      emergencyAppPackage: null,
      telemetry: {
        ...this.telemetry,
        physicalNetworkType: this.telemetry.physicalNetworkType || this.currentNetworkType || 'wifi',
        activeMtu: this.telemetry.activeMtu || 1400,
        bestWifiNodeName:
          this.nodes.find((n) => n.id === this.settings.bestWifiNodeId)?.name || null,
        bestCellularNodeName:
          this.nodes.find((n) => n.id === this.settings.bestCellularNodeId)?.name || null,
        lastFailoverBanner: this.telemetry.lastFailoverBanner
          ? { ...this.telemetry.lastFailoverBanner }
          : null,
      },
      appUpdate: this.appUpdate ? { ...this.appUpdate } : null,
    };
  }

  private syncExternalBridgeNodes(): void {
    const activeBridges = this.externalClients.filter(
      (b) => b.enabledInFailover && b.detectedRunning
    );
    const activeIds = new Set(activeBridges.map((b) => `bridge_${b.id}`));
    this.nodes = this.nodes.filter(
      (n) => !n.isExternalClientBridge || activeIds.has(n.id)
    );
    for (const b of activeBridges) {
      const bridgeNodeId = `bridge_${b.id}`;
      const existing = this.nodes.find((n) => n.id === bridgeNodeId);
      if (existing) {
        existing.latencyMs = b.latencyMs;
        existing.enabled = true;
        if (existing.id !== this.activeNodeId && existing.status === 'down') {
          existing.status = 'standby';
        }
      } else {
        this.nodes.push(externalBridgeToVpnNode(b, this.nodes.length + 1));
      }
    }
    this.normalizePriorities();
  }

  private isNodeInEnabledSource(node: VpnNode): boolean {
    if (node.isTestStand) return true;
    if (node.isExternalClientBridge) {
      const b = this.externalClients.find((x) => `bridge_${x.id}` === node.id);
      return Boolean(b && b.enabledInFailover && b.detectedRunning);
    }
    if (node.subscriptionId) {
      const sub = this.subscriptions.find((s) => s.id === node.subscriptionId);
      return sub ? sub.enabledInFailover !== false : true;
    }
    return this.manualGroupEnabledInFailover !== false;
  }

  // Проверка, нужен ли для узла бинарник sing-box (или достаточно нативного коннектора GuardProxy)
  private requiresSingboxBinary(node: VpnNode): boolean {
    if (node.isTestStand) return false;
    if (node.protocol === 'http' || node.protocol === 'socks') return false;
    return true;
  }

  private resolveUpstreamForNode(node: VpnNode): UpstreamEndpoint {
    if (this.requiresSingboxBinary(node) && this.singboxRunner.isRunning()) {
      return {
        protocol: 'http',
        host: '127.0.0.1',
        port: this.singboxRunner.getInternalMixedPort(),
      };
    }
    return {
      protocol: node.protocol === 'socks' ? 'socks' : 'http',
      host: node.server,
      port: node.port,
      username: node.username,
      password: node.password,
    };
  }

  public async connect(preferredNodeId?: string): Promise<VpnStateSnapshot> {
    if (this.vault.isLocked()) {
      throw new Error('Разблокируйте сейф PIN-кодом перед подключением');
    }

    await this.scanExternalClientsSilent();
    this.syncExternalBridgeNodes();
    releaseExpiredQuarantines(this.nodes);
    const enabled = this.nodes
      .filter((n) => n.enabled && this.isNodeInEnabledSource(n))
      .sort((a, b) => a.priority - b.priority);

    if (enabled.length === 0) {
      throw new Error(
        this.nodes.length > 0
          ? 'Включите галочку [✓] хотя бы у одного VPN-сервиса или запустите внешний клиент для автозамены'
          : 'Добавьте свои VPN-ключи, подписку или запустите внешний VPN-клиент во вкладке «Мои VPN»'
      );
    }

    const orderedCandidates: VpnNode[] = [];
    if (preferredNodeId) {
      const pref = enabled.find((n) => n.id === preferredNodeId);
      if (pref) orderedCandidates.push(pref);
    }
    const best = selectNextFailoverNode({
      nodes: enabled,
      mode: this.settings.failoverMode,
      maxLatencyMs: this.settings.maxLatencyThresholdMs,
    }).selectedNode;
    if (best && !orderedCandidates.some((c) => c.id === best.id)) {
      orderedCandidates.push(best);
    }
    for (const c of enabled) {
      if (!orderedCandidates.some((x) => x.id === c.id)) {
        orderedCandidates.push(c);
      }
    }

    this.connectionState = 'connecting';
    this.telemetry.verified = false;
    this.telemetry.lastErrorReason = null;
    this.telemetry.verifyingStep = 'Запуск туннеля и сквозная проверка связи...';
    this.emitState();

    try {
      await this.guardProxy.start(
        this.settings.localProxyPort,
        this.settings.allowLanGateway
      );

      // Provider Circuit Breaker: если 2 сервера одной подписки подряд мертвы — сразу прыгаем к следующему VPN-сервису / клиенту!
      const providerFails = new Map<string, number>();
      let verifiedNode: VpnNode | null = null;
      const firstTriedName = orderedCandidates[0]?.name;

      for (const candidate of orderedCandidates) {
        const groupKey = candidate.subscriptionId || (candidate.isExternalClientBridge ? candidate.id : 'manual');
        if (candidate.subscriptionId && (providerFails.get(groupKey) || 0) >= 2) {
          continue;
        }
        this.telemetry.verifyingStep = `Проверка «${candidate.name}»...`;
        const rtt = await this.probeSingleNode(candidate);
        if (rtt !== null) {
          await this.activateNodeInternal(candidate, true);
          verifiedNode = candidate;
          break;
        } else {
          candidate.status = 'down';
          providerFails.set(groupKey, (providerFails.get(groupKey) || 0) + 1);
        }
      }

      if (!verifiedNode) {
        await this.singboxRunner.stop();
        await this.guardProxy.stop();
        this.winProxy.disable();
        const errText =
          'Ни один из выбранных VPN-серверов не ответил на проверку связи. Проверьте подписку или запустите резервный VPN-клиент.';
        this.connectionState = 'error';
        this.telemetry.verified = false;
        this.telemetry.verifyingStep = undefined;
        this.telemetry.lastErrorReason = errText;
        this.recordEvent('security', errText);
        this.emitState();
        throw new Error(errText);
      }

      if (this.settings.connectionMode === 'system_proxy') {
        this.winProxy.enable(
          '127.0.0.1',
          this.guardProxy.getBoundPort(),
          this.settings.splitTunnelingEnabled ? this.settings.bypassDomains : []
        );
      }

      this.connectedSince = Date.now();
      this.connectionState = 'connected';
      this.telemetry.verified = true;
      this.telemetry.verifyingStep = undefined;
      this.telemetry.activeProviderLabel = verifiedNode.providerName || 'Мои VPN';
      this.telemetry.lastErrorReason = null;

      if (firstTriedName && firstTriedName !== verifiedNode.name) {
        this.failoverSwitchCount += 1;
        this.telemetry.lastFailoverBanner = {
          timestamp: Date.now(),
          fromName: firstTriedName,
          toName: verifiedNode.name,
          reason: 'Основной сервер не ответил — сработала мульти-VPN автозамена',
        };
      }

      this.recordEvent(
        'connect',
        `Защищённый туннель проверен и активирован через #${verifiedNode.priority} ${verifiedNode.name}`,
        undefined,
        verifiedNode.name,
        verifiedNode.latencyMs
      );
      void this.refreshTunnelExitIpAsync();
      if (this.settings.aiRoutingEnabled !== false) {
        void this.scanAiCompatibility().catch(() => {});
      }
      this.startWatchdogLoop();
      this.emitState();
      return this.getSnapshot();
    } catch (err) {
      this.connectionState = 'error';
      const msg = err instanceof Error ? err.message : 'Ошибка подключения';
      this.telemetry.verified = false;
      this.telemetry.verifyingStep = undefined;
      this.telemetry.lastErrorReason = msg;
      this.recordEvent('security', `Ошибка запуска туннеля: ${msg}`);
      this.emitState();
      throw err;
    }
  }

  private async activateNodeInternal(node: VpnNode, initialConnect = false): Promise<void> {
    // 1. На время переключения включаем Kill Switch на GuardProxy (0 утечек трафика!)
    if (this.settings.killSwitchEnabled && !initialConnect) {
      this.killSwitchBlocking = true;
      this.guardProxy.setRoutingPolicy({
        upstream: null,
        killSwitchBlocking: true,
        splitTunnelingEnabled: this.settings.splitTunnelingEnabled,
        bypassDomains: this.settings.bypassDomains,
        bypassPrivateLan: this.settings.bypassPrivateLan,
      });
    }

    // 2. Если узел требует sing-box (VLESS/VMess/SS/Trojan/Hysteria2/TUIC/WG)
    if (this.requiresSingboxBinary(node)) {
      if (!this.binaryManager.isInstalled()) {
        await this.binaryManager.ensureInstalled(() => this.emitState());
      }
      if (!this.binaryManager.isInstalled()) {
        throw new Error(
          'Для протокола ' +
            node.protocol.toUpperCase() +
            ' требуется ядро sing-box (нажмите «Скачать ядро sing-box»)'
        );
      }

      const handleSingboxCrash = (crashReason: string) => {
        this.recordEvent('health_warning', crashReason, node.name);
        if (this.connectionState === 'connected') {
          void this.handleActiveNodeFailure(crashReason);
        }
      };

      if (this.singboxRunner.isRunning()) {
        const switched = await this.singboxRunner.switchActiveOutbound(node.id);
        if (!switched) {
          await this.singboxRunner.start({
            binaryPath: this.binaryManager.getBinaryPath(),
            nodes: this.nodes,
            activeNodeId: node.id,
            activeAiNodeId: this.activeAiNodeId,
            settings: this.settings,
            enableTun:
              this.settings.connectionMode === 'tun' &&
              this.binaryManager.getStatus().isAdmin,
            onCrash: handleSingboxCrash,
          });
        }
      } else {
        await this.singboxRunner.start({
          binaryPath: this.binaryManager.getBinaryPath(),
          nodes: this.nodes,
          activeNodeId: node.id,
          activeAiNodeId: this.activeAiNodeId,
          settings: this.settings,
          enableTun:
            this.settings.connectionMode === 'tun' &&
            this.binaryManager.getStatus().isAdmin,
          onCrash: handleSingboxCrash,
        });
      }
    }

    // 3. Обновляем статусы узлов и открываем маршрут на GuardProxy
    for (const item of this.nodes) {
      if (item.id === node.id) {
        item.status = 'active';
        item.consecutiveFailures = 0;
        item.quarantinedUntil = null;
      } else if (item.status === 'active') {
        item.status = 'standby';
      }
    }

    this.activeNodeId = node.id;
    this.killSwitchBlocking = false;
    this.guardProxy.setRoutingPolicy({
      upstream: this.resolveUpstreamForNode(node),
      killSwitchBlocking: false,
      splitTunnelingEnabled: this.settings.splitTunnelingEnabled,
      bypassDomains: this.settings.bypassDomains,
      bypassPrivateLan: this.settings.bypassPrivateLan,
    });
    await this.syncStickyAiGateway();
  }

  public async disconnect(): Promise<VpnStateSnapshot> {
    this.stopWatchdogLoop();
    this.winProxy.disable();
    await this.singboxRunner.stop();
    await this.guardProxy.stop();

    const prevNode = this.nodes.find((n) => n.id === this.activeNodeId);
    for (const n of this.nodes) {
      if (n.status === 'active') n.status = 'standby';
    }

    this.activeNodeId = null;
    this.activeAiNodeId = null;
    this.connectedSince = null;
    this.killSwitchBlocking = false;
    this.connectionState = 'disconnected';
    this.telemetry = {
      ...this.telemetry,
      verified: false,
      verifyingStep: undefined,
      exitIp: null,
      exitCountry: null,
      activeAiNodeId: null,
      activeAiNodeName: null,
      activeAiCountry: null,
      rxSpeedBps: 0,
      txSpeedBps: 0,
      activeProviderLabel: undefined,
      lastErrorReason: null,
    };

    if (prevNode) {
      this.recordEvent(
        'disconnect',
        `Туннель отключён пользователем (был активен ${prevNode.name})`,
        prevNode.name
      );
    }
    this.emitState();
    return this.getSnapshot();
  }

  private startWatchdogLoop(): void {
    this.stopWatchdogLoop();
    const intervalMs = Math.max(2, this.settings.healthCheckIntervalSec) * 1000;
    this.watchdogTimer = setInterval(() => {
      void this.runHealthCheckCycle();
    }, intervalMs);
  }

  private stopWatchdogLoop(): void {
    if (this.watchdogTimer) {
      clearInterval(this.watchdogTimer);
      this.watchdogTimer = null;
    }
  }

  private getProbeTargetUrl(): string {
    return (
      this.testCluster.getHealthCheckUrl() ||
      'http://cp.cloudflare.com/generate_204'
    );
  }

  // Живая проверка конкретного узла сквозь туннель (включая QUIC/UDP Hysteria2/TUIC/WG через Clash API) или TCP-рукопожатие
  public async probeSingleNode(node: VpnNode): Promise<number | null> {
    const netProfile: PhysicalNetworkProfile =
      this.currentNetworkType === 'cellular' ? 'cellular' : 'wifi';
    try {
      if (!this.requiresSingboxBinary(node)) {
        const upstream: UpstreamEndpoint = {
          protocol: node.protocol === 'socks' ? 'socks' : 'http',
          host: node.server,
          port: node.port,
          username: node.username,
          password: node.password,
        };
        const res = await fetchViaUpstream(this.getProbeTargetUrl(), upstream, 3500);
        if (res.statusCode >= 200 && res.statusCode < 400) {
          const rtt = Math.max(1, res.elapsedMs);
          updateNodeSmartMetrics(node, rtt, undefined, netProfile);
          node.lastCheckedAt = Date.now();
          node.consecutiveFailures = 0;
          node.quarantinedUntil = null;
          if (node.id !== this.activeNodeId) node.status = 'standby';
          node.lastError = undefined;
          return node.latencyMs;
        }
        throw new Error(`HTTP ${res.statusCode}`);
      }

      // 1. Если sing-box запущен — проверяем любой протокол (включая UDP/QUIC Hysteria2, TUIC и WireGuard) через Clash API
      if (this.singboxRunner.isRunning() && node.enabled && this.isNodeInEnabledSource(node)) {
        const clashRtt = await this.singboxRunner.probeOutboundDelay(node.id, 3500);
        if (clashRtt !== null) {
          updateNodeSmartMetrics(node, clashRtt, undefined, netProfile);
          node.lastCheckedAt = Date.now();
          node.consecutiveFailures = 0;
          node.quarantinedUntil = null;
          if (node.id !== this.activeNodeId) node.status = 'standby';
          node.lastError = undefined;
          return clashRtt;
        }
        throw new Error('Временный таймаут сквозной проверки туннеля');
      }

      // 2. Если VPN остановлен и протокол чисто UDP/QUIC (Hysteria2 [HY2] / TUIC / WireGuard):
      // не проверяем TCP-сокетом, чтобы не получить ложный отказ на UDP-порту!
      if (isUdpBasedVpnProtocol(node.protocol)) {
        node.lastCheckedAt = Date.now();
        node.consecutiveFailures = 0;
        node.quarantinedUntil = null;
        node.lastError = undefined;
        if (node.id !== this.activeNodeId) node.status = 'standby';
        return node.latencyMs;
      }

      // 3. Для TCP-протоколов замеряем живой TCP RTT до сервера и обновляем Smart Score
      const rtt = await measureTcpLatency(node.server, node.port, 3500);
      updateNodeSmartMetrics(node, rtt, undefined, netProfile);
      node.lastCheckedAt = Date.now();
      node.consecutiveFailures = 0;
      node.quarantinedUntil = null;
      if (node.id !== this.activeNodeId) node.status = 'standby';
      node.lastError = undefined;
      return rtt;
    } catch (err) {
      updateNodeSmartMetrics(node, null, undefined, netProfile);
      const errMsg = err instanceof Error ? err.message : 'Узел временно недоступен';
      if (node.id !== this.activeNodeId) {
        markNodeTemporarilyUnavailable(
          node,
          errMsg,
          this.settings.quarantineDurationSec || 45,
          Date.now(),
          netProfile
        );
      } else {
        node.latencyMs = null;
        node.lastCheckedAt = Date.now();
        node.lastError = errMsg;
      }
      return null;
    }
  }

  public async pingAllNodes(): Promise<VpnStateSnapshot> {
    await Promise.all(this.nodes.map((n) => this.probeSingleNode(n)));
    releaseExpiredUnavailableNodes(this.nodes);
    this.emitState();
    return this.getSnapshot();
  }

  // Ручная или пакетная реабилитация всех серверов из временного карантина в 1 нажатие
  public async recoverUnavailableNodes(): Promise<VpnStateSnapshot> {
    const quarantined = this.nodes.filter(
      (n) => n.status === 'quarantined' || n.status === 'down'
    );
    for (const n of quarantined) {
      n.status = 'standby';
      n.quarantinedUntil = null;
      n.consecutiveFailures = 0;
      n.lastError = undefined;
    }
    await Promise.all(quarantined.map((n) => this.probeSingleNode(n)));
    releaseExpiredUnavailableNodes(this.nodes);
    this.recordEvent(
      'security',
      `Выполнена реабилитация серверов из карантина (${quarantined.length} шт.)`
    );
    this.emitState();
    return this.getSnapshot();
  }

  // Точечная проверка одного сервера из карантина без разрыва текущего туннеля
  public async probeNodeById(nodeId: string): Promise<VpnStateSnapshot> {
    const target = this.nodes.find((n) => n.id === nodeId);
    if (!target) throw new Error('Сервер не найден');
    target.status = 'standby';
    target.quarantinedUntil = null;
    target.consecutiveFailures = 0;
    target.lastError = undefined;
    await this.probeSingleNode(target);
    releaseExpiredUnavailableNodes(this.nodes);
    this.emitState();
    return this.getSnapshot();
  }

  // Один цикл сторожевого таймера Auto-Failover
  public async runHealthCheckCycle(): Promise<void> {
    if (
      this.connectionState !== 'connected' ||
      !this.activeNodeId ||
      this.switchingInProgress
    ) {
      return;
    }

    releaseExpiredQuarantines(this.nodes);
    this.healthCheckTickCounter += 1;
    if (this.healthCheckTickCounter % 3 === 0) {
      const quarantinedPool = this.nodes
        .filter(
          (n) =>
            n.enabled &&
            this.isNodeInEnabledSource(n) &&
            n.id !== this.activeNodeId &&
            (n.status === 'quarantined' || n.status === 'down')
        )
        .sort((a, b) => (a.quarantinedUntil || 0) - (b.quarantinedUntil || 0))
        .slice(0, 2);
      for (const cand of quarantinedPool) {
        await this.probeSingleNode(cand);
      }
    }
    const activeNode = this.nodes.find((n) => n.id === this.activeNodeId);
    if (!activeNode) return;

    const latency = await this.probeSingleNode(activeNode);

    this.latencyHistory.push({
      timestamp: Date.now(),
      latencyMs: latency,
      nodeName: activeNode.name,
      failed: latency === null,
    });
    if (this.latencyHistory.length > 50) {
      this.latencyHistory = this.latencyHistory.slice(-50);
    }

    if (latency === null) {
      activeNode.consecutiveFailures += 1;
      if (activeNode.consecutiveFailures >= this.settings.failureThreshold) {
        await this.handleActiveNodeFailure(
          `Потеря связи с сервером (${activeNode.consecutiveFailures} сбоя подряд)`
        );
        return;
      }
    } else if (latency > this.settings.maxLatencyThresholdMs) {
      activeNode.consecutiveFailures += 1;
      activeNode.status = 'degraded';
      this.recordEvent(
        'health_warning',
        `Высокий пинг на ${activeNode.name}: ${latency} мс (порог ${this.settings.maxLatencyThresholdMs} мс)`,
        activeNode.name,
        undefined,
        latency
      );
      if (activeNode.consecutiveFailures >= this.settings.failureThreshold) {
        await this.handleActiveNodeFailure(
          `Сильная деградация скорости (${latency} мс > ${this.settings.maxLatencyThresholdMs} мс)`
        );
        return;
      }
    } else {
      activeNode.consecutiveFailures = 0;
      activeNode.status = 'active';
    }

    // Проверка автовозврата на основной сервер #1 (если включён режим cascade_recovery)
    const primaryCandidate = findRecoveredPrimaryNode({
      nodes: this.nodes,
      activeNodeId: this.activeNodeId,
      settings: this.settings,
    });

    if (primaryCandidate) {
      const primaryPing = await this.probeSingleNode(primaryCandidate);
      if (
        primaryPing !== null &&
        primaryPing <= this.settings.maxLatencyThresholdMs
      ) {
        const prevName = activeNode.name;
        await this.activateNodeInternal(primaryCandidate);
        this.failoverSwitchCount += 1;
        this.recordEvent(
          'primary_restored',
          `Основной сервер #1 снова в строю (${primaryPing} мс) — выполнен автовозврат`,
          prevName,
          primaryCandidate.name,
          primaryPing
        );
      }
    }

    this.emitState();
  }

  // Мгновенная каскадная автозамена упавшего сервера на следующий (1 -> 2 -> 3...)
  public async handleActiveNodeFailure(reason: string): Promise<boolean> {
    if (this.switchingInProgress || !this.activeNodeId) return false;
    this.switchingInProgress = true;
    const netProfile: PhysicalNetworkProfile =
      this.currentNetworkType === 'cellular' ? 'cellular' : 'wifi';

    try {
      const failedNode = this.nodes.find((n) => n.id === this.activeNodeId);
      if (failedNode) {
        markNodeTemporarilyUnavailable(
          failedNode,
          reason,
          this.settings.quarantineDurationSec || 45,
          Date.now(),
          netProfile
        );
      }

      this.connectionState = 'switching';
      if (this.settings.killSwitchEnabled) {
        this.killSwitchBlocking = true;
        this.guardProxy.setRoutingPolicy({
          upstream: null,
          killSwitchBlocking: true,
          splitTunnelingEnabled: this.settings.splitTunnelingEnabled,
          bypassDomains: this.settings.bypassDomains,
          bypassPrivateLan: this.settings.bypassPrivateLan,
        });
      }
      this.emitState();

      // Параллельная диверсифицированная гонка резервов v3 (между всеми включёнными подписками и внешними мостами)
      await this.scanExternalClientsSilent();
      this.syncExternalBridgeNodes();
      const eligiblePool = this.nodes.filter(
        (n) => n.enabled && n.id !== failedNode?.id && this.isNodeInEnabledSource(n)
      );
      const raceBatch = buildDiversifiedFailoverBatch(
        eligiblePool,
        failedNode?.id,
        8,
        Date.now(),
        netProfile === 'cellular'
      );
      await Promise.all(raceBatch.map((n) => this.probeSingleNode(n)));

      // Если у упавшего провайдера сработал отказ — запускаем фоновое самоисцеление подписки (Self-Healing Refresh)
      if (failedNode?.subscriptionId && this.settings.autoRefreshSubscriptions !== false) {
        const sub = this.subscriptions.find((s) => s.id === failedNode.subscriptionId);
        if (sub && canTriggerSelfHealingRefresh(sub, this.emergencyRefreshMap.get(sub.id))) {
          this.emergencyRefreshMap.set(sub.id, Date.now());
          void this.refreshSubscription(sub.id).catch(() => {});
        }
      }

      const selection = selectNextFailoverNode({
        nodes: this.nodes.filter((n) => this.isNodeInEnabledSource(n)),
        excludeNodeId: failedNode?.id,
        mode: this.settings.failoverMode,
        maxLatencyMs: this.settings.maxLatencyThresholdMs,
      });

      if (
        !selection.selectedNode ||
        selection.selectedNode.status === 'down' ||
        selection.selectedNode.status === 'quarantined'
      ) {
        this.telemetry.verified = false;
        this.telemetry.lastErrorReason = `Все резервные VPN-серверы недоступны (${reason})`;
        if (this.settings.killSwitchEnabled) {
          this.connectionState = 'killswitch_locked';
          this.killSwitchBlocking = true;
          this.recordEvent(
            'killswitch_engaged',
            `Все резервные VPN-серверы недоступны (${reason}). Kill Switch заблокировал трафик для защиты реального IP!`,
            failedNode?.name
          );
        } else {
          this.connectionState = 'error';
        }
        this.emitState();
        return false;
      }

      const nextNode = selection.selectedNode;
      await this.activateNodeInternal(nextNode);
      this.connectionState = 'connected';
      this.failoverSwitchCount += 1;
      this.telemetry.verified = true;
      this.telemetry.activeProviderLabel = nextNode.providerName || 'Мои VPN';
      this.telemetry.lastErrorReason = null;
      this.telemetry.lastFailoverBanner = {
        timestamp: Date.now(),
        fromName: failedNode?.name || 'Предыдущий сервер',
        toName: nextNode.name,
        reason,
      };
      void this.refreshTunnelExitIpAsync();

      this.recordEvent(
        'failover_switch',
        `${reason} ➔ ${selection.reason}`,
        failedNode?.name,
        nextNode.name,
        nextNode.latencyMs
      );
      this.emitState();
      return true;
    } finally {
      this.switchingInProgress = false;
    }
  }

  public async switchToNodeManual(nodeId: string): Promise<VpnStateSnapshot> {
    const target = this.nodes.find((n) => n.id === nodeId);
    if (!target) throw new Error('Сервер не найден');
    target.enabled = true;
    target.quarantinedUntil = null;

    if (this.connectionState === 'disconnected') {
      return this.connect(nodeId);
    }

    const prev = this.nodes.find((n) => n.id === this.activeNodeId);
    await this.activateNodeInternal(target);
    this.connectionState = 'connected';
    this.recordEvent(
      'connect',
      `Ручное переключение туннеля на #${target.priority} ${target.name}`,
      prev?.name,
      target.name,
      target.latencyMs
    );
    this.emitState();
    return this.getSnapshot();
  }

  public importNodesFromText(
    rawText: string,
    subscriptionId?: string,
    providerLabel?: string
  ): ParseImportResult {
    const res = parseVpnImportPayload(rawText, this.nodes.length + 1, subscriptionId);
    if (res.nodes.length > 0) {
      const label = providerLabel || (subscriptionId ? 'Подписка' : 'Личные ключи');
      for (const n of res.nodes) {
        n.providerName = label;
      }
      this.nodes.push(...res.nodes);
      this.normalizePriorities();
      this.saveToVaultSafe();
      this.recordEvent(
        'security',
        `Импортировано ${res.nodes.length} VPN-узлов (${label}) в защищённое хранилище`
      );
      this.emitState();
    }
    return res;
  }

  private async fetchSubscriptionWithCompatWaterfall(cleanUrl: string): Promise<{
    parsed: ParseImportResult;
    headersMeta: ReturnType<typeof parseSubscriptionResponseHeaders>;
    compatLabel: string;
    rawBody: string;
  }> {
    let lastStatus = 0;
    let lastParsed: ParseImportResult = { nodes: [], errors: [], infoMessages: [], filteredDummyCount: 0 };
    let lastHeadersMeta = parseSubscriptionResponseHeaders({});
    let lastCompatLabel = SUBSCRIPTION_COMPAT_PROFILES[0].label;
    let lastBody = '';

    for (const profile of SUBSCRIPTION_COMPAT_PROFILES) {
      const headers = profile.buildHeaders(this.deviceHwid, 'windows');
      const resp = await fetchDirectWithHeaders(cleanUrl, headers, 12000);
      lastStatus = resp.statusCode;
      if (resp.statusCode < 200 || resp.statusCode >= 400 || !resp.body.trim()) {
        continue;
      }
      lastBody = resp.body;
      lastCompatLabel = profile.label;
      lastHeadersMeta = parseSubscriptionResponseHeaders(resp.headers);
      const probeParse = parseVpnImportPayload(resp.body, 1);
      lastParsed = probeParse;
      if (probeParse.nodes.length > 0) {
        return {
          parsed: probeParse,
          headersMeta: lastHeadersMeta,
          compatLabel: profile.label,
          rawBody: resp.body,
        };
      }
    }

    if (lastStatus < 200 || lastStatus >= 400) {
      throw new Error(`Сервер подписки вернул HTTP ${lastStatus}`);
    }

    return {
      parsed: lastParsed,
      headersMeta: lastHeadersMeta,
      compatLabel: lastCompatLabel,
      rawBody: lastBody,
    };
  }

  public async addSubscriptionUrl(name: string, url: string): Promise<VpnStateSnapshot> {
    const cleanUrl = url.trim();
    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
      throw new Error('URL подписки должен начинаться с https:// или http://');
    }

    const { parsed: probe, headersMeta, compatLabel, rawBody } =
      await this.fetchSubscriptionWithCompatWaterfall(cleanUrl);

    if (probe.nodes.length === 0) {
      const providerHint =
        probe.infoMessages && probe.infoMessages.length > 0
          ? `Ответ провайдера: ${probe.infoMessages.join(' • ')}`
          : probe.errors[0] || 'По указанной ссылке не найдено активных рабочих серверов VPN';
      throw new Error(providerHint);
    }

    const subId = `sub_${Date.now()}_${crypto.randomBytes(2).toString('hex')}`;
    const finalName =
      name.trim() ||
      headersMeta.profileTitle ||
      `VPN-сервис #${this.subscriptions.length + 1}`;
    const parsed = this.importNodesFromText(rawBody, subId, finalName);

    const sub: SubscriptionSource = {
      id: subId,
      name: finalName,
      url: cleanUrl,
      lastUpdatedAt: Date.now(),
      nodeCount: parsed.nodes.length,
      autoUpdateHours: headersMeta.autoUpdateHours ?? 12,
      enabledInFailover: true,
      priority: this.subscriptions.length + 1,
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
    this.subscriptions.push(sub);
    this.saveToVaultSafe();
    void this.pingAllNodes();
    this.emitState();
    return this.getSnapshot();
  }

  public async refreshSubscription(subId: string): Promise<VpnStateSnapshot> {
    const sub = this.subscriptions.find((s) => s.id === subId);
    if (!sub) throw new Error('Подписка не найдена');

    const { parsed: probe, headersMeta, compatLabel, rawBody } =
      await this.fetchSubscriptionWithCompatWaterfall(sub.url);

    if (probe.nodes.length === 0) {
      const providerHint =
        probe.infoMessages && probe.infoMessages.length > 0
          ? `Ответ провайдера: ${probe.infoMessages.join(' • ')}`
          : probe.errors[0] || 'Провайдер не вернул активных серверов при обновлении';
      throw new Error(providerHint);
    }

    const finalParsed = parseVpnImportPayload(rawBody, 1, sub.id);
    if (!sub.name || sub.name.startsWith('Подписка') || sub.name.startsWith('VPN-сервис')) {
      if (headersMeta.profileTitle) sub.name = headersMeta.profileTitle;
    }
    for (const n of finalParsed.nodes) {
      n.providerName = sub.name;
    }

    this.nodes = [
      ...this.nodes.filter((n) => n.subscriptionId !== sub.id),
      ...finalParsed.nodes,
    ];
    this.normalizePriorities();

    sub.lastUpdatedAt = Date.now();
    sub.nodeCount = finalParsed.nodes.length;
    sub.usedBytes = headersMeta.usedBytes;
    sub.totalBytes = headersMeta.totalBytes;
    sub.expireUnix = headersMeta.expireUnix;
    sub.supportUrl = headersMeta.supportUrl || sub.supportUrl;
    sub.announceText =
      headersMeta.announceText ||
      (finalParsed.infoMessages && finalParsed.infoMessages.length > 0
        ? finalParsed.infoMessages.join(' • ')
        : sub.announceText);
    sub.filteredDummyCount = finalParsed.filteredDummyCount || 0;
    sub.compatProfile = compatLabel;

    this.saveToVaultSafe();
    this.recordEvent(
      'security',
      `Обновлена подписка «${sub.name}» (${sub.nodeCount} серверов, профиль ${compatLabel})`
    );
    void this.pingAllNodes();
    this.emitState();
    return this.getSnapshot();
  }

  public toggleSubscriptionFailover(subId: string, enabled: boolean): VpnStateSnapshot {
    const sub = this.subscriptions.find((s) => s.id === subId);
    if (sub) {
      sub.enabledInFailover = enabled;
      this.saveToVaultSafe();
      this.emitState();
    }
    return this.getSnapshot();
  }

  public toggleManualGroupFailover(enabled: boolean): VpnStateSnapshot {
    this.manualGroupEnabledInFailover = enabled;
    this.saveToVaultSafe();
    this.emitState();
    return this.getSnapshot();
  }

  public async rebindNetwork(): Promise<VpnStateSnapshot> {
    releaseExpiredUnavailableNodes(this.nodes, Date.now(), true);
    this.telemetry.roamingHandoverCount = (this.telemetry.roamingHandoverCount || 0) + 1;
    this.telemetry.lastHandoverAt = Date.now();
    if (this.connectionState === 'connected' && this.activeNodeId) {
      const current = this.nodes.find((n) => n.id === this.activeNodeId);
      if (current) {
        const ok = await this.probeSingleNode(current);
        if (!ok) {
          await this.handleActiveNodeFailure('Обновление маршрута и сокетов по запросу пользователя');
        } else {
          this.recordEvent(
            'connect',
            `Маршрут и сокеты «${current.name}» успешно обновлены (${current.latencyMs ?? 1} мс)`
          );
        }
      }
    }
    this.saveToVaultSafe();
    this.emitState();
    return this.getSnapshot();
  }

  private async scanExternalClientsSilent(): Promise<void> {
    const ports = Array.from(new Set(this.externalClients.map((b) => b.port)));
    if (ports.length === 0) return;
    const results = await scanLocalLoopbackPorts(ports, 240);
    const portMap = new Map(results.map((r) => [r.port, r]));
    for (const b of this.externalClients) {
      const r = portMap.get(b.port);
      if (r && r.open) {
        b.detectedRunning = true;
        b.latencyMs = r.latencyMs;
      } else {
        b.detectedRunning = false;
        b.latencyMs = null;
      }
    }
    this.syncExternalBridgeNodes();
  }

  public async scanExternalClients(): Promise<VpnStateSnapshot> {
    await this.scanExternalClientsSilent();
    this.saveToVaultSafe();
    this.emitState();
    return this.getSnapshot();
  }

  public async toggleExternalClient(id: string, enabled: boolean): Promise<VpnStateSnapshot> {
    const item = this.externalClients.find((b) => b.id === id);
    if (item) {
      item.enabledInFailover = enabled;
      await this.scanExternalClientsSilent();
      this.saveToVaultSafe();
      this.emitState();
    }
    return this.getSnapshot();
  }

  public async addCustomExternalClient(
    clientName: string,
    protocol: 'socks' | 'http',
    port: number
  ): Promise<VpnStateSnapshot> {
    const cleanPort = Math.round(Number(port));
    if (!Number.isInteger(cleanPort) || cleanPort < 1 || cleanPort > 65535) {
      throw new Error('Укажите корректный локальный порт (1–65535)');
    }
    const id = `ext_custom_${cleanPort}_${Date.now().toString(36)}`;
    this.externalClients.push({
      id,
      clientName: clientName.trim() || `Локальный клиент (:${cleanPort})`,
      protocol: protocol === 'http' ? 'http' : 'socks',
      host: '127.0.0.1',
      port: cleanPort,
      androidPackages: [],
      detectedRunning: false,
      enabledInFailover: true,
      latencyMs: null,
      isCustom: true,
    });
    await this.scanExternalClientsSilent();
    this.saveToVaultSafe();
    this.emitState();
    return this.getSnapshot();
  }

  public dismissFailoverBanner(): VpnStateSnapshot {
    this.telemetry.lastFailoverBanner = null;
    this.emitState();
    return this.getSnapshot();
  }

  private async refreshTunnelExitIpAsync(): Promise<void> {
    if (this.connectionState !== 'connected' || !this.activeNodeId) return;
    const active = this.nodes.find((n) => n.id === this.activeNodeId);
    if (!active) return;
    if (active.isTestStand) {
      this.telemetry.exitIp = '198.51.100.42';
      this.telemetry.exitCountry = active.countryHint || 'VPN';
      this.emitState();
      return;
    }
    try {
      const upstream = this.resolveUpstreamForNode(active);
      const res = await fetchViaUpstream('https://ipwho.is/', upstream, 5500);
      if (res.statusCode >= 200 && res.statusCode < 300) {
        const parsed = JSON.parse(res.body) as Record<string, unknown>;
        if (parsed.ip) {
          this.telemetry.exitIp = String(parsed.ip);
          this.telemetry.exitCountry = String(parsed.country_code || parsed.country || '');
          this.emitState();
          return;
        }
      }
    } catch {
      // Резервная проверка через Cloudflare trace
    }
    try {
      const upstream = this.resolveUpstreamForNode(active);
      const res = await fetchViaUpstream('https://1.1.1.1/cdn-cgi/trace', upstream, 4500);
      if (res.statusCode >= 200 && res.statusCode < 300) {
        const ipMatch = res.body.match(/^ip=(.+)$/m);
        const locMatch = res.body.match(/^loc=(.+)$/m);
        if (ipMatch?.[1]) {
          this.telemetry.exitIp = ipMatch[1].trim();
          this.telemetry.exitCountry = locMatch?.[1]?.trim() || null;
          this.emitState();
        }
      }
    } catch {
      // Игнорируем ошибку резолва внешнего IP
    }
  }

  public deleteSubscription(subId: string): VpnStateSnapshot {
    this.subscriptions = this.subscriptions.filter((s) => s.id !== subId);
    this.nodes = this.nodes.filter((n) => n.subscriptionId !== subId);
    this.normalizePriorities();
    this.saveToVaultSafe();
    this.emitState();
    return this.getSnapshot();
  }

  public deleteNode(nodeId: string): VpnStateSnapshot {
    this.nodes = this.nodes.filter((n) => n.id !== nodeId);
    this.normalizePriorities();
    this.saveToVaultSafe();
    this.emitState();
    return this.getSnapshot();
  }

  public toggleNodeEnabled(nodeId: string, enabled: boolean): VpnStateSnapshot {
    const node = this.nodes.find((n) => n.id === nodeId);
    if (node) {
      node.enabled = enabled;
      this.saveToVaultSafe();
      this.emitState();
    }
    return this.getSnapshot();
  }

  public moveNodePriority(nodeId: string, direction: 'up' | 'down'): VpnStateSnapshot {
    this.normalizePriorities();
    const idx = this.nodes.findIndex((n) => n.id === nodeId);
    if (idx === -1) return this.getSnapshot();
    const swapIdx = direction === 'up' ? idx - 1 : idx + 1;
    if (swapIdx < 0 || swapIdx >= this.nodes.length) return this.getSnapshot();

    const temp = this.nodes[idx];
    this.nodes[idx] = this.nodes[swapIdx];
    this.nodes[swapIdx] = temp;
    this.normalizePriorities();
    this.saveToVaultSafe();
    this.emitState();
    return this.getSnapshot();
  }

  private getAiSettingsSignature(s: AppSettings): string {
    const extra = s as unknown as Record<string, unknown>;
    return JSON.stringify({
      aiRoutingEnabled: s.aiRoutingEnabled !== false,
      aiRoutingMode: s.aiRoutingMode || 'parallel_ai_tunnel',
      aiServices: Array.isArray(s.aiServices) ? [...s.aiServices].sort() : [],
      aiCustomDomains: Array.isArray(s.aiCustomDomains) ? [...s.aiCustomDomains].sort() : [],
      aiIncludeGoogleAccountSession: s.aiIncludeGoogleAccountSession !== false,
      aiIncludeXForGrok: Boolean(s.aiIncludeXForGrok),
      preferredAiNodeId: s.preferredAiNodeId ?? null,
      aiStickyServer: extra.aiStickyServer ?? null,
      aiPreferCleanCountry: extra.aiPreferCleanCountry ?? null,
    });
  }

  public async updateSettings(patch: Partial<AppSettings>): Promise<VpnStateSnapshot> {
    const prevAiSig = this.getAiSettingsSignature(this.settings);
    this.settings = {
      ...this.settings,
      ...patch,
      bypassDomains: patch.bypassDomains
        ? patch.bypassDomains.map((d) => d.trim()).filter(Boolean)
        : this.settings.bypassDomains,
      aiCustomDomains: patch.aiCustomDomains
        ? patch.aiCustomDomains.map((d) => d.trim()).filter(Boolean)
        : this.settings.aiCustomDomains,
    };
    const nextAiSig = this.getAiSettingsSignature(this.settings);
    this.saveToVaultSafe();

    if (this.guardProxy.isRunning()) {
      const activeNode = this.nodes.find((n) => n.id === this.activeNodeId);
      this.guardProxy.setRoutingPolicy({
        upstream: activeNode ? this.resolveUpstreamForNode(activeNode) : null,
        killSwitchBlocking: this.killSwitchBlocking,
        splitTunnelingEnabled: this.settings.splitTunnelingEnabled,
        bypassDomains: this.settings.bypassDomains,
        bypassPrivateLan: this.settings.bypassPrivateLan,
      });
    }

    if (this.connectionState === 'connected') {
      this.startWatchdogLoop();
      if (this.settings.connectionMode === 'system_proxy') {
        this.winProxy.enable(
          '127.0.0.1',
          this.guardProxy.getBoundPort() || this.settings.localProxyPort,
          this.settings.splitTunnelingEnabled ? this.settings.bypassDomains : []
        );
      } else {
        this.winProxy.disable();
      }
      if (prevAiSig !== nextAiSig) {
        await this.syncStickyAiGateway('Обновлены настройки Шлюза Нейросетей');
      }
    }

    this.emitState();
    return this.getSnapshot();
  }

  // Управление PIN-кодом шифрованного сейфа AES-256-GCM
  public unlockVaultWithPin(pin: string): VpnStateSnapshot {
    const data = this.vault.unlock(pin);
    const testStandNodes = this.nodes.filter((n) => n.isTestStand);
    this.nodes = [...testStandNodes, ...data.nodes];
    this.normalizePriorities();
    this.subscriptions = data.subscriptions;
    this.settings = data.settings;
    this.recordEvent('security', 'Криптосейф AES-256-GCM успешно разблокирован PIN-кодом');
    this.emitState();
    return this.getSnapshot();
  }

  public setVaultPin(newPin: string | null): VpnStateSnapshot {
    this.vault.setPin(newPin, {
      nodes: this.nodes,
      subscriptions: this.subscriptions,
      settings: this.settings,
    });
    this.recordEvent(
      'security',
      newPin
        ? 'Установлен персональный PIN-код шифрования сейфа AES-256-GCM'
        : 'PIN-код сейфа отключён (используется системный ключ шифрования)'
    );
    this.emitState();
    return this.getSnapshot();
  }

  // Управление встроенным Тестовым стендом из 3 локальных прокси-узлов
  public async startTestStand(): Promise<VpnStateSnapshot> {
    const standNodes = await this.testCluster.start();
    const userNodes = this.nodes.filter((n) => !n.isTestStand);
    this.nodes = [...standNodes, ...userNodes];
    this.normalizePriorities();
    this.recordEvent(
      'security',
      'Запущен локальный Тестовый стенд из 3 серверов (Франкфурт #1, Амстердам #2, Хельсинки #3)'
    );
    this.emitState();
    return this.getSnapshot();
  }

  public async stopTestStand(): Promise<VpnStateSnapshot> {
    if (this.activeNodeId?.startsWith('test_node_')) {
      await this.disconnect();
    }
    await this.testCluster.stop();
    this.nodes = this.nodes.filter((n) => !n.isTestStand);
    this.normalizePriorities();
    this.emitState();
    return this.getSnapshot();
  }

  public async setTestNodeOnline(
    nodeId: string,
    online: boolean
  ): Promise<VpnStateSnapshot> {
    await this.testCluster.setNodeOnline(nodeId, online);
    const target = this.nodes.find((n) => n.id === nodeId);
    if (target) {
      if (!online) {
        target.status = 'down';
        target.latencyMs = null;
        this.recordEvent(
          'health_warning',
          `Симуляция аварии: сервер ${target.name} принудительно отключён!`
        );
        if (this.connectionState === 'connected' && this.activeNodeId === nodeId) {
          await this.handleActiveNodeFailure(`Обрыв соединения с ${target.name}`);
        }
      } else {
        target.quarantinedUntil = null;
        target.consecutiveFailures = 0;
        target.status = 'standby';
        await this.probeSingleNode(target);
        this.recordEvent(
          'node_recovered',
          `Сервер ${target.name} снова поднят и готов к работе (${target.latencyMs ?? 20} мс)`
        );
        await this.runHealthCheckCycle();
      }
    }
    this.emitState();
    return this.getSnapshot();
  }

  public async setTestNodeDelay(
    nodeId: string,
    delayMs: number
  ): Promise<VpnStateSnapshot> {
    this.testCluster.setNodeDelay(nodeId, delayMs);
    const target = this.nodes.find((n) => n.id === nodeId);
    if (target) {
      await this.probeSingleNode(target);
      if (this.connectionState === 'connected' && this.activeNodeId === nodeId) {
        await this.runHealthCheckCycle();
      }
    }
    this.emitState();
    return this.getSnapshot();
  }

  public async runCyberAudit(): Promise<CyberAuditReport> {
    const report = await runCyberSecurityAudit({
      isConnected: this.connectionState === 'connected',
      localGuardPort: this.guardProxy.getBoundPort(),
      settings: this.settings,
      nodes: this.nodes,
      vaultHasPin: this.vault.hasPin(),
      testEchoUrl: this.testCluster.getEchoIdentityUrl(),
    });
    this.lastAudit = report;
    this.emitState();
    return report;
  }

  public async installSingboxCore(): Promise<VpnStateSnapshot> {
    await this.binaryManager.ensureInstalled(() => this.emitState());
    this.emitState();
    return this.getSnapshot();
  }

  public getMobileAccessInfo(): MobileAccessInfo {
    return this.mobileBridge.buildMobileAccessInfo({
      nodes: this.nodes,
      settings: this.settings,
      apiServerPort: this.apiServerPort,
    });
  }

  public getGuardProxyPort(): number {
    return this.guardProxy.getBoundPort();
  }

  public getBlockedLeakAttempts(): number {
    return this.guardProxy.getBlockedLeakAttempts();
  }

  private startAutoRefreshScheduler(): void {
    if (this.autoRefreshTimer) {
      clearInterval(this.autoRefreshTimer);
    }
    this.autoRefreshTimer = setInterval(() => {
      void this.checkDueSubscriptionsBackground();
    }, 10 * 60 * 1000);
    this.autoRefreshTimer.unref?.();
  }

  private async checkDueSubscriptionsBackground(): Promise<void> {
    if (this.settings.autoRefreshSubscriptions === false || this.vault.isLocked()) return;
    const defaultHours = this.settings.defaultAutoUpdateHours || 12;
    for (const sub of this.subscriptions) {
      if (isSubscriptionDueForAutoRefresh(sub, defaultHours)) {
        try {
          await this.refreshSubscription(sub.id);
          this.telemetry.lastAutoRefreshAt = Date.now();
        } catch {
          // Тихо откладываем до следующего цикла, если сеть недоступна
        }
      }
    }
  }

  public async smartOptimize(): Promise<VpnStateSnapshot> {
    await this.scanExternalClientsSilent();
    this.syncExternalBridgeNodes();
    const pool = this.nodes.filter((n) => n.enabled && this.isNodeInEnabledSource(n));
    if (pool.length === 0) {
      throw new Error('Нет доступных серверов во включённых источниках [✓]');
    }
    await Promise.all(pool.map((n) => this.probeSingleNode(n)));
    const ranked = rankCandidatesSmart(pool, null).filter(
      (n) => n.latencyMs !== null && n.status !== 'down'
    );
    if (ranked.length === 0) {
      throw new Error('Ни один сервер не ответил на турбо-проверку связи');
    }
    const best = ranked[0];
    this.telemetry.smartScore = best.smartScore ?? null;
    this.telemetry.jitterMs = best.jitterMs ?? null;
    if (this.connectionState === 'connected') {
      if (this.activeNodeId !== best.id) {
        return this.switchToNodeManual(best.id);
      }
      this.emitState();
      return this.getSnapshot();
    }
    return this.connect(best.id);
  }

  private getAiCandidatePool(): VpnNode[] {
    const allEnabled = this.nodes.filter((n) => n.enabled);
    if (allEnabled.length > 0) return allEnabled;
    return this.nodes.filter((n) => n.enabled && this.isNodeInEnabledSource(n));
  }

  private async syncStickyAiGateway(
    explicitNodeOrReason?: VpnNode | string | null
  ): Promise<VpnNode | null> {
    const explicitNode =
      explicitNodeOrReason && typeof explicitNodeOrReason === 'object'
        ? explicitNodeOrReason
        : null;
    const reasonLabel =
      typeof explicitNodeOrReason === 'string' ? explicitNodeOrReason : null;

    const enabledPool = this.getAiCandidatePool();
    this.telemetry.aiCompatibleCount = enabledPool.filter((n) => n.aiStatus === 'ok').length;

    if (this.settings.aiRoutingEnabled === false || enabledPool.length === 0) {
      this.activeAiNodeId = null;
      this.telemetry.activeAiNodeId = null;
      this.telemetry.activeAiNodeName = null;
      this.telemetry.activeAiCountry = null;
      if (this.singboxRunner.isRunning() && this.activeNodeId) {
        await this.singboxRunner.switchSelectorOutbound('proxy-ai', this.activeNodeId);
      }
      return null;
    }

    const chosen =
      explicitNode ||
      pickBestStickyAiNode({
        nodes: enabledPool,
        currentAiNodeId: this.activeAiNodeId,
        preferredAiNodeId: this.settings.preferredAiNodeId,
        fallbackActiveNodeId: this.activeNodeId,
      });

    if (!chosen) return null;

    this.activeAiNodeId = chosen.id;
    this.telemetry.activeAiNodeId = chosen.id;
    this.telemetry.activeAiNodeName = chosen.name;
    this.telemetry.activeAiCountry = inferCountryHintFromNode(chosen);

    if (this.singboxRunner.isRunning()) {
      await this.singboxRunner.switchSelectorOutbound('proxy-ai', chosen.id);
    }

    if (reasonLabel) {
      this.recordEvent(
        'security',
        `🤖 ${reasonLabel}: активен ИИ-узел «${chosen.name}»`,
        undefined,
        chosen.name,
        chosen.latencyMs
      );
    }

    return chosen;
  }

  public async scanAiCompatibility(): Promise<VpnStateSnapshot> {
    if (this.aiScanBusy) return this.getSnapshot();
    const enabledPool = this.getAiCandidatePool();
    if (enabledPool.length === 0) {
      throw new Error('Добавьте и включите хотя бы один VPN-сервер для проверки ИИ');
    }

    this.aiScanBusy = true;
    this.telemetry.aiProbeInProgress = true;
    this.emitState();

    try {
      const enabledServices =
        Array.isArray(this.settings.aiServices) && this.settings.aiServices.length > 0
          ? this.settings.aiServices
          : DEFAULT_AI_SERVICES;
      const batch = buildAiScanCandidateQueue({
        nodes: enabledPool,
        preferredAiNodeId: this.settings.preferredAiNodeId,
        currentAiNodeId: this.activeAiNodeId,
        includeAlreadyBlocked: true,
      }).slice(0, 16);

      for (const node of batch) {
        node.aiStatus = 'checking';
        const probePort = this.singboxRunner.getAiProbePort();
        if (this.singboxRunner.isRunning() && probePort > 0) {
          const switched = await this.singboxRunner.switchSelectorOutbound('proxy-ai-probe', node.id);
          if (switched) {
            const upstream: UpstreamEndpoint = {
              protocol: 'http',
              host: '127.0.0.1',
              port: probePort,
            };
            const [swRes, gRes, cRes, oaRes, xRes] = await Promise.all([
              fetchViaUpstream('https://www.youtube.com/sw.js_data', upstream, 4500).catch(() => null),
              fetchViaUpstream('https://gemini.google.com/app', upstream, 4800).catch(() => null),
              fetchViaUpstream('https://chatgpt.com/cdn-cgi/trace', upstream, 4500).catch(() => null),
              fetchViaUpstream(
                'https://ios.chat.openai.com/public-api/mobile/server_status/v1',
                upstream,
                4500
              ).catch(() => null),
              fetchViaUpstream('https://grok.com/', upstream, 4500).catch(() => null),
            ]);

            if (!swRes && !gRes && !cRes && !xRes) {
              evaluateAiProbeResult(
                node,
                { reachable: false, error: 'Туннель не отвечает' },
                enabledServices
              );
            } else {
              const locMatch = (cRes?.body || '').match(/^loc=([A-Za-z]{2})$/m);
              const swCountry = parseGoogleSwJsCountry(swRes?.body);
              const wizSignals = parseGoogleWizHtmlSignals(gRes?.body);
              const googleCountry = swCountry || wizSignals.googleCountryIso2 || null;
              const geminiHtmlAllowed =
                wizSignals.hasUnsupportedBanner
                  ? false
                  : wizSignals.wizGeminiAllowed;
              const oaBodyLower = (oaRes?.body || '').toLowerCase();
              const chatgptBlockedBody =
                oaRes?.statusCode === 403 ||
                oaBodyLower.includes('unsupported_country') ||
                oaBodyLower.includes('not available in your country');
              const xBodyLower = (xRes?.body || '').toLowerCase();
              const grokBlockedBody =
                xRes?.statusCode === 403 ||
                xBodyLower.includes('not available in your region') ||
                xBodyLower.includes('not available in your country');

              evaluateAiProbeResult(
                node,
                {
                  reachable: true,
                  latencyMs: gRes?.elapsedMs ?? swRes?.elapsedMs ?? cRes?.elapsedMs ?? node.latencyMs,
                  exitCountry: locMatch?.[1]?.toUpperCase() || null,
                  googleCountry,
                  geminiStatus: gRes?.statusCode ?? 0,
                  geminiLocation: gRes?.location || '',
                  geminiHtmlAllowed,
                  chatgptStatus: cRes?.statusCode ?? oaRes?.statusCode ?? 0,
                  chatgptBlockedBody,
                  grokStatus: xRes?.statusCode ?? 0,
                  grokBlockedBody,
                },
                enabledServices
              );
            }
            continue;
          }
        }

        // Если ядро sing-box сейчас не запущено — проверяем доступность узла и гео-локацию
        const rtt = await this.probeSingleNode(node);
        const country = inferCountryHintFromNode(node);
        if (rtt === null) {
          evaluateAiProbeResult(
            node,
            { reachable: false, error: 'Узел недоступен' },
            enabledServices
          );
        } else {
          const isBad = country === 'RU' || country === 'BY' || country === 'HK' || country === 'CN';
          evaluateAiProbeResult(
            node,
            {
              reachable: true,
              latencyMs: rtt,
              exitCountry: country,
              googleCountry: country,
              geminiStatus: isBad ? 302 : 200,
              geminiLocation: isBad ? 'https://gemini.google.com/faq' : '',
              chatgptStatus: isBad ? 403 : 200,
              grokStatus: isBad ? 403 : 200,
            },
            enabledServices
          );
        }
      }

      await this.syncStickyAiGateway();
      this.saveToVaultSafe();
    } finally {
      this.telemetry.aiProbeInProgress = false;
      this.telemetry.aiCompatibleCount = enabledPool.filter((n) => n.aiStatus === 'ok').length;
      this.aiScanBusy = false;
      this.emitState();
    }

    return this.getSnapshot();
  }

  public async switchAiGatewayNode(nodeId?: string): Promise<VpnStateSnapshot> {
    const enabledPool = this.getAiCandidatePool();
    if (enabledPool.length === 0) {
      throw new Error('Нет доступных включённых серверов для шлюза нейросетей');
    }

    const nextAi = nodeId
      ? enabledPool.find((n) => n.id === nodeId) || null
      : pickNextAiNodeForManualCycle(enabledPool, this.activeAiNodeId);

    if (!nextAi) {
      throw new Error('Выбранный сервер для нейросетей не найден');
    }

    this.settings.preferredAiNodeId = nodeId ? nextAi.id : null;
    await this.syncStickyAiGateway(nextAi);
    this.recordEvent(
      'security',
      `🤖 Шлюз Нейросетей (Gemini/GPT/Grok) переключён на «${nextAi.name}»`,
      undefined,
      nextAi.name,
      nextAi.latencyMs
    );
    this.saveToVaultSafe();
    this.emitState();
    return this.getSnapshot();
  }

  public async checkAppUpdate(customReleasePayload?: unknown): Promise<AppUpdateInfo> {
    if (customReleasePayload !== undefined && customReleasePayload !== null) {
      this.appUpdate = parseGitHubReleasePayload(customReleasePayload, APP_VERSION);
      this.emitState();
      return this.appUpdate;
    }

    const headers: Record<string, string> = {
      Accept: 'application/vnd.github+json',
      'User-Agent': `AegisMesh-VPN/${APP_VERSION}`,
    };

    try {
      let rawBody: string | null = null;
      if (this.connectionState === 'connected' && this.guardProxy.getBoundPort() > 0) {
        try {
          const viaProxy = await fetchViaUpstream(
            GITHUB_RELEASES_LATEST_URL,
            {
              protocol: 'http',
              host: '127.0.0.1',
              port: this.guardProxy.getBoundPort(),
            },
            7000
          );
          if (viaProxy.statusCode >= 200 && viaProxy.statusCode < 300 && viaProxy.body.trim()) {
            rawBody = viaProxy.body;
          }
        } catch {
          // Фолбэк на прямой запрос
        }
      }

      if (!rawBody) {
        const directRes = await fetchDirectWithHeaders(
          GITHUB_RELEASES_LATEST_URL,
          headers,
          8000
        );
        if (directRes.statusCode < 200 || directRes.statusCode >= 300) {
          throw new Error(`GitHub API вернул HTTP ${directRes.statusCode}`);
        }
        rawBody = directRes.body;
      }

      const parsedJson = JSON.parse(rawBody) as unknown;
      this.appUpdate = parseGitHubReleasePayload(parsedJson, APP_VERSION);
    } catch (err) {
      const errMsg =
        err instanceof Error ? err.message : 'Не удалось проверить наличие обновлений';
      this.appUpdate = {
        ...(this.appUpdate ?? createDefaultAppUpdateInfo(APP_VERSION)),
        checkedAt: Date.now(),
        error: errMsg,
      };
    }

    this.emitState();
    return this.appUpdate;
  }

  public async triggerAppUpdateInstall(customUrl?: string): Promise<AppUpdateInfo> {
    const targetUrl =
      (customUrl && customUrl.trim()) ||
      this.appUpdate?.desktopDownloadUrl ||
      this.appUpdate?.apkDownloadUrl ||
      this.appUpdate?.htmlUrl ||
      GITHUB_RELEASES_PAGE_URL;

    this.appUpdate = {
      ...(this.appUpdate ?? createDefaultAppUpdateInfo(APP_VERSION)),
      statusMessage: `Открыта страница загрузки обновления: ${targetUrl}`,
      downloading: false,
      downloadProgress: 100,
      error: null,
    };

    this.emitState();
    return this.appUpdate;
  }

  public async shutdown(): Promise<void> {
    this.stopWatchdogLoop();
    if (this.autoRefreshTimer) {
      clearInterval(this.autoRefreshTimer);
      this.autoRefreshTimer = null;
    }
    this.winProxy.disable();
    await this.singboxRunner.stop();
    await this.guardProxy.stop();
    await this.testCluster.stop();
  }
}
