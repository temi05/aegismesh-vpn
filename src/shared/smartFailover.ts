// Умное ядро Автозамены AegisMesh VPN v3.1:
// Smart Score (0–100 ★), EMA-пинг, джиттер, параллельная диверсифицированная гонка между провайдерами,
// поддержка QUIC/UDP протоколов (Hysteria2/TUIC/WireGuard без ложного TCP-бана), авто-реабилитация серверов из карантина,
// детектор «зомби-туннелей» (DPI-заморозка), анти-флаппинг (гистерезис), автообновление подписок и пресеты Per-App VPN.
import type {
  InstalledUserApp,
  PhysicalNetworkProfile,
  SubscriptionSource,
  VpnNode,
  VpnProtocol,
} from './types';

/**
 * Определяет, работает ли VPN-протокол исключительно поверх UDP / QUIC (без TCP-слушателя на том же порту).
 * Для Hysteria2 [HY2], TUIC и WireGuard обычная проверка TCP-сокетом (Socket.connect) всегда даёт ложный таймаут,
 * поэтому такие узлы нельзя браковать TCP-пингом — они проверяются сквозным запросом через Clash API ядра sing-box!
 */
export function isUdpBasedVpnProtocol(
  protocolOrNode: VpnProtocol | Pick<VpnNode, 'protocol'> | string | null | undefined
): boolean {
  if (!protocolOrNode) return false;
  const protocol =
    typeof protocolOrNode === 'string' ? protocolOrNode : protocolOrNode.protocol;
  return protocol === 'hysteria2' || protocol === 'tuic' || protocol === 'wireguard';
}

/**
 * Распознаёт выделенные мобильные релеи и обходные серверы (`LTE`, `4G`, `5G`, `через РФ`, `via RU`,
 * `Relay`, `Мост`, `Обход`, `Вайт / White`, `МТС / МегаФон / Билайн / Т2 / Yota`, входной домен `ru.*`)
 * БЕЗ автоматического включения любого зарубежного `VLESS Reality` узла.
 */
export function isDedicatedMobileRelayNode(
  node: Pick<VpnNode, 'name' | 'server'> & Partial<Pick<VpnNode, 'tls' | 'protocol'>>
): boolean {
  const name = (node.name || '').toLowerCase();
  const server = (node.server || '').toLowerCase();
  const text = `${name} ${server}`;
  if (
    /(\blte\b|\b4g\b|\b5g\b|мобил|mobile|через\s*(?:🇷🇺\s*)?(?:рф|росси|ru)|via\s*(?:ru|russia)|обход|вайт|white|relay|bridge|мост|мтс|\bmts\b|мегафон|megafon|билайн|beeline|tele2|\bt2\b|yota)/i.test(
      text
    )
  ) {
    return true;
  }
  if (/(^ru\.|\.ru\.)/i.test(server)) {
    return true;
  }
  return false;
}

/**
 * Распознаёт серверы, адаптированные для работы на мобильном интернете (4G / LTE / 5G)
 * и обхода фильтрации ТСПУ сотовых операторов:
 * - выделенные мобильные релеи (`isDedicatedMobileRelayNode`);
 * - узлы с маскировкой `VLESS Reality` (`tls === 'reality'`).
 */
export function isMobileCarrierFriendlyNode(
  node: Pick<VpnNode, 'name' | 'server' | 'tls' | 'protocol'>
): boolean {
  return isDedicatedMobileRelayNode(node) || node.tls === 'reality';
}

/**
 * Переводит временно не ответивший сервер в краткосрочный карантин с гарантированным таймером автовозврата
 * и экспоненциальным откатом (45с -> 68с -> 90с -> 113с, макс. 120с).
 */
export function markNodeTemporarilyUnavailable(
  node: VpnNode,
  reason?: string,
  baseDurationSec = 45,
  now = Date.now(),
  networkType?: PhysicalNetworkProfile
): void {
  const failures = Math.max(1, (node.consecutiveFailures || 0) + 1);
  node.consecutiveFailures = failures;
  const cleanBase = Math.max(15, baseDurationSec || 45);
  const backoffSec = Math.min(
    120,
    Math.round(cleanBase * Math.min(2.5, 1 + (failures - 1) * 0.5))
  );
  node.status = 'quarantined';
  node.latencyMs = null;
  node.lastCheckedAt = now;
  node.quarantinedUntil = now + backoffSec * 1000;
  node.quarantinedOnNetwork = networkType || node.quarantinedOnNetwork || null;
  node.unavailableReason = reason ?? null;
  if (reason !== undefined) {
    node.lastError = reason;
  }
}

/**
 * Принудительно снимает карантин со всех серверов и полностью сбрасывает счётчик ошибок.
 */
export function releaseAllUnavailableNodes(nodes: VpnNode[]): number {
  let released = 0;
  for (const node of nodes) {
    if (node.status === 'quarantined' || node.status === 'down') {
      node.status = 'standby';
      node.quarantinedUntil = null;
      node.quarantinedOnNetwork = null;
      node.unavailableReason = null;
      node.consecutiveFailures = 0;
      node.lastError = undefined;
      released += 1;
    }
  }
  return released;
}

/**
 * При смене физической сети (например, с Wi-Fi на LTE или с Wi-Fi 1 на Wi-Fi 2)
 * мгновенно освобождает серверы, которые попали в карантин на ПРЕДЫДУЩЕЙ сети,
 * так как на новой сети маршрутизация и фильтрация оператора совершенно другие!
 */
export function releaseQuarantineForNetworkShift(
  nodes: VpnNode[],
  newNetworkType: PhysicalNetworkProfile
): number {
  let released = 0;
  for (const node of nodes) {
    if (node.status !== 'quarantined' && node.status !== 'down') {
      continue;
    }
    if (!node.quarantinedOnNetwork || node.quarantinedOnNetwork !== newNetworkType) {
      node.status = 'standby';
      node.quarantinedUntil = null;
      node.quarantinedOnNetwork = null;
      node.unavailableReason = null;
      node.consecutiveFailures = 0;
      node.lastError = undefined;
      released += 1;
    }
  }
  return released;
}

/**
 * Автоматически возвращает серверы из списка недоступных по истечении таймера карантина,
 * снимает ложные TCP-ошибки с UDP/QUIC серверов ([HY2]/TUIC/WG) и защищает список от полного опустошения
 * при кратковременной потере связи (лифт / смена Wi-Fi ↔ LTE).
 * При выходе по таймеру сохраняет `consecutiveFailures`, чтобы при повторном падении карантин увеличивался экспоненциально.
 */
export function releaseExpiredUnavailableNodes(
  nodes: VpnNode[],
  now = Date.now(),
  enableMassOfflineGuard = true
): number {
  let released = 0;

  for (const node of nodes) {
    if (node.status !== 'quarantined' && node.status !== 'down') {
      continue;
    }

    // 1. Мгновенная очистка старых ложных ошибок TCP Socket.connect у UDP/QUIC протоколов (Hysteria2 / TUIC / WireGuard)
    if (
      isUdpBasedVpnProtocol(node.protocol) &&
      typeof node.lastError === 'string' &&
      /failed to connect to|econnrefused|tcp/i.test(node.lastError)
    ) {
      node.status = 'standby';
      node.quarantinedUntil = null;
      node.quarantinedOnNetwork = null;
      node.unavailableReason = null;
      node.consecutiveFailures = 0;
      node.lastError = undefined;
      released += 1;
      continue;
    }

    // 2. Выход по истечении таймера карантина (сохраняем consecutiveFailures для экспоненциального бэкоффа при повторном падении)
    if (node.quarantinedUntil !== null && node.quarantinedUntil <= now) {
      node.status = 'standby';
      node.quarantinedUntil = null;
      node.quarantinedOnNetwork = null;
      node.unavailableReason = null;
      node.lastError = undefined;
      released += 1;
      continue;
    }

    // 3. Страховка от «вечного down» без таймера (от прошлых сессий): назначаем короткий остаток или сразу выпускаем
    if (node.quarantinedUntil === null) {
      const checkedAt = node.lastCheckedAt || 0;
      if (!checkedAt || now - checkedAt >= 45_000) {
        node.status = 'standby';
        node.quarantinedOnNetwork = null;
        node.unavailableReason = null;
        node.lastError = undefined;
        released += 1;
      } else {
        node.status = 'quarantined';
        node.quarantinedUntil = checkedAt + 45_000;
      }
    }
  }

  // 4. Защита от массового офлайна (Mass-Offline Guard):
  // Если пропал мобильный сигнал и вообще ВСЕ включённые серверы разом попали в карантин —
  // сразу возвращаем их в строй, чтобы список никогда не блокировался целиком!
  if (enableMassOfflineGuard) {
    const enabledUserNodes = nodes.filter((n) => n.enabled && !n.isTestStand);
    if (enabledUserNodes.length > 1) {
      const availableCount = enabledUserNodes.filter(
        (n) => n.status !== 'quarantined' && n.status !== 'down'
      ).length;
      if (availableCount === 0) {
        for (const n of enabledUserNodes) {
          n.status = 'standby';
          n.quarantinedUntil = null;
          n.quarantinedOnNetwork = null;
          n.unavailableReason = null;
          n.consecutiveFailures = 0;
          n.lastError = undefined;
          released += 1;
        }
      }
    }
  }

  return released;
}

/**
 * Возвращает оставшееся время карантина узла в секундах для наглядного обратного отсчёта в UI.
 */
export function getUnavailableRemainingSec(
  node: VpnNode,
  now = Date.now(),
  fallbackSec = 45
): number {
  if (node.quarantinedUntil && node.quarantinedUntil > now) {
    return Math.max(1, Math.ceil((node.quarantinedUntil - now) / 1000));
  }
  if (node.lastCheckedAt && node.lastCheckedAt + fallbackSec * 1000 > now) {
    return Math.max(
      1,
      Math.ceil((node.lastCheckedAt + fallbackSec * 1000 - now) / 1000)
    );
  }
  return 0;
}

export interface ZombieStallSample {
  prevTxPackets: number;
  currTxPackets: number;
  prevRxBytes: number;
  currRxBytes: number;
}

/**
 * Обновляет умные метрики узла (EMA-задержка, джиттер, процент успеха, скорость и итоговый Smart Score 0–100 ★)
 * с раздельной памятью для домашнего Wi-Fi (`wifiScore`) и мобильной сети LTE/4G (`cellularScore`).
 * Изолирует EMA и джиттер между Wi-Fi и LTE, чтобы переход с 15 мс Wi-Fi на 110 мс LTE не вызывал ложный скачок джиттера!
 */
export function updateNodeSmartMetrics(
  node: VpnNode,
  sampleRttMs: number | null,
  measuredSpeedKbps?: number | null,
  networkType: PhysicalNetworkProfile = 'unknown'
): number {
  const prevSuccess = typeof node.successRate === 'number' ? node.successRate : 85;

  if (typeof measuredSpeedKbps === 'number' && measuredSpeedKbps >= 0) {
    node.measuredSpeedKbps = Math.round(measuredSpeedKbps);
  }

  if (sampleRttMs === null || sampleRttMs <= 0) {
    node.successRate = Math.max(0, Math.round(prevSuccess * 0.65 - 12));
    const degradedScore = Math.max(5, Math.round((node.smartScore ?? 40) * 0.45));
    node.smartScore = degradedScore;
    // Снижаем оценку только той сети, на которой произошёл таймаут, чтобы сбой на LTE не портил память домашнего Wi-Fi!
    if (networkType === 'cellular') {
      node.cellularScore = Math.max(5, Math.round((node.cellularScore ?? 40) * 0.45));
    } else if (networkType === 'wifi' || networkType === 'ethernet') {
      node.wifiScore = Math.max(5, Math.round((node.wifiScore ?? 45) * 0.45));
    }
    return degradedScore;
  }

  // При успешном ответе сбрасываем счётчик последовательных сбоев и флаги карантина
  node.consecutiveFailures = 0;
  node.quarantinedUntil = null;
  node.quarantinedOnNetwork = null;
  node.unavailableReason = null;
  node.lastError = undefined;

  const cleanRtt = Math.round(sampleRttMs);
  const normalizedNet =
    networkType === 'ethernet' ? 'wifi' : networkType;
  const switchedNetwork =
    normalizedNet !== 'unknown' &&
    Boolean(node.lastSuccessNetwork && node.lastSuccessNetwork !== normalizedNet);

  let prevEma: number;
  if (normalizedNet === 'cellular') {
    if (typeof node.cellularEmaLatencyMs === 'number' && node.cellularEmaLatencyMs > 0) {
      prevEma = node.cellularEmaLatencyMs;
    } else if (
      switchedNetwork ||
      (typeof node.wifiEmaLatencyMs === 'number' && node.wifiEmaLatencyMs > 0)
    ) {
      prevEma = cleanRtt;
    } else {
      prevEma =
        typeof node.emaLatencyMs === 'number' && node.emaLatencyMs > 0
          ? node.emaLatencyMs
          : cleanRtt;
    }
  } else if (normalizedNet === 'wifi') {
    if (typeof node.wifiEmaLatencyMs === 'number' && node.wifiEmaLatencyMs > 0) {
      prevEma = node.wifiEmaLatencyMs;
    } else if (
      switchedNetwork ||
      (typeof node.cellularEmaLatencyMs === 'number' && node.cellularEmaLatencyMs > 0)
    ) {
      prevEma = cleanRtt;
    } else {
      prevEma =
        typeof node.emaLatencyMs === 'number' && node.emaLatencyMs > 0
          ? node.emaLatencyMs
          : cleanRtt;
    }
  } else {
    prevEma =
      typeof node.emaLatencyMs === 'number' && node.emaLatencyMs > 0
        ? node.emaLatencyMs
        : cleanRtt;
  }

  const prevJitter = switchedNetwork
    ? 0
    : typeof node.jitterMs === 'number' && node.jitterMs >= 0
      ? node.jitterMs
      : 0;

  const delta = Math.abs(cleanRtt - prevEma);
  const nextEma = Math.round(prevEma * 0.65 + cleanRtt * 0.35);
  const nextJitter = Math.round(prevJitter * 0.65 + delta * 0.35);
  const nextSuccess = Math.min(100, Math.round(prevSuccess * 0.78 + 22));

  node.latencyMs = cleanRtt;
  node.emaLatencyMs = nextEma;
  node.jitterMs = nextJitter;
  node.successRate = nextSuccess;

  // 1. Оценка задержки (0..50 баллов)
  let latencyPoints = 50;
  if (nextEma <= 55) {
    latencyPoints = 50;
  } else if (nextEma <= 140) {
    latencyPoints = Math.round(50 - ((nextEma - 55) / 85) * 11);
  } else if (nextEma <= 350) {
    latencyPoints = Math.round(39 - ((nextEma - 140) / 210) * 17);
  } else if (nextEma <= 900) {
    latencyPoints = Math.max(4, Math.round(22 - ((nextEma - 350) / 550) * 18));
  } else {
    latencyPoints = 2;
  }

  // 2. Оценка стабильности / отсутствия джиттера (0..20 баллов)
  let jitterPoints = 20;
  if (nextJitter <= 12) {
    jitterPoints = 20;
  } else if (nextJitter <= 45) {
    jitterPoints = 15;
  } else if (nextJitter <= 100) {
    jitterPoints = 8;
  } else {
    jitterPoints = 2;
  }

  // 3. Оценка надёжности истории ответов (0..18 баллов)
  const reliabilityPoints = Math.round((nextSuccess / 100) * 18);

  // 4. Оценка реальной скорости потока (от -15 до +12 баллов)
  let speedPoints = 8; // нейтральный бонус, если замер скорости ещё не запускался
  const speed = node.measuredSpeedKbps;
  if (typeof speed === 'number' && speed > 0) {
    if (speed >= 12000) speedPoints = 12;
    else if (speed >= 4000) speedPoints = 10;
    else if (speed >= 1200) speedPoints = 7;
    else if (speed >= 400) speedPoints = 3;
    else speedPoints = -15; // сервер «задушен» по скорости
  }

  const totalScore = Math.max(
    1,
    Math.min(100, latencyPoints + jitterPoints + reliabilityPoints + speedPoints)
  );
  node.smartScore = totalScore;

  if (normalizedNet === 'cellular') {
    node.cellularEmaLatencyMs = nextEma;
    node.cellularScore = totalScore;
    node.lastSuccessNetwork = 'cellular';
  } else if (normalizedNet === 'wifi') {
    node.wifiEmaLatencyMs = nextEma;
    node.wifiScore = totalScore;
    node.lastSuccessNetwork = 'wifi';
  }

  return totalScore;
}

/**
 * Вычисляет эффективный сетевой рейтинг узла с учётом особенностей протокола на текущей сети:
 * - На мобильной сети (LTE/4G): +18 для выделенных LTE / [через РФ] релеев, +10 для обычных VLESS Reality (+6 дополнительно для LTE Reality);
 *   осторожная оценка непроверенных прямых UDP/QUIC узлов.
 * - На домашнем Wi-Fi: бонус для скоростных прямых узлов и подтверждённых Wi-Fi чемпионов.
 */
export function getNetworkProtocolAdjustedScore(
  node: VpnNode,
  networkType: PhysicalNetworkProfile
): number {
  const fallbackBase =
    node.smartScore ??
    (node.latencyMs ? Math.max(15, 90 - Math.round(node.latencyMs / 10)) : 50);

  if (networkType === 'cellular') {
    let score = node.cellularScore ?? fallbackBase;
    const dedicatedRelay = isDedicatedMobileRelayNode(node);
    if (dedicatedRelay) {
      score += 18;
    }
    if (node.tls === 'reality') {
      score += dedicatedRelay ? 6 : 10;
    }
    // Если протокол чисто UDP/QUIC (Hysteria2/TUIC/WG) и не является выделенным релеем через РФ,
    // и ещё не доказал свою работоспособность на LTE — даём приоритет TCP Reality/релеям
    if (
      isUdpBasedVpnProtocol(node.protocol) &&
      !dedicatedRelay &&
      (node.cellularScore ?? 0) < 65
    ) {
      score -= 12;
    }
    return Math.max(1, Math.min(125, score));
  }

  if (networkType === 'wifi' || networkType === 'ethernet') {
    let score = node.wifiScore ?? fallbackBase;
    const isDedicatedSlowLteRelay = /\blte\b|\b4g\b/i.test(node.name || '');
    if (
      !isDedicatedSlowLteRelay &&
      (isUdpBasedVpnProtocol(node.protocol) || node.tls === 'reality')
    ) {
      score += 6;
    }
    return Math.max(1, Math.min(120, score));
  }

  return fallbackBase;
}

/**
 * Выбирает запомненный лучший сервер («чемпион») для указанного типа сети (Wi-Fi или LTE/4G).
 */
export function pickRememberedNetworkChampion(
  nodes: VpnNode[],
  networkType: PhysicalNetworkProfile,
  rememberedNodeId?: string | null,
  now = Date.now()
): VpnNode | null {
  const available = nodes.filter(
    (n) =>
      n.enabled &&
      n.status !== 'down' &&
      !(n.quarantinedUntil && n.quarantinedUntil > now)
  );
  if (available.length === 0) return null;

  if (rememberedNodeId) {
    const remembered = available.find((n) => n.id === rememberedNodeId);
    if (remembered) return remembered;
  }

  if (networkType === 'cellular') {
    const cellCandidates = available
      .filter((n) => (n.cellularScore ?? 0) >= 55 || isMobileCarrierFriendlyNode(n))
      .sort(
        (a, b) =>
          getNetworkProtocolAdjustedScore(b, 'cellular') -
          getNetworkProtocolAdjustedScore(a, 'cellular')
      );
    return cellCandidates[0] || null;
  }

  if (networkType === 'wifi' || networkType === 'ethernet') {
    const wifiCandidates = available
      .filter((n) => (n.wifiScore ?? 0) >= 55)
      .sort(
        (a, b) =>
          getNetworkProtocolAdjustedScore(b, 'wifi') -
          getNetworkProtocolAdjustedScore(a, 'wifi')
      );
    return wifiCandidates[0] || null;
  }

  return null;
}

/**
 * Ключ группы провайдера для диверсификации кандидатов между разными VPN-подписками и внешними клиентами.
 */
export function getNodeProviderGroupKey(node: VpnNode): string {
  if (node.isExternalClientBridge) return `bridge:${node.id}`;
  if (node.subscriptionId) return `sub:${node.subscriptionId}`;
  return 'manual:keys';
}

/**
 * Сортирует доступные узлы по умному рейтингу (Smart Score -> EMA-пинг -> приоритет пользователя).
 */
export function rankCandidatesSmart(
  nodes: VpnNode[],
  excludeNodeId?: string | null,
  now = Date.now(),
  preferMobileFriendly = false,
  preferTcpOverUdp = false
): VpnNode[] {
  return [...nodes]
    .filter((n) => n.enabled && n.id !== excludeNodeId)
    .sort((a, b) => {
      const aQuarantined =
        Boolean(a.quarantinedUntil && a.quarantinedUntil > now) || a.status === 'down';
      const bQuarantined =
        Boolean(b.quarantinedUntil && b.quarantinedUntil > now) || b.status === 'down';
      if (aQuarantined !== bQuarantined) return aQuarantined ? 1 : -1;

      if (preferTcpOverUdp) {
        const aTcp = !isUdpBasedVpnProtocol(a.protocol);
        const bTcp = !isUdpBasedVpnProtocol(b.protocol);
        if (aTcp !== bTcp) return aTcp ? -1 : 1;
      }

      if (preferMobileFriendly) {
        const aDed = isDedicatedMobileRelayNode(a);
        const bDed = isDedicatedMobileRelayNode(b);
        if (aDed !== bDed) return aDed ? -1 : 1;

        const aMob = isMobileCarrierFriendlyNode(a);
        const bMob = isMobileCarrierFriendlyNode(b);
        if (aMob !== bMob) return aMob ? -1 : 1;
      }

      const aScore = preferMobileFriendly
        ? getNetworkProtocolAdjustedScore(a, 'cellular')
        : (a.wifiScore ??
          a.smartScore ??
          (a.latencyMs ? Math.max(15, 90 - Math.round(a.latencyMs / 10)) : 50));
      const bScore = preferMobileFriendly
        ? getNetworkProtocolAdjustedScore(b, 'cellular')
        : (b.wifiScore ??
          b.smartScore ??
          (b.latencyMs ? Math.max(15, 90 - Math.round(b.latencyMs / 10)) : 50));
      if (Math.abs(bScore - aScore) >= 4) return bScore - aScore;

      const aLat =
        (preferMobileFriendly ? a.cellularEmaLatencyMs : a.wifiEmaLatencyMs) ??
        a.emaLatencyMs ??
        a.latencyMs ??
        9999;
      const bLat =
        (preferMobileFriendly ? b.cellularEmaLatencyMs : b.wifiEmaLatencyMs) ??
        b.emaLatencyMs ??
        b.latencyMs ??
        9999;
      if (aLat !== bLat) return aLat - bLat;

      return a.priority - b.priority;
    });
}

/**
 * Формирует диверсифицированный пакет кандидатов для параллельной гонки (Parallel Hedged Race):
 * берёт лучший узел из Подписки №1, затем лучший из Подписки №2, затем внешний мост 127.0.0.1 и личные ключи по кругу.
 * Если текущий упавший узел работал по чистому UDP/QUIC (`hysteria2`/`tuic`/`wireguard`) или передан `preferTcpOverUdp = true`,
 * автоматически повышает приоритет TCP / VLESS Reality узлов для мгновенного ухода от блокировки UDP оператором!
 */
export function buildDiversifiedFailoverBatch(
  nodes: VpnNode[],
  excludeNodeId?: string | null,
  maxBatchSize = 6,
  nowOrIsCellular: number | boolean = Date.now(),
  preferMobileOrPreferTcp = false,
  preferTcpOverUdpArg = false
): VpnNode[] {
  const now =
    typeof nowOrIsCellular === 'number' ? nowOrIsCellular : Date.now();
  const preferMobileFriendly =
    typeof nowOrIsCellular === 'boolean'
      ? nowOrIsCellular
      : Boolean(preferMobileOrPreferTcp);
  const explicitPreferTcp =
    typeof nowOrIsCellular === 'boolean'
      ? Boolean(preferMobileOrPreferTcp)
      : Boolean(preferTcpOverUdpArg);

  const failingActiveNode = excludeNodeId
    ? nodes.find((n) => n.id === excludeNodeId)
    : undefined;
  const effectivePreferTcp =
    explicitPreferTcp ||
    Boolean(failingActiveNode && isUdpBasedVpnProtocol(failingActiveNode.protocol));

  const ranked = rankCandidatesSmart(
    nodes,
    excludeNodeId,
    now,
    preferMobileFriendly,
    effectivePreferTcp
  );
  if (ranked.length <= maxBatchSize) return ranked;

  const buckets = new Map<string, VpnNode[]>();
  for (const node of ranked) {
    const key = getNodeProviderGroupKey(node);
    const list = buckets.get(key) || [];
    list.push(node);
    buckets.set(key, list);
  }

  // Если требуется уход с UDP на TCP/Reality, внутри каждой подписки выдвигаем лучший TCP-узел на 1-е место
  if (effectivePreferTcp) {
    for (const list of buckets.values()) {
      const tcpIdx = list.findIndex((n) => !isUdpBasedVpnProtocol(n.protocol));
      if (tcpIdx > 0) {
        const [tcpNode] = list.splice(tcpIdx, 1);
        list.unshift(tcpNode);
      }
    }
  } else if (preferMobileFriendly) {
    // Если мы на мобильном интернете (LTE/4G), гарантируем, что в первую же гонку попадут все LTE / «через РФ» серверы из всех подписок!
    for (const list of buckets.values()) {
      const dedIdx = list.findIndex((n) => isDedicatedMobileRelayNode(n));
      const mobIdx =
        dedIdx >= 0 ? dedIdx : list.findIndex((n) => isMobileCarrierFriendlyNode(n));
      if (mobIdx > 0) {
        const [mobNode] = list.splice(mobIdx, 1);
        list.unshift(mobNode);
      }
    }
  }

  const batch: VpnNode[] = [];
  let addedInRound = true;
  while (batch.length < maxBatchSize && addedInRound) {
    addedInRound = false;
    for (const list of buckets.values()) {
      if (list.length > 0 && batch.length < maxBatchSize) {
        const picked = list.shift();
        if (picked) {
          batch.push(picked);
          addedInRound = true;
        }
      }
    }
  }
  return batch;
}

/**
 * Защита от пинг-понга серверов (Anti-Flap Hysteresis):
 * разрешает упреждающий переход на более быстрый сервер только при существенном преимуществе и после паузы охлаждения.
 */
export function shouldPreemptivelySwitchNode(params: {
  activeNode: VpnNode;
  challengerNode: VpnNode;
  lastSwitchAtMs: number;
  now?: number;
  cooldownMs?: number;
}): boolean {
  const now = params.now ?? Date.now();
  const cooldownMs = params.cooldownMs ?? 15000;
  if (now - params.lastSwitchAtMs < cooldownMs) return false;
  if (params.activeNode.id === params.challengerNode.id) return false;

  const activeScore = params.activeNode.smartScore ?? 60;
  const challengerScore = params.challengerNode.smartScore ?? 0;
  const activeLat = params.activeNode.emaLatencyMs ?? params.activeNode.latencyMs ?? 250;
  const challengerLat = params.challengerNode.emaLatencyMs ?? params.challengerNode.latencyMs ?? 9999;

  return challengerScore >= activeScore + 18 && activeLat - challengerLat >= 35;
}

/**
 * Детектор «зомби-туннеля» (DPI-заморозка соединения после рукопожатия):
 * устройство активно отправляет пакеты в туннель, но в ответ приходит почти 0 байт.
 */
export function detectZombieTunnelStall(sample: ZombieStallSample): boolean {
  const deltaTxPackets = sample.currTxPackets - sample.prevTxPackets;
  const deltaRxBytes = sample.currRxBytes - sample.prevRxBytes;
  return deltaTxPackets >= 14 && deltaRxBytes <= 64;
}

/**
 * Проверяет, пора ли обновить подписку по фоновому расписанию.
 */
export function isSubscriptionDueForAutoRefresh(
  sub: SubscriptionSource,
  defaultAutoUpdateHours = 12,
  now = Date.now()
): boolean {
  if (!sub.url || !sub.url.startsWith('http')) return false;
  const hours = sub.autoUpdateHours && sub.autoUpdateHours > 0 ? sub.autoUpdateHours : defaultAutoUpdateHours;
  if (!sub.lastUpdatedAt) return true;
  return now - sub.lastUpdatedAt >= hours * 3600 * 1000;
}

/**
 * Разрешает экстренное самоисцеление подписки (Self-Healing Refresh), если все её узлы упали,
 * но не чаще 1 раза в 15 минут.
 */
export function canTriggerSelfHealingRefresh(
  sub: SubscriptionSource,
  lastEmergencyRefreshAt: number | undefined,
  now = Date.now()
): boolean {
  if (!sub.url || !sub.url.startsWith('http')) return false;
  if (!lastEmergencyRefreshAt) return true;
  return now - lastEmergencyRefreshAt >= 15 * 60 * 1000;
}

/**
 * Автоматически подсказывает категорию установленного Android-приложения для удобной настройки Per-App VPN в 1 тап.
 */
export function classifyAndroidAppCategory(
  packageName: string,
  appName: string
): InstalledUserApp['categoryHint'] {
  const hay = `${packageName} ${appName}`.toLowerCase();

  if (
    /sber|tinkoff|tbank|vtb|alfabank|raiffeisen|gazprombank|sovcombank|gosuslugi|nalog|yandex\.taxi|yandex\.go|ozon|wildberries|avito|mirpay|sbp|pochta|vkusvill|dodo|samokat/.test(
      hay
    ) ||
    /сбер|т-банк|тинькофф|втб|альфа|госуслуг|налог|такси|озон|вайлдберриз|авито/.test(hay)
  ) {
    return 'bank_gov';
  }

  if (
    /youtube|twitch|spotify|netflix|tiktok|musically|soundcloud|kinopoisk|plex|vlc|newpipe|revanced/.test(
      hay
    )
  ) {
    return 'video_music';
  }

  if (
    /telegram|messenger|discord|instagram|whatsapp|twitter|zhiliaoapp|snapchat|facebook|reddit|threads|signal|viber/.test(
      hay
    )
  ) {
    return 'social_media';
  }

  if (/chrome|firefox|opera|brave|vivaldi|browser|duckduckgo|kiwi|edge/.test(hay)) {
    return 'browser';
  }

  return 'other';
}
