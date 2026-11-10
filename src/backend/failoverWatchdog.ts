// Алгоритм каскадной автозамены серверов (Smart Failover / Строгая очередь 1->2->3 / Автовозврат)
import {
  rankCandidatesSmart,
  releaseExpiredUnavailableNodes,
} from '../shared/smartFailover';
import type { AppSettings, FailoverMode, VpnNode } from '../shared/types';

export interface CandidateSelectionResult {
  selectedNode: VpnNode | null;
  reason: string;
}

export function isNodeEligible(node: VpnNode, now = Date.now()): boolean {
  if (!node.enabled) return false;
  if (node.quarantinedUntil && node.quarantinedUntil > now) {
    return false;
  }
  if (node.status === 'down' || node.status === 'quarantined') {
    return false;
  }
  return true;
}

// Снятие карантина с узлов, у которых истёк срок охлаждения (включая реабилитацию старых down и UDP/QUIC)
export function releaseExpiredQuarantines(nodes: VpnNode[], now = Date.now()): boolean {
  return releaseExpiredUnavailableNodes(nodes, now) > 0;
}

// Выбор лучшего резервного сервера при отказе или деградации текущего VPN
export function selectNextFailoverNode(params: {
  nodes: VpnNode[];
  excludeNodeId?: string | null;
  mode: FailoverMode;
  maxLatencyMs: number;
  now?: number;
}): CandidateSelectionResult {
  const now = params.now ?? Date.now();
  releaseExpiredQuarantines(params.nodes, now);

  const ordered = [...params.nodes]
    .filter((n) => n.enabled && n.id !== params.excludeNodeId)
    .sort((a, b) => a.priority - b.priority);

  if (ordered.length === 0) {
    return {
      selectedNode: null,
      reason: 'В списке нет других включённых резервных VPN-серверов',
    };
  }

  // Фильтруем узлы, не находящиеся в карантине
  let candidates = ordered.filter((n) => isNodeEligible(n, now));

  // Если вообще все резервные серверы попали в карантин, пробуем реабилитировать самый давний по приоритету
  if (candidates.length === 0) {
    candidates = ordered;
  }

  if (params.mode === 'smart_fastest') {
    // Умный Failover v3: выбираем узел с лучшим комплексным рейтингом Smart Score (0–100 ★: EMA-пинг, джиттер, стабильность и скорость)
    const smartRanked = rankCandidatesSmart(candidates, params.excludeNodeId, now).filter(
      (n) =>
        n.latencyMs !== null &&
        n.latencyMs > 0 &&
        n.latencyMs <= params.maxLatencyMs &&
        n.status !== 'down'
    );

    if (smartRanked.length > 0) {
      const best = smartRanked[0];
      const scoreBadge = best.smartScore ? `, рейтинг ${best.smartScore}★` : '';
      return {
        selectedNode: best,
        reason: `Умный Failover v3 выбрал лучший узел (${best.latencyMs} мс${scoreBadge})`,
      };
    }

    // Если все узлы выше порога или без рейтинга — берём самый быстрый из измеренных
    const withAnyPing = rankCandidatesSmart(candidates, params.excludeNodeId, now).filter(
      (n) => n.latencyMs !== null && n.status !== 'down'
    );

    if (withAnyPing.length > 0) {
      return {
        selectedNode: withAnyPing[0],
        reason: `Переключение на доступный узел с минимальной задержкой (${withAnyPing[0].latencyMs} мс)`,
      };
    }
  }

  // Для strict_cascade и cascade_recovery (а также фолбэка smart_fastest) идём строго по очереди приоритета 1 -> 2 -> 3
  const nextInCascade =
    candidates.find((n) => n.status !== 'down') ?? candidates[0];

  return {
    selectedNode: nextInCascade,
    reason: `Каскадный переход по очереди приоритета (#${nextInCascade.priority} ${nextInCascade.name})`,
  };
}

// Проверка, нужно ли в режиме cascade_recovery вернуться на основной (#1) сервер
export function findRecoveredPrimaryNode(params: {
  nodes: VpnNode[];
  activeNodeId: string | null;
  settings: AppSettings;
  now?: number;
}): VpnNode | null {
  if (params.settings.failoverMode !== 'cascade_recovery' || !params.activeNodeId) {
    return null;
  }
  const now = params.now ?? Date.now();
  const enabledOrdered = [...params.nodes]
    .filter((n) => n.enabled)
    .sort((a, b) => a.priority - b.priority);

  if (enabledOrdered.length < 2) return null;

  const primary = enabledOrdered[0];
  if (primary.id === params.activeNodeId) return null;
  if (!isNodeEligible(primary, now)) return null;

  return primary;
}
