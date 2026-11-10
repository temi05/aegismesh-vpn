// Главный экран Stitch v2: Кристально понятный честный статус VPN, Мульти-VPN источники с галочками [✓]
// и компактная очередь серверов (активный сервер всегда №1 сверху, недоступные свёрнуты вниз)
import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  ClipboardPaste,
  ExternalLink,
  Play,
  Plus,
  RefreshCw,
  X,
  Zap,
} from 'lucide-react';
import { getUnavailableRemainingSec } from '../../shared/smartFailover';
import { formatSpeedHuman } from '../../shared/subscriptionMeta';
import type { VpnNode, VpnStateSnapshot } from '../../shared/types';
import { aegisApi } from '../api';
import { AiGatewayPanel } from './AiGatewayPanel';
import { MultiVpnSourcesPanel } from './MultiVpnSourcesPanel';
import { TacticalIcon } from './TacticalIcon';

interface Props {
  snapshot: VpnStateSnapshot;
  onUpdate: (next: VpnStateSnapshot) => void;
  onNotify: (msg: string, isError?: boolean) => void;
  onGoToNodes: () => void;
}

function formatSessionClock(connectedSince: number | null, now: number): string {
  if (!connectedSince) return '00:00:00';
  const sec = Math.max(0, Math.floor((now - connectedSince) / 1000));
  const h = String(Math.floor(sec / 3600)).padStart(2, '0');
  const m = String(Math.floor((sec % 3600) / 60)).padStart(2, '0');
  const s = String(sec % 60).padStart(2, '0');
  return `${h}:${m}:${s}`;
}

export const ShieldCascadeView: React.FC<Props> = ({
  snapshot,
  onUpdate,
  onNotify,
  onGoToNodes,
}) => {
  const [busy, setBusy] = useState(false);
  const [showUnavailable, setShowUnavailable] = useState(false);
  const [manualPasteInput, setManualPasteInput] = useState('');
  const [showQuickInput, setShowQuickInput] = useState(false);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const userNodes = snapshot.nodes
    .filter((n) => !n.isTestStand)
    .sort((a, b) => a.priority - b.priority);

  const isSourceChecked = (node: VpnNode): boolean => {
    if (node.isExternalClientBridge) return true;
    if (node.subscriptionId) {
      const sub = snapshot.subscriptions.find((s) => s.id === node.subscriptionId);
      return sub ? sub.enabledInFailover !== false : true;
    }
    return snapshot.manualGroupEnabledInFailover !== false;
  };

  const activePoolNodes = userNodes.filter((n) => n.enabled && isSourceChecked(n));
  const activeNode = userNodes.find((n) => n.id === snapshot.activeNodeId) || null;

  const isVerifiedConnected =
    snapshot.connectionState === 'connected' &&
    snapshot.telemetry?.verified !== false;
  const isVerifying =
    snapshot.connectionState === 'connecting' ||
    snapshot.connectionState === 'switching' ||
    (snapshot.connectionState === 'connected' && snapshot.telemetry?.verified === false);
  const isError =
    snapshot.connectionState === 'error' ||
    snapshot.connectionState === 'killswitch_locked';

  const healthyStandbyNodes = activePoolNodes.filter(
    (n) =>
      n.id !== activeNode?.id &&
      n.status !== 'down' &&
      n.status !== 'quarantined'
  );
  const unavailableNodes = userNodes.filter(
    (n) =>
      n.id !== activeNode?.id &&
      (n.status === 'down' || n.status === 'quarantined')
  );

  // Живой секундомер ближайшего автовозврата из карантина
  const minQuarantineRemainSec =
    unavailableNodes.length > 0
      ? Math.min(
          ...unavailableNodes.map((n) =>
            Math.max(0, getUnavailableRemainingSec(n, now))
          )
        )
      : 0;

  // Как только у любого сервера в карантине таймер доходит до 0 сек — мгновенно синхронизируем состояние,
  // чтобы сервер сам вышел из списка недоступных прямо на глазах пользователя без ручных действий!
  useEffect(() => {
    if (unavailableNodes.length > 0 && minQuarantineRemainSec === 0 && !busy) {
      void aegisApi
        .getState()
        .then((fresh) => onUpdate(fresh))
        .catch(() => {});
    }
  }, [unavailableNodes.length, minQuarantineRemainSec, busy, onUpdate]);

  const emergencyApp = (snapshot.installedVpnApps || []).find(
    (a) => a.packageName === snapshot.emergencyAppPackage
  );
  const failoverBanner = snapshot.telemetry?.lastFailoverBanner || null;

  const handleToggleVpn = async () => {
    if (busy) return;
    if (!isVerifiedConnected && !isVerifying && activePoolNodes.length === 0) {
      onNotify(
        'Добавьте свой VPN-ключ, подписку или запустите внешний VPN-клиент',
        true
      );
      setShowQuickInput(true);
      return;
    }
    setBusy(true);
    try {
      if (isVerifiedConnected || isVerifying || snapshot.connectionState === 'killswitch_locked') {
        const next = await aegisApi.disconnect();
        onUpdate(next);
        onNotify('VPN-туннель отключён');
      } else {
        const next = await aegisApi.connect();
        onUpdate(next);
        const conn = next.nodes.find((n) => n.id === next.activeNodeId);
        onNotify(
          conn
            ? `Туннель проверен! Подключено к «${conn.name}»`
            : 'VPN-туннель проверен и подключён'
        );
      }
    } catch (err) {
      const fresh = await aegisApi.getState().catch(() => null);
      if (fresh) onUpdate(fresh);
      onNotify(err instanceof Error ? err.message : 'Сбой подключения VPN', true);
    } finally {
      setBusy(false);
    }
  };

  const handleOneTapPasteImport = async (explicitText?: string) => {
    let payload = (explicitText ?? '').trim();
    if (!payload) {
      try {
        payload = (await navigator.clipboard.readText()).trim();
      } catch {
        setShowQuickInput(true);
        onNotify('Вставьте ссылку или ключ в открывшееся поле ниже', false);
        return;
      }
    }
    if (!payload) {
      setShowQuickInput(true);
      onNotify('Буфер обмена пуст — вставьте ключ или https:// подписку ниже', true);
      return;
    }

    setBusy(true);
    try {
      const isSubUrl =
        /^https?:\/\/\S+$/i.test(payload) &&
        !payload.includes('\n') &&
        !/:\/\/[^/]*@/.test(payload);
      if (isSubUrl) {
        const next = await aegisApi.addSubscription('', payload);
        onUpdate(next);
        setManualPasteInput('');
        setShowQuickInput(false);
        const addedSub = next.subscriptions[next.subscriptions.length - 1];
        onNotify(
          `Подписка «${addedSub?.name || 'VPN'}» загружена (${addedSub?.nodeCount || 0} серверов)!`
        );
        return;
      }
      const { result, snapshot: next } = await aegisApi.importNodes(payload);
      onUpdate(next);
      if (result.nodes.length > 0) {
        setManualPasteInput('');
        setShowQuickInput(false);
        onNotify(`Добавлено рабочих серверов в автозамену: ${result.nodes.length}`);
      } else {
        const msg =
          result.infoMessages && result.infoMessages.length > 0
            ? result.infoMessages.join(' • ')
            : result.errors[0] || 'Не удалось распознать ключ или ссылку подписки';
        onNotify(msg, true);
      }
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Ошибка импорта VPN', true);
    } finally {
      setBusy(false);
    }
  };

  const handleSmartOptimize = async () => {
    if (busy) return;
    if (activePoolNodes.length === 0) {
      onNotify('Сначала добавьте VPN-подписку, ключ или внешний клиент', true);
      setShowQuickInput(true);
      return;
    }
    setBusy(true);
    try {
      const next = await aegisApi.smartOptimize();
      onUpdate(next);
      const best = next.nodes.find((n) => n.id === next.activeNodeId);
      const speedBadge = next.telemetry?.measuredBandwidthKbps
        ? `, ${(next.telemetry.measuredBandwidthKbps / 1000).toFixed(1)} Мбит/с`
        : '';
      onNotify(
        best
          ? `⚡ Выбран лучший сервер: «${best.name}» (${best.latencyMs ?? 'ОК'} мс, рейтинг ${best.smartScore ?? 92}★${speedBadge})`
          : '⚡ Турбо-подбор лучшего VPN завершён'
      );
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Сбой турбо-подбора VPN', true);
    } finally {
      setBusy(false);
    }
  };

  const handleConnectSpecific = async (node: VpnNode) => {
    if (busy) return;
    setBusy(true);
    try {
      const next = await aegisApi.switchNode(node.id);
      onUpdate(next);
      onNotify(`Туннель переключён на «${node.name}»`);
    } catch (err) {
      const fresh = await aegisApi.getState().catch(() => null);
      if (fresh) onUpdate(fresh);
      onNotify(err instanceof Error ? err.message : 'Сервер не прошёл проверку', true);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-4">
      {/* ЯНТАРНЫЙ БАННЕР СРАБОТАВШЕЙ АВТОЗАМЕНЫ */}
      {failoverBanner && (
        <div className="p-3.5 rounded-lg bg-[#FFB020]/15 border border-[#FFB020]/60 flex items-start justify-between gap-3">
          <div className="flex items-start gap-2.5 min-w-0">
            <Zap size={18} className="text-[#FFB020] flex-shrink-0 mt-0.5" />
            <div className="text-xs space-y-0.5 min-w-0">
              <div className="font-badge-code text-[#FFB020] font-bold uppercase">
                Сработала Мульти-VPN Автозамена
              </div>
              <div className="text-on-surface">
                <span className="text-on-surface-variant">{failoverBanner.fromName}</span>{' '}
                <ArrowRight size={12} className="inline mx-1 text-[#FFB020]" />{' '}
                <strong className="text-primary">{failoverBanner.toName}</strong>
              </div>
              <div className="text-on-surface-variant text-[11px] truncate">
                {failoverBanner.reason}
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={async () => {
              const next = await aegisApi.dismissFailoverBanner();
              onUpdate(next);
            }}
            className="p-1 text-on-surface-variant hover:text-on-surface cursor-pointer"
            title="Скрыть уведомление"
          >
            <X size={16} />
          </button>
        </div>
      )}

      {/* 1. КАРТОЧКА ЧЕСТНОГО СТАТУСА VPN (HERO CARD — STITCH TACTICAL TELEMETRY v3.6) */}
      <div
        className={`relative overflow-hidden rounded-2xl bg-surface p-4 md:p-6 border transition-all ${
          isVerifiedConnected
            ? 'border-primary-container/80 shield-glow'
            : isVerifying || busy
              ? 'border-[#FFB020]/70 amber-glow'
              : isError
                ? 'border-error/80 crimson-glow'
                : 'border-outline-variant'
        }`}
      >
        {/* Фирменный верхний градиентный акцент Stitch и мягкое радиальное свечение */}
        <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-secondary-container via-primary-container to-secondary-container opacity-80" />
        <div className="pointer-events-none absolute -top-24 left-1/2 -translate-x-1/2 w-72 h-40 rounded-full bg-primary-container/10 blur-3xl" />

        <div className="relative grid grid-cols-1 md:grid-cols-[1fr_auto] gap-4 items-center">
          {/* Верхний блок статуса и заголовка узла */}
          <div className="order-1 md:col-start-1 md:row-start-1 flex flex-col items-center md:items-start text-center md:text-left space-y-2.5 w-full min-w-0">
            <div className="flex flex-wrap items-center justify-center md:justify-start gap-2 w-full">
              <div
                className={`inline-flex items-center gap-2 px-3 py-1 rounded-full border font-badge-code text-[11px] font-bold ${
                  isVerifiedConnected
                    ? 'bg-primary-container/15 border-primary-container/50 text-primary-container'
                    : isVerifying || busy
                      ? 'bg-[#FFB020]/15 border-[#FFB020]/50 text-[#FFB020]'
                      : isError
                        ? 'bg-error-container/30 border-error/50 text-error'
                        : 'bg-surface-container-high border-outline-variant text-on-surface-variant'
                }`}
              >
                <span
                  className={`w-2 h-2 rounded-full flex-shrink-0 ${
                    isVerifiedConnected
                      ? 'bg-primary-container animate-pulse'
                      : isVerifying || busy
                        ? 'bg-[#FFB020] animate-ping'
                        : isError
                          ? 'bg-error'
                          : 'bg-outline'
                  }`}
                />
                <span>
                  {isVerifiedConnected
                    ? 'VPN РАБОТАЕТ • ТУННЕЛЬ ПРОВЕРЕН'
                    : isVerifying || busy
                      ? 'ПРОВЕРКА ТУННЕЛЯ...'
                      : isError
                        ? 'СБОЙ ПОДКЛЮЧЕНИЯ • VPN ВЫКЛЮЧЕН'
                        : 'VPN ВЫКЛЮЧЕН'}
                </span>
              </div>

              <span className="font-badge-code text-[10px] px-2 py-1 rounded-full bg-surface-container-high border border-outline-variant/60 text-secondary">
                {activeNode ? `${activeNode.protocol.toUpperCase()} • ` : ''}
                {snapshot.telemetry?.physicalNetworkType === 'cellular'
                  ? '📶 LTE'
                  : '🏠 Wi-Fi'}
              </span>
            </div>

            <div className="w-full min-w-0">
              <h2 className="font-headline-lg text-xl md:text-2xl text-on-surface font-bold text-center md:text-left">
                {isVerifiedConnected && activeNode
                  ? activeNode.name
                  : isVerifying || busy
                    ? snapshot.telemetry?.verifyingStep || 'Проверяем сквозной доступ в интернет...'
                    : isError
                      ? 'Не удалось установить рабочий туннель'
                      : activePoolNodes.length > 0
                        ? `Готово к защите (${activePoolNodes.length} серв. в автозамене)`
                        : 'Добавьте свой VPN или включите внешний клиент'}
              </h2>
              <p className="font-body-sm text-xs text-on-surface-variant mt-1 text-center md:text-left">
                {isVerifiedConnected && activeNode
                  ? `Источник: ${activeNode.providerName || 'Мои VPN'} • Протокол: ${activeNode.protocol.toUpperCase()}`
                  : isError
                    ? snapshot.telemetry?.lastErrorReason ||
                      'Ни один из отмеченных серверов не ответил. Ложный значок VPN отключён.'
                    : 'Значок «Работает» загорается только после реальной проверки связи сквозь VPN-туннель.'}
              </p>
            </div>
          </div>

          {/* Центральная тактическая кнопка-щит (Tactical Shield Orb) */}
          <div className="order-2 md:col-start-2 md:row-start-1 md:row-span-2 flex justify-center py-1 md:py-0">
            <button
              type="button"
              disabled={busy}
              onClick={handleToggleVpn}
              className={`w-36 h-36 md:w-40 md:h-40 rounded-full flex-shrink-0 border-2 flex flex-col items-center justify-center text-center p-3 active:scale-95 transition-all cursor-pointer ${
                isVerifiedConnected
                  ? 'bg-gradient-to-b from-[#0f2922] to-[#081715] border-primary-container ring-4 ring-primary-container/15 shield-glow'
                  : isVerifying || busy
                    ? 'bg-gradient-to-b from-[#29200f] to-[#171208] border-[#FFB020] ring-4 ring-[#FFB020]/15'
                    : 'bg-gradient-to-b from-[#131D29] to-[#0A1018] border-secondary-container/70 ring-4 ring-secondary-container/15 cyan-glow'
              }`}
            >
              <div
                className={`w-11 h-11 rounded-full flex items-center justify-center mb-1.5 ${
                  isVerifiedConnected
                    ? 'bg-primary-container/20 text-primary-container'
                    : isVerifying || busy
                      ? 'bg-[#FFB020]/20 text-[#FFB020]'
                      : 'bg-secondary-container/20 text-secondary'
                }`}
              >
                <TacticalIcon
                  name={isVerifiedConnected ? 'shield' : 'power_settings_new'}
                  size={24}
                />
              </div>
              <span className="font-badge-code text-xs font-bold tracking-wider text-on-surface">
                {isVerifying || busy
                  ? 'ПРОВЕРКА...'
                  : isVerifiedConnected
                    ? 'ОТКЛЮЧИТЬ'
                    : 'ВКЛЮЧИТЬ VPN'}
              </span>
              <span className="font-telemetry-sm text-[11px] text-on-surface-variant font-mono mt-0.5">
                {isVerifiedConnected
                  ? formatSessionClock(snapshot.connectedSince, now)
                  : 'АВТОЗАМЕНА'}
              </span>
            </button>
          </div>

          {/* Симметричная сетка быстрых действий (под Щитом на смартфонах, слева на ПК) */}
          <div className="order-3 md:col-start-1 md:row-start-2 w-full space-y-2">
            {isError && emergencyApp && (
              <button
                type="button"
                onClick={async () => {
                  try {
                    const next = await aegisApi.launchEmergencyApp(emergencyApp.packageName);
                    onUpdate(next);
                  } catch (err) {
                    onNotify(err instanceof Error ? err.message : 'Не удалось открыть приложение', true);
                  }
                }}
                className="w-full px-4 py-2.5 min-h-[44px] rounded-xl bg-[#FFB020] text-[#0A0E14] font-badge-code text-xs font-bold flex items-center justify-center gap-2 cursor-pointer"
              >
                <ExternalLink size={15} />
                <span>Открыть резервный VPN: {emergencyApp.appName}</span>
              </button>
            )}

            {activePoolNodes.length > 0 && (
              <button
                type="button"
                disabled={busy}
                onClick={() => void handleSmartOptimize()}
                className="w-full py-2.5 px-4 min-h-[44px] rounded-xl bg-primary-container/15 hover:bg-primary-container/25 border border-primary-container/60 text-primary-container font-telemetry-md text-xs font-bold flex items-center justify-center gap-2 transition-colors cursor-pointer"
              >
                <Zap size={15} />
                <span>⚡ Турбо-подбор лучшего VPN</span>
              </button>
            )}

            <div className="grid grid-cols-2 gap-2 w-full">
              <button
                type="button"
                disabled={busy}
                onClick={() => void handleOneTapPasteImport()}
                className="w-full py-2.5 px-3 min-h-[44px] rounded-xl bg-surface-container-high hover:bg-surface-variant border border-primary-container/40 text-primary font-telemetry-md text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
              >
                <ClipboardPaste size={15} className="flex-shrink-0" />
                <span className="truncate">+ Вставить ключ</span>
              </button>
              <button
                type="button"
                onClick={onGoToNodes}
                className="w-full py-2.5 px-3 min-h-[44px] rounded-xl bg-surface-container hover:bg-surface-container-high border border-outline-variant text-on-surface font-telemetry-md text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
              >
                <Plus size={15} className="flex-shrink-0" />
                <span className="truncate">🔑 Мои VPN ({userNodes.length})</span>
              </button>
            </div>
          </div>
        </div>

        {/* Раскрываемое поле ручной вставки (если буфер недоступен) */}
        {showQuickInput && (
          <div className="mt-4 pt-3 border-t border-outline-variant flex flex-col sm:flex-row gap-2">
            <input
              type="text"
              value={manualPasteInput}
              onChange={(e) => setManualPasteInput(e.target.value)}
              placeholder="Вставьте https:// ссылку подписки или ключ vless://, hy2://, ss://, wg://..."
              className="flex-1 bg-[#070A0F] border border-outline-variant rounded-xl px-3 py-2.5 min-h-[44px] text-xs text-on-surface font-mono focus:border-primary-container focus:outline-none"
            />
            <button
              type="button"
              disabled={busy}
              onClick={() => void handleOneTapPasteImport(manualPasteInput)}
              className="px-4 py-2.5 min-h-[44px] rounded-xl bg-primary-container text-on-primary font-badge-code text-xs font-bold cursor-pointer"
            >
              Добавить
            </button>
          </div>
        )}

        {/* 4 ПОНЯТНЫЕ ПЛИТКИ ЖИВОЙ ТЕЛЕМЕТРИИ (STITCH TACTICAL TELEMETRY GRID) */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-2.5 mt-4 pt-4 border-t border-outline-variant/60">
          {/* 1. СЕРВИС / ПРОТОКОЛ */}
          <div className="p-3 rounded-xl bg-surface-container-lowest/90 border border-outline-variant/60 flex flex-col justify-between gap-1.5">
            <div className="flex items-center justify-between gap-1">
              <span className="font-telemetry-sm text-[10px] tracking-wider uppercase text-on-surface-variant truncate">
                СЕРВИС / ПРОТОКОЛ
              </span>
              {isVerifiedConnected && activeNode && (
                <span className="font-badge-code text-[9px] px-1.5 py-0.5 rounded bg-surface-container-high text-secondary border border-outline-variant/60 flex-shrink-0">
                  {activeNode.protocol.toUpperCase()}
                </span>
              )}
            </div>
            <span className="font-telemetry-md text-xs text-on-surface font-bold truncate block">
              {isVerifiedConnected && activeNode
                ? activeNode.providerName || 'Мои VPN'
                : 'Не подключён'}
            </span>
          </div>

          {/* 2. ВНЕШНИЙ IP */}
          <div className="p-3 rounded-xl bg-surface-container-lowest/90 border border-outline-variant/60 flex flex-col justify-between gap-1.5">
            <div className="flex items-center justify-between gap-1">
              <span className="font-telemetry-sm text-[10px] tracking-wider uppercase text-on-surface-variant truncate">
                ВНЕШНИЙ IP
              </span>
              {isVerifiedConnected && snapshot.telemetry?.exitCountry && (
                <span className="font-badge-code text-[9px] px-1.5 py-0.5 rounded bg-secondary-container/15 text-secondary-container border border-secondary-container/35 flex-shrink-0">
                  [{snapshot.telemetry.exitCountry}]
                </span>
              )}
            </div>
            <span className="font-telemetry-md text-xs text-secondary font-mono font-bold truncate block">
              {isVerifiedConnected
                ? snapshot.telemetry?.exitIp || 'Проверка...'
                : 'Без маскировки'}
            </span>
          </div>

          {/* 3. ПИНГ И РЕЙТИНГ */}
          <div className="p-3 rounded-xl bg-surface-container-lowest/90 border border-outline-variant/60 flex flex-col justify-between gap-1.5">
            <div className="flex items-center justify-between gap-1">
              <span className="font-telemetry-sm text-[10px] tracking-wider uppercase text-on-surface-variant truncate">
                ПИНГ И РЕЙТИНГ
              </span>
              {isVerifiedConnected && activeNode?.smartScore && (
                <span className="font-badge-code text-[9px] px-1.5 py-0.5 rounded bg-[#FFB020]/15 text-[#FFB020] border border-[#FFB020]/40 font-bold flex-shrink-0">
                  {activeNode.smartScore}★
                </span>
              )}
            </div>
            <span className="font-telemetry-md text-xs text-primary-container font-mono font-bold truncate block">
              {isVerifiedConnected && activeNode?.latencyMs
                ? `${activeNode.latencyMs} мс${
                    typeof activeNode.jitterMs === 'number' ? ` • ±${activeNode.jitterMs} мс` : ''
                  }`
                : '—'}
            </span>
          </div>

          {/* 4. СКОРОСТЬ ПОТОКА */}
          <div className="p-3 rounded-xl bg-surface-container-lowest/90 border border-outline-variant/60 flex flex-col justify-between gap-1.5">
            <div className="flex items-center justify-between gap-1">
              <span className="font-telemetry-sm text-[10px] tracking-wider uppercase text-on-surface-variant truncate">
                СКОРОСТЬ ПОТОКА
              </span>
              {isVerifiedConnected && snapshot.telemetry?.measuredBandwidthKbps ? (
                <span className="font-badge-code text-[9px] px-1.5 py-0.5 rounded bg-primary-container/15 text-primary-container border border-primary-container/35 flex-shrink-0">
                  {(snapshot.telemetry.measuredBandwidthKbps / 1000).toFixed(1)}M
                </span>
              ) : null}
            </div>
            <span className="font-telemetry-md text-xs text-on-surface font-mono font-bold truncate block">
              {isVerifiedConnected
                ? `↓ ${formatSpeedHuman(snapshot.telemetry?.rxSpeedBps)} • ↑ ${formatSpeedHuman(snapshot.telemetry?.txSpeedBps)}`
                : '0 КБ/с'}
            </span>
          </div>
        </div>

        {/* 1.2. ПЛАШКА ИНТЕЛЛЕКТУАЛЬНОГО РОУМИНГА СЕТЕЙ (Wi-Fi ⇄ LTE) И СБРОСА СОКЕТОВ В 1 ТАП */}
        <div className="mt-2.5 p-2.5 rounded-lg bg-surface-container-lowest border border-outline-variant flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2 text-[11px] min-w-0">
            <span
              className={`px-2 py-0.5 rounded font-badge-code font-bold ${
                snapshot.telemetry?.physicalNetworkType === 'cellular'
                  ? 'bg-[#FFB020]/20 text-[#FFB020] border border-[#FFB020]/40'
                  : 'bg-secondary/15 text-secondary border border-secondary/35'
              }`}
            >
              {snapshot.telemetry?.physicalNetworkType === 'cellular'
                ? `📶 Мобильная сеть LTE/4G • MTU ${snapshot.telemetry?.activeMtu || 1360}`
                : `🏠 Сеть Wi-Fi • MTU ${snapshot.telemetry?.activeMtu || 1400}`}
            </span>
            <span className="text-on-surface-variant truncate">
              Память сетей:{' '}
              <strong className="text-on-surface">
                🏠 {snapshot.telemetry?.bestWifiNodeName || 'авто'}
              </strong>{' '}
              •{' '}
              <strong className="text-on-surface">
                📶 {snapshot.telemetry?.bestCellularNodeName || 'авто'}
              </strong>
            </span>
            {(snapshot.telemetry?.roamingHandoverCount || 0) > 0 && (
              <span className="px-1.5 py-0.5 rounded bg-primary-container/15 text-primary-container font-badge-code text-[10px]">
                Бесшовных смен сети: {snapshot.telemetry?.roamingHandoverCount}
              </span>
            )}
          </div>
          <button
            type="button"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                const next = await aegisApi.rebindNetwork();
                onUpdate(next);
                onNotify('Сокеты сброшены, маршрут успешно обновлён под текущую сеть');
              } catch (err) {
                onNotify((err as Error).message, true);
              } finally {
                setBusy(false);
              }
            }}
            className="px-2.5 py-1 rounded border border-secondary/40 bg-secondary/10 text-secondary font-badge-code text-[11px] font-bold hover:bg-secondary/20 transition-colors cursor-pointer flex items-center gap-1"
            title="Мгновенно закрывает зависшие соединения и перепривязывает туннель к текущей сети Wi-Fi или LTE без отключения VPN"
          >
            <RefreshCw size={12} />
            Сбросить сокеты / Маршрут
          </button>
        </div>
      </div>

      {/* 1.5. УМНЫЙ ШЛЮЗ ДЛЯ НЕЙРОСЕТЕЙ (GEMINI • CHATGPT • GROK) */}
      <AiGatewayPanel
        snapshot={snapshot}
        onUpdate={onUpdate}
        onNotify={onNotify}
        variant="compact"
      />

      {/* 2. ЧТО УЧАСТВУЕТ В АВТОЗАМЕНЕ (ГАЛОЧКИ [✓] ПОДПИСОК И ВНЕШНИХ КЛИЕНТОВ) */}
      <MultiVpnSourcesPanel
        snapshot={snapshot}
        onUpdate={onUpdate}
        onNotify={onNotify}
        onAddMore={onGoToNodes}
      />

      {/* 3. ПОДКЛЮЧЁННЫЙ СЕРВЕР (ВСЕГДА №1 СВЕРХУ) И КОМПАКТНАЯ ОЧЕРЕДЬ РЕЗЕРВА */}
      <div className="rounded-lg bg-surface border border-outline-variant p-4 space-y-3">
        <div className="flex items-center justify-between gap-2 pb-2 border-b border-outline-variant">
          <div>
            <h3 className="font-headline-md text-sm md:text-base text-on-surface font-bold">
              Подключённый сервер и очередь резерва
            </h3>
            <p className="font-body-sm text-xs text-on-surface-variant">
              Автозамен за сессию: <strong className="text-primary">{snapshot.failoverSwitchCount}</strong>
            </p>
          </div>
          {userNodes.length > 0 && (
            <button
              type="button"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                try {
                  const next = await aegisApi.pingAll();
                  onUpdate(next);
                  onNotify('Пинг всех серверов обновлён');
                } finally {
                  setBusy(false);
                }
              }}
              className="px-2.5 py-1.5 min-h-[38px] rounded bg-surface-container-high hover:bg-surface-variant border border-outline-variant text-on-surface font-badge-code text-[11px] flex items-center gap-1.5 cursor-pointer"
            >
              <RefreshCw size={13} className={busy ? 'animate-spin' : ''} />
              <span>Пинг</span>
            </button>
          )}
        </div>

        {/* Активный подключённый сервер — ВСЕГДА закреплён №1 сверху */}
        {isVerifiedConnected && activeNode && (
          <div className="p-3.5 rounded-lg bg-primary-container/10 border-2 border-primary-container flex items-center justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-badge-code text-[10px] px-2 py-0.5 rounded bg-primary-container text-on-primary font-bold">
                  СЕЙЧАС ПОДКЛЮЧЕН
                </span>
                <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-surface-container-high text-secondary border border-outline-variant">
                  {activeNode.providerName || 'Мои VPN'}
                </span>
                {activeNode.smartScore && (
                  <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-[#FFB020]/15 text-[#FFB020] border border-[#FFB020]/40 font-bold">
                    {activeNode.smartScore}★ УМНЫЙ РЕЙТИНГ
                  </span>
                )}
                {snapshot.telemetry?.nativeWatchdogActive && (
                  <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-primary-container/15 text-primary-container border border-primary-container/40">
                    СТОРОЖ 24/7
                  </span>
                )}
                {snapshot.settings.aiRoutingEnabled !== false &&
                  snapshot.telemetry?.activeAiNodeId === activeNode.id && (
                    <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-[#38BDF8]/15 text-[#38BDF8] border border-[#38BDF8]/45 font-bold">
                      🤖 ШЛЮЗ ИИ
                    </span>
                  )}
                {activeNode.aiStatus === 'ok' && (
                  <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-primary-container/15 text-primary-container border border-primary-container/40">
                    {activeNode.aiGeminiOk ? 'Gemini✓' : 'AI OK'}
                  </span>
                )}
              </div>
              <div className="font-headline-md text-sm md:text-base text-on-surface font-bold truncate mt-1">
                {activeNode.name}
              </div>
              <div className="font-telemetry-sm text-[11px] text-on-surface-variant font-mono">
                {activeNode.protocol.toUpperCase()} • {activeNode.server}:{activeNode.port}
              </div>
            </div>
            <div className="text-right flex-shrink-0">
              <div className="font-mono text-sm font-bold text-primary-container">
                {activeNode.latencyMs ? `${activeNode.latencyMs} мс` : 'ОК'}
              </div>
              <div className="font-badge-code text-[10px] text-primary">РАБОТАЕТ</div>
            </div>
          </div>
        )}

        {/* Компактные строки здоровых резервных серверов */}
        {healthyStandbyNodes.length > 0 ? (
          <div className="space-y-2">
            {healthyStandbyNodes.map((node, index) => (
              <div
                key={node.id}
                className="p-3 rounded-lg bg-surface-container-lowest border border-outline-variant hover:border-primary-container/50 flex items-center justify-between gap-3 transition-colors"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-surface-container-high text-primary border border-outline-variant">
                      {isVerifiedConnected ? `РЕЗЕРВ #${index + 1}` : `ОЧЕРЕДЬ #${index + 1}`}
                    </span>
                    <span className="font-telemetry-sm text-[11px] text-secondary truncate">
                      {node.providerName || 'Мои VPN'}
                    </span>
                    {snapshot.settings.aiRoutingEnabled !== false &&
                      snapshot.telemetry?.activeAiNodeId === node.id && (
                        <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-[#38BDF8]/20 text-[#38BDF8] border border-[#38BDF8]/50 font-bold">
                          🤖 ШЛЮЗ ИИ
                        </span>
                      )}
                    {node.aiStatus === 'ok' && (
                      <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-primary-container/15 text-primary-container border border-primary-container/40">
                        {node.aiGeminiOk ? 'Gemini✓' : 'AI OK'}
                      </span>
                    )}
                    {node.aiStatus === 'blocked' && (
                      <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-surface-container-high text-on-surface-variant border border-outline-variant">
                        Без ИИ{node.aiExitCountry ? ` (${node.aiExitCountry})` : ''}
                      </span>
                    )}
                  </div>
                  <div className="font-headline-md text-sm text-on-surface font-semibold truncate mt-0.5">
                    {node.name}
                  </div>
                </div>

                <div className="flex items-center gap-2.5 flex-shrink-0">
                  {node.smartScore && (
                    <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-surface-container-high text-[#FFB020] border border-[#FFB020]/30 font-bold">
                      {node.smartScore}★
                    </span>
                  )}
                  <span className="font-mono text-xs text-primary-container font-bold">
                    {node.latencyMs !== null ? `${node.latencyMs} мс` : 'Готов'}
                  </span>
                  {snapshot.settings.aiRoutingEnabled !== false &&
                    snapshot.telemetry?.activeAiNodeId !== node.id &&
                    node.aiStatus !== 'blocked' && (
                      <button
                        type="button"
                        disabled={busy}
                        title="Назначить этот сервер специально для нейросетей (Gemini / GPT / Grok)"
                        onClick={async () => {
                          setBusy(true);
                          try {
                            const next = await aegisApi.switchAiNode(node.id);
                            onUpdate(next);
                            onNotify(`🤖 Шлюз Нейросетей закреплён на «${node.name}»`);
                          } catch (err) {
                            onNotify(
                              err instanceof Error ? err.message : 'Сбой переключения ИИ',
                              true
                            );
                          } finally {
                            setBusy(false);
                          }
                        }}
                        className="px-2 py-2 min-h-[38px] rounded bg-[#38BDF8]/10 hover:bg-[#38BDF8]/25 border border-[#38BDF8]/40 text-[#38BDF8] text-[11px] font-badge-code transition-colors cursor-pointer"
                      >
                        ИИ
                      </button>
                    )}
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void handleConnectSpecific(node)}
                    className="px-3 py-2 min-h-[38px] rounded bg-surface-container-high hover:bg-primary-container hover:text-on-primary border border-outline-variant text-xs font-badge-code flex items-center gap-1 transition-colors cursor-pointer"
                  >
                    <Play size={12} />
                    <span>Вкл</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : !isVerifiedConnected && unavailableNodes.length === 0 ? (
          <div className="p-4 rounded-lg bg-surface-container-lowest border border-dashed border-outline-variant text-center text-xs text-on-surface-variant">
            Список серверов пока пуст. Нажмите <strong>«+ Вставить ключ или подписку»</strong> выше или запустите сторонний VPN-клиент (Happ, v2rayNG, Throne, NekoBox, Clash, ByeDPI).
          </div>
        ) : null}

        {/* Свёрнутый аккордеон временного карантина с живым таймером автовозврата */}
        {unavailableNodes.length > 0 && (
          <div className="pt-2 border-t border-outline-variant">
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => setShowUnavailable((v) => !v)}
                className="flex-1 min-w-[200px] py-2 px-3 min-h-[40px] rounded bg-surface-container-low hover:bg-surface-container border border-outline-variant text-xs text-on-surface-variant flex items-center justify-between gap-2 cursor-pointer"
              >
                <span className="flex items-center gap-1.5 min-w-0 flex-wrap">
                  <AlertTriangle size={14} className="text-[#FFB020] flex-shrink-0" />
                  <span className="truncate">
                    Временный карантин: {unavailableNodes.length}
                  </span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface-container-high text-primary-container border border-primary-container/30 font-mono">
                    {minQuarantineRemainSec > 0
                      ? `автовозврат ~${minQuarantineRemainSec} с`
                      : 'автовозврат...'}
                  </span>
                </span>
                {showUnavailable ? (
                  <ChevronUp size={15} className="flex-shrink-0" />
                ) : (
                  <ChevronDown size={15} className="flex-shrink-0" />
                )}
              </button>

              <button
                type="button"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    const prevCount = unavailableNodes.length;
                    const next = await aegisApi.recoverUnavailableNodes();
                    onUpdate(next);
                    const stillQuarantined = next.nodes.filter(
                      (n) =>
                        !n.isTestStand &&
                        n.id !== next.activeNodeId &&
                        (n.status === 'down' || n.status === 'quarantined')
                    ).length;
                    const restored = Math.max(0, prevCount - stillQuarantined);
                    onNotify(
                      restored > 0
                        ? `Вернулись в строй серверов: ${restored}`
                        : 'Серверы перепроверены — недоступные выйдут автоматически по мере оживления'
                    );
                  } catch (err) {
                    onNotify(
                      err instanceof Error ? err.message : 'Сбой проверки карантина',
                      true
                    );
                  } finally {
                    setBusy(false);
                  }
                }}
                className="py-2 px-3 min-h-[40px] rounded bg-primary-container/15 hover:bg-primary-container/25 border border-primary-container/40 text-xs text-primary-container font-semibold flex items-center gap-1.5 flex-shrink-0 cursor-pointer"
              >
                <RefreshCw size={13} className={busy ? 'animate-spin' : ''} />
                <span>Вернуть все</span>
              </button>
            </div>

            {showUnavailable && (
              <div className="space-y-1.5 mt-2">
                <div className="text-[11px] text-on-surface-variant px-1">
                  Серверы не застревают здесь навсегда: AegisMesh сам возвращает их по таймеру и тихо проверяет в фоне.
                </div>
                {unavailableNodes.map((node) => {
                  const remainSec = getUnavailableRemainingSec(node, now);
                  return (
                    <div
                      key={node.id}
                      className="p-2.5 rounded bg-surface-container-lowest/60 border border-error/30 flex items-center justify-between gap-2 text-xs opacity-90"
                    >
                      <div className="min-w-0">
                        <div className="font-semibold text-on-surface truncate flex items-center gap-1.5 flex-wrap">
                          <span className="truncate">{node.name}</span>
                          <span className="text-on-surface-variant font-normal text-[11px]">
                            ({node.providerName || 'Мои VPN'})
                          </span>
                          {remainSec > 0 && (
                            <span className="text-[10px] font-mono text-primary-container bg-surface-container px-1.5 py-0.5 rounded">
                              ~{remainSec} с
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-error truncate mt-0.5">
                          {node.lastError || 'Временный таймаут сквозной проверки'}
                        </div>
                      </div>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={async () => {
                          setBusy(true);
                          try {
                            const next = await aegisApi.probeNode(node.id);
                            onUpdate(next);
                            const updated = next.nodes.find((x) => x.id === node.id);
                            if (
                              updated &&
                              updated.status !== 'down' &&
                              updated.status !== 'quarantined'
                            ) {
                              onNotify(
                                `Сервер «${node.name}» снова в строю${updated.latencyMs ? ` (${updated.latencyMs} мс)` : ''}!`
                              );
                            } else {
                              onNotify(
                                `«${node.name}» пока не ответил — автовозврат повторится автоматически`,
                                true
                              );
                            }
                          } catch (err) {
                            onNotify(
                              err instanceof Error ? err.message : 'Ошибка проверки сервера',
                              true
                            );
                          } finally {
                            setBusy(false);
                          }
                        }}
                        className="px-2.5 py-1.5 min-h-[34px] rounded bg-surface-container hover:bg-surface-container-high border border-outline-variant text-[11px] text-on-surface flex-shrink-0 cursor-pointer"
                      >
                        Проверить
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
