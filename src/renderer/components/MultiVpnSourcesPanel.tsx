// Секция «Что участвует в автозамене» (Мульти-VPN оркестратор Stitch v2):
// Галочки [✓] для разных VPN-подписок, личных ключей и внешних VPN-клиентов (Happ, v2rayNG, Throne, NekoBox, Clash, Hiddify, ByeDPI, Orbot)
import React, { useState } from 'react';
import { Check, ChevronDown, ChevronUp, Plus, Radar, RefreshCw } from 'lucide-react';
import { formatBytesHuman } from '../../shared/subscriptionMeta';
import type { VpnStateSnapshot } from '../../shared/types';
import { aegisApi } from '../api';
import { TacticalIcon } from './TacticalIcon';

interface Props {
  snapshot: VpnStateSnapshot;
  onUpdate: (next: VpnStateSnapshot) => void;
  onNotify: (msg: string, isError?: boolean) => void;
  onAddMore?: () => void;
}

export const MultiVpnSourcesPanel: React.FC<Props> = ({
  snapshot,
  onUpdate,
  onNotify,
  onAddMore,
}) => {
  const [scanning, setScanning] = useState(false);
  const [showAllClients, setShowAllClients] = useState(false);

  const userNodes = snapshot.nodes.filter(
    (n) => !n.isTestStand && !n.isExternalClientBridge
  );
  const manualNodes = userNodes.filter((n) => !n.subscriptionId);
  const externalClients = snapshot.externalClients || [];
  const runningOrCheckedClients = externalClients.filter(
    (c) => c.detectedRunning || c.enabledInFailover
  );
  const displayedClients = showAllClients
    ? externalClients
    : runningOrCheckedClients.length > 0
      ? runningOrCheckedClients
      : externalClients.slice(0, 3);

  const manualChecked = snapshot.manualGroupEnabledInFailover !== false;

  const handleScanClients = async () => {
    setScanning(true);
    try {
      const next = await aegisApi.scanExternalClients();
      onUpdate(next);
      const found = (next.externalClients || []).filter((c) => c.detectedRunning);
      onNotify(
        found.length > 0
          ? `Найдено запущенных внешних VPN-клиентов: ${found.length}`
          : 'Запущенные локальные прокси-клиенты (127.0.0.1) пока не обнаружены'
      );
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Ошибка сканирования портов', true);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="rounded-lg bg-surface border border-outline-variant p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-outline-variant">
        <div>
          <h3 className="font-headline-md text-sm md:text-base text-on-surface font-bold flex items-center gap-2">
            <TacticalIcon name="hub" size={17} className="text-primary-container" />
            <span>Что участвует в автозамене</span>
          </h3>
          <p className="font-body-sm text-xs text-on-surface-variant mt-0.5">
            Отметьте галочками все подписки и внешние VPN-клиенты — при сбое одного AegisMesh мгновенно переключится на другой.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={scanning}
            onClick={handleScanClients}
            className="px-2.5 py-1.5 min-h-[38px] rounded bg-surface-container-high hover:bg-surface-variant border border-secondary-container/50 text-secondary font-badge-code text-[11px] flex items-center gap-1.5 cursor-pointer"
          >
            {scanning ? <RefreshCw size={13} className="animate-spin" /> : <Radar size={14} />}
            <span>{scanning ? 'Поиск...' : 'Найти клиенты'}</span>
          </button>
          {onAddMore && (
            <button
              type="button"
              onClick={onAddMore}
              className="px-2.5 py-1.5 min-h-[38px] rounded bg-primary-container/15 hover:bg-primary-container/25 border border-primary-container/40 text-primary font-badge-code text-[11px] flex items-center gap-1 cursor-pointer"
            >
              <Plus size={13} />
              <span>Добавить</span>
            </button>
          )}
        </div>
      </div>

      <div className="space-y-2">
        {/* Уровень 1А: Независимые подписки (разные VPN-сервисы) */}
        {snapshot.subscriptions.map((sub, idx) => {
          const checked = sub.enabledInFailover !== false;
          const subNodes = userNodes.filter((n) => n.subscriptionId === sub.id);
          const aliveCount = subNodes.filter(
            (n) => n.status !== 'down' && n.status !== 'quarantined'
          ).length;
          return (
            <div
              key={sub.id}
              onClick={async () => {
                const next = await aegisApi.toggleSubscriptionFailover(sub.id, !checked);
                onUpdate(next);
              }}
              className={`p-3 rounded-lg border flex items-center justify-between gap-3 cursor-pointer transition-colors ${
                checked
                  ? 'bg-surface-container-lowest border-primary-container/50'
                  : 'bg-surface-container-lowest/50 border-outline-variant opacity-70'
              }`}
            >
              <div className="flex items-center gap-3 min-w-0">
                <div
                  className={`w-6 h-6 rounded flex items-center justify-center flex-shrink-0 border ${
                    checked
                      ? 'bg-primary-container text-on-primary border-primary-container'
                      : 'bg-surface-container border-outline'
                  }`}
                >
                  {checked && <Check size={15} strokeWidth={3} />}
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-headline-md text-sm text-on-surface font-bold truncate">
                      {sub.name}
                    </span>
                    <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-primary-container/15 text-primary-container border border-primary-container/30">
                      СЕРВИС #{idx + 1}
                    </span>
                  </div>
                  <div className="font-telemetry-sm text-[11px] text-on-surface-variant truncate mt-0.5">
                    Доступно серверов: <strong className="text-on-surface">{aliveCount}</strong> из{' '}
                    {subNodes.length}
                    {sub.totalBytes
                      ? ` • Трафик: ${formatBytesHuman(sub.usedBytes)} / ${formatBytesHuman(sub.totalBytes)}`
                      : ''}
                  </div>
                </div>
              </div>
              <span className="font-badge-code text-[10px] text-on-surface-variant flex-shrink-0">
                {checked ? 'В АВТОЗАМЕНЕ' : 'ВЫКЛ'}
              </span>
            </div>
          );
        })}

        {/* Уровень 1Б: Группа личных ключей (Outline / WireGuard / VLESS) */}
        {manualNodes.length > 0 && (
          <div
            onClick={async () => {
              const next = await aegisApi.toggleManualGroupFailover(!manualChecked);
              onUpdate(next);
            }}
            className={`p-3 rounded-lg border flex items-center justify-between gap-3 cursor-pointer transition-colors ${
              manualChecked
                ? 'bg-surface-container-lowest border-primary-container/50'
                : 'bg-surface-container-lowest/50 border-outline-variant opacity-70'
            }`}
          >
            <div className="flex items-center gap-3 min-w-0">
              <div
                className={`w-6 h-6 rounded flex items-center justify-center flex-shrink-0 border ${
                  manualChecked
                    ? 'bg-primary-container text-on-primary border-primary-container'
                    : 'bg-surface-container border-outline'
                }`}
              >
                {manualChecked && <Check size={15} strokeWidth={3} />}
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-headline-md text-sm text-on-surface font-bold">
                    Личные ключи (VLESS / WG / SS)
                  </span>
                </div>
                <div className="font-telemetry-sm text-[11px] text-on-surface-variant mt-0.5">
                  Серверов в группе: <strong className="text-on-surface">{manualNodes.length}</strong>
                </div>
              </div>
            </div>
            <span className="font-badge-code text-[10px] text-on-surface-variant flex-shrink-0">
              {manualChecked ? 'В АВТОЗАМЕНЕ' : 'ВЫКЛ'}
            </span>
          </div>
        )}

        {/* Уровень 2: Локальные мосты к внешним запущенным VPN-клиентам (127.0.0.1) */}
        {displayedClients.map((bridge) => {
          const checked = bridge.enabledInFailover;
          return (
            <div
              key={bridge.id}
              onClick={async () => {
                const next = await aegisApi.toggleExternalClient(bridge.id, !checked);
                onUpdate(next);
              }}
              className={`p-3 rounded-lg border flex items-center justify-between gap-3 cursor-pointer transition-colors ${
                checked && bridge.detectedRunning
                  ? 'bg-surface-container-lowest border-secondary-container/70'
                  : checked
                    ? 'bg-surface-container-lowest border-[#FFB020]/50'
                    : 'bg-surface-container-lowest/40 border-outline-variant opacity-80'
              }`}
            >
              <div className="flex items-center gap-3 min-w-0">
                <div
                  className={`w-6 h-6 rounded flex items-center justify-center flex-shrink-0 border ${
                    checked
                      ? 'bg-secondary-container text-[#041318] border-secondary-container'
                      : 'bg-surface-container border-outline'
                  }`}
                >
                  {checked && <Check size={15} strokeWidth={3} />}
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-headline-md text-sm text-on-surface font-bold truncate">
                      {bridge.clientName}
                    </span>
                    <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-secondary-container/15 text-secondary border border-secondary-container/30 font-mono">
                      127.0.0.1:{bridge.port}
                    </span>
                  </div>
                  <div className="font-telemetry-sm text-[11px] mt-0.5 flex items-center gap-1.5">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        bridge.detectedRunning ? 'bg-primary-container' : 'bg-outline'
                      }`}
                    />
                    <span
                      className={
                        bridge.detectedRunning
                          ? 'text-primary-container font-semibold'
                          : 'text-on-surface-variant'
                      }
                    >
                      {bridge.detectedRunning
                        ? `Клиент запущен (${bridge.latencyMs ?? 2} мс) — готов к автозамене`
                        : checked
                          ? 'Отмечен (запустите клиент в режиме Прокси)'
                          : 'Внешний VPN-клиент (не запущен)'}
                    </span>
                  </div>
                </div>
              </div>
              <span className="font-badge-code text-[10px] text-secondary flex-shrink-0">
                МОСТ
              </span>
            </div>
          );
        })}

        {externalClients.length > displayedClients.length || showAllClients ? (
          <button
            type="button"
            onClick={() => setShowAllClients((v) => !v)}
            className="w-full py-2 px-3 rounded bg-surface-container-low hover:bg-surface-container border border-outline-variant text-xs text-on-surface-variant flex items-center justify-center gap-1.5 cursor-pointer"
          >
            {showAllClients ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            <span>
              {showAllClients
                ? 'Свернуть список внешних VPN-клиентов'
                : `Показать все внешние VPN-клиенты (${externalClients.length})`}
            </span>
          </button>
        ) : null}
      </div>
    </div>
  );
};
