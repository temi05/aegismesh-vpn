// Экран «Мои VPN и Клиенты» (Stitch v2):
// Единая вставка в 1 тап, карточки подписок с трафиком и HWID, внешние VPN-клиенты 127.0.0.1 и управление приоритетами
import React, { useRef, useState } from 'react';
import {
  ArrowDown,
  ArrowUp,
  Check,
  ChevronDown,
  ChevronUp,
  ClipboardPaste,
  FileUp,
  Link2,
  Play,
  Plus,
  Radar,
  RefreshCw,
  Server,
  Trash2,
} from 'lucide-react';
import { formatBytesHuman } from '../../shared/subscriptionMeta';
import type { VpnStateSnapshot } from '../../shared/types';
import { aegisApi } from '../api';

interface Props {
  snapshot: VpnStateSnapshot;
  onUpdate: (next: VpnStateSnapshot) => void;
  onNotify: (msg: string, isError?: boolean) => void;
}

function formatExpireDate(unix?: number | null): string | null {
  if (!unix || unix <= 0) return null;
  const ms = unix > 1e12 ? unix : unix * 1000;
  try {
    return new Date(ms).toLocaleDateString('ru-RU');
  } catch {
    return null;
  }
}

export const NodesVaultView: React.FC<Props> = ({ snapshot, onUpdate, onNotify }) => {
  const [rawInput, setRawInput] = useState('');
  const [subName, setSubName] = useState('');
  const [showManualForm, setShowManualForm] = useState(false);
  const [customClientName, setCustomClientName] = useState('');
  const [customClientPort, setCustomClientPort] = useState('');
  const [customClientProto, setCustomClientProto] = useState<'socks' | 'http'>('socks');
  const [busy, setBusy] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const importUniversalPayload = async (payloadRaw: string, customName = '') => {
    const payload = payloadRaw.trim();
    if (!payload) {
      onNotify('Вставьте ссылку подписки https:// или ключ vless://, hy2://, ss://, wg://', true);
      return;
    }
    setBusy(true);
    try {
      const isSubUrl =
        /^https?:\/\/\S+$/i.test(payload) &&
        !payload.includes('\n') &&
        !/:\/\/[^/]*@/.test(payload);

      if (isSubUrl) {
        const next = await aegisApi.addSubscription(customName, payload);
        onUpdate(next);
        setRawInput('');
        setSubName('');
        const last = next.subscriptions[next.subscriptions.length - 1];
        onNotify(
          `Подписка «${last?.name || 'VPN'}» добавлена (${last?.nodeCount || 0} серверов)`
        );
        return;
      }

      const { result, snapshot: next } = await aegisApi.importNodes(payload);
      onUpdate(next);
      if (result.nodes.length > 0) {
        setRawInput('');
        onNotify(
          `Добавлено рабочих серверов: ${result.nodes.length}${
            result.filteredDummyCount ? ` (скрыто заглушек: ${result.filteredDummyCount})` : ''
          }`
        );
      } else {
        const msg =
          result.infoMessages && result.infoMessages.length > 0
            ? result.infoMessages.join(' • ')
            : result.errors[0] || 'Не удалось распознать формат VPN-ключа';
        onNotify(msg, true);
      }
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Ошибка добавления VPN', true);
    } finally {
      setBusy(false);
    }
  };

  const handlePasteOneTap = async () => {
    try {
      const clip = (await navigator.clipboard.readText()).trim();
      if (!clip) {
        setShowManualForm(true);
        onNotify('Буфер обмена пуст — вставьте ключ или ссылку вручную ниже', true);
        return;
      }
      await importUniversalPayload(clip, subName);
    } catch {
      setShowManualForm(true);
      onNotify('Вставьте ключ или ссылку долгим нажатием в поле ввода ниже', false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const content = await file.text();
      await importUniversalPayload(content, file.name.replace(/\.[^.]+$/, ''));
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Ошибка чтения файла', true);
    } finally {
      e.target.value = '';
    }
  };

  const handleRefreshAllSubscriptions = async () => {
    if (snapshot.subscriptions.length === 0) {
      onNotify('Нет подключённых подписок для обновления', true);
      return;
    }
    setBusy(true);
    try {
      let latestSnap = snapshot;
      for (const sub of snapshot.subscriptions) {
        latestSnap = await aegisApi.refreshSubscription(sub.id);
      }
      onUpdate(latestSnap);
      onNotify(`Обновлено подписок: ${snapshot.subscriptions.length}`);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Ошибка обновления подписок', true);
    } finally {
      setBusy(false);
    }
  };

  const handlePingAllNodes = async () => {
    if (snapshot.nodes.length === 0) {
      onNotify('Серверы пока не добавлены', true);
      return;
    }
    setBusy(true);
    try {
      const next = await aegisApi.pingAll();
      onUpdate(next);
      onNotify('Пинг всех серверов проверен');
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Ошибка проверки пинга', true);
    } finally {
      setBusy(false);
    }
  };

  const externalClients = snapshot.externalClients || [];

  return (
    <div className="max-w-5xl mx-auto space-y-4">
      {/* 1. ЕДИНЫЙ БЛОК ДОБАВЛЕНИЯ КЛЮЧА ИЛИ ПОДПИСКИ В 1 ТАП */}
      <div className="rounded-xl relative overflow-hidden bg-surface border border-outline-variant p-4 md:p-5 space-y-3.5">
        <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-secondary-container via-primary-container to-secondary-container opacity-80" />
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="font-headline-md text-base md:text-lg text-on-surface font-bold">
              Добавить подписку или VPN-ключи
            </h2>
            <p className="font-body-sm text-xs text-on-surface-variant mt-0.5">
              Автоматически распознаёт <strong className="text-secondary">https:// подписки</strong> (с поддержкой HWID),{' '}
              <strong className="text-primary">VLESS Reality</strong>, VMess, Trojan, Shadowsocks, Hysteria2, TUIC и WireGuard.
            </p>
          </div>
        </div>

        <div className="space-y-2">
          <button
            type="button"
            disabled={busy}
            onClick={() => void handlePasteOneTap()}
            className="w-full py-3 px-4 min-h-[48px] rounded-xl bg-primary-container text-on-primary font-badge-code text-xs font-bold flex items-center justify-center gap-2 shield-glow cursor-pointer"
          >
            <ClipboardPaste size={17} />
            <span>{busy ? 'ЗАГРУЗКА...' : '+ Вставить из буфера (ключ или подписку)'}</span>
          </button>

          <input
            ref={fileInputRef}
            type="file"
            accept=".conf,.txt,.json"
            className="hidden"
            onChange={handleFileUpload}
          />

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 w-full">
            <button
              type="button"
              disabled={busy}
              onClick={() => fileInputRef.current?.click()}
              className="w-full px-3 py-2.5 min-h-[42px] rounded-lg bg-surface-container-high hover:bg-surface-variant border border-outline-variant text-on-surface font-telemetry-md text-xs flex items-center justify-center gap-1.5 cursor-pointer"
            >
              <FileUp size={15} className="text-secondary" />
              <span>Загрузить .conf</span>
            </button>

            <button
              type="button"
              disabled={busy}
              onClick={() => void handlePingAllNodes()}
              className="w-full px-3 py-2.5 min-h-[42px] rounded-lg bg-surface-container-high hover:bg-surface-variant border border-secondary-container/40 text-secondary font-badge-code text-xs flex items-center justify-center gap-1.5 cursor-pointer"
            >
              <RefreshCw size={14} className={busy ? 'animate-spin' : ''} />
              <span>Пинг всех</span>
            </button>

            <button
              type="button"
              disabled={busy || snapshot.subscriptions.length === 0}
              onClick={() => void handleRefreshAllSubscriptions()}
              className="w-full px-3 py-2.5 min-h-[42px] rounded-lg bg-surface-container-high hover:bg-surface-variant border border-primary-container/40 text-primary font-badge-code text-xs flex items-center justify-center gap-1.5 disabled:opacity-50 cursor-pointer"
            >
              <RefreshCw size={14} className={busy ? 'animate-spin' : ''} />
              <span>Обновить подписки</span>
            </button>

            <button
              type="button"
              onClick={() => setShowManualForm((v) => !v)}
              className="w-full px-3 py-2.5 min-h-[42px] rounded-lg bg-surface-container hover:bg-surface-container-high border border-outline-variant text-on-surface-variant text-xs flex items-center justify-center gap-1 cursor-pointer"
            >
              <span>Ввести вручную</span>
              {showManualForm ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
            </button>
          </div>
        </div>

        {showManualForm && (
          <div className="pt-3 border-t border-outline-variant space-y-2.5">
            <input
              type="text"
              value={subName}
              onChange={(e) => setSubName(e.target.value)}
              placeholder="Название VPN-сервиса (необязательно — определится автоматически)"
              className="w-full bg-[#070A0F] border border-outline-variant rounded-lg px-3 py-2.5 min-h-[42px] text-xs text-on-surface focus:border-primary-container focus:outline-none"
            />
            <textarea
              rows={3}
              value={rawInput}
              onChange={(e) => setRawInput(e.target.value)}
              placeholder="Вставьте сюда https:// ссылку подписки, список ключей vless://..., hy2://..., ss://... или JSON / WireGuard [Interface]"
              className="w-full bg-[#070A0F] border border-outline-variant rounded-lg p-3 text-xs text-on-surface font-mono focus:border-primary-container focus:outline-none"
            />
            <button
              type="button"
              disabled={busy}
              onClick={() => void importUniversalPayload(rawInput, subName)}
              className="w-full sm:w-auto px-4 py-2.5 min-h-[44px] rounded-lg bg-primary-container text-on-primary font-badge-code text-xs font-bold flex items-center justify-center gap-1.5 cursor-pointer"
            >
              <Plus size={15} />
              <span>Добавить в мои VPN</span>
            </button>
          </div>
        )}
      </div>

      {/* 2. МОИ ПОДПИСКИ И VPN-СЕРВИСЫ (С МЕТАДАННЫМИ ТРАФИКА И ГАЛОЧКАМИ АВТОЗАМЕНЫ) */}
      {snapshot.subscriptions.length > 0 && (
        <div className="rounded-xl relative overflow-hidden bg-surface border border-outline-variant p-4 md:p-5 space-y-3">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-secondary-container via-primary-container to-secondary-container opacity-75" />
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-outline-variant">
            <div className="flex items-center gap-2">
              <Link2 size={17} className="text-secondary" />
              <h3 className="font-headline-md text-sm md:text-base text-on-surface font-bold">
                Подключённые VPN-подписки ({snapshot.subscriptions.length})
              </h3>
            </div>
            <button
              type="button"
              disabled={busy}
              onClick={() => void handleRefreshAllSubscriptions()}
              className="w-full sm:w-auto px-3 py-1.5 min-h-[36px] rounded-lg bg-surface-container-high hover:bg-surface-variant border border-secondary-container/40 text-secondary font-badge-code text-xs flex items-center justify-center gap-1.5 cursor-pointer"
            >
              <RefreshCw size={13} className={busy ? 'animate-spin' : ''} />
              <span>Обновить подписки</span>
            </button>
          </div>

          <div className="space-y-3">
            {snapshot.subscriptions.map((sub) => {
              const checked = sub.enabledInFailover !== false;
              const expDate = formatExpireDate(sub.expireUnix);
              const pct =
                sub.totalBytes && sub.totalBytes > 0 && sub.usedBytes
                  ? Math.min(100, Math.round((sub.usedBytes / sub.totalBytes) * 100))
                  : null;
              return (
                <div
                  key={sub.id}
                  className="p-3.5 rounded-xl relative overflow-hidden bg-surface-container-lowest border border-outline-variant space-y-2.5"
                >
                  <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-secondary-container via-primary-container to-secondary-container" />
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2.5">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <button
                        type="button"
                        onClick={async () => {
                          const next = await aegisApi.toggleSubscriptionFailover(sub.id, !checked);
                          onUpdate(next);
                        }}
                        className={`w-6 h-6 rounded-md flex items-center justify-center border flex-shrink-0 cursor-pointer ${
                          checked
                            ? 'bg-primary-container text-on-primary border-primary-container'
                            : 'bg-surface-container border-outline'
                        }`}
                        title="Участвует в автозамене"
                      >
                        {checked && <Check size={14} strokeWidth={3} />}
                      </button>
                      <div className="min-w-0">
                        <div className="font-headline-md text-sm text-on-surface font-bold truncate">
                          {sub.name}
                        </div>
                        <div className="flex flex-wrap items-center gap-1.5 mt-0.5">
                          <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-primary-container/15 text-primary-container">
                            {sub.nodeCount} СЕРВ.
                          </span>
                          {sub.compatProfile && (
                            <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-surface-container-high text-secondary">
                              {sub.compatProfile}
                            </span>
                          )}
                          {sub.filteredDummyCount ? (
                            <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-[#FFB020]/15 text-[#FFB020]">
                              Скрыто инфо-заглушек: {sub.filteredDummyCount}
                            </span>
                          ) : null}
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 sm:flex items-center gap-1.5 w-full sm:w-auto">
                      <button
                        type="button"
                        disabled={busy}
                        onClick={async () => {
                          setBusy(true);
                          try {
                            const next = await aegisApi.refreshSubscription(sub.id);
                            onUpdate(next);
                            onNotify(`Подписка «${sub.name}» обновлена`);
                          } catch (err) {
                            onNotify(err instanceof Error ? err.message : 'Ошибка обновления', true);
                          } finally {
                            setBusy(false);
                          }
                        }}
                        className="w-full sm:w-auto px-2.5 py-1.5 min-h-[36px] rounded-lg bg-surface-container-high hover:bg-surface-variant border border-outline-variant text-xs text-on-surface flex items-center justify-center gap-1 cursor-pointer"
                      >
                        <RefreshCw size={13} className={busy ? 'animate-spin' : ''} />
                        <span>Обновить</span>
                      </button>
                      <button
                        type="button"
                        onClick={async () => {
                          const next = await aegisApi.deleteSubscription(sub.id);
                          onUpdate(next);
                          onNotify(`Подписка «${sub.name}» удалена`);
                        }}
                        className="w-full sm:w-auto p-2 min-h-[36px] rounded-lg bg-error-container/30 hover:bg-error-container/60 border border-error/40 text-error flex items-center justify-center gap-1 cursor-pointer"
                        title="Удалить подписку"
                      >
                        <Trash2 size={14} />
                        <span className="sm:hidden text-xs">Удалить</span>
                      </button>
                    </div>
                  </div>

                  {(sub.totalBytes || sub.usedBytes !== null || expDate) && (
                    <div className="space-y-1 pt-1">
                      <div className="flex justify-between text-[11px] text-on-surface-variant font-mono">
                        <span>
                          Трафик: {formatBytesHuman(sub.usedBytes)}
                          {sub.totalBytes ? ` из ${formatBytesHuman(sub.totalBytes)}` : ''}
                        </span>
                        {expDate && <span>До {expDate}</span>}
                      </div>
                      {pct !== null && (
                        <div className="h-1.5 rounded-full bg-surface-container-high overflow-hidden">
                          <div
                            className="h-full bg-gradient-to-r from-secondary-container to-primary-container"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      )}
                    </div>
                  )}

                  {sub.announceText && (
                    <div className="text-[11px] text-on-surface-variant bg-surface-container/60 px-2.5 py-1.5 rounded">
                      {sub.announceText}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 3. ВНЕШНИЕ VPN-КЛИЕНТЫ НА УСТРОЙСТВЕ (ЛОКАЛЬНЫЙ МОСТ 127.0.0.1) */}
      <div className="rounded-xl relative overflow-hidden bg-surface border border-outline-variant p-4 md:p-5 space-y-3">
        <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-secondary-container via-primary-container to-secondary-container opacity-75" />
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-outline-variant">
          <div>
            <h3 className="font-headline-md text-sm md:text-base text-on-surface font-bold">
              Внешние VPN-клиенты (Мост 127.0.0.1)
            </h3>
            <p className="font-body-sm text-xs text-on-surface-variant mt-0.5">
              Если подписка привязана к закрытому клиенту (например Happ с шифрованием), запустите его в режиме «Только прокси» и отметьте галочкой.
            </p>
          </div>
          <button
            type="button"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                const next = await aegisApi.scanExternalClients();
                onUpdate(next);
                onNotify('Локальные порты внешних VPN-клиентов просканированы');
              } finally {
                setBusy(false);
              }
            }}
            className="w-full sm:w-auto px-3 py-2 min-h-[38px] rounded-lg bg-surface-container-high hover:bg-surface-variant border border-secondary-container/50 text-secondary font-badge-code text-xs flex items-center justify-center gap-1.5 cursor-pointer"
          >
            <Radar size={14} />
            <span>Сканировать порты</span>
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {externalClients.map((bridge) => (
            <div
              key={bridge.id}
              onClick={async () => {
                const next = await aegisApi.toggleExternalClient(
                  bridge.id,
                  !bridge.enabledInFailover
                );
                onUpdate(next);
              }}
              className={`p-3 rounded-xl border flex items-center justify-between gap-2.5 cursor-pointer ${
                bridge.enabledInFailover
                  ? 'bg-surface-container-lowest border-secondary-container/70'
                  : 'bg-surface-container-lowest/50 border-outline-variant'
              }`}
            >
              <div className="flex items-center gap-2.5 min-w-0">
                <div
                  className={`w-5 h-5 rounded flex items-center justify-center flex-shrink-0 border ${
                    bridge.enabledInFailover
                      ? 'bg-secondary-container text-[#041318] border-secondary-container'
                      : 'bg-surface-container border-outline'
                  }`}
                >
                  {bridge.enabledInFailover && <Check size={13} strokeWidth={3} />}
                </div>
                <div className="min-w-0">
                  <div className="text-xs font-bold text-on-surface truncate">
                    {bridge.clientName}
                  </div>
                  <div className="text-[11px] font-mono text-on-surface-variant">
                    {bridge.protocol.toUpperCase()} 127.0.0.1:{bridge.port} •{' '}
                    <span
                      className={
                        bridge.detectedRunning ? 'text-primary-container font-bold' : ''
                      }
                    >
                      {bridge.detectedRunning ? 'Запущен' : 'Оффлайн'}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Добавление своего кастомного порта внешнего клиента */}
        <div className="pt-2 border-t border-outline-variant grid grid-cols-2 sm:flex sm:flex-wrap gap-2">
          <input
            type="text"
            value={customClientName}
            onChange={(e) => setCustomClientName(e.target.value)}
            placeholder="Имя клиента (напр. Мой Прокси)"
            className="col-span-2 sm:flex-1 min-w-[140px] bg-[#070A0F] border border-outline-variant rounded-lg px-2.5 py-2 text-xs text-on-surface"
          />
          <select
            value={customClientProto}
            onChange={(e) => setCustomClientProto(e.target.value as 'socks' | 'http')}
            className="bg-[#070A0F] border border-outline-variant rounded-lg px-2.5 py-2 text-xs text-on-surface"
          >
            <option value="socks">SOCKS5</option>
            <option value="http">HTTP</option>
          </select>
          <input
            type="number"
            value={customClientPort}
            onChange={(e) => setCustomClientPort(e.target.value)}
            placeholder="Порт (напр. 10809)"
            className="w-full sm:w-36 bg-[#070A0F] border border-outline-variant rounded-lg px-2.5 py-2 text-xs text-on-surface font-mono"
          />
          <button
            type="button"
            onClick={async () => {
              try {
                const next = await aegisApi.addCustomExternalClient(
                  customClientName,
                  customClientProto,
                  Number(customClientPort)
                );
                onUpdate(next);
                setCustomClientName('');
                setCustomClientPort('');
                onNotify('Локальный мост внешнего клиента добавлен');
              } catch (err) {
                onNotify(err instanceof Error ? err.message : 'Ошибка добавления порта', true);
              }
            }}
            className="col-span-2 sm:col-span-1 px-3 py-2 min-h-[38px] rounded-lg bg-surface-container-high hover:bg-surface-variant border border-outline-variant text-xs text-primary font-badge-code flex items-center justify-center cursor-pointer"
          >
            + Порт
          </button>
        </div>
      </div>

      {/* 4. ВСЕ СЕРВЕРЫ И УПРАВЛЕНИЕ ПОРЯДКОМ ОЧЕРЕДИ */}
      <div className="rounded-xl relative overflow-hidden bg-surface border border-outline-variant p-4 md:p-5 space-y-3">
        <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-primary-container via-secondary-container to-primary-container opacity-75" />
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-outline-variant">
          <div className="flex items-center gap-2">
            <Server size={17} className="text-primary-container" />
            <h3 className="font-headline-md text-sm md:text-base text-on-surface font-bold">
              Все серверы в очереди ({snapshot.nodes.length})
            </h3>
          </div>
          {snapshot.nodes.length > 0 && (
            <button
              type="button"
              onClick={() => void handlePingAllNodes()}
              className="w-full sm:w-auto px-3 py-1.5 min-h-[36px] rounded-lg bg-surface-container-high border border-outline-variant text-xs text-on-surface flex items-center justify-center gap-1.5 cursor-pointer"
            >
              <RefreshCw size={13} className={busy ? 'animate-spin' : ''} />
              <span>Пинг всех</span>
            </button>
          )}
        </div>

        {snapshot.nodes.length === 0 ? (
          <div className="text-xs text-on-surface-variant py-3 text-center">
            Серверы пока не добавлены. Нажмите «+ Вставить из буфера» вверху страницы.
          </div>
        ) : (
          <div className="space-y-2">
            {snapshot.nodes.map((node, index) => {
              const isCurrent =
                node.id === snapshot.activeNodeId && snapshot.connectionState === 'connected';
              return (
                <div
                  key={node.id}
                  className={`p-3 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 ${
                    isCurrent
                      ? 'bg-primary-container/10 border-primary-container'
                      : 'bg-surface-container-lowest border-outline-variant'
                  }`}
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-surface-container-high text-primary">
                        #{node.priority}
                      </span>
                      <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-secondary-container/15 text-secondary">
                        {node.providerName || 'Личные ключи'}
                      </span>
                      <span className="text-sm font-bold text-on-surface truncate">
                        {node.name}
                      </span>
                    </div>
                    <div className="text-[11px] font-mono text-on-surface-variant mt-0.5 truncate">
                      {node.protocol.toUpperCase()} • {node.server}:{node.port} •{' '}
                      {node.latencyMs !== null ? `${node.latencyMs} мс` : 'не проверен'}
                    </div>
                  </div>

                  <div className="flex items-center justify-between sm:justify-end gap-1.5 w-full sm:w-auto">
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        disabled={index === 0}
                        onClick={async () => {
                          const next = await aegisApi.moveNodePriority(node.id, 'up');
                          onUpdate(next);
                        }}
                        className="p-2 rounded-lg bg-surface-container border border-outline-variant text-on-surface disabled:opacity-40 cursor-pointer"
                        title="Выше"
                      >
                        <ArrowUp size={13} />
                      </button>
                      <button
                        type="button"
                        disabled={index === snapshot.nodes.length - 1}
                        onClick={async () => {
                          const next = await aegisApi.moveNodePriority(node.id, 'down');
                          onUpdate(next);
                        }}
                        className="p-2 rounded-lg bg-surface-container border border-outline-variant text-on-surface disabled:opacity-40 cursor-pointer"
                        title="Ниже"
                      >
                        <ArrowDown size={13} />
                      </button>
                      <button
                        type="button"
                        onClick={async () => {
                          const next = await aegisApi.toggleNode(node.id, !node.enabled);
                          onUpdate(next);
                        }}
                        className="px-2.5 py-1.5 min-h-[34px] rounded-lg bg-surface-container border border-outline-variant text-[11px] text-on-surface cursor-pointer"
                      >
                        {node.enabled ? 'Вкл' : 'Выкл'}
                      </button>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={async () => {
                          try {
                            const next = await aegisApi.switchNode(node.id);
                            onUpdate(next);
                            onNotify(`Подключено к «${node.name}»`);
                          } catch (err) {
                            onNotify(err instanceof Error ? err.message : 'Ошибка подключения', true);
                          }
                        }}
                        className="px-3 py-1.5 min-h-[34px] rounded-lg bg-primary-container text-on-primary font-badge-code text-[11px] font-bold flex items-center gap-1 cursor-pointer"
                      >
                        <Play size={12} />
                        <span>{isCurrent ? 'Активен' : 'Старт'}</span>
                      </button>
                      {!node.isExternalClientBridge && (
                        <button
                          type="button"
                          onClick={async () => {
                            const next = await aegisApi.deleteNode(node.id);
                            onUpdate(next);
                            onNotify(`Сервер «${node.name}» удалён`);
                          }}
                          className="p-2 rounded-lg bg-error-container/30 border border-error/40 text-error cursor-pointer"
                          title="Удалить"
                        >
                          <Trash2 size={13} />
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
