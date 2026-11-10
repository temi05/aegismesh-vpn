import React, { useEffect, useRef, useState } from 'react';
import {
  KeyRound,
  Lock,
  Monitor,
  Radar,
  Route,
  Shield,
  Smartphone,
} from 'lucide-react';
import type { VpnStateSnapshot } from '../shared/types';
import { aegisApi, isNativeMobileApp } from './api';
import { DiagnosticsAuditView } from './components/DiagnosticsAuditView';
import { NodesVaultView } from './components/NodesVaultView';
import { RoutingSecurityView } from './components/RoutingSecurityView';
import { ShieldCascadeView } from './components/ShieldCascadeView';
import { TacticalIcon } from './components/TacticalIcon';

type TabId = 'shield' | 'nodes' | 'audit' | 'routing';

const NAV_ITEMS: Array<{
  id: TabId;
  label: string;
  shortLabel: string;
  iconName: string;
  icon: React.ReactNode;
}> = [
  {
    id: 'shield',
    label: 'Главный экран VPN',
    shortLabel: 'VPN',
    iconName: 'hub',
    icon: <Shield size={18} />,
  },
  {
    id: 'nodes',
    label: 'Мои VPN и Клиенты',
    shortLabel: 'Мои VPN',
    iconName: 'vpn_key',
    icon: <KeyRound size={18} />,
  },
  {
    id: 'audit',
    label: 'Проверка IP и Журнал',
    shortLabel: 'Проверка IP',
    iconName: 'terminal',
    icon: <Radar size={18} />,
  },
  {
    id: 'routing',
    label: 'Настройки и Защита',
    shortLabel: 'Настройки',
    iconName: 'alt_route',
    icon: <Route size={18} />,
  },
];

function formatUptime(connectedSince: number | null, now: number): string {
  if (!connectedSince) return '00ч 00м 00с';
  const diffSec = Math.max(0, Math.floor((now - connectedSince) / 1000));
  const h = Math.floor(diffSec / 3600);
  const m = Math.floor((diffSec % 3600) / 60);
  const s = diffSec % 60;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(h)}ч ${pad(m)}м ${pad(s)}с`;
}

export const App: React.FC = () => {
  const [snapshot, setSnapshot] = useState<VpnStateSnapshot | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('shield');
  const [mobilePreview, setMobilePreview] = useState(false);
  const [unlockPin, setUnlockPin] = useState('');
  const [toast, setToast] = useState<{ text: string; isError: boolean } | null>(null);
  const [nowTick, setNowTick] = useState<number>(() => Date.now());
  const [busyAction, setBusyAction] = useState(false);
  const busyRef = useRef(false);
  busyRef.current = busyAction;

  const isMobileApp = isNativeMobileApp();

  const showToast = (text: string, isError = false) => {
    setToast({ text, isError });
    window.setTimeout(() => {
      setToast((prev) => (prev?.text === text ? null : prev));
    }, 4200);
  };

  useEffect(() => {
    let mounted = true;

    const poll = async () => {
      if (busyRef.current) return;
      try {
        const data = await aegisApi.getState();
        if (mounted && !busyRef.current && data && Array.isArray(data.nodes)) {
          setSnapshot(data);
        }
      } catch {
        // Ожидание инициализации движка
      }
    };

    void poll();
    const timer = window.setInterval(poll, 1800);
    const clockTimer = window.setInterval(() => setNowTick(Date.now()), 1000);
    const updateTimer = window.setTimeout(() => {
      aegisApi
        .checkAppUpdate()
        .then((r) => {
          if (mounted && !busyRef.current && r?.snapshot) {
            setSnapshot(r.snapshot);
          }
        })
        .catch(() => {});
    }, 2500);
    return () => {
      mounted = false;
      window.clearInterval(timer);
      window.clearInterval(clockTimer);
      window.clearTimeout(updateTimer);
    };
  }, []);

  const handleToggleMobileWidget = async () => {
    const nextCompact = !mobilePreview;
    setMobilePreview(nextCompact);
    if (window.aegisElectron?.toggleMiniWidget) {
      try {
        await window.aegisElectron.toggleMiniWidget(nextCompact);
      } catch {
        // В браузере просто переключаем компактную рамку 412px
      }
    }
  };

  if (!snapshot || !Array.isArray(snapshot.nodes)) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-3 bg-[#070A0F] text-on-surface px-4 text-center">
        <div className="w-12 h-12 rounded bg-surface-container-high border border-primary-container flex items-center justify-center shield-glow text-primary-container">
          <TacticalIcon name="security" size={24} />
        </div>
        <div className="font-headline-md text-headline-md text-primary font-bold tracking-wider">
          Запуск защищённого ядра AegisMesh VPN...
        </div>
      </div>
    );
  }

  const userNodes = snapshot.nodes.filter((n) => !n.isTestStand);
  const enabledUserNodes = userNodes.filter((n) => n.enabled);
  const isConnected =
    snapshot.connectionState === 'connected' &&
    snapshot.telemetry?.verified !== false;
  const isConnecting = snapshot.connectionState === 'connecting';
  const isSwitching = snapshot.connectionState === 'switching';
  const isErrorState = snapshot.connectionState === 'error';
  const isKillLocked = snapshot.connectionState === 'killswitch_locked';
  const activeNode = userNodes.find((n) => n.id === snapshot.activeNodeId) || null;
  const securityScore =
    snapshot.lastAudit?.securityScore ??
    (isConnected ? 96 : snapshot.settings.killSwitchEnabled ? 75 : 50);
  const activeLatency =
    activeNode?.latencyMs ??
    enabledUserNodes.find((n) => n.latencyMs !== null)?.latencyMs ??
    null;

  const handlePowerAction = async () => {
    if (busyAction) return;
    const hasRunningExternal = (snapshot.externalClients || []).some(
      (b) => b.enabledInFailover && b.detectedRunning
    );
    if (
      !isConnected &&
      !isConnecting &&
      !isSwitching &&
      !isKillLocked &&
      enabledUserNodes.length === 0 &&
      !hasRunningExternal
    ) {
      setActiveTab('nodes');
      showToast('Сначала добавьте свой VPN-ключ, подписку или включите внешний клиент', true);
      return;
    }

    setBusyAction(true);
    try {
      if (isConnected || isConnecting || isSwitching || isKillLocked) {
        const next = await aegisApi.disconnect();
        setSnapshot(next);
        showToast('VPN-туннель отключён');
      } else {
        const next = await aegisApi.connect();
        setSnapshot(next);
        const connNode = next.nodes.find((n) => n.id === next.activeNodeId);
        showToast(
          connNode
            ? `Туннель проверен! Активен «${connNode.name}»`
            : 'VPN-туннель проверен и активирован'
        );
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Ошибка запуска VPN', true);
    } finally {
      setBusyAction(false);
    }
  };

  const handleEmergencyStop = async () => {
    if (busyAction) return;
    setBusyAction(true);
    try {
      const next = await aegisApi.disconnect();
      setSnapshot(next);
      showToast('Аварийный стоп выполнен: VPN-сессия остановлена');
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Ошибка остановки', true);
    } finally {
      setBusyAction(false);
    }
  };

  const handlePingAll = async () => {
    if (userNodes.length === 0) {
      showToast('Список VPN пуст — добавьте свои серверы для проверки пинга', true);
      return;
    }
    try {
      const next = await aegisApi.pingAll();
      setSnapshot(next);
      showToast('Реальный пинг всех ваших VPN-серверов обновлён');
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Ошибка проверки пинга', true);
    }
  };

  return (
    <div
      className={`min-h-screen font-body-md text-on-surface antialiased flex flex-col bg-[#070A0F] ${
        mobilePreview ? 'app-shell mobile-preview-mode' : 'pb-24 md:pb-0'
      }`}
    >
      {/* 1. ЛЕВАЯ БОКОВАЯ ПАНЕЛЬ НА ПК (Stitch Tactical Telemetry) */}
      {!mobilePreview && (
        <aside className="hidden md:flex fixed top-0 left-0 h-screen w-64 border-r border-outline-variant bg-surface-container-lowest flex-col justify-between p-4 z-50 select-none">
          <div className="space-y-4">
            <div className="flex items-center gap-3 pb-3 border-b border-outline-variant">
              <div className="w-10 h-10 rounded bg-surface-container-high border border-primary-container flex items-center justify-center shield-glow text-primary-container">
                <TacticalIcon name="security" size={20} />
              </div>
              <div>
                <h1 className="text-headline-md font-headline-md text-primary tracking-wider uppercase font-bold leading-none">
                  AEGISMESH
                </h1>
                <p className="font-telemetry-sm text-telemetry-sm text-on-surface-variant mt-1">
                  SING-BOX VPN CORE
                </p>
              </div>
            </div>

            <div className="px-2.5 py-1.5 rounded bg-surface-container border border-outline-variant flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span
                  className={`w-2 h-2 rounded-full ${
                    isConnected ? 'bg-primary-container animate-ping' : 'bg-[#FFB020]'
                  }`}
                />
                <span className="font-badge-code text-badge-code text-primary uppercase">
                  ИНДЕКС {securityScore}/100
                </span>
              </div>
              <span className="font-badge-code text-badge-code text-primary-container font-bold">
                ЗАЩИТА
              </span>
            </div>

            <nav className="space-y-1 pt-1">
              {NAV_ITEMS.map((item) => {
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setActiveTab(item.id)}
                    className={
                      isActive
                        ? 'w-full flex items-center gap-3 px-3 py-2.5 rounded bg-surface-container text-primary border-l-2 border-primary-container font-telemetry-md text-telemetry-md cursor-pointer transition-transform duration-100 group text-left'
                        : 'w-full flex items-center gap-3 px-3 py-2.5 rounded text-on-surface-variant hover:text-on-surface hover:bg-surface-container-low transition-colors duration-150 font-telemetry-md text-telemetry-md cursor-pointer group text-left'
                    }
                  >
                    <TacticalIcon
                      name={item.iconName}
                      size={18}
                      className={
                        isActive ? 'text-primary-container' : 'group-hover:text-secondary'
                      }
                    />
                    <span className="flex-1 truncate font-telemetry-md">{item.label}</span>
                    {item.id === 'shield' && (
                      <span className="font-badge-code text-badge-code px-1.5 py-0.5 rounded bg-primary-container/20 text-primary-container border border-primary-container/40">
                        {isConnected ? 'ВКЛ' : 'ВЫКЛ'}
                      </span>
                    )}
                    {item.id === 'nodes' && (
                      <span className="font-badge-code text-badge-code px-1.5 py-0.5 rounded bg-surface-container-high text-secondary border border-outline-variant">
                        {userNodes.length} VPN
                      </span>
                    )}
                    {item.id === 'routing' && (
                      <span className="font-badge-code text-badge-code px-1.5 py-0.5 rounded bg-surface-container-high text-on-surface-variant border border-outline-variant">
                        {snapshot.settings.bypassDomains.length} ПРАВ
                      </span>
                    )}
                  </button>
                );
              })}
            </nav>
          </div>

          <div className="space-y-3 pt-3 border-t border-outline-variant">
            <div className="p-2.5 rounded bg-surface-container-low border border-outline-variant font-telemetry-sm text-telemetry-sm space-y-1">
              <div className="flex justify-between items-center text-on-surface-variant">
                <span>{`Версия: v${snapshot.appUpdate?.currentVersion || '3.6.0'}`}</span>
                <span className="text-primary-container font-mono font-bold">
                  {snapshot.appUpdate?.updateAvailable
                    ? `⬆️ v${snapshot.appUpdate.latestVersion}`
                    : 'OK'}
                </span>
              </div>
              <div className="flex justify-between items-center text-on-surface-variant">
                <span>Ядро:</span>
                <span className="text-primary font-mono font-bold truncate max-w-[130px]">
                  {snapshot.coreStatus.version || 'sing-box 1.14'}
                </span>
              </div>
              <div className="flex justify-between items-center text-on-surface-variant">
                <span>Сессия:</span>
                <span className="text-on-surface font-mono">
                  {formatUptime(snapshot.connectedSince, nowTick)}
                </span>
              </div>
              <div className="flex justify-between items-center text-on-surface-variant pt-1 border-t border-outline-variant">
                <span>Хранилище:</span>
                <span className="text-primary-container font-bold">AES-256-GCM</span>
              </div>
            </div>

            <button
              type="button"
              onClick={handleEmergencyStop}
              className="w-full py-2.5 px-3 rounded bg-error-container text-white border border-error/50 font-badge-code text-badge-code tracking-wider flex items-center justify-center gap-2 crimson-glow hover:bg-error-container/90 active:scale-95 transition-all duration-100 cursor-pointer"
            >
              <TacticalIcon name="emergency_home" size={16} />
              <span>АВАРИЙНЫЙ СТОП</span>
            </button>
          </div>
        </aside>
      )}

      {/* 2. ВЕРХНЯЯ ПАНЕЛЬ ТЕЛЕМЕТРИИ (Адаптивная под смартфон и ПК) */}
      <header
        className={`safe-top-header ${
          mobilePreview
            ? 'sticky top-0 left-0 right-0 px-3 pb-2.5'
            : 'sticky md:fixed top-0 md:left-64 right-0 min-h-[3.75rem] px-3.5 md:px-6 pb-2 md:py-0'
        } border-b border-outline-variant bg-surface-container-lowest z-40 flex justify-between items-center gap-2 select-none`}
      >
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex items-center gap-2 min-w-0">
            <div className="md:hidden w-8 h-8 rounded bg-surface-container-high border border-primary-container/60 flex items-center justify-center text-primary-container flex-shrink-0">
              <TacticalIcon name="security" size={16} />
            </div>
            <div className="min-w-0">
              <span className="text-base md:text-headline-md font-headline-md text-primary font-bold tracking-tight truncate block">
                AegisMesh VPN
              </span>
              <span className="md:hidden font-telemetry-sm text-[10px] text-on-surface-variant block truncate">
                {isConnected && activeNode
                  ? `Работает: ${activeNode.providerName ? `${activeNode.providerName} • ` : ''}${activeNode.name}`
                  : isConnecting || isSwitching
                    ? 'Сквозная проверка туннеля...'
                    : isErrorState
                      ? 'Сбой подключения (VPN выкл.)'
                      : `Серверов: ${userNodes.length}`}
              </span>
            </div>
          </div>

          {!mobilePreview && (
            <div className="hidden lg:flex items-center gap-4 text-telemetry-md font-telemetry-md border-l border-outline-variant pl-5">
              <div className="flex items-center gap-2 text-primary font-bold">
                <span
                  className={`w-2 h-2 rounded-full ${
                    isConnected
                      ? 'bg-primary-container animate-pulse'
                      : isConnecting || isSwitching
                        ? 'bg-[#FFB020] animate-ping'
                        : isErrorState
                          ? 'bg-error'
                          : 'bg-outline'
                  }`}
                />
                <span>
                  {isConnected
                    ? 'VPN РАБОТАЕТ • ПРОВЕРЕН'
                    : isConnecting || isSwitching
                      ? 'ПРОВЕРКА ТУННЕЛЯ...'
                      : isKillLocked
                        ? 'СТАТУС: KILL SWITCH'
                        : isErrorState
                          ? 'СБОЙ СВЯЗИ'
                          : 'VPN ВЫКЛЮЧЕН'}
                </span>
              </div>
              <span className="text-outline-variant">/</span>
              <div className="flex items-center gap-1.5 text-secondary">
                <TacticalIcon name="reorder" size={14} />
                <span>КАСКАД: {enabledUserNodes.length} СЕРВ.</span>
              </div>
              <span className="text-outline-variant">/</span>
              <div className="flex items-center gap-1.5 text-primary-container font-mono">
                <TacticalIcon name="speed" size={14} />
                <span>ПИНГ: {activeLatency !== null ? `${activeLatency} МС` : '—'}</span>
              </div>
            </div>
          )}
        </div>

        <div className="flex items-center gap-1.5 md:gap-2.5 flex-shrink-0">
          {!mobilePreview && (
            <button
              type="button"
              onClick={() => setActiveTab('nodes')}
              className="hidden sm:flex px-3 py-1.5 rounded bg-surface-container-high hover:bg-surface-variant border border-outline-variant text-on-surface font-telemetry-md text-telemetry-md items-center gap-1.5 transition-all cursor-pointer"
            >
              <TacticalIcon name="cloud_upload" size={15} />
              <span>ДОБАВИТЬ VPN</span>
            </button>
          )}

          {!isMobileApp && (
            <button
              type="button"
              onClick={handleToggleMobileWidget}
              title="Переключить компактный мобильный вид или полный экран ПК"
              className="hidden sm:flex px-2.5 py-1.5 rounded bg-surface-container-high hover:bg-surface-variant border border-outline-variant text-secondary font-telemetry-sm text-telemetry-sm items-center gap-1.5 transition-all cursor-pointer"
            >
              {mobilePreview ? (
                <>
                  <Monitor size={14} />
                  <span>ПК вид</span>
                </>
              ) : (
                <>
                  <Smartphone size={14} />
                  <span>Мини-виджет</span>
                </>
              )}
            </button>
          )}

          {snapshot.appUpdate?.updateAvailable && (
            <button
              type="button"
              onClick={() => {
                setActiveTab('routing');
                showToast(
                  `Доступно обновление AegisMesh VPN v${snapshot.appUpdate?.latestVersion} — откройте Центр обновлений`
                );
              }}
              className="px-2.5 py-1.5 min-h-[36px] rounded bg-primary-container/20 hover:bg-primary-container/30 border border-primary-container text-primary-container shield-glow font-badge-code text-[11px] font-bold flex items-center gap-1 transition-all cursor-pointer"
              title="Открыть Центр обновлений AegisMesh VPN"
            >
              <span>{`⬆️ Обновление v${snapshot.appUpdate.latestVersion}`}</span>
            </button>
          )}

          <button
            type="button"
            onClick={handlePingAll}
            className="w-9 h-9 rounded flex items-center justify-center text-on-surface-variant hover:text-primary bg-surface-container md:bg-transparent border border-outline-variant md:border-none transition-all cursor-pointer"
            title="Проверить пинг ваших серверов"
          >
            <TacticalIcon name="sync" size={16} />
          </button>

          <button
            type="button"
            disabled={busyAction}
            onClick={handlePowerAction}
            className={`px-3 py-2 md:py-1.5 min-h-[38px] rounded font-badge-code text-badge-code tracking-wider active:scale-95 transition-all flex items-center gap-1.5 cursor-pointer ${
              isConnected
                ? 'bg-error-container text-white border border-error/40 crimson-glow hover:bg-error-container/90'
                : 'bg-primary-container text-on-primary border border-primary-container shield-glow hover:opacity-95'
            }`}
          >
            <TacticalIcon name={isConnected ? 'power_settings_new' : 'bolt'} size={15} />
            <span>{isConnected ? 'ОТКЛЮЧИТЬ' : 'ПОДКЛЮЧИТЬ'}</span>
          </button>
        </div>
      </header>

      {/* Всплывающее уведомление */}
      {toast && (
        <div
          className={`${
            mobilePreview ? 'mx-3 mt-2' : 'md:ml-64 md:mt-20 mx-3.5 md:mx-6 mt-2.5'
          } p-3 rounded border font-telemetry-md text-telemetry-md flex items-center justify-between z-30 ${
            toast.isError
              ? 'bg-error-container/30 border-error text-error'
              : 'bg-primary-container/15 border-primary-container text-primary'
          }`}
        >
          <span className="text-xs md:text-sm">{toast.text}</span>
          <button
            type="button"
            onClick={() => setToast(null)}
            className="text-xs opacity-75 hover:opacity-100 ml-3 px-1"
          >
            ✕
          </button>
        </div>
      )}

      {/* Разблокировка криптосейфа PIN-кодом */}
      {snapshot.vaultLocked ? (
        <div
          className={`${
            mobilePreview ? 'p-4' : 'md:ml-64 md:mt-16 p-4 md:p-6'
          } flex-1 flex items-center justify-center`}
        >
          <div className="max-w-md w-full rounded bg-surface border border-primary-container/50 p-6 shield-glow space-y-4">
            <div className="flex items-center gap-2 text-primary font-headline-md text-headline-md">
              <Lock size={20} className="text-primary-container" />
              <span>Криптосейф заблокирован</span>
            </div>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              Введите ваш персональный PIN-код для доступа к сохранённым VPN-ключам:
            </p>
            <input
              type="password"
              className="w-full bg-[#070A0F] border border-outline-variant rounded p-3 text-on-surface font-telemetry-sm text-telemetry-sm focus:border-primary-container focus:outline-none"
              placeholder="Ваш PIN-код..."
              value={unlockPin}
              onChange={(e) => setUnlockPin(e.target.value)}
            />
            <button
              type="button"
              className="w-full py-3 px-4 rounded bg-primary-container text-on-primary font-badge-code text-badge-code tracking-wider uppercase cursor-pointer"
              onClick={async () => {
                try {
                  const next = await aegisApi.unlockVault(unlockPin);
                  setSnapshot(next);
                  setUnlockPin('');
                  showToast('Криптосейф успешно разблокирован');
                } catch (err) {
                  showToast(err instanceof Error ? err.message : 'Неверный PIN-код', true);
                }
              }}
            >
              Разблокировать сейф
            </button>
          </div>
        </div>
      ) : (
        <main
          className={
            mobilePreview
              ? 'p-3 flex-1'
              : `md:ml-64 ${toast ? 'mt-2' : 'md:mt-16'} p-3.5 md:p-6 flex-1 min-h-[calc(100vh-4rem)]`
          }
        >
          {activeTab === 'shield' && (
            <ShieldCascadeView
              snapshot={snapshot}
              onUpdate={setSnapshot}
              onNotify={showToast}
              onGoToNodes={() => setActiveTab('nodes')}
            />
          )}
          {activeTab === 'nodes' && (
            <NodesVaultView snapshot={snapshot} onUpdate={setSnapshot} onNotify={showToast} />
          )}
          {activeTab === 'routing' && (
            <RoutingSecurityView snapshot={snapshot} onUpdate={setSnapshot} onNotify={showToast} />
          )}
          {activeTab === 'audit' && (
            <DiagnosticsAuditView
              snapshot={snapshot}
              onUpdate={setSnapshot}
              onNotify={showToast}
            />
          )}
        </main>
      )}

      {/* Нижняя панель навигации для смартфонов (Thumb Zone >= 68px, кнопки >= 48px) */}
      <nav className={`bottom-tab-bar ${mobilePreview ? '' : 'md:hidden'}`}>
        {NAV_ITEMS.map((item) => (
          <button
            key={item.id}
            type="button"
            className={`tab-btn ${activeTab === item.id ? 'active' : ''}`}
            onClick={() => setActiveTab(item.id)}
          >
            {item.icon}
            <span>{item.shortLabel}</span>
          </button>
        ))}
      </nav>
    </div>
  );
};
