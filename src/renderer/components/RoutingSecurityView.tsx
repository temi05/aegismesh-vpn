import React, { useState } from 'react';
import {
  ChevronDown,
  ChevronUp,
  Cpu,
  Download,
  ExternalLink,
  Globe,
  Lock,
  Plus,
  QrCode,
  RefreshCw,
  Route,
  ShieldAlert,
  Smartphone,
  Trash2,
} from 'lucide-react';
import type {
  AppSettings,
  ConnectionMode,
  DnsProviderId,
  FailoverMode,
  VpnStateSnapshot,
} from '../../shared/types';
import { aegisApi, isNativeMobileApp } from '../api';
import { AiGatewayPanel } from './AiGatewayPanel';
import { MobileBridgeView } from './MobileBridgeView';
import { PerAppVpnPanel } from './PerAppVpnPanel';

interface Props {
  snapshot: VpnStateSnapshot;
  onUpdate: (next: VpnStateSnapshot) => void;
  onNotify: (msg: string, isError?: boolean) => void;
}

export const RoutingSecurityView: React.FC<Props> = ({ snapshot, onUpdate, onNotify }) => {
  const s = snapshot.settings;
  const [newDomain, setNewDomain] = useState('');
  const [pinInput, setPinInput] = useState('');
  const [installingCore, setInstallingCore] = useState(false);
  const [checkingUpdate, setCheckingUpdate] = useState(false);
  const [installingUpdate, setInstallingUpdate] = useState(false);
  const [showQrExport, setShowQrExport] = useState(false);
  const isMobile = isNativeMobileApp();
  const installedApps = snapshot.installedVpnApps || [];
  const appUpdate = snapshot.appUpdate;
  const currentVer = appUpdate?.currentVersion || '3.6.0';
  const latestVer = appUpdate?.latestVersion || currentVer;
  const hasUpdate = Boolean(appUpdate?.updateAvailable);
  const apkSizeMb =
    appUpdate?.apkSizeBytes && appUpdate.apkSizeBytes > 0
      ? (appUpdate.apkSizeBytes / (1024 * 1024)).toFixed(1)
      : null;

  const handleCheckAppUpdate = async () => {
    if (checkingUpdate) return;
    setCheckingUpdate(true);
    try {
      const res = await aegisApi.checkAppUpdate();
      if (res?.snapshot) {
        onUpdate(res.snapshot);
      }
      if (res?.update?.updateAvailable) {
        onNotify(
          `Доступна новая версия AegisMesh VPN v${res.update.latestVersion} (${res.update.releaseTitle})`
        );
      } else {
        onNotify(`У вас установлена актуальная версия v${res?.update?.currentVersion || '3.6.0'}`);
      }
    } catch (err) {
      onNotify(
        err instanceof Error ? err.message : 'Ошибка проверки обновлений на GitHub',
        true
      );
    } finally {
      setCheckingUpdate(false);
    }
  };

  const handleInstallAppUpdate = async (targetUrl?: string) => {
    if (installingUpdate) return;
    setInstallingUpdate(true);
    try {
      const res = await aegisApi.installAppUpdate(targetUrl);
      if (res?.snapshot) {
        onUpdate(res.snapshot);
      }
      onNotify(
        res?.update?.statusMessage ||
          'Запущено скачивание и установка обновления AegisMesh VPN'
      );
    } catch (err) {
      onNotify(
        err instanceof Error ? err.message : 'Ошибка запуска установки обновления',
        true
      );
    } finally {
      setInstallingUpdate(false);
    }
  };

  const patchSettings = async (patch: Partial<AppSettings>, message?: string) => {
    try {
      const next = await aegisApi.updateSettings(patch);
      onUpdate(next);
      if (message) onNotify(message);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Ошибка сохранения настроек', true);
    }
  };

  const handleAddBypassDomain = async () => {
    const clean = newDomain.trim().toLowerCase();
    if (!clean) return;
    if (s.bypassDomains.includes(clean)) {
      onNotify('Этот домен уже есть в списке исключений Split Tunneling', true);
      return;
    }
    await patchSettings(
      { bypassDomains: [...s.bypassDomains, clean] },
      `Домен ${clean} добавлен в прямой маршрут без VPN`
    );
    setNewDomain('');
  };

  const handleRemoveBypassDomain = async (domain: string) => {
    await patchSettings(
      { bypassDomains: s.bypassDomains.filter((d) => d !== domain) },
      `Домен ${domain} удалён из списка исключений`
    );
  };

  return (
    <div>
      {/* Центр обновлений AegisMesh VPN (GitHub Releases + OTA .APK в 1 клик) */}
      <div
        className="card"
        style={{
          marginBottom: 14,
          border: hasUpdate
            ? '1px solid rgba(56, 189, 248, 0.55)'
            : '1px solid rgba(0, 229, 176, 0.28)',
        }}
      >
        <div className="card-header" style={{ flexWrap: 'wrap', gap: 8 }}>
          <div className="card-title">
            <RefreshCw
              size={18}
              color={hasUpdate ? '#38BDF8' : 'var(--emerald-shield)'}
              className={checkingUpdate ? 'animate-spin' : ''}
            />
            <span>🔄 Центр обновлений AegisMesh VPN (GitHub Releases)</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span
              className="badge mono"
              style={{
                padding: '4px 10px',
                fontWeight: 700,
                background: hasUpdate
                  ? 'rgba(56, 189, 248, 0.16)'
                  : 'rgba(0, 229, 176, 0.14)',
                color: hasUpdate ? '#38BDF8' : 'var(--emerald-shield)',
                border: hasUpdate
                  ? '1px solid rgba(56, 189, 248, 0.45)'
                  : '1px solid rgba(0, 229, 176, 0.38)',
              }}
            >
              {hasUpdate
                ? `Доступна новая версия v${latestVer}`
                : 'Актуальная версия'}
            </span>
            <button
              type="button"
              className="btn btn-sm"
              disabled={checkingUpdate}
              onClick={() => void handleCheckAppUpdate()}
            >
              {checkingUpdate
                ? '⏳ Проверяем GitHub...'
                : '🔄 Проверить обновления (GitHub)'}
            </button>
          </div>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: 10,
            padding: 12,
            borderRadius: 10,
            background: 'var(--bg-elevated)',
            marginBottom: 12,
          }}
        >
          <div>
            <div style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
              Установленная версия:
            </div>
            <div className="mono" style={{ fontWeight: 700, fontSize: 14 }}>
              v{currentVer}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
              Последний релиз на GitHub:
            </div>
            <div
              className="mono"
              style={{
                fontWeight: 700,
                fontSize: 14,
                color: hasUpdate ? '#38BDF8' : 'var(--emerald-shield)',
              }}
            >
              v{latestVer}{' '}
              {appUpdate?.releaseTitle ? `• ${appUpdate.releaseTitle}` : ''}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
              Последняя проверка:
            </div>
            <div className="mono" style={{ fontSize: 12.5 }}>
              {appUpdate?.checkedAt
                ? new Date(appUpdate.checkedAt).toLocaleTimeString('ru-RU')
                : 'Только что'}
            </div>
          </div>
        </div>

        {appUpdate?.releaseNotes && (
          <div
            style={{
              padding: 12,
              borderRadius: 10,
              background: '#080d16',
              border: '1px solid var(--border-subtle)',
              marginBottom: 12,
            }}
          >
            <div
              style={{
                fontWeight: 700,
                fontSize: 12,
                color: '#38BDF8',
                marginBottom: 6,
              }}
            >
              📋 Список изменений (Release Notes):
            </div>
            <div
              style={{
                fontSize: 12,
                color: 'var(--text-secondary)',
                whiteSpace: 'pre-wrap',
                lineHeight: 1.45,
              }}
            >
              {appUpdate.releaseNotes}
            </div>
          </div>
        )}

        {appUpdate?.statusMessage && (
          <div
            style={{
              padding: '8px 12px',
              borderRadius: 8,
              background: 'rgba(0, 229, 176, 0.1)',
              border: '1px solid rgba(0, 229, 176, 0.35)',
              color: 'var(--emerald-shield)',
              fontSize: 12,
              marginBottom: 10,
            }}
          >
            {appUpdate.statusMessage}
          </div>
        )}

        {appUpdate?.error && (
          <div
            style={{
              padding: '8px 12px',
              borderRadius: 8,
              background: 'rgba(255, 176, 32, 0.1)',
              border: '1px solid rgba(255, 176, 32, 0.35)',
              color: 'var(--amber-failover)',
              fontSize: 12,
              marginBottom: 10,
            }}
          >
            ⚠️ {appUpdate.error}
          </div>
        )}

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            disabled={installingUpdate}
            onClick={() => void handleInstallAppUpdate()}
          >
            <Download size={14} />{' '}
            {installingUpdate
              ? 'Подготовка пакета обновления...'
              : `📲 Скачать и установить .APK в 1 клик${apkSizeMb ? ` (${apkSizeMb} МБ)` : ''}`}
          </button>

          {!isMobile && (
            <button
              type="button"
              className="btn btn-sm"
              disabled={installingUpdate}
              onClick={() =>
                void handleInstallAppUpdate(
                  appUpdate?.desktopDownloadUrl || appUpdate?.htmlUrl || undefined
                )
              }
            >
              <ExternalLink size={14} /> ⬇️ Скачать обновление с GitHub
            </button>
          )}
        </div>
      </div>

      <div className="grid-2">
        {/* Настройки Auto-Failover и Kill Switch */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <ShieldAlert size={18} color="var(--emerald-shield)" />
              <span>Алгоритм автозамены (Auto-Failover) и Kill Switch</span>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div>
              <label style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>
                Режим каскадного переключения при падении или лагах:
              </label>
              <select
                className="select"
                style={{ marginTop: 4 }}
                value={s.failoverMode}
                onChange={(e) =>
                  patchSettings(
                    { failoverMode: e.target.value as FailoverMode },
                    'Режим Auto-Failover обновлён'
                  )
                }
              >
                <option value="strict_cascade">
                  Строгая очередь по приоритету (Сервер #1 ➔ #2 ➔ #3...)
                </option>
                <option value="cascade_recovery">
                  Каскад + Автовозврат на #1, когда основной сервер оживёт
                </option>
                <option value="smart_fastest">
                  Умный Failover (выбор самого быстрого живого узла)
                </option>
              </select>
            </div>

            <div className="grid-2">
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  Порог высокого пинга (мс):
                </label>
                <input
                  type="number"
                  className="input mono"
                  min={150}
                  max={5000}
                  value={s.maxLatencyThresholdMs}
                  onChange={(e) =>
                    patchSettings({ maxLatencyThresholdMs: Number(e.target.value) || 900 })
                  }
                />
              </div>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  Интервал проверки (сек):
                </label>
                <input
                  type="number"
                  className="input mono"
                  min={2}
                  max={60}
                  value={s.healthCheckIntervalSec}
                  onChange={(e) =>
                    patchSettings({ healthCheckIntervalSec: Number(e.target.value) || 4 })
                  }
                />
              </div>
            </div>

            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: 12,
                background: 'var(--bg-elevated)',
                borderRadius: 10,
              }}
            >
              <div>
                <div style={{ fontWeight: 700, fontSize: 13 }}>
                  Бескомпромиссный Kill Switch (Защита от утечки IP)
                </div>
                <div style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                  Мгновенно блокирует трафик на шлюзе в момент переключения 1 ➔ 2
                </div>
              </div>
              <button
                type="button"
                className={`btn btn-sm ${s.killSwitchEnabled ? 'btn-primary' : ''}`}
                onClick={() =>
                  patchSettings(
                    { killSwitchEnabled: !s.killSwitchEnabled },
                    `Kill Switch ${!s.killSwitchEnabled ? 'включён' : 'выключен'}`
                  )
                }
              >
                {s.killSwitchEnabled ? 'ВКЛЮЧЁН' : 'ВЫКЛЮЧЕН'}
              </button>
            </div>

            {/* Настройки Умной Автозамены v3.0: Контроль скорости, DPI-антизависание и Автообновление подписок */}
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 10,
                padding: 12,
                background: 'var(--bg-elevated)',
                borderRadius: 10,
                border: '1px solid rgba(0, 229, 176, 0.22)',
              }}
            >
              <div style={{ fontWeight: 700, fontSize: 12.5, color: 'var(--emerald-shield)' }}>
                ⚡ Умная Автозамена v3.0 (Скорость • DPI-защита • Автообновление)
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 12.5 }}>
                    Контроль просадки скорости (Speed-Aware Failover)
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                    Переключает VPN, если реальная скорость потока падает ниже порога
                  </div>
                </div>
                <button
                  type="button"
                  className={`btn btn-sm ${s.speedFailoverEnabled !== false ? 'btn-primary' : ''}`}
                  onClick={() =>
                    patchSettings(
                      { speedFailoverEnabled: s.speedFailoverEnabled === false },
                      `Контроль скорости ${s.speedFailoverEnabled === false ? 'включён' : 'выключен'}`
                    )
                  }
                >
                  {s.speedFailoverEnabled !== false ? 'ВКЛ' : 'ВЫКЛ'}
                </button>
              </div>

              {s.speedFailoverEnabled !== false && (
                <div>
                  <label style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                    Минимальная допустимая скорость потока (Кбит/с):
                  </label>
                  <input
                    type="number"
                    className="input mono"
                    min={100}
                    max={20000}
                    value={s.minThroughputKbps ?? 350}
                    onChange={(e) =>
                      patchSettings({ minThroughputKbps: Math.max(100, Number(e.target.value) || 350) })
                    }
                  />
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 12.5 }}>
                    Детектор DPI-заморозки (Zombie-туннели) и Анти-флаппинг
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                    Распознаёт «тихое зависание» трафика и защищает от лишних прыжков
                  </div>
                </div>
                <button
                  type="button"
                  className={`btn btn-sm ${s.zombieCheckEnabled !== false ? 'btn-primary' : ''}`}
                  onClick={() =>
                    patchSettings(
                      {
                        zombieCheckEnabled: s.zombieCheckEnabled === false,
                        antiFlapEnabled: s.zombieCheckEnabled === false,
                      },
                      `DPI-детектор и анти-флаппинг ${s.zombieCheckEnabled === false ? 'включены' : 'выключены'}`
                    )
                  }
                >
                  {s.zombieCheckEnabled !== false ? 'ВКЛ' : 'ВЫКЛ'}
                </button>
              </div>

              <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 12.5 }}>
                    Автообновление и самоисцеление подписок
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                    Обновляет https:// подписки по расписанию и при смене IP провайдером
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  <select
                    className="select"
                    style={{ width: 'auto', padding: '5px 8px', fontSize: 12 }}
                    value={s.defaultAutoUpdateHours ?? 12}
                    onChange={(e) =>
                      patchSettings(
                        {
                          autoRefreshSubscriptions: Number(e.target.value) > 0,
                          defaultAutoUpdateHours: Number(e.target.value) || 12,
                        },
                        'Расписание автообновления подписок сохранено'
                      )
                    }
                  >
                    <option value={6}>Каждые 6 ч</option>
                    <option value={12}>Каждые 12 ч</option>
                    <option value={24}>Каждые 24 ч</option>
                    <option value={0}>Выключено</option>
                  </select>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Режим подключения и Защищённый DNS (DoH) */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Globe size={18} color="var(--cyan-mobile)" />
              <span>Шлюз трафика и Защищённый DNS (DoH)</span>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div>
              <label style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>
                Режим работы сетевого туннеля:
              </label>
              <select
                className="select"
                style={{ marginTop: 4 }}
                value={s.connectionMode}
                onChange={(e) =>
                  patchSettings(
                    { connectionMode: e.target.value as ConnectionMode },
                    'Режим подключения обновлён'
                  )
                }
              >
                <option value="proxy_only">
                  Локальный шлюз GuardProxy (127.0.0.1:{s.localProxyPort}) — без прав админа
                </option>
                <option value="system_proxy">
                  Системный прокси Windows (автонастройка браузеров и приложений)
                </option>
                <option value="tun">
                  Виртуальный адаптер TUN (весь трафик ОС через ядро sing-box)
                </option>
              </select>
            </div>

            <div>
              <label style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>
                Шифрованный провайдер DNS-over-HTTPS (защита от перехвата провайдером):
              </label>
              <select
                className="select"
                style={{ marginTop: 4 }}
                value={s.dnsProvider}
                onChange={(e) =>
                  patchSettings(
                    { dnsProvider: e.target.value as DnsProviderId },
                    'Провайдер Secure DNS обновлён'
                  )
                }
              >
                <option value="cloudflare">Cloudflare 1.1.1.1 (Максимальная скорость)</option>
                <option value="adguard">
                  AdGuard DNS (Блокировка рекламы, трекеров и фишинга)
                </option>
                <option value="quad9">Quad9 9.9.9.9 (Швейцарская защита от вредоносов)</option>
                <option value="google">Google Public DNS 8.8.8.8</option>
              </select>
            </div>

            {/* Бесшовный роуминг Wi-Fi ⇄ LTE, память лучших серверов и адаптивный MTU v3.4 */}
            <div
              style={{
                marginTop: 6,
                padding: '10px 12px',
                borderRadius: 10,
                background: 'rgba(6, 182, 212, 0.06)',
                border: '1px solid rgba(6, 182, 212, 0.25)',
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
              }}
            >
              <div style={{ fontSize: 12.5, fontWeight: 700, color: 'var(--cyan-mobile)' }}>
                📶 Интеллектуальный роуминг Wi-Fi ⇄ LTE и Мобильный MTU v3.4
              </div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  Авто-профиль сети (помнить лучший сервер отдельно для Wi-Fi и для LTE):
                </span>
                <button
                  type="button"
                  className={`btn btn-sm ${s.networkProfileAutoSwitchEnabled !== false ? 'btn-primary' : ''}`}
                  onClick={() =>
                    patchSettings(
                      { networkProfileAutoSwitchEnabled: s.networkProfileAutoSwitchEnabled === false },
                      s.networkProfileAutoSwitchEnabled === false
                        ? 'Автопереключение лучших серверов Wi-Fi ⇄ LTE включено'
                        : 'Автопереключение профилей сети отключено'
                    )
                  }
                >
                  {s.networkProfileAutoSwitchEnabled !== false ? 'Включено' : 'Выкл'}
                </button>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  Адаптивный MTU для LTE/4G (1360 байт против потери пакетов оператора):
                </span>
                <button
                  type="button"
                  className={`btn btn-sm ${s.adaptiveMobileMtu !== false ? 'btn-primary' : ''}`}
                  onClick={() =>
                    patchSettings(
                      { adaptiveMobileMtu: s.adaptiveMobileMtu === false },
                      'Настройка адаптивного мобильного MTU сохранена'
                    )
                  }
                >
                  {s.adaptiveMobileMtu !== false ? '1360 (Авто)' : '1400 (Фикс)'}
                </button>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    Лучший сервер для 🏠 Wi-Fi:
                  </label>
                  <select
                    className="select"
                    style={{ marginTop: 3, fontSize: 11.5 }}
                    value={s.bestWifiNodeId || ''}
                    onChange={(e) =>
                      patchSettings(
                        { bestWifiNodeId: e.target.value ? e.target.value : null },
                        'Предпочтительный сервер для Wi-Fi обновлён'
                      )
                    }
                  >
                    <option value="">Авто (обучается сам)</option>
                    {snapshot.nodes
                      .filter((n) => n.enabled)
                      .map((n) => (
                        <option key={n.id} value={n.id}>
                          {n.name}
                        </option>
                      ))}
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    Лучший сервер для 📶 LTE / 4G:
                  </label>
                  <select
                    className="select"
                    style={{ marginTop: 3, fontSize: 11.5 }}
                    value={s.bestCellularNodeId || ''}
                    onChange={(e) =>
                      patchSettings(
                        { bestCellularNodeId: e.target.value ? e.target.value : null },
                        'Предпочтительный сервер для LTE/4G обновлён'
                      )
                    }
                  >
                    <option value="">Авто (LTE / через РФ)</option>
                    {snapshot.nodes
                      .filter((n) => n.enabled)
                      .map((n) => (
                        <option key={n.id} value={n.id}>
                          {n.name}
                        </option>
                      ))}
                  </select>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid-2">
        {/* Раздельное туннелирование (Split Tunneling) */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Route size={18} color="var(--amber-failover)" />
              <span>Раздельное туннелирование (Split Tunneling)</span>
            </div>
            <button
              type="button"
              className={`btn btn-sm ${s.splitTunnelingEnabled ? 'btn-primary' : ''}`}
              onClick={() =>
                patchSettings({ splitTunnelingEnabled: !s.splitTunnelingEnabled })
              }
            >
              {s.splitTunnelingEnabled ? 'Активно' : 'Выключено'}
            </button>
          </div>

          <p style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginBottom: 10 }}>
            Домены из этого списка открываются напрямую через вашего провайдера в обход VPN (банки,
            Госуслуги, локальные сервисы):
          </p>

          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            <input
              className="input mono"
              placeholder="Например: *.ru или sberbank.ru"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
            />
            <button type="button" className="btn btn-primary" onClick={handleAddBypassDomain}>
              <Plus size={16} /> Добавить
            </button>
          </div>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {s.bypassDomains.map((dom) => (
              <span key={dom} className="badge mono" style={{ padding: '5px 10px' }}>
                {dom}
                <button
                  type="button"
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--ruby-killswitch)',
                    cursor: 'pointer',
                    marginLeft: 4,
                  }}
                  onClick={() => handleRemoveBypassDomain(dom)}
                >
                  <Trash2 size={12} />
                </button>
              </span>
            ))}
          </div>
        </div>

        {/* Ядро sing-box и Криптосейф AES-256-GCM */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Cpu size={18} color="var(--emerald-shield)" />
              <span>Ядро sing-box и Криптосейф AES-256-GCM</span>
            </div>
          </div>

          <div
            style={{
              padding: 12,
              background: 'var(--bg-elevated)',
              borderRadius: 10,
              marginBottom: 12,
            }}
          >
            <div style={{ fontWeight: 700, fontSize: 13 }}>
              Статус мультипротокольного ядра sing-box:{' '}
              <span style={{ color: 'var(--emerald-shield)' }}>
                {snapshot.coreStatus.installed
                  ? `Установлено (${snapshot.coreStatus.version || 'v1.10+'})`
                  : 'Работает встроенный движок GuardProxy'}
              </span>
            </div>
            <div style={{ fontSize: 11.5, color: 'var(--text-secondary)', marginTop: 4 }}>
              Для локального стенда и HTTP/SOCKS5 прокси внешнее ядро не требуется. Для протоколов
              VLESS Reality / Hysteria2 / WireGuard можно скачать официальное ядро sing-box в 1 клик:
            </div>
            {!snapshot.coreStatus.installed && (
              <button
                type="button"
                className="btn btn-sm"
                style={{ marginTop: 8 }}
                disabled={installingCore || snapshot.coreStatus.downloading}
                onClick={async () => {
                  setInstallingCore(true);
                  try {
                    const next = await aegisApi.installSingboxCore();
                    onUpdate(next);
                    onNotify('Официальное ядро sing-box успешно установлено!');
                  } catch (err) {
                    onNotify(
                      err instanceof Error ? err.message : 'Ошибка скачивания ядра',
                      true
                    );
                  } finally {
                    setInstallingCore(false);
                  }
                }}
              >
                <Download size={14} />{' '}
                {installingCore ? 'Загрузка с GitHub...' : 'Скачать ядро sing-box'}
              </button>
            )}
          </div>

          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <Lock size={16} color="var(--amber-failover)" />
            <input
              type="password"
              className="input"
              placeholder="Новый PIN-код для шифрования ключей (AES-256)"
              value={pinInput}
              onChange={(e) => setPinInput(e.target.value)}
            />
            <button
              type="button"
              className="btn btn-sm"
              onClick={async () => {
                const next = await aegisApi.setVaultPin(pinInput.trim() || null);
                onUpdate(next);
                setPinInput('');
                onNotify(
                  pinInput.trim()
                    ? 'PIN-код криптосейфа установлен'
                    : 'PIN-код снят (используется системный ключ)'
                );
              }}
            >
              {pinInput.trim() ? 'Задать PIN' : 'Сбросить PIN'}
            </button>
          </div>
        </div>
      </div>

      {/* Умный шлюз для Нейросетей (Google Gemini • ChatGPT • Grok) */}
      <AiGatewayPanel
        snapshot={snapshot}
        onUpdate={onUpdate}
        onNotify={onNotify}
        variant="detailed"
      />

      {/* Умная маршрутизация по приложениям (Per-App VPN) + Плитка в шторке и Виджет Android */}
      {isMobile && (
        <PerAppVpnPanel snapshot={snapshot} onUpdate={onUpdate} onNotify={onNotify} />
      )}

      {/* Уровень 3: Аварийное закрытое VPN-приложение Android (если недоступны все подписки и прокси-мосты) */}
      {isMobile && (
        <div className="card" style={{ marginTop: 14 }}>
          <div className="card-header">
            <div className="card-title">
              <Smartphone size={18} color="var(--amber-failover)" />
              <span>Резервное VPN-приложение на телефоне (Аварийный перехват)</span>
            </div>
            <button
              type="button"
              className="btn btn-sm"
              onClick={async () => {
                const next = await aegisApi.scanExternalClients();
                onUpdate(next);
                onNotify('Список установленных VPN-приложений обновлён');
              }}
            >
              <RefreshCw size={13} /> Обновить список
            </button>
          </div>
          <p style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginBottom: 10 }}>
            Если у вас установлено закрытое однокнопочное VPN-приложение из Google Play (без ключей
            и без локального прокси), выберите его здесь. Если все ваши подписки упадут, AegisMesh
            отключит свой туннель и предложит запустить это приложение в 1 касание:
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
            <select
              className="select"
              style={{ flex: 1, minWidth: 220 }}
              value={snapshot.emergencyAppPackage || ''}
              onChange={async (e) => {
                const val = e.target.value || null;
                const next = await aegisApi.selectEmergencyApp(val);
                onUpdate(next);
                onNotify(
                  val
                    ? 'Резервное VPN-приложение сохранено'
                    : 'Резервное VPN-приложение отключено'
                );
              }}
            >
              <option value="">— Не выбрано —</option>
              {installedApps.map((app) => (
                <option key={app.packageName} value={app.packageName}>
                  {app.appName} ({app.packageName})
                </option>
              ))}
            </select>
            {snapshot.emergencyAppPackage && (
              <button
                type="button"
                className="btn btn-sm"
                onClick={async () => {
                  try {
                    const next = await aegisApi.launchEmergencyApp(
                      snapshot.emergencyAppPackage || undefined
                    );
                    onUpdate(next);
                  } catch (err) {
                    onNotify(
                      err instanceof Error ? err.message : 'Ошибка открытия приложения',
                      true
                    );
                  }
                }}
              >
                <ExternalLink size={13} /> Открыть сейчас
              </button>
            )}
          </div>
        </div>
      )}

      {/* Сворачиваемый блок Экспорта профиля sing-box и QR-моста ПК ↔ Смартфон */}
      <div className="card" style={{ marginTop: 14 }}>
        <div
          className="card-header"
          style={{ cursor: 'pointer', marginBottom: showQrExport ? 12 : 0 }}
          onClick={() => setShowQrExport((v) => !v)}
        >
          <div className="card-title">
            <QrCode size={18} color="var(--cyan-mobile)" />
            <span>Экспорт конфигурации sing-box и QR-синхронизация с ПК</span>
          </div>
          <button type="button" className="btn btn-sm">
            {showQrExport ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
            <span>{showQrExport ? 'Свернуть' : 'Открыть'}</span>
          </button>
        </div>
        {showQrExport && (
          <MobileBridgeView snapshot={snapshot} onUpdate={onUpdate} onNotify={onNotify} />
        )}
      </div>
    </div>
  );
};
