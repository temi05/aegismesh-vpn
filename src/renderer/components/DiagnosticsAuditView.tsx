import React, { useState } from 'react';
import {
  Bot,
  CheckCircle2,
  Clock,
  Radar,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import type { VpnStateSnapshot } from '../../shared/types';
import { aegisApi } from '../api';

interface Props {
  snapshot: VpnStateSnapshot;
  onUpdate: (next: VpnStateSnapshot) => void;
  onNotify: (msg: string, isError?: boolean) => void;
}

export const DiagnosticsAuditView: React.FC<Props> = ({
  snapshot,
  onUpdate,
  onNotify,
}) => {
  const [scanning, setScanning] = useState(false);
  const audit = snapshot.lastAudit;

  const rawSnap = snapshot as VpnStateSnapshot & {
    activeAiNodeName?: string | null;
    activeAiCountry?: string | null;
    aiCompatibleCount?: number;
  };
  const aiGatewayEnabled = snapshot.settings?.aiRoutingEnabled !== false;
  const activeAiNodeName =
    snapshot.telemetry?.activeAiNodeName ??
    rawSnap.activeAiNodeName ??
    snapshot.nodes.find(
      (n) =>
        n.id ===
        (snapshot.telemetry?.activeAiNodeId ||
          snapshot.settings?.preferredAiNodeId ||
          snapshot.activeNodeId)
    )?.name ??
    null;
  const activeAiCountry =
    snapshot.telemetry?.activeAiCountry ?? rawSnap.activeAiCountry ?? null;
  const aiCompatibleCount =
    snapshot.telemetry?.aiCompatibleCount ??
    rawSnap.aiCompatibleCount ??
    snapshot.nodes.filter((n) => n.enabled && n.aiStatus === 'ok').length;

  const handleRunScan = async () => {
    setScanning(true);
    try {
      const { report, snapshot: next } = await aegisApi.runAudit();
      onUpdate(next);
      onNotify(`Аудит завершён: индекс киберзащиты ${report.securityScore} / 100`);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Ошибка кибераудита', true);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-4">
      {/* Диагностический статус Умного шлюза Нейросетей (AI Gateway / proxy-ai) */}
      <div
        className="card rounded-xl relative overflow-hidden"
        style={{
          marginBottom: 14,
          border: aiGatewayEnabled
            ? '1px solid rgba(56, 189, 248, 0.4)'
            : '1px solid var(--border-subtle)',
        }}
      >
        <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-[#38BDF8] via-primary-container to-[#38BDF8] opacity-75" />
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Bot size={18} color="#38BDF8" />
            <div>
              <div style={{ fontWeight: 700, fontSize: 13.5 }}>
                AI Gateway (<code>proxy-ai</code>) • Шлюз Нейросетей (Gemini / ChatGPT / Grok)
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
                Активный ИИ-сервер:{' '}
                <strong style={{ color: '#38BDF8' }}>
                  {activeAiNodeName || 'Автоподбор при подключении'}
                </strong>
                {activeAiCountry ? ` (${activeAiCountry})` : ''}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:flex items-center gap-2 w-full sm:w-auto">
            <span
              className="badge mono text-center justify-center"
              style={{
                padding: '5px 10px',
                background: 'rgba(0, 229, 176, 0.14)',
                color: 'var(--emerald-shield)',
                border: '1px solid rgba(0, 229, 176, 0.35)',
                fontWeight: 700,
              }}
            >
              AI OK: {aiCompatibleCount}
            </span>
            <span
              className="badge mono text-center justify-center"
              style={{
                padding: '5px 10px',
                background: aiGatewayEnabled
                  ? 'rgba(56, 189, 248, 0.16)'
                  : 'var(--bg-elevated)',
                color: aiGatewayEnabled ? '#38BDF8' : 'var(--text-secondary)',
                border: aiGatewayEnabled
                  ? '1px solid rgba(56, 189, 248, 0.45)'
                  : '1px solid var(--border-subtle)',
                fontWeight: 700,
              }}
            >
              {aiGatewayEnabled ? 'ШЛЮЗ ИИ АКТИВЕН' : 'ШЛЮЗ ИИ ВЫКЛ'}
            </span>
          </div>
        </div>
      </div>

      <div className="grid-2">
        {/* Блок сканера утечек IP и DNS (Cyber Score) */}
        <div className="card rounded-xl relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-primary-container via-secondary-container to-primary-container opacity-80" />
          <div className="card-header flex-col sm:flex-row sm:items-center gap-2.5">
            <div className="card-title">
              <Radar size={18} color="var(--emerald-shield)" />
              <span>Интерактивный сканер утечек (IP / DNS / Kill Switch)</span>
            </div>
            <button
              type="button"
              className="btn btn-primary btn-sm w-full sm:w-auto justify-center"
              disabled={scanning}
              onClick={handleRunScan}
            >
              {scanning ? 'Сканирование...' : 'Запустить сканирование утечек'}
            </button>
          </div>

          {!audit ? (
            <div style={{ padding: '16px 0', color: 'var(--text-secondary)' }}>
              Нажмите «Запустить сканирование утечек», чтобы сравнить ваш прямой IP провайдера и
              внешний IP внутри зашифрованного VPN-туннеля.
            </div>
          ) : (
            <div>
              <div
                className="rounded-xl relative overflow-hidden"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: 12,
                  background: 'var(--bg-elevated)',
                  border: '1px solid rgba(0, 245, 155, 0.25)',
                  marginBottom: 12,
                }}
              >
                <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-primary-container via-secondary-container to-primary-container opacity-75" />
                <div>
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                    Вердикт безопасности:
                  </div>
                  <div style={{ fontWeight: 700, fontSize: 14 }}>{audit.verdict}</div>
                </div>
                <div
                  className="mono"
                  style={{
                    fontSize: 22,
                    fontWeight: 700,
                    color:
                      audit.securityScore >= 80
                        ? 'var(--emerald-shield)'
                        : 'var(--amber-failover)',
                  }}
                >
                  {audit.securityScore}/100
                </div>
              </div>

              <div className="grid-2" style={{ marginBottom: 12 }}>
                <div
                  className="rounded-xl"
                  style={{
                    padding: 10,
                    background: '#080d16',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                    Прямой IP провайдера:
                  </div>
                  <div className="mono" style={{ fontWeight: 700, fontSize: 13 }}>
                    {audit.directIp || 'Скрыт / Оффлайн'}
                  </div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                    {audit.directCountry || 'Локальный контур'} • {audit.directOrg || 'ISP'}
                  </div>
                </div>

                <div
                  className="rounded-xl"
                  style={{
                    padding: 10,
                    background: 'rgba(0, 245, 155, 0.06)',
                    border: '1px solid var(--border-highlight)',
                  }}
                >
                  <div style={{ fontSize: 11, color: 'var(--emerald-shield)' }}>
                    Защищённый IP туннеля:
                  </div>
                  <div className="mono" style={{ fontWeight: 700, fontSize: 13 }}>
                    {audit.tunnelIp || 'Туннель не активен'}
                  </div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                    {audit.tunnelCountry || '—'} • {audit.tunnelOrg || 'AegisMesh Guard'}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {audit.checks.map((chk) => (
                  <div
                    key={chk.id}
                    className="rounded-xl"
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: 8,
                      padding: '8px 10px',
                      background: 'var(--bg-elevated)',
                      fontSize: 12.5,
                    }}
                  >
                    {chk.passed ? (
                      <CheckCircle2
                        size={16}
                        color="var(--emerald-shield)"
                        style={{ flexShrink: 0, marginTop: 2 }}
                      />
                    ) : (
                      <XCircle
                        size={16}
                        color="var(--amber-failover)"
                        style={{ flexShrink: 0, marginTop: 2 }}
                      />
                    )}
                    <div>
                      <div style={{ fontWeight: 700 }}>{chk.title}</div>
                      <div style={{ color: 'var(--text-secondary)', fontSize: 11.5 }}>
                        {chk.detail}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Полный журнал событий Auto-Failover */}
        <div className="card rounded-xl relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-secondary-container via-primary-container to-secondary-container opacity-75" />
          <div className="card-header">
            <div className="card-title">
              <ShieldCheck size={18} color="var(--cyan-mobile)" />
              <span>Хронологический журнал Auto-Failover ({snapshot.events.length})</span>
            </div>
          </div>

          {snapshot.events.length === 0 ? (
            <div style={{ padding: '16px 0', color: 'var(--text-secondary)' }}>
              Событий пока нет. Добавьте свои VPN-ключи и включите щит, чтобы увидеть журнал
              подключений и автозамен.
            </div>
          ) : (
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
                maxHeight: 420,
                overflowY: 'auto',
              }}
            >
              {snapshot.events.map((ev) => {
                const timeStr = new Date(ev.timestamp).toLocaleTimeString('ru-RU');
                const isSwitch = ev.type === 'failover_switch';
                const isKill = ev.type === 'killswitch_engaged';
                return (
                  <div
                    key={ev.id}
                    className="rounded-xl"
                    style={{
                      padding: '9px 11px',
                      background: isSwitch
                        ? 'rgba(255, 176, 32, 0.09)'
                        : isKill
                          ? 'rgba(255, 59, 92, 0.1)'
                          : 'var(--bg-elevated)',
                      border: `1px solid ${
                        isSwitch
                          ? 'rgba(255, 176, 32, 0.35)'
                          : isKill
                            ? 'rgba(255, 59, 92, 0.4)'
                            : 'var(--border-subtle)'
                      }`,
                      fontSize: 12.5,
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        color: 'var(--text-secondary)',
                        fontSize: 11,
                        marginBottom: 3,
                      }}
                    >
                      <span className="mono">
                        <Clock size={11} style={{ marginRight: 4 }} />
                        {timeStr}
                      </span>
                      {ev.latencyMs !== undefined && ev.latencyMs !== null && (
                        <span className="mono">{ev.latencyMs} мс</span>
                      )}
                    </div>
                    <div style={{ fontWeight: 600 }}>{ev.reason}</div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
