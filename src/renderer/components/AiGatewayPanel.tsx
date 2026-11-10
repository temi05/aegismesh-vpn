// Панель Умного шлюза для Нейросетей AegisMesh VPN v3.1 (Google Gemini, ChatGPT, Grok, Claude и др.)
// Поддерживает компактный режим для Главного экрана (управление в 1 тап) и расширенный режим для Настроек.
import React, { useState } from 'react';
import {
  Bot,
  CheckCircle2,
  Plus,
  RefreshCw,
  SearchCheck,
  Sparkles,
  Trash2,
  XCircle,
} from 'lucide-react';
import {
  AI_SERVICE_CATALOG,
  DEFAULT_AI_SERVICES,
  inferCountryHintFromNode,
} from '../../shared/aiRouting';
import type {
  AiRoutingMode,
  AiServicePresetId,
  AppSettings,
  VpnStateSnapshot,
} from '../../shared/types';
import { aegisApi } from '../api';

interface Props {
  snapshot: VpnStateSnapshot;
  onUpdate: (next: VpnStateSnapshot) => void;
  onNotify: (msg: string, isError?: boolean) => void;
  variant: 'compact' | 'detailed';
}

export const AiGatewayPanel: React.FC<Props> = ({
  snapshot,
  onUpdate,
  onNotify,
  variant,
}) => {
  const [busyAi, setBusyAi] = useState(false);
  const [customAiDomain, setCustomAiDomain] = useState('');

  const s = snapshot.settings;
  const aiEnabled = s.aiRoutingEnabled !== false;
  const aiMode: AiRoutingMode = s.aiRoutingMode || 'parallel_ai_tunnel';
  const enabledServices =
    Array.isArray(s.aiServices) && s.aiServices.length > 0
      ? s.aiServices
      : DEFAULT_AI_SERVICES;

  const userNodes = snapshot.nodes.filter((n) => !n.isTestStand && n.enabled);
  const activeAiId =
    snapshot.telemetry?.activeAiNodeId || s.preferredAiNodeId || snapshot.activeNodeId;
  const activeAiNode = userNodes.find((n) => n.id === activeAiId) || null;
  const aiOkNodes = userNodes.filter((n) => n.aiStatus === 'ok');
  const aiProbing = Boolean(snapshot.telemetry?.aiProbeInProgress) || busyAi;

  const patchSettings = async (patch: Partial<AppSettings>, msg?: string) => {
    try {
      const next = await aegisApi.updateSettings(patch);
      onUpdate(next);
      if (msg) onNotify(msg);
    } catch (err) {
      onNotify(
        err instanceof Error ? err.message : 'Ошибка обновления настроек ИИ-шлюза',
        true
      );
    }
  };

  const handleScanAi = async () => {
    if (aiProbing) return;
    if (userNodes.length === 0) {
      onNotify('Сначала добавьте VPN-подписку или ключ', true);
      return;
    }
    setBusyAi(true);
    try {
      const next = await aegisApi.scanAiNodes();
      onUpdate(next);
      const okCount = next.nodes.filter((n) => n.enabled && n.aiStatus === 'ok').length;
      const aiName = next.telemetry?.activeAiNodeName;
      onNotify(
        okCount > 0
          ? `🤖 Проверка базы Google завершена: найдено ${okCount} серверов для Gemini/GPT/Grok${aiName ? ` (активен «${aiName}»)` : ''}`
          : snapshot.connectionState !== 'connected'
            ? 'Подключите VPN и нажмите «Проверить ИИ», чтобы проверить реальный регион серверов в базе Google'
            : 'Ни один из проверенных серверов не открыл Gemini (в базе Google их IP числится как RU). Попробуйте другую подписку или сервер США/Европы',
        okCount === 0
      );
    } catch (err) {
      onNotify(
        err instanceof Error ? err.message : 'Ошибка проверки серверов для нейросетей',
        true
      );
    } finally {
      setBusyAi(false);
    }
  };

  const handleCycleAiNode = async (explicitNodeId?: string) => {
    if (busyAi) return;
    if (userNodes.length === 0) {
      onNotify('Нет доступных серверов для ИИ-шлюза', true);
      return;
    }
    setBusyAi(true);
    try {
      const next = await aegisApi.switchAiNode(explicitNodeId);
      onUpdate(next);
      const aiName = next.telemetry?.activeAiNodeName || 'новый сервер';
      const cc = next.telemetry?.activeAiCountry;
      onNotify(
        `🤖 Шлюз Нейросетей переключён на «${aiName}»${cc ? ` (${cc})` : ''}`
      );
    } catch (err) {
      onNotify(
        err instanceof Error ? err.message : 'Не удалось переключить сервер ИИ',
        true
      );
    } finally {
      setBusyAi(false);
    }
  };

  const toggleAiService = async (serviceId: AiServicePresetId) => {
    const exists = enabledServices.includes(serviceId);
    const nextList = exists
      ? enabledServices.filter((id) => id !== serviceId)
      : [...enabledServices, serviceId];
    if (nextList.length === 0) {
      onNotify('Оставьте включённой хотя бы одну группу нейросетей', true);
      return;
    }
    await patchSettings(
      { aiServices: nextList },
      'Список маршрутизируемых нейросетей обновлён'
    );
  };

  const handleAddCustomDomain = async () => {
    const clean = customAiDomain
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .split('/')[0]
      .trim();
    if (!clean) return;
    const prev = s.aiCustomDomains || [];
    if (prev.includes(clean)) {
      onNotify('Этот домен уже добавлен в ИИ-шлюз', true);
      return;
    }
    await patchSettings(
      { aiCustomDomains: [...prev, clean] },
      `Домен ${clean} добавлен в выделенный ИИ-туннель`
    );
    setCustomAiDomain('');
  };

  if (variant === 'compact') {
    const aiCountry =
      snapshot.telemetry?.activeAiCountry ||
      (activeAiNode ? inferCountryHintFromNode(activeAiNode) : null);

    return (
      <div className="rounded-xl bg-surface border border-[#38BDF8]/40 p-3.5 md:p-4 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-[#38BDF8]/15 border border-[#38BDF8]/40 flex items-center justify-center flex-shrink-0">
              <Sparkles size={16} className="text-[#38BDF8]" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="font-headline-md text-xs md:text-sm font-bold text-on-surface">
                  Шлюз Нейросетей (Gemini • GPT • Grok)
                </span>
                {aiEnabled && aiOkNodes.length > 0 && (
                  <span className="font-badge-code text-[10px] px-1.5 py-0.5 rounded bg-primary-container/15 text-primary-container border border-primary-container/40 font-bold">
                    AI OK: {aiOkNodes.length}
                  </span>
                )}
              </div>
              <p className="text-[11px] text-on-surface-variant truncate">
                {aiEnabled
                  ? aiMode === 'parallel_ai_tunnel'
                    ? 'Отдельный стабильный канал для ИИ — не сбрасывается при смене основного VPN'
                    : 'Режим: весь трафик устройства идёт только через AI-совместимые серверы'
                  : 'Выделенная маршрутизация для нейросетей отключена'}
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={() =>
              void patchSettings(
                { aiRoutingEnabled: !aiEnabled },
                `Шлюз Нейросетей ${!aiEnabled ? 'включён' : 'выключен'}`
              )
            }
            className={`px-3 py-1.5 min-h-[36px] rounded-lg font-badge-code text-[11px] font-bold border transition-colors cursor-pointer ${
              aiEnabled
                ? 'bg-[#38BDF8]/20 border-[#38BDF8]/60 text-[#38BDF8]'
                : 'bg-surface-container-high border-outline-variant text-on-surface-variant'
            }`}
          >
            {aiEnabled ? 'АКТИВЕН' : 'ВЫКЛ'}
          </button>
        </div>

        {aiEnabled && (
          <div className="pt-2 border-t border-outline-variant flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
            <div className="text-xs min-w-0">
              <span className="text-on-surface-variant">Сервер для ИИ: </span>
              {activeAiNode ? (
                <strong className="text-[#38BDF8] font-semibold">
                  {activeAiNode.name}
                  {aiCountry ? ` (${aiCountry})` : ''}
                </strong>
              ) : (
                <span className="text-on-surface-variant">Автоподбор при подключении</span>
              )}
              {activeAiNode?.aiStatus === 'ok' && (
                <span className="ml-1.5 inline-flex items-center gap-1 text-[10px] font-badge-code px-1.5 py-0.5 rounded bg-primary-container/15 text-primary-container border border-primary-container/40">
                  {activeAiNode.aiGeminiOk
                    ? `Gemini✓${activeAiNode.aiExitCountry ? ` (Google: ${activeAiNode.aiExitCountry})` : ''}`
                    : ''}
                  {activeAiNode.aiChatgptOk ? ' GPT✓' : ''}
                  {activeAiNode.aiGrokOk ? ' Grok✓' : ''}
                </span>
              )}
              {activeAiNode?.aiStatus === 'blocked' && (
                <span className="ml-1.5 inline-flex items-center gap-1 text-[10px] font-badge-code px-1.5 py-0.5 rounded bg-error-container/30 text-error border border-error/40">
                  {activeAiNode.aiBlockReason || 'ИИ ограничен'}
                </span>
              )}
              {aiProbing && (
                <div className="mt-1 text-[11px] text-[#38BDF8]">
                  ⏳ Проверяем реальный регион серверов в базе Google для Gemini...
                </div>
              )}
              {!aiProbing &&
                aiOkNodes.length === 0 &&
                userNodes.some((n) => n.aiStatus === 'blocked') && (
                  <div className="mt-1.5 text-[11px] text-amber-300/95 bg-amber-500/10 border border-amber-400/30 rounded-lg px-2.5 py-1.5 leading-snug">
                    ⚠️ Проверенные серверы помечены в базе Google как <strong>RU</strong> («YouTube без рекламы» блокирует Gemini). Включите VPN и нажмите <strong>«Проверить ИИ»</strong> для поиска по всем подпискам или добавьте чистый сервер США/Европы.
                  </div>
                )}
            </div>

            <div className="flex items-center gap-2 flex-shrink-0">
              <button
                type="button"
                disabled={aiProbing || userNodes.length === 0}
                onClick={() => void handleScanAi()}
                className="flex-1 sm:flex-initial px-3 py-2 min-h-[38px] rounded-lg bg-surface-container-high hover:bg-surface-variant border border-outline-variant text-on-surface font-badge-code text-[11px] flex items-center justify-center gap-1.5 cursor-pointer"
              >
                <SearchCheck size={13} className={aiProbing ? 'animate-pulse text-[#38BDF8]' : 'text-[#38BDF8]'} />
                <span>{aiProbing ? 'Проверка...' : 'Проверить ИИ'}</span>
              </button>

              <button
                type="button"
                disabled={busyAi || userNodes.length < 2}
                onClick={() => void handleCycleAiNode()}
                className="flex-1 sm:flex-initial px-3 py-2 min-h-[38px] rounded-lg bg-[#38BDF8]/15 hover:bg-[#38BDF8]/25 border border-[#38BDF8]/50 text-[#38BDF8] font-badge-code text-[11px] font-bold flex items-center justify-center gap-1.5 cursor-pointer"
              >
                <RefreshCw size={13} className={busyAi ? 'animate-spin' : ''} />
                <span>Сменить ИИ</span>
              </button>
            </div>
          </div>
        )}
      </div>
    );
  }

  // Детальная панель для вкладки «Настройки»
  return (
    <div className="card" style={{ marginTop: 14, border: '1px solid rgba(56, 189, 248, 0.35)' }}>
      <div className="card-header">
        <div className="card-title">
          <Bot size={18} color="#38BDF8" />
          <span>Умный шлюз для Нейросетей (Google Gemini • ChatGPT • Grok)</span>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn btn-sm"
            disabled={aiProbing || userNodes.length === 0}
            onClick={() => void handleScanAi()}
          >
            <SearchCheck size={14} />{' '}
            {aiProbing ? 'Проверяем Gemini/GPT/Grok...' : 'Проверить серверы на ИИ'}
          </button>
          <button
            type="button"
            className={`btn btn-sm ${aiEnabled ? 'btn-primary' : ''}`}
            onClick={() =>
              void patchSettings(
                { aiRoutingEnabled: !aiEnabled },
                `Умный шлюз Нейросетей ${!aiEnabled ? 'включён' : 'выключен'}`
              )
            }
          >
            {aiEnabled ? 'ВКЛЮЧЁН' : 'ВЫКЛЮЧЕН'}
          </button>
        </div>
      </div>

      <p style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginBottom: 12 }}>
        Решает проблему, когда обычный интернет через VPN работает, а <strong>Gemini</strong>,{' '}
        <strong>ChatGPT</strong> или <strong>Grok</strong> пишут «Недоступно в вашей стране» или
        обрывают ответ при автозамене. Ядро <code>sing-box</code> направляет трафик и DNS-запросы
        нейросетей в отдельный проверенный <strong>AI-совместимый сервер</strong> и удерживает его
        стабильным.
      </p>

      <div className="grid-2" style={{ marginBottom: 12 }}>
        <div>
          <label style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
            Режим маршрутизации нейросетей:
          </label>
          <select
            className="select"
            style={{ marginTop: 4 }}
            value={aiMode}
            onChange={(e) =>
              void patchSettings(
                { aiRoutingMode: e.target.value as AiRoutingMode },
                'Режим маршрутизации нейросетей обновлён'
              )
            }
          >
            <option value="parallel_ai_tunnel">
              Параллельный ИИ-туннель (весь телефон — самый быстрый VPN, ИИ — проверенный AI-сервер)
            </option>
            <option value="strict_ai_only">
              Весь телефон только через AI-серверы (переключать весь VPN туда, где работают ИИ)
            </option>
          </select>
        </div>

        <div>
          <label style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
            Закреплённый сервер для нейросетей:
          </label>
          <select
            className="select"
            style={{ marginTop: 4 }}
            value={s.preferredAiNodeId || ''}
            onChange={(e) => {
              const val = e.target.value || null;
              if (val) {
                void handleCycleAiNode(val);
              } else {
                void patchSettings(
                  { preferredAiNodeId: null },
                  'Включён автоматический подбор лучшего AI-сервера'
                );
              }
            }}
          >
            <option value="">
              ⚡ Автоматически (лучший рабочий сервер для Gemini / GPT / Grok)
            </option>
            {userNodes.map((n) => {
              const cc = inferCountryHintFromNode(n);
              const badge =
                n.aiStatus === 'ok'
                  ? `🤖 AI OK${n.aiExitCountry ? ` [Google: ${n.aiExitCountry}]` : ''}`
                  : n.aiStatus === 'blocked'
                    ? `❌ ${n.aiBlockReason || 'Блок ИИ'}`
                    : '⏳ Не проверен';
              return (
                <option key={n.id} value={n.id}>
                  {n.name} {cc ? `(${cc})` : ''} — {badge}
                </option>
              );
            })}
          </select>
        </div>
      </div>

      {/* Чипы выбора нейросетей */}
      <div style={{ marginBottom: 12 }}>
        <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 6 }}>
          Какие нейросети направлять через защищённый ИИ-шлюз:
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))', gap: 8 }}>
          {AI_SERVICE_CATALOG.map((preset) => {
            const active = enabledServices.includes(preset.id);
            return (
              <div
                key={preset.id}
                onClick={() => void toggleAiService(preset.id)}
                style={{
                  padding: 10,
                  borderRadius: 10,
                  cursor: 'pointer',
                  background: active ? 'rgba(56, 189, 248, 0.1)' : 'var(--bg-elevated)',
                  border: active
                    ? '1px solid rgba(56, 189, 248, 0.55)'
                    : '1px solid var(--border-subtle)',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: 8,
                }}
              >
                {active ? (
                  <CheckCircle2 size={16} color="#38BDF8" style={{ flexShrink: 0, marginTop: 2 }} />
                ) : (
                  <XCircle size={16} color="var(--text-muted)" style={{ flexShrink: 0, marginTop: 2 }} />
                )}
                <div>
                  <div style={{ fontWeight: 700, fontSize: 12.5 }}>{preset.title}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                    {preset.description}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Дополнительные опции для Gemini на Android и Grok в X */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 12 }}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: 8,
            padding: 10,
            borderRadius: 10,
            background: 'var(--bg-elevated)',
          }}
        >
          <div>
            <div style={{ fontWeight: 600, fontSize: 12.5 }}>
              Маршрутизировать сессию аккаунта Google для стабильной работы Gemini
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
              Направляет accounts.google.com через ИИ-сервер (видео YouTube остаётся на самом быстром основном VPN)
            </div>
          </div>
          <button
            type="button"
            className={`btn btn-sm ${s.aiIncludeGoogleAccountSession !== false ? 'btn-primary' : ''}`}
            onClick={() =>
              void patchSettings(
                { aiIncludeGoogleAccountSession: s.aiIncludeGoogleAccountSession === false },
                'Настройка сессии Google для Gemini обновлена'
              )
            }
          >
            {s.aiIncludeGoogleAccountSession !== false ? 'ВКЛ' : 'ВЫКЛ'}
          </button>
        </div>

        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: 8,
            padding: 10,
            borderRadius: 10,
            background: 'var(--bg-elevated)',
          }}
        >
          <div>
            <div style={{ fontWeight: 600, fontSize: 12.5 }}>
              Направлять X (Twitter) через ИИ-шлюз (для встроенного в X чата Grok)
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
              Включите, если пользуетесь Grok внутри приложения X, а не отдельно на grok.com
            </div>
          </div>
          <button
            type="button"
            className={`btn btn-sm ${s.aiIncludeXForGrok ? 'btn-primary' : ''}`}
            onClick={() =>
              void patchSettings(
                { aiIncludeXForGrok: !s.aiIncludeXForGrok },
                'Маршрутизация X (Twitter) для Grok обновлена'
              )
            }
          >
            {s.aiIncludeXForGrok ? 'ВКЛ' : 'ВЫКЛ'}
          </button>
        </div>
      </div>

      {/* Добавление своих ИИ-доменов */}
      <div>
        <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 6 }}>
          Дополнительные сайты или API нейросетей (по желанию):
        </div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
          <input
            type="text"
            className="input mono"
            placeholder="Например: huggingface.co, midjourney.com, openrouter.ai"
            value={customAiDomain}
            onChange={(e) => setCustomAiDomain(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void handleAddCustomDomain()}
          />
          <button type="button" className="btn btn-primary" onClick={() => void handleAddCustomDomain()}>
            <Plus size={15} /> Добавить
          </button>
        </div>

        {(s.aiCustomDomains || []).length > 0 && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {(s.aiCustomDomains || []).map((dom) => (
              <span
                key={dom}
                className="badge badge-standby mono"
                style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '5px 10px' }}
              >
                {dom}
                <button
                  type="button"
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--crimson-alert)',
                    cursor: 'pointer',
                    padding: 0,
                    display: 'inline-flex',
                  }}
                  onClick={() =>
                    void patchSettings({
                      aiCustomDomains: (s.aiCustomDomains || []).filter((x) => x !== dom),
                    })
                  }
                >
                  <Trash2 size={12} />
                </button>
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
