// Панель умной маршрутизации по приложениям Android (Per-App VPN v3.0) + памятка по Плитке в шторке и Виджету
import React, { useEffect, useMemo, useState } from 'react';
import { AppWindow, Check, Layers, RefreshCw, Search, Sparkles } from 'lucide-react';
import type { AppSettings, PerAppVpnMode, VpnStateSnapshot } from '../../shared/types';
import { aegisApi } from '../api';

interface Props {
  snapshot: VpnStateSnapshot;
  onUpdate: (next: VpnStateSnapshot) => void;
  onNotify: (msg: string, isError?: boolean) => void;
}

const CATEGORY_LABELS: Record<string, string> = {
  bank_gov: 'Банки / Гос / Такси',
  video_music: 'Видео / Музыка',
  social_media: 'Мессенджеры / Соцсети',
  browser: 'Браузер',
  other: 'Приложение',
};

export const PerAppVpnPanel: React.FC<Props> = ({ snapshot, onUpdate, onNotify }) => {
  const [search, setSearch] = useState('');
  const [loadingApps, setLoadingApps] = useState(false);

  const mode: PerAppVpnMode = snapshot.settings.perAppMode || 'all';
  const selectedList = snapshot.settings.perAppPackages || [];
  const selectedSet = useMemo(() => new Set(selectedList), [selectedList]);
  const apps = snapshot.installedUserApps || [];

  useEffect(() => {
    if (apps.length === 0 && !loadingApps) {
      void handleReloadApps(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleReloadApps = async (silent = false) => {
    setLoadingApps(true);
    try {
      const next = await aegisApi.loadInstalledApps();
      onUpdate(next);
      if (!silent) {
        onNotify(`Найдено приложений на устройстве: ${(next.installedUserApps || []).length}`);
      }
    } catch (err) {
      if (!silent) {
        onNotify(err instanceof Error ? err.message : 'Ошибка загрузки приложений', true);
      }
    } finally {
      setLoadingApps(false);
    }
  };

  const savePerAppPatch = async (patch: Partial<AppSettings>, note?: string) => {
    try {
      const next = await aegisApi.updateSettings(patch);
      onUpdate(next);
      if (note) onNotify(note);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Не удалось сохранить правила приложений', true);
    }
  };

  const toggleAppPackage = async (pkg: string) => {
    const nextPackages = selectedSet.has(pkg)
      ? selectedList.filter((p) => p !== pkg)
      : [...selectedList, pkg];
    const nextMode: PerAppVpnMode = mode === 'all' ? 'exclude_selected' : mode;
    await savePerAppPatch({
      perAppMode: nextMode,
      perAppPackages: nextPackages,
    });
  };

  const applyPresetBypassBanks = async () => {
    const bankPkgs = apps
      .filter((a) => a.categoryHint === 'bank_gov')
      .map((a) => a.packageName);
    if (bankPkgs.length === 0) {
      onNotify('Банковские и локальные приложения не обнаружены — отметьте нужные вручную', true);
      return;
    }
    await savePerAppPatch(
      {
        perAppMode: 'exclude_selected',
        perAppPackages: Array.from(new Set([...selectedList, ...bankPkgs])),
      },
      `Банки и локальные сервисы (${bankPkgs.length} шт.) пущены напрямую без VPN`
    );
  };

  const applyPresetOnlyMediaAndSocial = async () => {
    const mediaPkgs = apps
      .filter(
        (a) =>
          a.categoryHint === 'video_music' ||
          a.categoryHint === 'social_media' ||
          a.categoryHint === 'browser'
      )
      .map((a) => a.packageName);
    if (mediaPkgs.length === 0) {
      onNotify('Отметьте нужные приложения в списке ниже вручную', true);
      return;
    }
    await savePerAppPatch(
      {
        perAppMode: 'only_selected',
        perAppPackages: mediaPkgs,
      },
      `Режим «Только выбранные»: через VPN пойдут ${mediaPkgs.length} приложений`
    );
  };

  const filteredApps = useMemo(() => {
    const q = search.trim().toLowerCase();
    const list = q
      ? apps.filter(
          (a) =>
            a.appName.toLowerCase().includes(q) || a.packageName.toLowerCase().includes(q)
        )
      : apps;
    // Поднимаем отмеченные приложения наверх, чтобы их всегда было видно
    return [...list].sort((a, b) => {
      const aSel = selectedSet.has(a.packageName) ? 1 : 0;
      const bSel = selectedSet.has(b.packageName) ? 1 : 0;
      if (aSel !== bSel) return bSel - aSel;
      return a.appName.localeCompare(b.appName, 'ru');
    });
  }, [apps, search, selectedSet]);

  return (
    <div className="space-y-3.5 mt-3.5">
      {/* Памятка: Плитка в верхней шторке Android + Виджет 4x1 */}
      <div className="rounded-xl bg-surface border border-primary-container/40 p-4">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-lg bg-primary-container/15 border border-primary-container/40 flex items-center justify-center text-primary-container flex-shrink-0">
            <Layers size={19} />
          </div>
          <div className="min-w-0 space-y-1">
            <h3 className="font-headline-md text-sm text-on-surface font-bold">
              Плитка в шторке Android и Виджет рабочего стола (v3.0)
            </h3>
            <p className="text-xs text-on-surface-variant leading-relaxed">
              • <strong>Верхняя шторка:</strong> смахните шторку Android вниз ➔ нажмите «Изменить» (карандаш) ➔ перетащите плитку <strong>«AegisMesh VPN»</strong> наверх для включения каскада в 1 касание.
              <br />• <strong>Виджет на экран:</strong> зажмите пустое место на рабочем столе телефона ➔ «Виджеты» ➔ добавьте <strong>«AegisMesh VPN»</strong> (кнопки ВКЛ/ВЫКЛ и мгновенная смена сервера ⚡).
            </p>
          </div>
        </div>
      </div>

      {/* Карточка Per-App VPN */}
      <div className="rounded-xl bg-surface border border-outline-variant p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <AppWindow size={18} className="text-secondary" />
            <div>
              <h3 className="font-headline-md text-sm text-on-surface font-bold">
                Маршрутизация по приложениям (Per-App VPN)
              </h3>
              <p className="text-[11px] text-on-surface-variant">
                Выбрано приложений: <strong className="text-primary">{selectedList.length}</strong> из {apps.length}
              </p>
            </div>
          </div>
          <button
            type="button"
            disabled={loadingApps}
            onClick={() => void handleReloadApps(false)}
            className="px-3 py-2 min-h-[40px] rounded-lg bg-surface-container-high hover:bg-surface-variant border border-outline-variant text-xs font-badge-code text-on-surface flex items-center gap-1.5 cursor-pointer"
          >
            <RefreshCw size={13} className={loadingApps ? 'animate-spin' : ''} />
            <span>Обновить список</span>
          </button>
        </div>

        {/* 3 понятных режима */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          {(
            [
              {
                id: 'all',
                title: 'Все приложения',
                desc: 'Весь телефон защищён через VPN',
              },
              {
                id: 'exclude_selected',
                title: 'Кроме выбранных',
                desc: 'Банки и такси работают напрямую без VPN',
              },
              {
                id: 'only_selected',
                title: 'Только выбранные',
                desc: 'VPN только для YouTube, соцсетей и игр',
              },
            ] as const
          ).map((opt) => {
            const active = mode === opt.id;
            return (
              <button
                key={opt.id}
                type="button"
                onClick={() =>
                  void savePerAppPatch(
                    { perAppMode: opt.id },
                    `Режим приложений: ${opt.title}`
                  )
                }
                className={`p-3 min-h-[54px] rounded-lg border text-left transition-all cursor-pointer ${
                  active
                    ? 'bg-primary-container/15 border-primary-container text-on-surface'
                    : 'bg-surface-container-lowest border-outline-variant text-on-surface-variant hover:border-outline'
                }`}
              >
                <div className="font-badge-code text-xs font-bold text-on-surface">
                  {opt.title}
                </div>
                <div className="text-[11px] text-on-surface-variant mt-0.5">{opt.desc}</div>
              </button>
            );
          })}
        </div>

        {/* Умные пресеты в 1 тап */}
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => void applyPresetBypassBanks()}
            className="px-3 py-2 min-h-[40px] rounded-lg bg-surface-container-high hover:bg-surface-variant border border-[#FFB020]/40 text-[#FFB020] text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
          >
            <Sparkles size={13} />
            <span>Банки и такси без VPN</span>
          </button>
          <button
            type="button"
            onClick={() => void applyPresetOnlyMediaAndSocial()}
            className="px-3 py-2 min-h-[40px] rounded-lg bg-surface-container-high hover:bg-surface-variant border border-secondary/40 text-secondary text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
          >
            <Sparkles size={13} />
            <span>VPN только для видео, соцсетей и браузеров</span>
          </button>
          {selectedList.length > 0 && (
            <button
              type="button"
              onClick={() =>
                void savePerAppPatch(
                  { perAppPackages: [], perAppMode: 'all' },
                  'Фильтр приложений сброшен — все приложения через VPN'
                )
              }
              className="px-3 py-2 min-h-[40px] rounded-lg bg-surface-container border border-outline-variant text-xs text-on-surface-variant cursor-pointer"
            >
              Сбросить выбор
            </button>
          )}
        </div>

        {/* Поиск по приложениям */}
        <div className="relative">
          <Search
            size={15}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant"
          />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Поиск приложения по названию (YouTube, Telegram, Сбер, Chrome...)"
            className="w-full bg-[#070A0F] border border-outline-variant rounded-lg pl-9 pr-3 py-2.5 min-h-[44px] text-xs text-on-surface focus:border-primary-container focus:outline-none"
          />
        </div>

        {/* Прокручиваемый список приложений с крупными тач-строками >= 48px */}
        <div className="max-h-72 overflow-y-auto space-y-1.5 pr-1">
          {filteredApps.length > 0 ? (
            filteredApps.slice(0, 120).map((app) => {
              const checked = selectedSet.has(app.packageName);
              return (
                <button
                  key={app.packageName}
                  type="button"
                  onClick={() => void toggleAppPackage(app.packageName)}
                  className={`w-full p-2.5 min-h-[48px] rounded-lg border flex items-center justify-between gap-3 text-left transition-colors cursor-pointer ${
                    checked
                      ? 'bg-primary-container/10 border-primary-container/60'
                      : 'bg-surface-container-lowest border-outline-variant hover:border-outline'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span
                      className={`w-5 h-5 rounded flex items-center justify-center flex-shrink-0 border ${
                        checked
                          ? 'bg-primary-container border-primary-container text-on-primary'
                          : 'border-outline text-transparent'
                      }`}
                    >
                      <Check size={13} strokeWidth={3} />
                    </span>
                    <div className="min-w-0">
                      <div className="text-xs font-semibold text-on-surface truncate">
                        {app.appName}
                      </div>
                      <div className="text-[10px] font-mono text-on-surface-variant truncate">
                        {app.packageName}
                      </div>
                    </div>
                  </div>
                  <span className="text-[10px] font-badge-code px-2 py-0.5 rounded bg-surface-container-high text-on-surface-variant flex-shrink-0">
                    {CATEGORY_LABELS[app.categoryHint || 'other']}
                  </span>
                </button>
              );
            })
          ) : (
            <div className="p-4 text-center text-xs text-on-surface-variant border border-dashed border-outline-variant rounded-lg">
              {loadingApps
                ? 'Сканируем установленные приложения на устройстве...'
                : 'Приложения не найдены — нажмите «Обновить список»'}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
