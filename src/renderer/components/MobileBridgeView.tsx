import React, { useEffect, useState } from 'react';
import QRCode from 'qrcode';
import {
  Copy,
  Download,
  QrCode,
  RefreshCw,
  Smartphone,
  Wifi,
} from 'lucide-react';
import type { MobileAccessInfo, VpnStateSnapshot } from '../../shared/types';
import { aegisApi, isNativeMobileApp } from '../api';

interface Props {
  snapshot: VpnStateSnapshot;
  onUpdate: (next: VpnStateSnapshot) => void;
  onNotify: (msg: string, isError?: boolean) => void;
}

export const MobileBridgeView: React.FC<Props> = ({ snapshot, onUpdate, onNotify }) => {
  const isMobileApp = isNativeMobileApp();
  const [info, setInfo] = useState<MobileAccessInfo | null>(null);
  const [singboxQr, setSingboxQr] = useState<string>('');
  const [remoteWebQr, setRemoteWebQr] = useState<string>('');
  const [loading, setLoading] = useState(false);

  const loadMobileBridge = async () => {
    setLoading(true);
    try {
      const data = await aegisApi.getMobileInfo();
      setInfo(data);

      const qr1 = await QRCode.toDataURL(data.singboxDeepLink, {
        width: 220,
        margin: 1,
        color: { dark: '#00F59B', light: '#070A0F' },
      });
      setSingboxQr(qr1);

      const qr2 = await QRCode.toDataURL(data.remoteWebUrl, {
        width: 220,
        margin: 1,
        color: { dark: '#00D2FF', light: '#070A0F' },
      });
      setRemoteWebQr(qr2);
    } catch (err) {
      onNotify(
        err instanceof Error ? err.message : 'Ошибка генерации мобильного моста',
        true
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadMobileBridge();
  }, [snapshot.nodes.length, snapshot.settings.allowLanGateway]);

  const handleDownloadProfile = () => {
    if (!info) return;
    const blob = new Blob([info.singboxProfileJson], {
      type: 'application/json;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'aegismesh-mobile-failover.json';
    a.click();
    URL.revokeObjectURL(url);
    onNotify('Мобильный профиль с автозаменой сохранён в файл .json');
  };

  const handleCopyText = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      onNotify(`${label} скопирован в буфер обмена`);
    } catch {
      onNotify('Не удалось скопировать в буфер обмена', true);
    }
  };

  return (
    <div>
      <div className="grid-2">
        {/* Режим 1: Автономный мобильный профиль с Auto-Failover для iOS / Android */}
        <div className="card card-highlight">
          <div className="card-header">
            <div className="card-title">
              <QrCode size={18} color="var(--emerald-shield)" />
              <span>1. Автономный профиль iOS / Android (с автозаменой)</span>
            </div>
            <button type="button" className="btn btn-sm" onClick={loadMobileBridge}>
              <RefreshCw size={13} /> Обновить QR
            </button>
          </div>

          <p style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginBottom: 12 }}>
            Упаковывает все ваши серверы ({info?.nodeCount ?? 0} шт.) в единый мобильный профиль{' '}
            <strong>sing-box (SFI для iPhone / SFA для Android)</strong> с встроенным сторожем{' '}
            <code>urltest</code>. Даже вдали от дома телефон сам будет переключать упавшие серверы!
          </p>

          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: 10,
              padding: 14,
              background: '#080d16',
              borderRadius: 12,
              border: '1px solid var(--border-subtle)',
              marginBottom: 12,
            }}
          >
            {singboxQr ? (
              <img
                src={singboxQr}
                alt="QR-код импорта sing-box"
                style={{ width: 190, height: 190, borderRadius: 10 }}
              />
            ) : (
              <div style={{ padding: 40, color: 'var(--text-secondary)' }}>
                {loading ? 'Генерация QR...' : 'Нет данных'}
              </div>
            )}
            <div style={{ fontSize: 11.5, color: 'var(--text-secondary)', textAlign: 'center' }}>
              Отсканируйте камерой в приложении <strong>sing-box</strong> или{' '}
              <strong>Hiddify</strong> на телефоне
            </div>
          </div>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            <button
              type="button"
              className="btn btn-primary"
              onClick={handleDownloadProfile}
            >
              <Download size={15} /> Скачать профиль .json
            </button>
            {info && (
              <button
                type="button"
                className="btn"
                onClick={() => handleCopyText(info.singboxProfileJson, 'JSON-профиль')}
              >
                <Copy size={15} /> Скопировать JSON
              </button>
            )}
          </div>
        </div>

        {/* Режим 2: Мобильный пульт управления по Wi-Fi + LAN-шлюз (для ПК) */}
        {!isMobileApp && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Smartphone size={18} color="var(--cyan-mobile)" />
              <span>2. Мобильный пульт Wi-Fi и Общий LAN-шлюз</span>
            </div>
          </div>

          <p style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginBottom: 12 }}>
            Отсканируйте этот QR-код камерой смартфона в одной Wi-Fi сети, чтобы открыть мобильный
            интерфейс AegisMesh прямо на телефоне (добавлять ключи, включать щит и управлять
            каскадом лёжа на диване):
          </p>

          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: 10,
              padding: 14,
              background: '#080d16',
              borderRadius: 12,
              border: '1px solid var(--border-subtle)',
              marginBottom: 12,
            }}
          >
            {remoteWebQr && (
              <img
                src={remoteWebQr}
                alt="QR-код Мобильного пульта"
                style={{ width: 190, height: 190, borderRadius: 10 }}
              />
            )}
            {info && (
              <div
                className="mono"
                style={{
                  fontSize: 11,
                  color: 'var(--cyan-mobile)',
                  wordBreak: 'break-all',
                  textAlign: 'center',
                }}
              >
                {info.remoteWebUrl}
              </div>
            )}
          </div>

          <div
            style={{
              padding: 12,
              background: 'var(--bg-elevated)',
              borderRadius: 10,
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              gap: 10,
            }}
          >
            <div>
              <div style={{ fontWeight: 700, fontSize: 13 }}>
                <Wifi size={14} style={{ marginRight: 6 }} />
                Раздача защищённого VPN по Wi-Fi (LAN-шлюз):
              </div>
              <div className="mono" style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                Прокси для телефона/TV: {info?.lanProxyAddress || '127.0.0.1:10809'}
              </div>
            </div>
            <button
              type="button"
              className={`btn btn-sm ${
                snapshot.settings.allowLanGateway ? 'btn-primary' : ''
              }`}
              onClick={async () => {
                const next = await aegisApi.updateSettings({
                  allowLanGateway: !snapshot.settings.allowLanGateway,
                });
                onUpdate(next);
                onNotify(
                  !snapshot.settings.allowLanGateway
                    ? 'Доступ к прокси-шлюзу из локальной Wi-Fi сети открыт'
                    : 'LAN-шлюз закрыт (только для этого ПК)'
                );
              }}
            >
              {snapshot.settings.allowLanGateway ? 'Раздача ВКЛ' : 'Раздача ВЫКЛ'}
            </button>
          </div>
        </div>
        )}
      </div>
    </div>
  );
};
