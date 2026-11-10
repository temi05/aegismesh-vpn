// Совместимость с защищёнными панелями подписок (Remnawave / Marzban / 3x-ui + HWID)
// и реестр локальных мостов к внешним VPN-клиентам (Happ, v2rayNG, Throne, NekoBox, Clash, Hiddify, ByeDPI, Orbot)
import type { ExternalVpnClientBridge, VpnNode } from './types';
import { decodeBase64Utf8 } from './uriParser';

export interface SubscriptionCompatProfile {
  id: string;
  label: string;
  buildHeaders: (hwid: string, platform: 'android' | 'windows') => Record<string, string>;
}

// Цепочка совместимых заголовков:
// 1) Shadowrocket/2075 + x-hwid — входит в белый список панелей Remnawave ("Happ, Throne, ShadowRocket")
//    и гарантированно получает открытый список VLESS/Trojan/Hy2/SS/WG без закрытого шифрования happ://crypt!
// 2) v2rayNG/1.9.39 + x-hwid — стандартный Android-клиент
// 3) Throne/1.0.8 + x-hwid — кроссплатформенный sing-box клиент (может вернуть URI или JSON outbounds)
export const SUBSCRIPTION_COMPAT_PROFILES: SubscriptionCompatProfile[] = [
  {
    id: 'shadowrocket_hwid',
    label: 'Shadowrocket + HWID',
    buildHeaders: (hwid) => ({
      'User-Agent': 'Shadowrocket/2075 CFNetwork/1568.200.51 Darwin/24.1.0',
      Accept: '*/*',
      'x-hwid': hwid,
      'x-device-os': 'iOS',
      'x-ver-os': '18.1',
      'x-device-model': 'iPhone16,2',
    }),
  },
  {
    id: 'v2rayng_hwid',
    label: 'v2rayNG + HWID',
    buildHeaders: (hwid, platform) => ({
      'User-Agent': 'v2rayNG/1.9.39',
      Accept: '*/*',
      'x-hwid': hwid,
      'x-device-os': platform === 'android' ? 'Android' : 'Windows',
      'x-ver-os': platform === 'android' ? '14' : '11',
      'x-device-model': platform === 'android' ? 'Pixel 8' : 'Desktop-PC',
    }),
  },
  {
    id: 'throne_hwid',
    label: 'Throne + HWID',
    buildHeaders: (hwid, platform) => ({
      'User-Agent': 'Throne/1.0.8',
      Accept: '*/*',
      'x-hwid': hwid,
      'x-device-os': platform === 'android' ? 'Android' : 'Windows',
      'x-ver-os': platform === 'android' ? '14' : '11',
      'x-device-model': platform === 'android' ? 'Android-Device' : 'Windows-PC',
    }),
  },
];

// Генерация стабильного валидного идентификатора HWID (ровно 32 hex-символа, проходит строгий regex Remnawave v2.7+/v3+)
export function generateValidHwid(): string {
  const chars = '0123456789ABCDEF';
  let out = '';
  for (let i = 0; i < 32; i += 1) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

export interface ParsedSubscriptionHeaders {
  profileTitle?: string;
  usedBytes: number | null;
  totalBytes: number | null;
  expireUnix: number | null;
  supportUrl?: string;
  announceText?: string;
  autoUpdateHours?: number;
}

function decodeHeaderValue(raw?: string): string | undefined {
  if (!raw) return undefined;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  if (trimmed.toLowerCase().startsWith('base64:')) {
    try {
      return decodeBase64Utf8(trimmed.slice(7).trim()).trim();
    } catch {
      return trimmed.slice(7).trim();
    }
  }
  try {
    return decodeURIComponent(trimmed);
  } catch {
    return trimmed;
  }
}

// Разбор заголовков ответа подписки (subscription-userinfo, profile-title, announce, support-url)
export function parseSubscriptionResponseHeaders(
  headers: Record<string, string | undefined>
): ParsedSubscriptionHeaders {
  const norm: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers || {})) {
    if (typeof v === 'string' && v.trim()) {
      norm[k.toLowerCase()] = v.trim();
    }
  }

  let profileTitle = decodeHeaderValue(norm['profile-title']);
  if (!profileTitle && norm['content-disposition']) {
    const utf8Match = norm['content-disposition'].match(/filename\*=UTF-8''([^;]+)/i);
    const plainMatch = norm['content-disposition'].match(/filename="?([^";]+)"?/i);
    if (utf8Match?.[1]) {
      profileTitle = decodeHeaderValue(utf8Match[1]);
    } else if (plainMatch?.[1]) {
      profileTitle = decodeHeaderValue(plainMatch[1]);
    }
  }

  let usedBytes: number | null = null;
  let totalBytes: number | null = null;
  let expireUnix: number | null = null;

  const userInfo = norm['subscription-userinfo'];
  if (userInfo) {
    const kv: Record<string, number> = {};
    for (const part of userInfo.split(';')) {
      const [rawK, rawV] = part.split('=');
      if (rawK && rawV) {
        const num = Number(rawV.trim());
        if (Number.isFinite(num) && num >= 0) {
          kv[rawK.trim().toLowerCase()] = num;
        }
      }
    }
    const up = kv.upload ?? 0;
    const down = kv.download ?? 0;
    if ('upload' in kv || 'download' in kv) {
      usedBytes = up + down;
    }
    if ('total' in kv && kv.total > 0) {
      totalBytes = kv.total;
    }
    if ('expire' in kv && kv.expire > 0) {
      expireUnix = kv.expire;
    }
  }

  const intervalRaw = Number(norm['profile-update-interval'] || '');
  const autoUpdateHours =
    Number.isFinite(intervalRaw) && intervalRaw >= 1 && intervalRaw <= 168
      ? Math.round(intervalRaw)
      : undefined;

  return {
    profileTitle: profileTitle || undefined,
    usedBytes,
    totalBytes,
    expireUnix,
    supportUrl: norm['support-url'],
    announceText: decodeHeaderValue(norm['announce']),
    autoUpdateHours,
  };
}

// Проверка: является ли узел служебной инфо-заглушкой провайдера (0.0.0.0:1, нулевой UUID и т.д.),
// которую НЕЛЬЗЯ включать в боевую очередь VPN-серверов!
export function isSyntheticDummyNode(node: Pick<VpnNode, 'server' | 'port' | 'protocol' | 'uuid' | 'isTestStand' | 'isExternalClientBridge'>): boolean {
  if (node.isTestStand || node.isExternalClientBridge) {
    return false;
  }
  const host = (node.server || '').trim().toLowerCase();
  if (!host) return true;

  // Заглушки адреса: 0.0.0.0, ::, 255.255.255.255, example.com, invalid
  if (
    host === '0.0.0.0' ||
    host.startsWith('0.') ||
    host === '::' ||
    host === '0:0:0:0:0:0:0:0' ||
    host === '255.255.255.255' ||
    host === 'example.com' ||
    host === 'invalid' ||
    host.endsWith('.invalid')
  ) {
    return true;
  }

  // Порт 0 или 1 — стандартный технический маркер фейк-узла в Remnawave / Marzban / 3x-ui
  if (!Number.isInteger(node.port) || node.port <= 1) {
    return true;
  }

  // Нулевой UUID (00000000-0000-0000-0000-000000000000)
  if (node.uuid && /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(node.uuid.trim())) {
    return true;
  }

  // Внутри крипто-протоколов (VLESS/VMess/Trojan/SS/Hy2/TUIC/WG) адрес 127.0.0.1 / localhost в подписке — всегда инфо-заглушка
  if (
    (host === '127.0.0.1' || host === 'localhost' || host === '::1') &&
    node.protocol !== 'socks' &&
    node.protocol !== 'http'
  ) {
    return true;
  }

  return false;
}

// Стандартные пресеты внешних VPN-клиентов (Proxy-Only / Local Bridge на 127.0.0.1) для Android и Windows
export function createDefaultExternalClientBridges(): ExternalVpnClientBridge[] {
  return [
    {
      id: 'ext_happ_v2ray_10808',
      clientName: 'Happ / v2rayNG / v2rayN',
      protocol: 'socks',
      host: '127.0.0.1',
      port: 10808,
      androidPackages: ['com.happproxy', 'com.happ.proxy', 'com.v2ray.ang'],
      detectedRunning: false,
      enabledInFailover: false,
      latencyMs: null,
    },
    {
      id: 'ext_throne_nekobox_2080',
      clientName: 'Throne / NekoBox / Hiddify',
      protocol: 'socks',
      host: '127.0.0.1',
      port: 2080,
      androidPackages: ['moe.nb4a', 'app.hiddify.com', 'io.nekohasekai.sagernet'],
      detectedRunning: false,
      enabledInFailover: false,
      latencyMs: null,
    },
    {
      id: 'ext_clash_flclash_7890',
      clientName: 'Clash / FlClash / Mihomo',
      protocol: 'http',
      host: '127.0.0.1',
      port: 7890,
      androidPackages: [
        'com.follow.clash',
        'com.github.kr328.clash',
        'com.metacubex.clash.meta',
      ],
      detectedRunning: false,
      enabledInFailover: false,
      latencyMs: null,
    },
    {
      id: 'ext_hiddify_desktop_12334',
      clientName: 'Hiddify Proxy (:12334)',
      protocol: 'socks',
      host: '127.0.0.1',
      port: 12334,
      androidPackages: ['app.hiddify.com'],
      detectedRunning: false,
      enabledInFailover: false,
      latencyMs: null,
    },
    {
      id: 'ext_byedpi_psiphon_1080',
      clientName: 'ByeDPI / Psiphon (:1080)',
      protocol: 'socks',
      host: '127.0.0.1',
      port: 1080,
      androidPackages: ['io.github.dovecoteescapee.byedpi', 'com.psiphon3', 'com.psiphon3.subscription'],
      detectedRunning: false,
      enabledInFailover: false,
      latencyMs: null,
    },
    {
      id: 'ext_orbot_tor_9050',
      clientName: 'Orbot / Tor (:9050)',
      protocol: 'socks',
      host: '127.0.0.1',
      port: 9050,
      androidPackages: ['org.torproject.android'],
      detectedRunning: false,
      enabledInFailover: false,
      latencyMs: null,
    },
  ];
}

// Преобразование активного моста к внешнему VPN-клиенту в виртуальный VpnNode для единого конвейера sing-box и GuardProxy
export function externalBridgeToVpnNode(
  bridge: ExternalVpnClientBridge,
  priority: number
): VpnNode {
  return {
    id: `bridge_${bridge.id}`,
    name: `Мост: ${bridge.clientName} (:${bridge.port})`,
    protocol: bridge.protocol,
    server: bridge.host,
    port: bridge.port,
    enabled: bridge.enabledInFailover && bridge.detectedRunning,
    priority,
    providerName: `Внешний клиент: ${bridge.clientName}`,
    isExternalClientBridge: true,
    externalPackageNames: [...bridge.androidPackages],
    countryHint: 'LOC',
    status: bridge.detectedRunning ? 'standby' : 'down',
    latencyMs: bridge.latencyMs,
    lastCheckedAt: Date.now(),
    consecutiveFailures: 0,
    quarantinedUntil: null,
  };
}

export function formatBytesHuman(bytes?: number | null): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes) || bytes < 0) {
    return '—';
  }
  if (bytes < 1024) return `${Math.round(bytes)} Б`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} КБ`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} МБ`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} ГБ`;
}

export function formatSpeedHuman(bytesPerSec?: number | null): string {
  if (!bytesPerSec || !Number.isFinite(bytesPerSec) || bytesPerSec <= 0) {
    return '0 КБ/с';
  }
  const mbps = (bytesPerSec * 8) / 1_000_000;
  if (mbps >= 1) {
    return `${mbps.toFixed(1)} Мбит/с`;
  }
  return `${Math.max(1, Math.round(bytesPerSec / 1024))} КБ/с`;
}
