// Универсальный парсер VPN-ключей, подписок (Base64 / текст) и файлов WireGuard (.conf)
import type {
  ParseImportResult,
  TlsSecurity,
  TransportType,
  VpnNode,
  VpnProtocol,
} from './types';
import { isSyntheticDummyNode } from './subscriptionMeta';

// Безопасная генерация уникального идентификатора (работает и в Node.js, и в браузере/мобильном WebView)
export function createId(prefix = 'node'): string {
  const rand =
    typeof globalThis.crypto !== 'undefined' && 'randomUUID' in globalThis.crypto
      ? globalThis.crypto.randomUUID().slice(0, 12)
      : Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4);
  return `${prefix}_${rand}`;
}

// Кроссплатформенное декодирование Base64 / Base64URL в UTF-8
export function decodeBase64Utf8(input: string): string {
  const clean = input.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (clean.length % 4)) % 4;
  const padded = clean + '='.repeat(padLen);

  const nodeBuffer = (
    globalThis as unknown as {
      Buffer?: {
        from(data: string, encoding: string): { toString(encoding: string): string };
      };
    }
  ).Buffer;
  if (typeof nodeBuffer !== 'undefined') {
    return nodeBuffer.from(padded, 'base64').toString('utf-8');
  }
  const binary = globalThis.atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder('utf-8').decode(bytes);
}

// Строгая проверка хоста на отсутствие опасных символов (защита от инъекций)
export function isValidHost(host: string): boolean {
  if (!host || host.length > 253) return false;
  const clean = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  if (!clean) return false;
  // Запрещаем пробелы, кавычки, управляющие символы и shell-метасимволы
  if (/[\s"'`;$|&<>\\]/.test(clean)) return false;
  return /^[a-zA-Z0-9._:-]+$/.test(clean);
}

export function isValidPort(port: number): boolean {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

// Автоопределение кода страны по названию узла, эмодзи флага или домену
export function detectCountryHint(name: string, host: string): string {
  const rawName = (name || '').trim();
  const rawHost = (host || '').trim();
  const strippedName = rawName.replace(
    /(через|via|relay|bridge|мост)\s+(?:🇷🇺\s*)?(рф|росси[а-яё]*|ru|russia|мск|msk)(?![a-zа-яё0-9])/gi,
    ' '
  );

  // 1. Проверка региональных индикаторов Unicode (флаги стран 🇩🇪, 🇳🇱, 🇺🇸, 🇷🇺 и др.) в очищенном имени
  const scanFlags = (str: string): string | null => {
    const chars = Array.from(str);
    for (let i = 0; i < chars.length - 1; i += 1) {
      const c1 = chars[i].codePointAt(0) ?? 0;
      const c2 = chars[i + 1].codePointAt(0) ?? 0;
      if (c1 >= 0x1f1e6 && c1 <= 0x1f1ff && c2 >= 0x1f1e6 && c2 <= 0x1f1ff) {
        return (
          String.fromCharCode(c1 - 0x1f1e6 + 65) + String.fromCharCode(c2 - 0x1f1e6 + 65)
        );
      }
    }
    return null;
  };

  const flagFromStripped = scanFlags(strippedName);
  if (flagFromStripped) return flagFromStripped;

  const patterns: Array<[RegExp, string]> = [
    [/(?:^|[^a-zа-яё0-9])(рф|ру|ru|rus|росси[а-яё]*|москв[а-яё]*|moscow|мск|msk|спб|spb|петербург[а-яё]*|питер|новосибирск[а-яё]*|екатеринбург[а-яё]*|казань)(?![a-zа-яё0-9])/i, 'RU'],
    [/(\bby\b|беларус|минск|minsk|belarus)/i, 'BY'],
    [/(\bhk\b|гонконг|hong\s*kong)/i, 'HK'],
    [/(\bcn\b|китай|china|beijing|shanghai)/i, 'CN'],
    [/(\bde\b|de-\d|герман|франкфурт|germany|frankfurt|falkenstein|berlin)/i, 'DE'],
    [/(\bnl\b|nl-\d|нидерланд|голланд|амстердам|netherlands|amsterdam)/i, 'NL'],
    [/(\bfi\b|fi-\d|финлянд|хельсинки|finland|helsinki)/i, 'FI'],
    [/(\bus\b|\busa\b|us-\d|сша|америк|united\s*states|new\s*york|miami|dallas|ashburn|los\s*angeles|chicago)/i, 'US'],
    [/(\btr\b|tr-\d|турци|стамбул|turkey|istanbul)/i, 'TR'],
    [/(\bkz\b|kz-\d|казахстан|алматы|астана|kazakhstan|almaty|astana)/i, 'KZ'],
    [/(\bgb\b|\buk\b|gb-\d|британ|англия|лондон|london|united\s*kingdom)/i, 'GB'],
    [/(\bfr\b|fr-\d|франци|париж|france|paris)/i, 'FR'],
    [/(\bpl\b|pl-\d|польш|варшав|poland|warsaw)/i, 'PL'],
    [/(\bse\b|se-\d|швеци|стокгольм|sweden|stockholm)/i, 'SE'],
    [/(\bsg\b|sg-\d|сингапур|singapore)/i, 'SG'],
    [/(\bjp\b|jp-\d|япони|токио|japan|tokyo)/i, 'JP'],
    [/(\bee\b|ee-\d|эстони|таллин|estonia|tallinn)/i, 'EE'],
    [/(\blv\b|lv-\d|латви|рига|latvia|riga)/i, 'LV'],
    [/(\blt\b|lt-\d|литв|вильнюс|lithuania|vilnius)/i, 'LT'],
    [/(\bch\b|ch-\d|швейцар|цюрих|switzerland|zurich)/i, 'CH'],
    [/(\bat\b|at-\d|австри|вена|austria|vienna)/i, 'AT'],
    [/\b(local|test|127\.0\.0\.1|localhost)\b/i, 'LOC'],
  ];

  // 2. Сначала проверяем очищенное имя узла (чтобы название страны в имени всегда имело приоритет над буквами в домене)
  for (const [regex, code] of patterns) {
    if (regex.test(strippedName)) return code;
  }

  // 3. Если в очищенном имени страны нет, проверяем исходное имя (на случай узлов вида «Мост РФ #1» или «🇷🇺 Relay»)
  const flagFromRaw = scanFlags(rawName);
  if (flagFromRaw) return flagFromRaw;
  for (const [regex, code] of patterns) {
    if (regex.test(rawName)) return code;
  }

  // 4. В последнюю очередь проверяем хост/домен (включая зоны .ru / .su / .рф / ru.*)
  if (/(^ru\.|\.ru\.|\.ru$|\.su$|\.xn--p1ai$|\bmsk\b|\bspb\b)/i.test(rawHost)) {
    return 'RU';
  }
  for (const [regex, code] of patterns) {
    if (regex.test(rawHost)) return code;
  }
  return 'GLB';
}

function createBaseNode(
  partial: Partial<VpnNode> & {
    protocol: VpnProtocol;
    server: string;
    port: number;
    name: string;
  },
  priority = 1
): VpnNode {
  const cleanServer =
    partial.server.startsWith('[') && partial.server.endsWith(']')
      ? partial.server.slice(1, -1)
      : partial.server;

  return {
    id: partial.id ?? createId('vpn'),
    enabled: true,
    priority,
    countryHint: detectCountryHint(partial.name, cleanServer),
    status: 'idle',
    latencyMs: null,
    lastCheckedAt: null,
    consecutiveFailures: 0,
    quarantinedUntil: null,
    ...partial,
    server: cleanServer,
  };
}

function normalizeTransport(raw?: string | null): TransportType {
  const val = (raw ?? 'tcp').toLowerCase();
  if (val === 'ws' || val === 'websocket') return 'ws';
  if (val === 'grpc') return 'grpc';
  if (val === 'httpupgrade') return 'httpupgrade';
  if (val === 'quic') return 'quic';
  if (val === 'h2' || val === 'http') return 'http';
  return 'tcp';
}

function normalizeTls(security?: string | null, defaultTls: TlsSecurity = 'none'): TlsSecurity {
  const val = (security ?? '').toLowerCase();
  if (val === 'reality') return 'reality';
  if (val === 'tls' || val === 'xtls' || val === '1' || val === 'true') return 'tls';
  if (val === 'none' || val === '0' || val === 'false') return 'none';
  return defaultTls;
}

function safeDecodeComponent(str: string): string {
  try {
    return decodeURIComponent(str.replace(/\+/g, '%20'));
  } catch {
    return str;
  }
}

// Парсер VLESS (включая XTLS-Reality, WS, gRPC, TLS)
function parseVlessUri(uri: string, priority: number): VpnNode {
  const url = new URL(uri);
  const uuid = safeDecodeComponent(url.username);
  const server = url.hostname;
  const port = Number(url.port || '443');
  if (!uuid) throw new Error('В VLESS-ссылке отсутствует UUID');
  if (!isValidHost(server) || !isValidPort(port)) {
    throw new Error(`Некорректный адрес сервера или порт в VLESS: ${server}:${url.port}`);
  }

  const p = url.searchParams;
  const tls = normalizeTls(p.get('security'), 'none');
  const transport = normalizeTransport(p.get('type'));
  const rawName = url.hash ? safeDecodeComponent(url.hash.slice(1)) : '';
  const name = rawName.trim() || `VLESS ${server}:${port}`;

  const rawFlow = (p.get('flow') || '').trim();
  const flow = rawFlow
    ? rawFlow.toLowerCase().startsWith('xtls-rprx-vision')
      ? 'xtls-rprx-vision'
      : rawFlow
    : undefined;

  const alpnRaw = p.get('alpn');
  const alpn = alpnRaw
    ? alpnRaw
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    : undefined;

  return createBaseNode(
    {
      name,
      protocol: 'vless',
      server,
      port,
      rawUri: uri,
      uuid,
      flow,
      transport,
      wsPath: p.get('path') || undefined,
      wsHost: p.get('host') || undefined,
      grpcServiceName:
        p.get('serviceName') ||
        (transport === 'grpc' ? p.get('path') || undefined : undefined),
      tls,
      sni: p.get('sni') || p.get('peer') || p.get('host') || undefined,
      alpn,
      fingerprint: p.get('fp') || undefined,
      allowInsecure: p.get('allowInsecure') === '1' || p.get('insecure') === '1',
      realityPublicKey: p.get('pbk') || undefined,
      realityShortId: p.get('sid') || undefined,
    },
    priority
  );
}

// Парсер VMess (поддержка Base64 JSON формата v2rayN и стандартного URI)
function parseVmessUri(uri: string, priority: number): VpnNode {
  const body = uri.slice('vmess://'.length).trim();
  const hashIdx = body.indexOf('#');
  const payloadPart = hashIdx >= 0 ? body.slice(0, hashIdx).trim() : body;
  const remarkPart = hashIdx >= 0 ? safeDecodeComponent(body.slice(hashIdx + 1)).trim() : '';

  if (!payloadPart.includes('@')) {
    let jsonStr: string;
    try {
      jsonStr = decodeBase64Utf8(payloadPart);
    } catch {
      throw new Error('Не удалось декодировать Base64 в ссылке VMess');
    }
    let data: Record<string, unknown>;
    try {
      data = JSON.parse(jsonStr) as Record<string, unknown>;
    } catch {
      throw new Error('Некорректный JSON внутри ссылки VMess');
    }

    const server = String(data.add ?? '').trim();
    const port = Number(data.port ?? 443);
    const uuid = String(data.id ?? '').trim();
    if (!uuid || !isValidHost(server) || !isValidPort(port)) {
      throw new Error('В конфиге VMess отсутствуют обязательные поля add/port/id');
    }

    const transport = normalizeTransport(String(data.net ?? 'tcp'));
    const tls = normalizeTls(String(data.tls ?? 'none'), 'none');
    const name =
      remarkPart || String(data.ps ?? '').trim() || `VMess ${server}:${port}`;
    const alpnStr = String(data.alpn ?? '').trim();
    const allowInsecure =
      data.allowInsecure === true ||
      data.allowInsecure === '1' ||
      data.allowInsecure === 1 ||
      data.verify_cert === false ||
      data.insecure === true ||
      data.insecure === '1';

    return createBaseNode(
      {
        name,
        protocol: 'vmess',
        server,
        port,
        rawUri: uri,
        uuid,
        alterId: Number(data.aid ?? 0) || 0,
        method: String(data.scy ?? 'auto') || 'auto',
        transport,
        wsPath: data.path ? String(data.path) : undefined,
        wsHost: data.host ? String(data.host) : undefined,
        grpcServiceName: data.serviceName
          ? String(data.serviceName)
          : transport === 'grpc' && data.path
            ? String(data.path)
            : undefined,
        tls,
        sni: data.sni ? String(data.sni) : data.host ? String(data.host) : undefined,
        alpn: alpnStr ? alpnStr.split(',').map((s) => s.trim()).filter(Boolean) : undefined,
        fingerprint: data.fp ? String(data.fp) : undefined,
        allowInsecure,
      },
      priority
    );
  }

  // Альтернативный URL-формат vmess://uuid@host:port?...#name
  const url = new URL(uri);
  const uuid = safeDecodeComponent(url.username);
  const server = url.hostname;
  const port = Number(url.port || '443');
  if (!uuid || !isValidHost(server) || !isValidPort(port)) {
    throw new Error('Некорректный формат URL ссылки VMess');
  }
  const p = url.searchParams;
  const transport = normalizeTransport(p.get('type'));
  const alpnRaw = p.get('alpn');
  const alpn = alpnRaw
    ? alpnRaw
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    : undefined;
  const name =
    (url.hash ? safeDecodeComponent(url.hash.slice(1)).trim() : '') ||
    `VMess ${server}:${port}`;

  return createBaseNode(
    {
      name,
      protocol: 'vmess',
      server,
      port,
      rawUri: uri,
      uuid,
      method: p.get('encryption') || p.get('scy') || 'auto',
      transport,
      wsPath: p.get('path') || undefined,
      wsHost: p.get('host') || undefined,
      grpcServiceName:
        p.get('serviceName') ||
        (transport === 'grpc' ? p.get('path') || undefined : undefined),
      tls: normalizeTls(p.get('security') || p.get('tls'), 'none'),
      sni: p.get('sni') || p.get('peer') || p.get('host') || undefined,
      alpn,
      fingerprint: p.get('fp') || undefined,
      allowInsecure:
        p.get('allowInsecure') === '1' ||
        p.get('insecure') === '1' ||
        p.get('allowInsecure') === 'true',
    },
    priority
  );
}

// Парсер Shadowsocks (SIP002, AEAD-2022 и Legacy Base64)
function parseShadowsocksUri(uri: string, priority: number): VpnNode {
  let raw = uri.slice('ss://'.length).trim();
  let hashName = '';
  const hashIdx = raw.indexOf('#');
  if (hashIdx !== -1) {
    hashName = safeDecodeComponent(raw.slice(hashIdx + 1)).trim();
    raw = raw.slice(0, hashIdx);
  }

  // Отделяем query параметры плагина, если есть
  const qIdx = raw.indexOf('?');
  if (qIdx !== -1) {
    raw = raw.slice(0, qIdx);
  }

  let userInfo = '';
  let hostPort = '';

  if (raw.includes('@')) {
    const atIdx = raw.lastIndexOf('@');
    userInfo = raw.slice(0, atIdx);
    hostPort = raw.slice(atIdx + 1);
    if (!userInfo.includes(':')) {
      let unescaped = userInfo;
      try {
        unescaped = decodeURIComponent(userInfo);
      } catch {
        unescaped = safeDecodeComponent(userInfo);
      }
      userInfo = unescaped.includes(':') ? unescaped : decodeBase64Utf8(unescaped);
    } else {
      userInfo = safeDecodeComponent(userInfo);
    }
  } else {
    let unescapedRaw = raw;
    try {
      unescapedRaw = decodeURIComponent(raw);
    } catch {
      unescapedRaw = safeDecodeComponent(raw);
    }
    const decoded = decodeBase64Utf8(unescapedRaw);
    const atIdx = decoded.lastIndexOf('@');
    if (atIdx === -1) {
      throw new Error('Некорректный формат ссылки Shadowsocks (отсутствует @host:port)');
    }
    userInfo = decoded.slice(0, atIdx);
    hostPort = decoded.slice(atIdx + 1);
  }

  const colonIdx = userInfo.indexOf(':');
  if (colonIdx === -1) {
    throw new Error('В Shadowsocks не найден метод шифрования и пароль');
  }
  const method = userInfo.slice(0, colonIdx).trim();
  const password = userInfo.slice(colonIdx + 1);

  const parsedHostUrl = new URL(`http://${hostPort}`);
  const server = parsedHostUrl.hostname;
  const port = Number(parsedHostUrl.port);
  if (!isValidHost(server) || !isValidPort(port)) {
    throw new Error(`Некорректный хост или порт в Shadowsocks: ${hostPort}`);
  }

  return createBaseNode(
    {
      name: hashName || `Shadowsocks ${server}:${port}`,
      protocol: 'shadowsocks',
      server,
      port,
      rawUri: uri,
      method,
      password,
    },
    priority
  );
}

// Парсер Trojan
function parseTrojanUri(uri: string, priority: number): VpnNode {
  const url = new URL(uri);
  const password = safeDecodeComponent(url.username);
  const server = url.hostname;
  const port = Number(url.port || '443');
  if (!password || !isValidHost(server) || !isValidPort(port)) {
    throw new Error('Некорректные параметры сервера или пароля в ссылке Trojan');
  }

  const p = url.searchParams;
  const transport = normalizeTransport(p.get('type'));
  const alpnRaw = p.get('alpn');
  const alpn = alpnRaw
    ? alpnRaw
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    : undefined;
  const name =
    (url.hash ? safeDecodeComponent(url.hash.slice(1)).trim() : '') ||
    `Trojan ${server}:${port}`;

  return createBaseNode(
    {
      name,
      protocol: 'trojan',
      server,
      port,
      rawUri: uri,
      password,
      transport,
      wsPath: p.get('path') || undefined,
      wsHost: p.get('host') || undefined,
      grpcServiceName:
        p.get('serviceName') ||
        (transport === 'grpc' ? p.get('path') || undefined : undefined),
      tls: normalizeTls(p.get('security'), 'tls'),
      sni: p.get('sni') || p.get('peer') || server,
      alpn,
      fingerprint: p.get('fp') || undefined,
      allowInsecure: p.get('allowInsecure') === '1' || p.get('insecure') === '1',
      realityPublicKey: p.get('pbk') || undefined,
      realityShortId: p.get('sid') || undefined,
    },
    priority
  );
}

// Парсер Hysteria2 / hy2
function parseHysteria2Uri(uri: string, priority: number): VpnNode {
  const normalized = uri.startsWith('hy2://')
    ? 'hysteria2://' + uri.slice('hy2://'.length)
    : uri;
  const url = new URL(normalized);
  const auth = url.password
    ? `${safeDecodeComponent(url.username)}:${safeDecodeComponent(url.password)}`
    : safeDecodeComponent(url.username);
  const server = url.hostname;
  const port = Number(url.port || '443');
  if (!isValidHost(server) || !isValidPort(port)) {
    throw new Error('Некорректный адрес сервера или порт в Hysteria2');
  }

  const p = url.searchParams;
  const alpnRaw = p.get('alpn');
  const alpn = alpnRaw
    ? alpnRaw
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    : undefined;
  const rawObfs = (p.get('obfs') || '').trim();
  const obfsType = rawObfs && rawObfs.toLowerCase() !== 'none' ? rawObfs : undefined;
  const mport = (p.get('mport') || p.get('ports') || '').trim() || undefined;
  const name =
    (url.hash ? safeDecodeComponent(url.hash.slice(1)).trim() : '') ||
    `Hysteria2 ${server}:${port}`;

  return createBaseNode(
    {
      name,
      protocol: 'hysteria2',
      server,
      port,
      rawUri: uri,
      password: auth,
      tls: 'tls',
      sni: p.get('sni') || server,
      alpn,
      allowInsecure: p.get('insecure') === '1' || p.get('allowInsecure') === '1',
      mport,
      obfsType,
      obfsPassword: p.get('obfs-password') || undefined,
      upMbps: p.get('upmbps') ? Number(p.get('upmbps')) : undefined,
      downMbps: p.get('downmbps') ? Number(p.get('downmbps')) : undefined,
    },
    priority
  );
}

// Парсер TUIC v5
function parseTuicUri(uri: string, priority: number): VpnNode {
  const url = new URL(uri);
  const p = url.searchParams;
  const decodedUser = safeDecodeComponent(url.username);
  let uuid = decodedUser;
  let password = safeDecodeComponent(url.password);
  if (!password && decodedUser.includes(':')) {
    const colonIdx = decodedUser.indexOf(':');
    uuid = decodedUser.slice(0, colonIdx);
    password = decodedUser.slice(colonIdx + 1);
  }
  if (!password) {
    password = p.get('password') || '';
  }

  const server = url.hostname;
  const port = Number(url.port || '443');
  if (!uuid || !isValidHost(server) || !isValidPort(port)) {
    throw new Error('Некорректные параметры UUID или сервера в ссылке TUIC');
  }

  const name =
    (url.hash ? safeDecodeComponent(url.hash.slice(1)).trim() : '') ||
    `TUIC ${server}:${port}`;
  const alpnRaw = p.get('alpn');

  return createBaseNode(
    {
      name,
      protocol: 'tuic',
      server,
      port,
      rawUri: uri,
      uuid,
      password,
      tls: 'tls',
      sni: p.get('sni') || server,
      alpn: alpnRaw ? alpnRaw.split(',').map((s) => s.trim()).filter(Boolean) : ['h3'],
      allowInsecure: p.get('allow_insecure') === '1' || p.get('insecure') === '1',
      congestionControl: p.get('congestion_control') || 'bbr',
      udpRelayMode: p.get('udp_relay_mode') || 'native',
    },
    priority
  );
}

function parseWireguardReserved(reservedRaw?: string | null): number[] | undefined {
  if (!reservedRaw) return undefined;
  const trimmed = reservedRaw.trim();
  if (!trimmed) return undefined;
  if (trimmed.includes(',')) {
    const nums = trimmed
      .split(',')
      .map((n) => Number(n.trim()))
      .filter((n) => Number.isInteger(n) && n >= 0 && n <= 255);
    return nums.length === 3 ? nums : undefined;
  }
  try {
    const clean = trimmed.replace(/-/g, '+').replace(/_/g, '/');
    const padded = clean + '='.repeat((4 - (clean.length % 4)) % 4);
    const nodeBuffer = (
      globalThis as unknown as {
        Buffer?: {
          from(data: string, encoding: string): ArrayLike<number>;
        };
      }
    ).Buffer;
    if (typeof nodeBuffer !== 'undefined') {
      const buf = nodeBuffer.from(padded, 'base64');
      if (buf.length === 3) return [buf[0], buf[1], buf[2]];
    } else if (typeof globalThis.atob === 'function') {
      const bin = globalThis.atob(padded);
      if (bin.length === 3) {
        return [bin.charCodeAt(0), bin.charCodeAt(1), bin.charCodeAt(2)];
      }
    }
  } catch {
    // ignore invalid base64
  }
  return undefined;
}

// Парсер WireGuard URI (wireguard:// или wg://)
function parseWireguardUri(uri: string, priority: number): VpnNode {
  const normalized = uri.startsWith('wg://')
    ? 'wireguard://' + uri.slice('wg://'.length)
    : uri;
  const url = new URL(normalized);
  const privateKey = safeDecodeComponent(url.username);
  const server = url.hostname;
  const port = Number(url.port || '51820');
  const p = url.searchParams;
  const publicKey = p.get('publickey') || p.get('public_key') || '';

  if (!privateKey || !publicKey || !isValidHost(server) || !isValidPort(port)) {
    throw new Error('В ссылке WireGuard требуются PrivateKey, PublicKey, сервер и порт');
  }

  const rawAddr = p.get('address') || p.get('ip') || '10.7.0.2/32';
  const addresses = rawAddr
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((entry) => (entry.includes('/') ? entry : entry.includes(':') ? `${entry}/128` : `${entry}/32`));
  const reserved = parseWireguardReserved(p.get('reserved'));

  const name =
    (url.hash ? safeDecodeComponent(url.hash.slice(1)).trim() : '') ||
    `WireGuard ${server}:${port}`;

  return createBaseNode(
    {
      name,
      protocol: 'wireguard',
      server,
      port,
      rawUri: uri,
      wgPrivateKey: privateKey,
      wgPublicKey: publicKey,
      wgPreSharedKey: p.get('presharedkey') || p.get('psk') || undefined,
      wgLocalAddress: addresses,
      wgMtu: p.get('mtu') ? Number(p.get('mtu')) : 1380,
      wgReserved: reserved && reserved.length === 3 ? reserved : undefined,
    },
    priority
  );
}

// Парсер классического текстового файла конфигурации WireGuard (.conf)
export function parseWireguardConf(
  confText: string,
  customName?: string,
  priority = 1
): VpnNode {
  const lines = confText.split(/\r?\n/);
  let section = '';
  const iface: Record<string, string> = {};
  const peer: Record<string, string> = {};

  for (const rawLine of lines) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    if (line.startsWith('[') && line.endsWith(']')) {
      section = line.slice(1, -1).trim().toLowerCase();
      continue;
    }
    const eqIdx = line.indexOf('=');
    if (eqIdx === -1) continue;
    const key = line.slice(0, eqIdx).trim().toLowerCase();
    const val = line.slice(eqIdx + 1).trim();
    if (section === 'interface') {
      iface[key] = val;
    } else if (section === 'peer') {
      peer[key] = val;
    }
  }

  const privateKey = iface.privatekey;
  const publicKey = peer.publickey;
  const endpoint = peer.endpoint;
  if (!privateKey || !publicKey || !endpoint) {
    throw new Error(
      'В файле WireGuard (.conf) отсутствуют обязательные поля PrivateKey, PublicKey или Endpoint'
    );
  }

  const epUrl = new URL(`http://${endpoint}`);
  const server = epUrl.hostname;
  const port = Number(epUrl.port || '51820');
  if (!isValidHost(server) || !isValidPort(port)) {
    throw new Error(`Некорректный Endpoint в конфиге WireGuard: ${endpoint}`);
  }

  const addresses = (iface.address || '10.7.0.2/32')
    .split(',')
    .map((a) => a.trim())
    .filter(Boolean)
    .map((a) => (a.includes('/') ? a : a.includes(':') ? `${a}/128` : `${a}/32`));

  return createBaseNode(
    {
      name: customName?.trim() || `WireGuard ${server}:${port}`,
      protocol: 'wireguard',
      server,
      port,
      rawUri: confText,
      wgPrivateKey: privateKey,
      wgPublicKey: publicKey,
      wgPreSharedKey: peer.presharedkey || undefined,
      wgLocalAddress: addresses,
      wgMtu: iface.mtu ? Number(iface.mtu) : 1408,
    },
    priority
  );
}

// Парсер SOCKS5 / HTTP прокси
function parseProxyUri(uri: string, priority: number): VpnNode {
  const url = new URL(uri);
  const scheme = url.protocol.replace(':', '').toLowerCase();
  const protocol: VpnProtocol = scheme.startsWith('socks') ? 'socks' : 'http';
  const server = url.hostname;
  const port = Number(url.port || (scheme === 'https' ? '443' : '1080'));
  if (!isValidHost(server) || !isValidPort(port)) {
    throw new Error(`Некорректный адрес или порт прокси: ${uri}`);
  }
  // Для http/https без порта и логина это обычно веб-ссылка подписки, а не прокси
  if (
    (scheme === 'http' || scheme === 'https') &&
    !url.port &&
    !url.username &&
    url.pathname &&
    url.pathname !== '/'
  ) {
    throw new Error(
      'Похоже, это ссылка-подписка (Subscription URL). Добавьте её через кнопку «Подписка по URL»'
    );
  }

  const name =
    (url.hash ? safeDecodeComponent(url.hash.slice(1)).trim() : '') ||
    `${protocol.toUpperCase()} ${server}:${port}`;

  return createBaseNode(
    {
      name,
      protocol,
      server,
      port,
      rawUri: uri,
      username: url.username ? safeDecodeComponent(url.username) : undefined,
      password: url.password ? safeDecodeComponent(url.password) : undefined,
      tls: scheme === 'https' ? 'tls' : 'none',
    },
    priority
  );
}

// Разбор одной строки URI
export function parseSingleVpnUri(uri: string, priority = 1): VpnNode {
  const trimmed = uri.trim();
  const lower = trimmed.toLowerCase();

  if (lower.startsWith('vless://')) return parseVlessUri(trimmed, priority);
  if (lower.startsWith('vmess://')) return parseVmessUri(trimmed, priority);
  if (lower.startsWith('ss://')) return parseShadowsocksUri(trimmed, priority);
  if (lower.startsWith('trojan://')) return parseTrojanUri(trimmed, priority);
  if (lower.startsWith('hysteria2://') || lower.startsWith('hy2://')) {
    return parseHysteria2Uri(trimmed, priority);
  }
  if (lower.startsWith('tuic://')) return parseTuicUri(trimmed, priority);
  if (lower.startsWith('wireguard://') || lower.startsWith('wg://')) {
    return parseWireguardUri(trimmed, priority);
  }
  if (
    lower.startsWith('socks5://') ||
    lower.startsWith('socks://') ||
    lower.startsWith('http://') ||
    lower.startsWith('https://')
  ) {
    return parseProxyUri(trimmed, priority);
  }

  throw new Error(`Неподдерживаемый протокол или формат строки: ${trimmed.slice(0, 32)}...`);
}

// Попытка извлечь VPN-узлы из JSON-профиля sing-box (если панель подписки вернула JSON с outbounds / endpoints)
function tryParseSingboxJsonOutbounds(
  rawJson: string,
  startingPriority: number,
  subscriptionId?: string
): VpnNode[] | null {
  if (!rawJson.startsWith('{') && !rawJson.startsWith('[')) return null;
  try {
    const parsed = JSON.parse(rawJson) as Record<string, unknown>;
    const outbounds = Array.isArray(parsed)
      ? (parsed as Array<Record<string, unknown>>)
      : Array.isArray(parsed.outbounds)
        ? (parsed.outbounds as Array<Record<string, unknown>>)
        : [];
    const endpoints =
      !Array.isArray(parsed) && Array.isArray(parsed.endpoints)
        ? (parsed.endpoints as Array<Record<string, unknown>>)
        : [];
    const combinedItems = [...outbounds, ...endpoints];
    if (combinedItems.length === 0) return null;

    const nodes: VpnNode[] = [];
    let prio = startingPriority;
    const supportedTypes = new Set([
      'vless',
      'vmess',
      'shadowsocks',
      'trojan',
      'hysteria2',
      'tuic',
      'wireguard',
      'socks',
      'http',
    ]);

    for (const item of combinedItems) {
      if (!item || typeof item !== 'object') continue;
      const type = String(item.type || '').toLowerCase();
      if (!supportedTypes.has(type)) continue;

      const peersArr = Array.isArray(item.peers)
        ? (item.peers as Array<Record<string, unknown>>)
        : undefined;
      const firstPeer = peersArr && peersArr.length > 0 ? peersArr[0] : undefined;

      const server = String(
        item.server || firstPeer?.address || firstPeer?.server || ''
      ).trim();
      const port = Number(
        item.server_port ||
          firstPeer?.port ||
          firstPeer?.server_port ||
          (type === 'wireguard' ? 51820 : 443)
      );
      if (!isValidHost(server) || !isValidPort(port)) continue;

      const tag = String(item.tag || `${type.toUpperCase()} ${server}:${port}`);
      const tlsObj = (item.tls as Record<string, unknown> | undefined) || undefined;
      const realityObj =
        (tlsObj?.reality as Record<string, unknown> | undefined) || undefined;
      const utlsObj = (tlsObj?.utls as Record<string, unknown> | undefined) || undefined;
      const transObj =
        (item.transport as Record<string, unknown> | undefined) || undefined;
      const transHeaders =
        (transObj?.headers as Record<string, unknown> | undefined) || undefined;
      const obfsObj = (item.obfs as Record<string, unknown> | undefined) || undefined;

      const tlsMode: TlsSecurity = tlsObj?.enabled
        ? realityObj?.enabled
          ? 'reality'
          : 'tls'
        : type === 'hysteria2' || type === 'tuic'
          ? 'tls'
          : 'none';

      const wsHostCandidate =
        transHeaders?.Host || transHeaders?.host || transObj?.host;
      const wsHost = Array.isArray(wsHostCandidate)
        ? wsHostCandidate[0]
          ? String(wsHostCandidate[0])
          : undefined
        : wsHostCandidate
          ? String(wsHostCandidate)
          : undefined;

      const alpn = Array.isArray(tlsObj?.alpn)
        ? tlsObj.alpn.map((a) => String(a).trim()).filter(Boolean)
        : typeof tlsObj?.alpn === 'string' && tlsObj.alpn.trim()
          ? tlsObj.alpn
              .split(',')
              .map((a) => a.trim())
              .filter(Boolean)
          : undefined;

      const rawFlow = item.flow ? String(item.flow).trim() : '';
      const flow = rawFlow
        ? rawFlow.toLowerCase().startsWith('xtls-rprx-vision')
          ? 'xtls-rprx-vision'
          : rawFlow
        : undefined;

      const wgLocalAddr = Array.isArray(item.address)
        ? item.address.map((a) => String(a).trim()).filter(Boolean)
        : Array.isArray(item.local_address)
          ? item.local_address.map((a) => String(a).trim()).filter(Boolean)
          : undefined;

      const wgReservedRaw = firstPeer?.reserved ?? item.reserved;
      const wgReserved = Array.isArray(wgReservedRaw)
        ? wgReservedRaw.map((n) => Number(n)).filter((n) => Number.isInteger(n))
        : typeof wgReservedRaw === 'string'
          ? parseWireguardReserved(wgReservedRaw)
          : undefined;

      const mport = Array.isArray(item.server_ports)
        ? item.server_ports.map((p) => String(p).trim()).filter(Boolean).join(',')
        : typeof item.server_ports === 'string' && item.server_ports.trim()
          ? item.server_ports.trim()
          : undefined;

      const node = createBaseNode(
        {
          protocol: type as VpnProtocol,
          server,
          port,
          name: tag,
          subscriptionId,
          uuid: item.uuid ? String(item.uuid) : undefined,
          password: item.password ? String(item.password) : undefined,
          username: item.username ? String(item.username) : undefined,
          method: item.method
            ? String(item.method)
            : item.security
              ? String(item.security)
              : undefined,
          alterId:
            typeof item.alter_id === 'number' ? item.alter_id : undefined,
          flow,
          tls: tlsMode,
          sni: tlsObj?.server_name ? String(tlsObj.server_name) : undefined,
          alpn,
          allowInsecure: Boolean(tlsObj?.insecure),
          fingerprint: utlsObj?.fingerprint ? String(utlsObj.fingerprint) : undefined,
          realityPublicKey: realityObj?.public_key
            ? String(realityObj.public_key)
            : undefined,
          realityShortId: realityObj?.short_id ? String(realityObj.short_id) : undefined,
          transport: transObj?.type
            ? normalizeTransport(String(transObj.type))
            : undefined,
          wsPath: transObj?.path ? String(transObj.path) : undefined,
          wsHost,
          grpcServiceName: transObj?.service_name
            ? String(transObj.service_name)
            : undefined,
          mport,
          upMbps:
            item.up_mbps !== undefined && item.up_mbps !== null
              ? Number(item.up_mbps)
              : undefined,
          downMbps:
            item.down_mbps !== undefined && item.down_mbps !== null
              ? Number(item.down_mbps)
              : undefined,
          obfsType:
            obfsObj?.type && String(obfsObj.type).toLowerCase() !== 'none'
              ? String(obfsObj.type)
              : undefined,
          obfsPassword: obfsObj?.password ? String(obfsObj.password) : undefined,
          congestionControl: item.congestion_control
            ? String(item.congestion_control)
            : undefined,
          udpRelayMode: item.udp_relay_mode ? String(item.udp_relay_mode) : undefined,
          wgPrivateKey: item.private_key ? String(item.private_key) : undefined,
          wgPublicKey: item.peer_public_key
            ? String(item.peer_public_key)
            : firstPeer?.public_key
              ? String(firstPeer.public_key)
              : undefined,
          wgPreSharedKey: item.pre_shared_key
            ? String(item.pre_shared_key)
            : firstPeer?.pre_shared_key
              ? String(firstPeer.pre_shared_key)
              : undefined,
          wgLocalAddress: wgLocalAddr,
          wgMtu: typeof item.mtu === 'number' ? item.mtu : undefined,
          wgReserved: wgReserved && wgReserved.length === 3 ? wgReserved : undefined,
        },
        prio
      );
      nodes.push(node);
      prio += 1;
    }
    return nodes.length > 0 ? nodes : null;
  } catch {
    return null;
  }
}

// Универсальный импорт: принимает одиночную ссылку, список ссылок, Base64-подписку, sing-box JSON или WireGuard .conf
export function parseVpnImportPayload(
  payload: string,
  startingPriority = 1,
  subscriptionId?: string,
  confNameHint?: string
): ParseImportResult {
  const trimmed = payload.trim();
  if (!trimmed) {
    return {
      nodes: [],
      errors: ['Пустые входные данные для импорта'],
      infoMessages: [],
      filteredDummyCount: 0,
    };
  }

  // 0. Закрытый зашифрованный контейнер happ://crypt — даём понятную подсказку про локальный мост
  if (/^happ:\/\/crypt/i.test(trimmed)) {
    return {
      nodes: [],
      errors: [
        'Эта ссылка зашифрована закрытым ключом Happ (happ://crypt). Запустите её в Happ в режиме прокси и отметьте галочкой «Внешний клиент: Happ (:10808)» в AegisMesh!',
      ],
      infoMessages: [],
      filteredDummyCount: 0,
    };
  }

  // 1. Проверяем, не JSON-профиль ли это от sing-box (с полем outbounds)
  const jsonNodes = tryParseSingboxJsonOutbounds(trimmed, startingPriority, subscriptionId);
  if (jsonNodes && jsonNodes.length > 0) {
    const realNodes: VpnNode[] = [];
    const infoMessages: string[] = [];
    let filteredDummyCount = 0;
    for (const n of jsonNodes) {
      if (isSyntheticDummyNode(n)) {
        filteredDummyCount += 1;
        if (n.name) infoMessages.push(n.name);
      } else {
        n.priority = startingPriority + realNodes.length;
        realNodes.push(n);
      }
    }
    return {
      nodes: realNodes,
      errors: [],
      infoMessages,
      filteredDummyCount,
    };
  }

  // 2. Проверяем, не классический ли это конфиг WireGuard ([Interface] + [Peer])
  if (/\[interface\]/i.test(trimmed) && /\[peer\]/i.test(trimmed)) {
    try {
      const wgNode = parseWireguardConf(trimmed, confNameHint, startingPriority);
      if (subscriptionId) wgNode.subscriptionId = subscriptionId;
      return { nodes: [wgNode], errors: [], infoMessages: [], filteredDummyCount: 0 };
    } catch (err) {
      return {
        nodes: [],
        errors: [err instanceof Error ? err.message : 'Ошибка разбора файла WireGuard'],
        infoMessages: [],
        filteredDummyCount: 0,
      };
    }
  }

  // 3. Если текст не содержит ://, пробуем декодировать его как Base64-подписку
  let workingText = trimmed;
  if (!workingText.includes('://')) {
    try {
      const decoded = decodeBase64Utf8(workingText.replace(/\s+/g, ''));
      if (
        decoded.includes('://') ||
        decoded.trim().startsWith('{') ||
        (/\[interface\]/i.test(decoded) && /\[peer\]/i.test(decoded))
      ) {
        return parseVpnImportPayload(decoded, startingPriority, subscriptionId, confNameHint);
      }
    } catch {
      // Оставляем исходный текст для отчёта об ошибке
    }
  }

  // 4. Построчный разбор всех ссылок с автоматическим отсечением инфо-заглушек (0.0.0.0:1, порт <= 1, нулевой UUID)
  const lines = workingText
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#') && !l.startsWith('//'));

  const nodes: VpnNode[] = [];
  const errors: string[] = [];
  const infoMessages: string[] = [];
  let filteredDummyCount = 0;
  let currentPriority = startingPriority;

  for (const line of lines) {
    try {
      const node = parseSingleVpnUri(line, currentPriority);
      if (isSyntheticDummyNode(node)) {
        filteredDummyCount += 1;
        if (node.name && node.name.trim()) {
          infoMessages.push(node.name.trim());
        }
        continue;
      }
      if (subscriptionId) node.subscriptionId = subscriptionId;
      nodes.push(node);
      currentPriority += 1;
    } catch (err) {
      errors.push(err instanceof Error ? err.message : `Ошибка разбора строки: ${line.slice(0, 40)}`);
    }
  }

  return { nodes, errors, infoMessages, filteredDummyCount };
}
