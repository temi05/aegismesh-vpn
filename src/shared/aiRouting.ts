// Модуль Умного шлюза для Нейросетей AegisMesh VPN v3.1 (Google Gemini, ChatGPT, Grok, Claude и др.)
// Реализует раздельную маршрутизацию ИИ-трафика (proxy-ai + dns-ai), реальную проверку совместимости серверов с ИИ
// и «липкое» удержание рабочего ИИ-сервера (Sticky AI Tunnel), чтобы диалоги не обрывались при автозамене основного VPN.

import type { AiServicePresetId, AppSettings, VpnNode } from './types';

export interface AiServicePresetMeta {
  id: AiServicePresetId;
  title: string;
  shortLabel: string;
  description: string;
  domains: string[];
}

export const DEFAULT_AI_SERVICES: AiServicePresetId[] = [
  'gemini',
  'chatgpt',
  'grok',
  'claude_other',
];

// Страны, в которых официально заблокированы Google Gemini, ChatGPT (OpenAI) и Grok (xAI)
export const AI_UNSUPPORTED_COUNTRY_CODES = new Set<string>([
  'RU',
  'BY',
  'CN',
  'HK',
  'MO',
  'IR',
  'KP',
  'CU',
  'SY',
]);

// Предпочтительные регионы с наилучшей поддержкой всех функций Gemini Live, ChatGPT Voice и Grok
export const AI_PREFERRED_COUNTRY_CODES = new Set<string>([
  'US',
  'NL',
  'DE',
  'FI',
  'SE',
  'GB',
  'FR',
  'PL',
  'CH',
  'AT',
  'CZ',
  'EE',
  'LV',
  'LT',
  'NO',
  'DK',
  'IE',
  'ES',
  'IT',
  'CA',
  'JP',
  'SG',
]);

export const AI_SERVICE_CATALOG: AiServicePresetMeta[] = [
  {
    id: 'gemini',
    title: 'Google Gemini & AI Studio',
    shortLabel: 'Gemini',
    description: 'Сайт gemini.google.com, приложение Gemini на Android (gRPC/Live), AI Studio и NotebookLM',
    domains: [
      'gemini.google.com',
      'bard.google.com',
      'aistudio.google.com',
      'makersuite.google.com',
      'notebooklm.google.com',
      'notebooklm.google',
      'generativelanguage.googleapis.com',
      'alkalimakersuite-pa.googleapis.com',
      'proactivebackend-pa.googleapis.com',
      'robinfrontend-pa.googleapis.com',
      'aisandbox-pa.googleapis.com',
      'assistant-s3-pa.googleapis.com',
      'speechs3proto2-pa.googleapis.com',
      'embeddedassistant.googleapis.com',
      'footprints-pa.googleapis.com',
      'aratea-pa.googleapis.com',
      'waa-pa.googleapis.com',
      'signaler-pa.googleapis.com',
      'scone-pa.googleapis.com',
      'jules.google.com',
      'idx.google.com',
      'labs.google',
      'deepmind.google',
      'ai.google.dev',
    ],
  },
  {
    id: 'chatgpt',
    title: 'ChatGPT & OpenAI',
    shortLabel: 'ChatGPT',
    description: 'Веб-версия и мобильное приложение ChatGPT, голосовой режим LiveKit, API и Sora',
    domains: [
      'chatgpt.com',
      'openai.com',
      'android.chat.openai.com',
      'ios.chat.openai.com',
      'ab.chatgpt.com',
      'auth.openai.com',
      'auth0.openai.com',
      'tcr9i.chat.openai.com',
      'oaistatic.com',
      'oaiusercontent.com',
      'sora.com',
      'livekit.cloud',
      'featuregates.org',
      'statsigapi.net',
      'ai.com',
    ],
  },
  {
    id: 'grok',
    title: 'Grok & xAI',
    shortLabel: 'Grok',
    description: 'Веб-клиент и приложение Grok (grok.com, x.ai, api.x.ai)',
    domains: [
      'grok.com',
      'assets.grok.com',
      'x.ai',
      'api.x.ai',
      'accounts.x.ai',
    ],
  },
  {
    id: 'claude_other',
    title: 'Claude, Perplexity, Copilot, DeepSeek',
    shortLabel: 'Claude/Другие',
    description: 'Anthropic Claude, Perplexity AI, Microsoft Copilot, GitHub Copilot, Cursor и DeepSeek',
    domains: [
      'claude.ai',
      'anthropic.com',
      'claudeusercontent.com',
      'perplexity.ai',
      'pplx.ai',
      'copilot.microsoft.com',
      'githubcopilot.com',
      'cursor.sh',
      'cursor.com',
      'deepseek.com',
      'mistral.ai',
      'poe.com',
    ],
  },
];

// Высокоскоростные медиа-домены YouTube и загрузки APK из Google Play, которые ставятся ПЕРЕД правилом ИИ
// и идут через самый быстрый основной VPN (proxy-active), чтобы видео 4K летало, а сессия Google не смешивалась с РФ
export const AI_FAST_MEDIA_BYPASS_DOMAINS = [
  'googlevideo.com',
  'youtube.com',
  'ytimg.com',
  'youtu.be',
  'youtubei.googleapis.com',
  'ggpht.com',
  'yt3.ggpht.com',
  'youtube-nocookie.com',
  'gvt1.com',
  'gvt2.com',
  'dl.google.com',
];

// Полный контур сессии Google Search / Account / GMS Phenotype / Google APIs:
// Исключает HTTP/2 Connection Coalescing и отравление cookie `.google.com` российским регионом при открытии Gemini в браузере и Android-приложении!
const GOOGLE_ACCOUNT_SESSION_DOMAINS = [
  'google.com',
  'www.google.com',
  'accounts.google.com',
  'myaccount.google.com',
  'ogs.google.com',
  'consent.google.com',
  'googleapis.com',
  'play.googleapis.com',
  'oauth2.googleapis.com',
  'gstatic.com',
  'googleusercontent.com',
  'lh3.googleusercontent.com',
];

// Дополнительные домены X (Twitter) для тех, кто запускает Grok прямо внутри приложения X
const X_TWITTER_GROK_DOMAINS = [
  'x.com',
  'twitter.com',
  'twimg.com',
];

/**
 * Собирает полный список точных доменов и доменных суффиксов нейросетей
 * для правил маршрутизации `route.rules` и `dns.rules` ядра sing-box.
 */
export function collectAiRoutingDomains(settings: Partial<AppSettings>): {
  exactDomains: string[];
  domainSuffixes: string[];
} {
  if (settings.aiRoutingEnabled === false) {
    return { exactDomains: [], domainSuffixes: [] };
  }

  const enabledIds = new Set<AiServicePresetId>(
    Array.isArray(settings.aiServices) && settings.aiServices.length > 0
      ? settings.aiServices
      : DEFAULT_AI_SERVICES
  );

  const rawPool: string[] = [];

  for (const preset of AI_SERVICE_CATALOG) {
    if (enabledIds.has(preset.id)) {
      rawPool.push(...preset.domains);
    }
  }

  if (enabledIds.has('gemini') && settings.aiIncludeGoogleAccountSession !== false) {
    rawPool.push(...GOOGLE_ACCOUNT_SESSION_DOMAINS);
  }

  if (enabledIds.has('grok') && settings.aiIncludeXForGrok === true) {
    rawPool.push(...X_TWITTER_GROK_DOMAINS);
  }

  if (Array.isArray(settings.aiCustomDomains)) {
    rawPool.push(...settings.aiCustomDomains);
  }

  const exactDomains: string[] = [];
  const domainSuffixes: string[] = [];

  for (const raw of rawPool) {
    const clean = raw
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .split('/')[0]
      .trim();
    if (!clean) continue;

    if (clean.startsWith('*.')) {
      const sfx = clean.slice(1);
      if (sfx.length > 1) domainSuffixes.push(sfx);
    } else if (clean.startsWith('.')) {
      if (clean.length > 1) domainSuffixes.push(clean);
    } else {
      exactDomains.push(clean);
      if (clean.includes('.')) {
        domainSuffixes.push(`.${clean}`);
      }
    }
  }

  return {
    exactDomains: Array.from(new Set(exactDomains)),
    domainSuffixes: Array.from(new Set(domainSuffixes)),
  };
}

/**
 * Собирает список высокоскоростных медиа-доменов YouTube и загрузок Google Play,
 * которые маршрутизируются через основной `proxy-active` ПЕРЕД контуром Google/ИИ (`proxy-ai`).
 */
export function collectFastMediaBypassDomains(): {
  exactDomains: string[];
  domainSuffixes: string[];
} {
  const exactDomains: string[] = [];
  const domainSuffixes: string[] = [];

  for (const dom of AI_FAST_MEDIA_BYPASS_DOMAINS) {
    const clean = dom.trim().toLowerCase();
    if (!clean) continue;
    exactDomains.push(clean);
    if (clean.includes('.')) {
      domainSuffixes.push(`.${clean}`);
    }
  }

  return {
    exactDomains: Array.from(new Set(exactDomains)),
    domainSuffixes: Array.from(new Set(domainSuffixes)),
  };
}

// Справочник 3-буквенных кодов стран ISO-3166-1 alpha-3 во внутренней структуре Google WIZ_global_data -> ISO-2
const GOOGLE_ISO3_TO_ISO2: Record<string, string> = {
  RUS: 'RU',
  BLR: 'BY',
  CHN: 'CN',
  HKG: 'HK',
  MAC: 'MO',
  IRN: 'IR',
  PRK: 'KP',
  CUB: 'CU',
  SYR: 'SY',
  USA: 'US',
  NLD: 'NL',
  DEU: 'DE',
  FIN: 'FI',
  SWE: 'SE',
  GBR: 'GB',
  FRA: 'FR',
  POL: 'PL',
  CHE: 'CH',
  AUT: 'AT',
  CZE: 'CZ',
  EST: 'EE',
  LVA: 'LV',
  LTU: 'LT',
  NOR: 'NO',
  DNK: 'DK',
  IRL: 'IE',
  ESP: 'ES',
  ITA: 'IT',
  CAN: 'CA',
  JPN: 'JP',
  SGP: 'SG',
  KOR: 'KR',
  TUR: 'TR',
  KAZ: 'KZ',
  ARE: 'AE',
  IND: 'IN',
  BRA: 'BR',
  AUS: 'AU',
};

/**
 * Извлекает ИСТИННЫЙ 2-буквенный GeoIP-регион из внутренней базы Google GFE (`https://www.youtube.com/sw.js_data`).
 * Решает главную проблему российских VPS в Нидерландах/Финляндии («YouTube без рекламы»),
 * где Cloudflare пишет `loc=NL`, а сама база Google видит этот IP как `"RU"` и блокирует Gemini!
 */
export function parseGoogleSwJsCountry(swBody?: string | null): string | null {
  if (!swBody) return null;
  const primary = swBody.match(
    /\["yt\.sw\.adr"\s*,\s*null\s*,\s*\[\[\[\s*"[a-zA-Z-]+"\s*,\s*"([A-Z]{2})"/
  );
  if (primary?.[1]) {
    return primary[1].toUpperCase();
  }
  const fallback = swBody.match(
    /\[\[\[\s*"[a-z]{2,3}(?:-[A-Za-z]{2,4})?"\s*,\s*"([A-Z]{2})"\s*,\s*null\s*,\s*"[0-9a-fA-F.:]+"/
  );
  return fallback?.[1] ? fallback[1].toUpperCase() : null;
}

/**
 * Разбирает HTML-ответ `gemini.google.com` (`WIZ_global_data`):
 * определяет внутренний 3-буквенный код страны Google (`RUS` -> `RU`, `NLD` -> `NL`, `USA` -> `US`),
 * флаг региональной доступности Gemini (`45631641`) и баннер неподдерживаемой страны.
 */
export function parseGoogleWizHtmlSignals(html?: string | null): {
  googleCountryIso2: string | null;
  wizGeminiAllowed: boolean | null;
  hasUnsupportedBanner: boolean;
} {
  if (!html) {
    return {
      googleCountryIso2: null,
      wizGeminiAllowed: null,
      hasUnsupportedBanner: false,
    };
  }

  let wizGeminiAllowed: boolean | null = null;
  if (/"45631641"\s*:\s*false/.test(html) || /45631641\s*,\s*null\s*,\s*false/.test(html)) {
    wizGeminiAllowed = false;
  } else if (/"45631641"\s*:\s*true/.test(html) || /45631641\s*,\s*null\s*,\s*true/.test(html)) {
    wizGeminiAllowed = true;
  }

  let googleCountryIso2: string | null = null;
  const iso3Regex = /,\s*null\s*,\s*"([A-Z]{3})"/g;
  let match: RegExpExecArray | null;
  while ((match = iso3Regex.exec(html)) !== null) {
    const mapped = GOOGLE_ISO3_TO_ISO2[match[1]];
    if (mapped) {
      googleCountryIso2 = mapped;
      break;
    }
  }

  const lower = html.toLowerCase();
  const hasUnsupportedBanner =
    lower.includes("gemini isn't currently supported") ||
    lower.includes('not currently supported in your country') ||
    lower.includes('не поддерживается в вашей стране') ||
    lower.includes('в этой стране gemini пока не работает');

  return {
    googleCountryIso2,
    wizGeminiAllowed,
    hasUnsupportedBanner,
  };
}

/**
 * Распознаёт подозрительные для ИИ-шлюза узлы (до завершения живой проверки базы Google):
 * - транзитные релеи через РФ (`[через РФ]`, `via RU`, `Relay`, `Мост`, `ru.*`, `*.ru`, `*.su`, `*.рф`);
 * - мобильные обходы белых списков (`LTE`, `4G`, `5G`, `Обход`, `White / Вайт`, `МТС / МегаФон / Билайн / Т2 / Yota`);
 * - серверы «YouTube без рекламы» (`YouTube`, `Ютуб`, `без рекламы`, `adfree`, `friedshrimp`), которые в базе Google имеют регион `RU`.
 */
export function isSuspiciousAiCandidateNode(
  node: Pick<VpnNode, 'name' | 'countryHint' | 'aiExitCountry'> & {
    server?: string;
    isExternalClientBridge?: boolean;
  }
): boolean {
  const nameText = (node.name || '').toLowerCase();
  const hostText = (node.server || '').toLowerCase();
  const combined = `${nameText} ${hostText}`;

  if (node.isExternalClientBridge && /byedpi/i.test(nameText)) {
    return true;
  }

  if (
    /(через\s*(рф|росси|ru)|via\s*(ru|russia)|(?:^|[^a-zа-яё0-9])(relay|bridge|мост|lte|4g|5g|мобил[а-яё]*|mobile|обход|вайт|white|мтс|mts|мегафон|megafon|билайн|beeline|tele2|t2|yota)(?![a-zа-яё0-9])|белые?\s*списк|youtube|ютуб|без\s*реклам|no[\s_-]*ads|ad[\s_-]*free|friedshrimp)/i.test(
      combined
    )
  ) {
    return true;
  }

  if (/(^ru\.|\.ru\.|\.ru$|\.su$|\.xn--p1ai$|\bmsk\b|\bspb\b)/i.test(hostText)) {
    return true;
  }

  return false;
}

/**
 * Быстрое эвристическое распознавание кода страны по названию узла, эмодзи-флагу, домену или полю countryHint
 * (используется для мгновенного первичного выбора сервера до завершения сетевого ИИ-сканера).
 */
export function inferCountryHintFromNode(
  node: Pick<VpnNode, 'name' | 'countryHint' | 'aiExitCountry'> & { server?: string }
): string | null {
  // 1. Высший приоритет — реальный регион, подтверждённый сетевым ИИ-пробником (база Google GFE / Cloudflare)
  if (node.aiExitCountry && /^[A-Za-z]{2}$/.test(node.aiExitCountry.trim())) {
    return node.aiExitCountry.trim().toUpperCase();
  }

  const rawName = (node.name || '').trim();
  const rawServer = (node.server || '').trim();
  const strippedName = rawName.replace(
    /(через|via|relay|bridge|мост)\s+(?:🇷🇺\s*)?(рф|росси[а-яё]*|ru|russia|мск|msk)(?![a-zа-яё0-9])/gi,
    ' '
  );

  const scanFlags = (str: string): string | null => {
    const flagMatch = Array.from(str);
    for (let i = 0; i < flagMatch.length - 1; i++) {
      const cp1 = flagMatch[i].codePointAt(0) ?? 0;
      const cp2 = flagMatch[i + 1].codePointAt(0) ?? 0;
      if (cp1 >= 0x1f1e6 && cp1 <= 0x1f1ff && cp2 >= 0x1f1e6 && cp2 <= 0x1f1ff) {
        const c1 = String.fromCharCode(65 + (cp1 - 0x1f1e6));
        const c2 = String.fromCharCode(65 + (cp2 - 0x1f1e6));
        return `${c1}${c2}`;
      }
    }
    return null;
  };

  // 2. Проверяем эмодзи-флаг в очищенном от транзитных приписок названии
  const flagFromStripped = scanFlags(strippedName);
  if (flagFromStripped) {
    return flagFromStripped;
  }

  const patterns: Array<[RegExp, string]> = [
    [/(?:^|[^a-zа-яё0-9])(рф|ру|ru|rus|росси[а-яё]*|москв[а-яё]*|moscow|мск|msk|спб|spb|петербург[а-яё]*|питер|новосибирск[а-яё]*|екатеринбург[а-яё]*|казань)(?![a-zа-яё0-9])/i, 'RU'],
    [/(\bby\b|беларус|минск|minsk|belarus)/i, 'BY'],
    [/(\bhk\b|гонконг|hong\s*kong)/i, 'HK'],
    [/(\bcn\b|китай|china|beijing|shanghai)/i, 'CN'],
    [/(\bnl\b|нидерланд|голланд|амстердам|netherlands|amsterdam)/i, 'NL'],
    [/(\bde\b|герман|франкфурт|germany|frankfurt|berlin|falkenstein)/i, 'DE'],
    [/(\bus\b|\busa\b|сша|америк|new\s*york|miami|dallas|los\s*angeles|chicago|ashburn)/i, 'US'],
    [/(\bfi\b|финлянд|хельсинки|finland|helsinki)/i, 'FI'],
    [/(\bse\b|швеци|стокгольм|sweden|stockholm)/i, 'SE'],
    [/(\bgb\b|\buk\b|британ|англия|лондон|london|united\s*kingdom)/i, 'GB'],
    [/(\bfr\b|франци|париж|france|paris)/i, 'FR'],
    [/(\bpl\b|польш|варшав|poland|warsaw)/i, 'PL'],
    [/(\bch\b|швейцар|цюрих|switzerland|zurich)/i, 'CH'],
    [/(\bat\b|австри|вена|austria|vienna)/i, 'AT'],
    [/(\bee\b|эстони|таллин|estonia|tallinn)/i, 'EE'],
    [/(\blv\b|латви|рига|latvia|riga)/i, 'LV'],
    [/(\blt\b|литв|вильнюс|lithuania|vilnius)/i, 'LT'],
    [/(\bjp\b|япони|токио|japan|tokyo)/i, 'JP'],
    [/(\bsg\b|сингапур|singapore)/i, 'SG'],
    [/(\bkz\b|казахстан|алматы|астана|almaty|astana)/i, 'KZ'],
    [/(\btr\b|турци|стамбул|turkey|istanbul)/i, 'TR'],
  ];

  // 3. Проверяем название узла (без транзитных приписок) — чтобы страна в имени всегда имела приоритет над ложным countryHint
  const lowerStripped = strippedName.toLowerCase();
  for (const [regex, code] of patterns) {
    if (regex.test(lowerStripped)) return code;
  }

  // 4. Если после удаления «через РФ / Мост РФ» другой страны в названии нет, проверяем исходное имя (узлы «Мост РФ #1», «Relay RU»)
  const flagFromRaw = scanFlags(rawName);
  if (flagFromRaw) return flagFromRaw;
  const lowerRaw = rawName.toLowerCase();
  for (const [regex, code] of patterns) {
    if (regex.test(lowerRaw)) return code;
  }

  // 5. Проверяем домен сервера (.ru, .su, .рф, msk, spb)
  if (rawServer) {
    if (/(^ru\.|\.ru\.|\.ru$|\.su$|\.xn--p1ai$|\bmsk\b|\bspb\b)/i.test(rawServer)) {
      return 'RU';
    }
  }

  // 6. В качестве последнего резерва используем countryHint (если он валидный 2-буквенный ISO)
  if (node.countryHint && /^[A-Za-z]{2}$/.test(node.countryHint.trim())) {
    return node.countryHint.trim().toUpperCase();
  }

  return null;
}

export interface RawAiProbeOutcome {
  reachable: boolean;
  exitCountry?: string | null;
  googleCountry?: string | null;
  geminiStatus?: number;
  geminiLocation?: string | null;
  geminiHtmlAllowed?: boolean | null;
  chatgptStatus?: number;
  chatgptBlockedBody?: boolean;
  grokStatus?: number;
  grokBlockedBody?: boolean;
  latencyMs?: number | null;
  error?: string | null;
}

/**
 * Честная глубокая оценка реальной проверки VPN-сервера на совместимость с Google Gemini, ChatGPT и Grok.
 * Сверяет ОБЕ базы геолокации: Cloudflare (`exitCountry`) И внутреннюю базу Google GFE/WIZ (`googleCountry`),
 * отсекая ложные «NL/FI для YouTube без рекламы», которые в базе Google числятся как `RU` и блокируют Gemini!
 */
export function evaluateAiProbeResult(
  node: VpnNode,
  probe: RawAiProbeOutcome,
  enabledServices: AiServicePresetId[] = DEFAULT_AI_SERVICES
): VpnNode {
  const now = Date.now();
  node.aiCheckedAt = now;

  if (!probe.reachable) {
    node.aiStatus = 'blocked';
    node.aiGeminiOk = false;
    node.aiChatgptOk = false;
    node.aiGrokOk = false;
    node.aiScore = 0;
    node.aiBlockReason = probe.error || 'Туннель не отвечает при проверке ИИ';
    return node;
  }

  const cfCountry = probe.exitCountry ? probe.exitCountry.trim().toUpperCase() : null;
  const googleCountry = probe.googleCountry ? probe.googleCountry.trim().toUpperCase() : null;
  const fallbackHint = inferCountryHintFromNode({
    name: node.name,
    server: node.server,
    countryHint: node.countryHint,
    aiExitCountry: null,
  });

  const requireGemini = enabledServices.length === 0 || enabledServices.includes('gemini');
  const effectiveCountry = (requireGemini && googleCountry)
    ? googleCountry
    : (cfCountry || googleCountry || fallbackHint);

  if (effectiveCountry) {
    node.aiExitCountry = effectiveCountry;
  }

  const cfUnsupported = Boolean(cfCountry && AI_UNSUPPORTED_COUNTRY_CODES.has(cfCountry));
  const googleUnsupported = Boolean(
    googleCountry && AI_UNSUPPORTED_COUNTRY_CODES.has(googleCountry)
  );
  const hintOnlyUnsupported =
    !cfCountry &&
    !googleCountry &&
    Boolean(fallbackHint && AI_UNSUPPORTED_COUNTRY_CODES.has(fallbackHint));

  if ((cfUnsupported && googleUnsupported) || (cfUnsupported && !googleCountry) || hintOnlyUnsupported) {
    const blockedCode = googleCountry || cfCountry || fallbackHint || 'RU';
    node.aiExitCountry = blockedCode;
    node.aiStatus = 'blocked';
    node.aiGeminiOk = false;
    node.aiChatgptOk = false;
    node.aiGrokOk = false;
    node.aiScore = 0;
    node.aiBlockReason = `Регион ${blockedCode} заблокирован у Gemini / ChatGPT / Grok`;
    return node;
  }

  // 1. Глубокий анализ Google Gemini (истинный GeoIP базы Google + редиректы /faq и /sorry/ + HTML-флаг 45631641)
  const gStatus = probe.geminiStatus ?? 0;
  const gLoc = (probe.geminiLocation || '').toLowerCase();
  const geminiCaptchaSorry = gLoc.includes('/sorry/');
  const geminiRedirectedToFaq =
    gLoc.includes('faq') ||
    gLoc.includes('unsupported') ||
    gLoc.includes('unavailable');

  // Защита от ложноположительного AI OK на российских и [через РФ] / LTE серверах:
  // 1) Нераскрытый HTTP 3xx редирект без подтверждённого зарубежного googleCountry НЕ считается успехом;
  // 2) Подозрительный транзитный узел ([через РФ] / LTE / YouTube без рекламы / ru.*) обязан явно доказать
  //    не-российский googleCountry или положительный ответ всех проверок, иначе он блокируется для Gemini!
  const suspiciousNode = isSuspiciousAiCandidateNode(node);
  const geminiHttpValid =
    (gStatus >= 200 && gStatus < 300) ||
    (gStatus >= 300 && gStatus < 400 && Boolean(googleCountry && !googleUnsupported));
  const suspiciousWithoutGoogleProof =
    suspiciousNode && !googleCountry && probe.geminiHtmlAllowed !== true;

  const geminiOk =
    !googleUnsupported &&
    !hintOnlyUnsupported &&
    !suspiciousWithoutGoogleProof &&
    geminiHttpValid &&
    !geminiRedirectedToFaq &&
    !geminiCaptchaSorry &&
    probe.geminiHtmlAllowed !== false;

  // 2. Глубокий анализ ChatGPT (Cloudflare GeoIP + JSON мобильного статуса OpenAI)
  const cStatus = probe.chatgptStatus ?? 0;
  const chatgptOk =
    !cfUnsupported &&
    !probe.chatgptBlockedBody &&
    cStatus >= 200 &&
    cStatus < 400;

  // 3. Глубокий анализ Grok (реальный ответ grok.com без HTTP 403)
  const xStatus = probe.grokStatus ?? 0;
  const grokOk =
    !cfUnsupported &&
    !probe.grokBlockedBody &&
    xStatus >= 200 &&
    xStatus < 400;

  node.aiGeminiOk = geminiOk;
  node.aiChatgptOk = chatgptOk;
  node.aiGrokOk = grokOk;

  let score = 0;
  if (geminiOk) score += 60;
  if (chatgptOk) score += 22;
  if (grokOk) score += 18;

  if (score > 0) {
    const bonusCountry = googleCountry || cfCountry || fallbackHint;
    if (bonusCountry && AI_PREFERRED_COUNTRY_CODES.has(bonusCountry)) {
      score = Math.min(100, score + 5);
    }
    const rtt = probe.latencyMs ?? node.emaLatencyMs ?? node.latencyMs;
    if (typeof rtt === 'number' && rtt > 350) {
      score = Math.max(25, score - Math.min(20, Math.round((rtt - 350) / 40)));
    }
  }

  // КРИТИЧЕСКОЕ ПРАВИЛО v3.2+: если у пользователя включён Gemini (основная нейросеть),
  // сервер НИКОГДА не получает статус `AI OK`, если база Google блокирует на нём Gemini!
  const passesRequiredAi = requireGemini
    ? geminiOk
    : (geminiOk || chatgptOk || grokOk);

  if (passesRequiredAi) {
    node.aiStatus = 'ok';
    node.aiScore = Math.max(50, Math.min(100, score));
    node.aiBlockReason = null;
  } else {
    node.aiStatus = 'blocked';
    node.aiScore = score;
    if (googleUnsupported) {
      node.aiExitCountry = googleCountry!;
      if (cfCountry && cfCountry !== googleCountry && !AI_UNSUPPORTED_COUNTRY_CODES.has(cfCountry)) {
        node.aiBlockReason = `База Google видит этот IP как ${googleCountry} (хотя сервер ${cfCountry}) — Gemini недоступен`;
      } else {
        node.aiBlockReason = `База Google определяет регион ${googleCountry} — Gemini недоступен`;
      }
    } else if (suspiciousWithoutGoogleProof) {
      node.aiBlockReason = 'Транзитный РФ / LTE сервер не прошёл проверку региона Google для Gemini';
    } else if (geminiCaptchaSorry) {
      node.aiBlockReason = 'Google блокирует IP этого VPS капчей (/sorry/) — Gemini недоступен';
    } else if (geminiRedirectedToFaq || probe.geminiHtmlAllowed === false) {
      node.aiBlockReason = `Google ограничивает Gemini для этого IP${effectiveCountry ? ` (${effectiveCountry})` : ''}`;
    } else if (gStatus === 403 || cStatus === 403 || xStatus === 403) {
      node.aiBlockReason = 'IP дата-центра заблокирован защитой ИИ (HTTP 403 / антифрод)';
    } else if (gStatus === 429 || cStatus === 429) {
      node.aiBlockReason = 'Слишком много запросов с этого IP (HTTP 429 Rate Limit)';
    } else {
      node.aiBlockReason = 'Нейросети недоступны через этот сервер';
    }
  }

  return node;
}

/**
 * Формирует умную очередь кандидатов для глубокого сканирования ИИ по ВСЕМ подпискам, личным ключам и мостам пользователя.
 * Чередует разные подписки (Round-Robin: Подписка 1 -> VPNUS -> Личные ключи -> Мост), ставя вперёд чистые зарубежные регионы (US/DE/NL/FI...),
 * чтобы мгновенно находить чистый для Google Gemini сервер, даже если в подписках 200+ мусорных/РФ/карантинных/LTE/YouTube-RU серверов!
 */
export function buildAiScanCandidateQueue(params: {
  nodes: VpnNode[];
  preferredAiNodeId?: string | null;
  currentAiNodeId?: string | null;
  includeAlreadyBlocked?: boolean;
}): VpnNode[] {
  const basePool = params.nodes.filter((n) => {
    if (!n.enabled) return false;
    if (n.status === 'down') return false;
    if (!params.includeAlreadyBlocked && n.aiStatus === 'blocked') return false;
    return true;
  });

  // Если есть кандидаты не из заблокированных стран (не RU/BY/CN/HK) и не в карантине,
  // исключаем явные РФ-серверы и карантинные узлы из первой волны сканера, чтобы они не забивали очередь!
  const nonRussianActive = basePool.filter((n) => {
    const c = inferCountryHintFromNode(n);
    const isUnsupported = Boolean(c && AI_UNSUPPORTED_COUNTRY_CODES.has(c));
    const isQuarantined = n.status === 'quarantined';
    return !isUnsupported && !isQuarantined;
  });
  const pool = nonRussianActive.length > 0 ? nonRussianActive : basePool;

  const scoreHint = (n: VpnNode): number => {
    const rawHint = inferCountryHintFromNode(n);
    if (n.aiStatus === 'ok' && n.aiGeminiOk !== false) return 600 + (n.aiScore ?? 85);
    if (rawHint && AI_UNSUPPORTED_COUNTRY_CODES.has(rawHint)) return -500;
    if (n.status === 'quarantined') return -400;

    let s = 100;
    if (rawHint === 'US') s += 75;
    else if (rawHint === 'DE') s += 65;
    else if (rawHint && AI_PREFERRED_COUNTRY_CODES.has(rawHint)) s += 55;
    else if (rawHint && rawHint !== 'GLB') s += 25;

    if (isSuspiciousAiCandidateNode(n)) {
      s -= 110;
    }
    if ((n.consecutiveFailures ?? 0) > 0 || (n.jitterMs ?? 0) > 80) {
      s -= 45;
    }
    if (n.isExternalClientBridge && /byedpi/i.test(n.name)) {
      s -= 180;
    }
    s += Math.round((n.smartScore ?? 50) * 0.2);
    return s;
  };

  const buckets = new Map<string, VpnNode[]>();
  for (const n of pool) {
    const key = n.subscriptionId
      ? `sub:${n.subscriptionId}`
      : n.isExternalClientBridge
        ? `bridge:${n.id}`
        : 'manual';
    const arr = buckets.get(key) || [];
    arr.push(n);
    buckets.set(key, arr);
  }

  for (const arr of buckets.values()) {
    arr.sort((a, b) => scoreHint(b) - scoreHint(a) || a.priority - b.priority);
  }

  const ordered: VpnNode[] = [];
  const seen = new Set<string>();
  const pushUnique = (n?: VpnNode | null) => {
    if (n && !seen.has(n.id)) {
      seen.add(n.id);
      ordered.push(n);
    }
  };

  if (params.preferredAiNodeId) {
    const pref = pool.find((n) => n.id === params.preferredAiNodeId);
    const prefCountry = pref ? inferCountryHintFromNode(pref) : null;
    if (pref && pref.aiStatus !== 'blocked' && !(prefCountry && AI_UNSUPPORTED_COUNTRY_CODES.has(prefCountry))) {
      pushUnique(pref);
    }
  }
  if (params.currentAiNodeId) {
    const cur = pool.find((n) => n.id === params.currentAiNodeId);
    const curCountry = cur ? inferCountryHintFromNode(cur) : null;
    if (
      cur &&
      cur.aiStatus !== 'blocked' &&
      !(curCountry && AI_UNSUPPORTED_COUNTRY_CODES.has(curCountry)) &&
      (cur.aiStatus === 'ok' || !isSuspiciousAiCandidateNode(cur))
    ) {
      pushUnique(cur);
    }
  }

  const bucketArrays = Array.from(buckets.values());
  // Проход 1: сначала по кругу (Round-Robin между подписками) собираем ТОЛЬКО чистые прямые зарубежные серверы
  // (без пометок [через РФ], LTE, Обход, YouTube без рекламы), чтобы подписка из одних РФ-релеев не тормозила сканер!
  for (let pass = 0; pass < 2; pass++) {
    const filteredBuckets = bucketArrays
      .map((arr) =>
        arr.filter((n) => {
          const isClean = n.aiStatus === 'ok' || !isSuspiciousAiCandidateNode(n);
          return pass === 0 ? isClean : !isClean;
        })
      )
      .filter((arr) => arr.length > 0);

    let round = 0;
    let addedInRound = true;
    while (addedInRound) {
      addedInRound = false;
      for (const arr of filteredBuckets) {
        if (round < arr.length) {
          pushUnique(arr[round]);
          addedInRound = true;
        }
      }
      round += 1;
    }
  }

  return ordered;
}

/**
 * Вычисляет рейтинг пригодности узла специально для ИИ-шлюза `proxy-ai`.
 * На холодном старте жёстко штрафует российские серверы, транзитные узлы `[через РФ]` / `ru.*`,
 * мобильные обходы `LTE #1` и серверы «YouTube без рекламы», отдавая приоритет чистым прямым узлам США и Европы!
 */
export function computeNodeAiRank(node: VpnNode): number {
  if (!node.enabled) return -1000;
  if (node.status === 'down' || node.status === 'quarantined') return -500;

  const country = inferCountryHintFromNode(node);
  if (country && AI_UNSUPPORTED_COUNTRY_CODES.has(country)) {
    return -400;
  }

  if (node.aiStatus === 'blocked') {
    return -350 + (node.aiScore ?? 0);
  }

  let rank = 0;

  if (node.aiStatus === 'ok') {
    rank += 250 + (node.aiScore ?? 80);
    if (node.aiGeminiOk) rank += 70;
    if (node.aiChatgptOk) rank += 20;
    if (node.aiGrokOk) rank += 15;
  } else {
    // Пока сетевая ИИ-проверка ещё не завершилась — используем строгую гео-эвристику и защиту от РФ-релеев
    rank += 50;
    if (country === 'US') {
      rank += 62;
    } else if (country === 'DE') {
      rank += 54;
    } else if (country && AI_PREFERRED_COUNTRY_CODES.has(country)) {
      rank += 45;
    }

    // Жёсткий штраф на холодном старте для [через РФ], ru.*, LTE #1, Обходов и YouTube без рекламы,
    // чтобы их низкий пинг из РФ (15 мс) никогда не перебивал чистые серверы США/Германии/Нидерландов!
    if (isSuspiciousAiCandidateNode(node)) {
      rank -= 95;
    }
    if ((node.consecutiveFailures ?? 0) > 0 || (node.jitterMs ?? 0) > 80) {
      rank -= 35;
    }
    if (node.isExternalClientBridge && /byedpi/i.test(node.name)) {
      rank -= 180;
    }
  }

  rank += Math.round((node.smartScore ?? 55) * 0.22);
  return rank;
}

/**
 * «Липкий» выбор лучшего сервера для ИИ-шлюза (`proxy-ai`):
 * - Удерживает текущий рабочий `🤖 AI OK` сервер при переключениях основного VPN, чтобы не рвать сессии Gemini / ChatGPT / Grok.
 * - Никогда не залипает на российских серверах, непроверенных `[через РФ]` / `LTE #1` релеях или заблокированных узлах, если есть чистый зарубежный сервер!
 */
export function pickBestStickyAiNode(params: {
  nodes: VpnNode[];
  currentAiNodeId?: string | null;
  preferredAiNodeId?: string | null;
  fallbackActiveNodeId?: string | null;
  nowMs?: number;
}): VpnNode | null {
  const now = params.nowMs ?? Date.now();
  const usable = params.nodes.filter((n) => {
    if (!n.enabled) return false;
    if (n.status === 'down') return false;
    if (
      n.status === 'quarantined' &&
      (n.quarantinedUntil === null || (n.quarantinedUntil ?? 0) > now)
    ) {
      return false;
    }
    return true;
  });

  if (usable.length === 0) return null;

  const sorted = [...usable].sort((a, b) => {
    const diff = computeNodeAiRank(b) - computeNodeAiRank(a);
    if (diff !== 0) return diff;
    return a.priority - b.priority;
  });
  const topLeader = sorted[0];

  // 1. Если пользователь вручную закрепил конкретный ИИ-сервер и он не заблокирован и не из РФ
  if (params.preferredAiNodeId) {
    const pinned = usable.find((n) => n.id === params.preferredAiNodeId);
    if (pinned && pinned.aiStatus !== 'blocked') {
      const pinnedCountry = inferCountryHintFromNode(pinned);
      if (!(pinnedCountry && AI_UNSUPPORTED_COUNTRY_CODES.has(pinnedCountry))) {
        return pinned;
      }
    }
  }

  // 2. Липкое удержание текущего ИИ-сервера (Sticky AI): не прыгаем между IP без необходимости!
  if (params.currentAiNodeId) {
    const current = usable.find((n) => n.id === params.currentAiNodeId);
    if (current) {
      const country = inferCountryHintFromNode(current);
      const isBadCountry = Boolean(country && AI_UNSUPPORTED_COUNTRY_CODES.has(country));
      if (!isBadCountry && current.aiStatus === 'ok' && current.aiGeminiOk !== false) {
        return current;
      }
      // На холодном старте удерживаем непроверенный сервер ТОЛЬКО если он не подозрительный ([через РФ] / LTE / YouTube-RU)
      // и в пуле ещё нет явно более сильного кандидата
      const hasVerifiedBetter = usable.some(
        (n) => n.id !== current.id && n.aiStatus === 'ok' && n.aiGeminiOk !== false
      );
      const currentSuspicious = isSuspiciousAiCandidateNode(current);
      const hasCleanerCandidate =
        topLeader &&
        topLeader.id !== current.id &&
        computeNodeAiRank(topLeader) >= computeNodeAiRank(current) + 25;

      if (
        current.aiStatus !== 'blocked' &&
        !isBadCountry &&
        !currentSuspicious &&
        !hasVerifiedBetter &&
        !hasCleanerCandidate
      ) {
        return current;
      }
    }
  }

  // 3. Выбираем лидера по комплексному ИИ-рейтингу (Gemini > ChatGPT > Grok > Чистая страна > Скорость)
  if (topLeader && computeNodeAiRank(topLeader) > -200) {
    return topLeader;
  }

  // 4. Безопасный фолбэк: избегаем российских и заблокированных серверов, если есть хотя бы один зарубежный
  const nonRussianFallback = sorted.find((n) => {
    const c = inferCountryHintFromNode(n);
    return !(c && AI_UNSUPPORTED_COUNTRY_CODES.has(c)) && n.aiStatus !== 'blocked';
  });
  if (nonRussianFallback) {
    return nonRussianFallback;
  }

  if (params.fallbackActiveNodeId) {
    const active = usable.find((n) => n.id === params.fallbackActiveNodeId);
    if (active) return active;
  }

  return topLeader || null;
}

/**
 * Циклический выбор СЛЕДУЮЩЕГО лучшего ИИ-сервера при нажатии кнопки «🔄 Сменить сервер ИИ» пользователем.
 * Строго исключает российские серверы, карантинные/мёртвые узлы и заблокированные для Gemini серверы!
 */
export function pickNextAiNodeForManualCycle(
  nodes: VpnNode[],
  currentAiNodeId?: string | null
): VpnNode | null {
  const now = Date.now();
  const usable = nodes
    .filter((n) => {
      if (!n.enabled) return false;
      if (n.status === 'down') return false;
      if (
        n.status === 'quarantined' &&
        (n.quarantinedUntil === null || (n.quarantinedUntil ?? 0) > now)
      ) {
        return false;
      }
      if (n.aiStatus === 'blocked') return false;
      const c = inferCountryHintFromNode(n);
      if (c && AI_UNSUPPORTED_COUNTRY_CODES.has(c)) return false;
      return true;
    })
    .sort((a, b) => computeNodeAiRank(b) - computeNodeAiRank(a) || a.priority - b.priority);

  const verifiedOkPool = usable.filter((n) => n.aiStatus === 'ok' && n.aiGeminiOk !== false);
  const cleanPositivePool = usable.filter(
    (n) => computeNodeAiRank(n) > 40 && !isSuspiciousAiCandidateNode(n)
  );

  const pool =
    verifiedOkPool.length > 0
      ? verifiedOkPool
      : cleanPositivePool.length > 0
        ? cleanPositivePool
        : usable.length > 0
          ? usable
          : nodes.filter((n) => n.enabled && n.status !== 'down');

  if (pool.length === 0) return null;
  if (!currentAiNodeId) return pool[0];

  const idx = pool.findIndex((n) => n.id === currentAiNodeId);
  if (idx === -1) return pool[0];
  return pool[(idx + 1) % pool.length];
}
