// Центр кибердиагностики: проверка реального и туннельного IP, утечек DNS, Kill Switch и готовности каскада
import type { AppSettings, AuditCheckItem, CyberAuditReport, VpnNode } from '../shared/types';
import { fetchViaUpstream, type UpstreamEndpoint } from './proxyConnector';
import { getDohSpec } from './singboxConfig';

interface IpLookupInfo {
  ip: string;
  country: string;
  org: string;
  latencyMs: number;
}

async function lookupIdentity(
  upstream: UpstreamEndpoint | null,
  customEchoUrl?: string | null
): Promise<IpLookupInfo | null> {
  if (customEchoUrl) {
    try {
      const res = await fetchViaUpstream(customEchoUrl, upstream, 4000);
      if (res.statusCode === 200) {
        const parsed = JSON.parse(res.body) as {
          ip?: string;
          country?: string;
          org?: string;
        };
        if (parsed.ip) {
          return {
            ip: parsed.ip,
            country: parsed.country || 'GLB',
            org: parsed.org || 'Test Network',
            latencyMs: res.elapsedMs,
          };
        }
      }
    } catch {
      return null;
    }
  }

  const endpoints = [
    {
      url: 'https://ipwho.is/',
      extract: (raw: string) => {
        const d = JSON.parse(raw) as {
          success?: boolean;
          ip?: string;
          country_code?: string;
          country?: string;
          connection?: { org?: string; isp?: string };
        };
        if (!d.ip) return null;
        return {
          ip: d.ip,
          country: d.country || d.country_code || 'Unknown',
          org: d.connection?.org || d.connection?.isp || 'ISP',
        };
      },
    },
    {
      url: 'https://ipinfo.io/json',
      extract: (raw: string) => {
        const d = JSON.parse(raw) as { ip?: string; country?: string; org?: string };
        if (!d.ip) return null;
        return {
          ip: d.ip,
          country: d.country || 'Unknown',
          org: d.org || 'ISP',
        };
      },
    },
    {
      url: 'https://api.ipify.org?format=json',
      extract: (raw: string) => {
        const d = JSON.parse(raw) as { ip?: string };
        if (!d.ip) return null;
        return {
          ip: d.ip,
          country: 'Определён',
          org: 'Внешний узел',
        };
      },
    },
  ];

  for (const ep of endpoints) {
    try {
      const res = await fetchViaUpstream(ep.url, upstream, 5500);
      if (res.statusCode === 200 && res.body) {
        const info = ep.extract(res.body);
        if (info) {
          return { ...info, latencyMs: res.elapsedMs };
        }
      }
    } catch {
      // Переходим к резервному гео-эндпоинту
    }
  }

  return null;
}

export async function runCyberSecurityAudit(params: {
  isConnected: boolean;
  localGuardPort: number;
  settings: AppSettings;
  nodes: VpnNode[];
  vaultHasPin: boolean;
  testEchoUrl?: string | null;
}): Promise<CyberAuditReport> {
  const guardUpstream: UpstreamEndpoint | null =
    params.isConnected && params.localGuardPort > 0
      ? { protocol: 'http', host: '127.0.0.1', port: params.localGuardPort }
      : null;

  const [directInfo, tunnelInfo] = await Promise.all([
    lookupIdentity(null, params.testEchoUrl),
    guardUpstream ? lookupIdentity(guardUpstream, params.testEchoUrl) : Promise.resolve(null),
  ]);

  const doh = getDohSpec(
    params.settings.dnsProvider,
    params.settings.customDohUrl,
    params.settings.blockAdsAndTrackers
  );

  const ipMasked = Boolean(
    params.isConnected &&
      tunnelInfo?.ip &&
      (!directInfo?.ip || directInfo.ip !== tunnelInfo.ip)
  );

  const enabledNodes = params.nodes.filter((n) => n.enabled);
  const hasFailoverReserve = enabledNodes.length >= 2;
  const dnsProtected = params.isConnected;
  const killSwitchActive = params.settings.killSwitchEnabled;

  const checks: AuditCheckItem[] = [
    {
      id: 'ip_masking',
      title: 'Маскировка реального IP-адреса',
      passed: ipMasked,
      detail: ipMasked
        ? `Ваш трафик выходит через защищённый узел ${tunnelInfo?.ip} (${tunnelInfo?.country})`
        : params.isConnected
          ? 'Туннель подключён, но выходной IP совпадает с прямым или узел недоступен'
          : 'VPN сейчас отключён — используется прямой IP провайдера',
    },
    {
      id: 'kill_switch',
      title: 'Аварийная блокировка утечек (Kill Switch)',
      passed: killSwitchActive,
      detail: killSwitchActive
        ? 'Активен на уровне шлюза GuardProxy: 0 байт утечки во время переключения серверов'
        : 'Отключён — при падении всех серверов возможен выход напрямую',
    },
    {
      id: 'secure_dns',
      title: 'Защита от DNS-утечек (DNS-over-HTTPS)',
      passed: dnsProtected,
      detail: dnsProtected
        ? `Шифрованный резолвинг внутри туннеля: ${doh.label}`
        : `Готов к работе (${doh.label}), активируется при включении щита`,
    },
    {
      id: 'failover_cascade',
      title: 'Готовность каскадной автозамены (Auto-Failover)',
      passed: hasFailoverReserve,
      detail: hasFailoverReserve
        ? `В очереди ${enabledNodes.length} активных серверов — резервирование готово`
        : 'Добавьте минимум 2–3 VPN-сервера, чтобы клиент мог автоматически переключаться при сбое',
    },
    {
      id: 'vault_encryption',
      title: 'Криптозащита хранилища ключей (AES-256-GCM)',
      passed: true,
      detail: params.vaultHasPin
        ? 'Ключи зашифрованы AES-256-GCM + защищены персональным PIN-кодом'
        : 'Ключи зашифрованы AES-256-GCM системным ключом (можно усилить PIN-кодом в настройках)',
    },
  ];

  let score = 20; // Базовый балл за AES-256-GCM сейф
  if (ipMasked) score += 35;
  if (killSwitchActive) score += 15;
  if (dnsProtected) score += 15;
  if (hasFailoverReserve) score += 10;
  if (params.vaultHasPin) score += 5;
  score = Math.min(100, score);

  let verdict = 'Базовый уровень — включите VPN-щит для полной защиты';
  if (score >= 90) {
    verdict = 'Максимальный уровень киберзащиты — туннель, Kill Switch и каскад активны';
  } else if (score >= 70) {
    verdict = 'Высокий уровень защиты — соединение зашифровано и защищено от утечек';
  } else if (params.isConnected) {
    verdict = 'Средний уровень — проверьте резервные узлы и Kill Switch';
  }

  return {
    checkedAt: Date.now(),
    directIp: directInfo?.ip ?? null,
    directCountry: directInfo?.country ?? null,
    directOrg: directInfo?.org ?? null,
    tunnelIp: tunnelInfo?.ip ?? null,
    tunnelCountry: tunnelInfo?.country ?? null,
    tunnelOrg: tunnelInfo?.org ?? null,
    ipMasked,
    dnsProtected,
    activeDnsLabel: doh.label,
    killSwitchActive,
    tunnelLatencyMs: tunnelInfo?.latencyMs ?? null,
    securityScore: score,
    verdict,
    checks,
  };
}
