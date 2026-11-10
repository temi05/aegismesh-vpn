// Кроссплатформенный генератор конфигурации ядра sing-box (1.12–1.14+) для нативного Android VpnService
import {
  AI_UNSUPPORTED_COUNTRY_CODES,
  collectAiRoutingDomains,
  collectFastMediaBypassDomains,
  computeNodeAiRank,
  inferCountryHintFromNode,
  pickBestStickyAiNode,
} from './aiRouting';
import type { AppSettings, DnsProviderId, VpnNode } from './types';

function resolveDohServerIp(provider: DnsProviderId, blockAds: boolean): string {
  if (blockAds && provider !== 'custom') {
    if (provider === 'adguard') return '94.140.14.14';
  }
  switch (provider) {
    case 'adguard':
      return '94.140.14.14';
    case 'quad9':
      return '9.9.9.9';
    case 'google':
      return '8.8.8.8';
    case 'cloudflare':
    default:
      return '1.1.1.1';
  }
}

function buildTransport(node: VpnNode): Record<string, unknown> | undefined {
  if (!node.transport || node.transport === 'tcp' || node.transport === 'quic') {
    return undefined;
  }
  if (node.transport === 'ws') {
    const headers: Record<string, string> = {};
    if (node.wsHost) headers.Host = node.wsHost;
    return {
      type: 'ws',
      path: node.wsPath || '/',
      ...(Object.keys(headers).length > 0 ? { headers } : {}),
    };
  }
  if (node.transport === 'grpc') {
    return {
      type: 'grpc',
      service_name: node.grpcServiceName || '',
    };
  }
  if (node.transport === 'httpupgrade') {
    return {
      type: 'httpupgrade',
      path: node.wsPath || '/',
      ...(node.wsHost ? { host: node.wsHost } : {}),
    };
  }
  if (node.transport === 'http') {
    return {
      type: 'http',
      path: node.wsPath || '/',
      ...(node.wsHost ? { host: [node.wsHost] } : {}),
    };
  }
  return undefined;
}

function buildTls(node: VpnNode): Record<string, unknown> | undefined {
  if (!node.tls || node.tls === 'none') return undefined;
  const tlsObj: Record<string, unknown> = {
    enabled: true,
    server_name: node.sni || node.server,
    insecure: Boolean(node.allowInsecure),
  };
  if (node.alpn && node.alpn.length > 0) {
    tlsObj.alpn = node.alpn;
  }
  if (node.fingerprint || node.tls === 'reality') {
    tlsObj.utls = {
      enabled: true,
      fingerprint: node.fingerprint || 'chrome',
    };
  }
  if (node.tls === 'reality') {
    tlsObj.reality = {
      enabled: true,
      public_key: node.realityPublicKey || '',
      short_id: node.realityShortId || '',
    };
  }
  return tlsObj;
}

export function nodeToSingboxUnit(
  node: VpnNode,
  tag: string
): { kind: 'outbound' | 'endpoint'; config: Record<string, unknown> } {
  if (node.protocol === 'wireguard') {
    const peer: Record<string, unknown> = {
      address: node.server,
      port: node.port,
      public_key: node.wgPublicKey || '',
      allowed_ips: ['0.0.0.0/0', '::/0'],
      persistent_keepalive_interval: 25,
    };
    if (node.wgPreSharedKey) peer.pre_shared_key = node.wgPreSharedKey;
    if (node.wgReserved && node.wgReserved.length === 3) peer.reserved = node.wgReserved;
    return {
      kind: 'endpoint',
      config: {
        type: 'wireguard',
        tag,
        system: false,
        mtu: node.wgMtu || 1380,
        address:
          node.wgLocalAddress && node.wgLocalAddress.length > 0
            ? node.wgLocalAddress
            : ['10.7.0.2/32'],
        private_key: node.wgPrivateKey || '',
        peers: [peer],
      },
    };
  }

  const transport = buildTransport(node);
  const tls = buildTls(node);

  switch (node.protocol) {
    case 'vless':
      return {
        kind: 'outbound',
        config: {
          type: 'vless',
          tag,
          server: node.server,
          server_port: node.port,
          uuid: node.uuid || '',
          ...(node.flow ? { flow: node.flow } : {}),
          ...(tls ? { tls } : {}),
          ...(transport ? { transport } : {}),
        },
      };
    case 'vmess':
      return {
        kind: 'outbound',
        config: {
          type: 'vmess',
          tag,
          server: node.server,
          server_port: node.port,
          uuid: node.uuid || '',
          security: node.method || 'auto',
          alter_id: node.alterId || 0,
          ...(tls ? { tls } : {}),
          ...(transport ? { transport } : {}),
        },
      };
    case 'shadowsocks':
      return {
        kind: 'outbound',
        config: {
          type: 'shadowsocks',
          tag,
          server: node.server,
          server_port: node.port,
          method: node.method || 'aes-256-gcm',
          password: node.password || '',
        },
      };
    case 'trojan':
      return {
        kind: 'outbound',
        config: {
          type: 'trojan',
          tag,
          server: node.server,
          server_port: node.port,
          password: node.password || '',
          ...(tls ? { tls } : {}),
          ...(transport ? { transport } : {}),
        },
      };
    case 'hysteria2':
      return {
        kind: 'outbound',
        config: {
          type: 'hysteria2',
          tag,
          server: node.server,
          server_port: node.port,
          password: node.password || '',
          ...(node.upMbps ? { up_mbps: node.upMbps } : {}),
          ...(node.downMbps ? { down_mbps: node.downMbps } : {}),
          ...(node.obfsType === 'salamander' && node.obfsPassword
            ? { obfs: { type: 'salamander', password: node.obfsPassword } }
            : {}),
          tls: tls || {
            enabled: true,
            server_name: node.sni || node.server,
            insecure: Boolean(node.allowInsecure),
          },
        },
      };
    case 'tuic':
      return {
        kind: 'outbound',
        config: {
          type: 'tuic',
          tag,
          server: node.server,
          server_port: node.port,
          uuid: node.uuid || '',
          password: node.password || '',
          congestion_control: node.congestionControl || 'bbr',
          udp_relay_mode: node.udpRelayMode || 'native',
          tls: tls || {
            enabled: true,
            server_name: node.sni || node.server,
            alpn: node.alpn || ['h3'],
            insecure: Boolean(node.allowInsecure),
          },
        },
      };
    case 'socks':
      return {
        kind: 'outbound',
        config: {
          type: 'socks',
          tag,
          server: node.server,
          server_port: node.port,
          version: '5',
          ...(node.username ? { username: node.username } : {}),
          ...(node.password ? { password: node.password } : {}),
        },
      };
    case 'http':
    default:
      return {
        kind: 'outbound',
        config: {
          type: 'http',
          tag,
          server: node.server,
          server_port: node.port,
          ...(node.username ? { username: node.username } : {}),
          ...(node.password ? { password: node.password } : {}),
          ...(tls ? { tls } : {}),
        },
      };
  }
}

function extractSplitDomains(rawList: string[]): {
  exactDomains: string[];
  domainSuffixes: string[];
} {
  const exactDomains: string[] = [];
  const domainSuffixes: string[] = [];

  for (const raw of rawList) {
    const item = raw.trim().toLowerCase();
    if (!item) continue;
    if (item.startsWith('*.')) {
      const suffix = item.slice(1);
      if (suffix.length > 1) domainSuffixes.push(suffix);
    } else if (item.startsWith('.')) {
      if (item.length > 1) domainSuffixes.push(item);
    } else {
      exactDomains.push(item);
      if (item.includes('.')) domainSuffixes.push(`.${item}`);
    }
  }

  return {
    exactDomains: Array.from(new Set(exactDomains)),
    domainSuffixes: Array.from(new Set(domainSuffixes)),
  };
}

export interface AndroidEmbeddedSingboxOptions {
  nodes: VpnNode[];
  aiExtraCandidateNodes?: VpnNode[];
  activeNodeId?: string | null;
  activeAiNodeId?: string | null;
  settings: AppSettings;
  localSocksPort?: number;
  aiProbePort?: number;
  clashApiPort?: number;
}

// Сборка конфига для встроенного нативного ядра libsingbox.so внутри Android VpnService
// Использует СТРОГО добавленные пользователем VPN-серверы, автозамену urltest + Clash API
// и выделенный параллельный шлюз proxy-ai + dns-ai для нейросетей (Gemini, ChatGPT, Grok)
export function buildAndroidEmbeddedSingboxConfig(
  opts: AndroidEmbeddedSingboxOptions
): Record<string, unknown> {
  const usableNodes = opts.nodes
    .filter((n) => n.enabled && !n.isTestStand)
    .sort((a, b) => a.priority - b.priority);

  if (usableNodes.length === 0) {
    throw new Error('Добавьте хотя бы один свой VPN-ключ перед запуском туннеля');
  }

  // Пул для ИИ-шлюза включает все основные серверы + дополнительные включённые серверы других подписок пользователя
  const mainIdSet = new Set(usableNodes.map((n) => n.id));
  const extraAiNodes = (opts.aiExtraCandidateNodes || [])
    .filter((n) => n.enabled && !n.isTestStand && !mainIdSet.has(n.id))
    .sort((a, b) => a.priority - b.priority);
  const allAiNodes = [...usableNodes, ...extraAiNodes];

  const localSocksPort = opts.localSocksPort || 20808;
  const aiProbePort = opts.aiProbePort || 20809;
  const clashApiPort = opts.clashApiPort || 29090;

  const outbounds: Array<Record<string, unknown>> = [];
  const endpoints: Array<Record<string, unknown>> = [];
  const nodeTags: string[] = [];
  const aiNodeTags: string[] = [];
  let activeTag = '';
  let activeAiTag = '';

  const chosenAiNode = pickBestStickyAiNode({
    nodes: allAiNodes,
    currentAiNodeId: opts.activeAiNodeId,
    preferredAiNodeId: opts.settings.preferredAiNodeId,
    fallbackActiveNodeId: opts.activeNodeId,
  });

  // Сортируем кандидатов для селектора proxy-ai по убыванию их ИИ-рейтинга (исключая явные РФ-серверы при наличии зарубежных)
  const foreignAiNodes = allAiNodes.filter((n) => {
    const c = inferCountryHintFromNode(n);
    return !(c && AI_UNSUPPORTED_COUNTRY_CODES.has(c)) && n.aiStatus !== 'blocked';
  });
  const orderedAiSelectorNodes = (foreignAiNodes.length > 0 ? foreignAiNodes : allAiNodes)
    .slice()
    .sort((a, b) => computeNodeAiRank(b) - computeNodeAiRank(a) || a.priority - b.priority);
  const cleanAiSelectorTags = orderedAiSelectorNodes.map((n) => `node-${n.id}`);

  for (const node of allAiNodes) {
    const tag = `node-${node.id}`;
    aiNodeTags.push(tag);
    if (mainIdSet.has(node.id)) {
      nodeTags.push(tag);
      if (opts.activeNodeId && node.id === opts.activeNodeId) {
        activeTag = tag;
      }
    }
    if (
      (chosenAiNode && node.id === chosenAiNode.id) ||
      (!chosenAiNode && opts.activeAiNodeId && node.id === opts.activeAiNodeId)
    ) {
      activeAiTag = tag;
    }
    const unit = nodeToSingboxUnit(node, tag);
    if (unit.kind === 'endpoint') {
      endpoints.push(unit.config);
    } else {
      outbounds.push(unit.config);
    }
  }

  if (!activeTag) {
    activeTag = opts.settings.failoverMode === 'smart_fastest' && nodeTags.length > 1
      ? 'auto-failover'
      : nodeTags[0];
  }
  if (!activeAiTag) {
    activeAiTag = cleanAiSelectorTags[0] || aiNodeTags[0] || activeTag;
  }

  const dohIp = resolveDohServerIp(
    opts.settings.dnsProvider,
    opts.settings.blockAdsAndTrackers
  );

  const urlTestGroup: Record<string, unknown> = {
    type: 'urltest',
    tag: 'auto-failover',
    outbounds: [...nodeTags],
    url: 'http://connectivitycheck.gstatic.com/generate_204',
    interval: `${Math.max(12, opts.settings.healthCheckIntervalSec * 2)}s`,
    tolerance: 70,
    interrupt_exist_connections: true,
  };

  const selectorGroup: Record<string, unknown> = {
    type: 'selector',
    tag: 'proxy-active',
    outbounds: ['auto-failover', ...nodeTags],
    default: activeTag,
    interrupt_exist_connections: true,
  };

  // Выделенный «липкий» селектор для нейросетей (Gemini, ChatGPT, Grok):
  // interrupt_exist_connections = true гарантирует мгновенный сброс старых HTTP/2-сокетов к заблокированному IP при смене ИИ-сервера
  // (при автозамене основного proxy-active селектор proxy-ai НЕ трогается, поэтому активные диалоги ИИ не обрываются!)
  const aiSelectorOutbounds = Array.from(
    new Set([activeAiTag, ...cleanAiSelectorTags, ...aiNodeTags])
  ).filter(Boolean);
  const aiSelectorGroup: Record<string, unknown> = {
    type: 'selector',
    tag: 'proxy-ai',
    outbounds: aiSelectorOutbounds,
    default: activeAiTag,
    interrupt_exist_connections: true,
  };

  // Изолированный фоновый селектор для тестирования кандидатов на совместимость с Gemini/ChatGPT/Grok без влияния на трафик пользователя
  const aiProbeSelectorGroup: Record<string, unknown> = {
    type: 'selector',
    tag: 'proxy-ai-probe',
    outbounds: [...aiNodeTags],
    default: activeAiTag,
    interrupt_exist_connections: true,
  };

  const routeRules: Array<Record<string, unknown>> = [
    { action: 'sniff' },
    { protocol: 'dns', action: 'hijack-dns' },
    { inbound: ['ai-probe-in'], outbound: 'proxy-ai-probe' },
  ];

  // Первым правилом DNS изолируем запросы фонового ИИ-сканера (ai-probe-in -> dns-ai-probe -> proxy-ai-probe),
  // чтобы проверочный запрос к www.youtube.com/sw.js_data НИКОГДА не утекал в mediaRule (dns-remote / proxy-active)!
  const dnsRules: Array<Record<string, unknown>> = [
    { inbound: ['ai-probe-in'], server: 'dns-ai-probe' },
  ];

  if (opts.settings.bypassPrivateLan) {
    routeRules.push({
      ip_is_private: true,
      outbound: 'direct',
    });
  }

  // Правила Умного шлюза для Нейросетей v3.2+:
  // 1) Мягкий перевод клиентского QUIC (UDP:443) на TCP TLS 1.3 для 100% точности SNI-сниффинга (даже при кэше DNS и постквантовом Kyber);
  // 2) Быстрый обход видеопотоков YouTube и загрузок Google Play в основной туннель proxy-active;
  // 3) Полный контур Google/Gemini/ChatGPT/Grok без утечек HTTP/2 Connection Coalescing всегда идёт в выделенный proxy-ai + dns-ai!
  if (opts.settings.aiRoutingEnabled !== false) {
    routeRules.push({
      inbound: ['mixed-in'],
      network: ['udp'],
      port: [443],
      action: 'reject',
    });

    const fastMedia = collectFastMediaBypassDomains();
    if (fastMedia.exactDomains.length > 0 || fastMedia.domainSuffixes.length > 0) {
      const mediaRule: Record<string, unknown> = {};
      if (fastMedia.exactDomains.length > 0) mediaRule.domain = fastMedia.exactDomains;
      if (fastMedia.domainSuffixes.length > 0) mediaRule.domain_suffix = fastMedia.domainSuffixes;
      routeRules.push({ ...mediaRule, outbound: 'proxy-active' });
      dnsRules.push({ ...mediaRule, server: 'dns-remote' });
    }

    const aiDomains = collectAiRoutingDomains(opts.settings);
    const aiRule: Record<string, unknown> = {};
    if (aiDomains.exactDomains.length > 0) aiRule.domain = aiDomains.exactDomains;
    if (aiDomains.domainSuffixes.length > 0) aiRule.domain_suffix = aiDomains.domainSuffixes;

    if (Object.keys(aiRule).length > 0) {
      routeRules.push({ ...aiRule, outbound: 'proxy-ai' });
      dnsRules.push({ ...aiRule, server: 'dns-ai' });
    }
  }

  if (opts.settings.splitTunnelingEnabled && opts.settings.bypassDomains.length > 0) {
    const { exactDomains, domainSuffixes } = extractSplitDomains(
      opts.settings.bypassDomains
    );
    const domainRule: Record<string, unknown> = {};
    if (exactDomains.length > 0) domainRule.domain = exactDomains;
    if (domainSuffixes.length > 0) domainRule.domain_suffix = domainSuffixes;

    if (Object.keys(domainRule).length > 0) {
      routeRules.push({ ...domainRule, outbound: 'direct' });
      dnsRules.push({ ...domainRule, server: 'dns-direct' });
    }
  }

  // На Android без root НЕ включаем auto_detect_interface и НЕ используем local DNS (/etc/resolv.conf),
  // т.к. маршрутизация сокетов самого приложения изолирована системным VpnService.addDisallowedApplication!
  return {
    log: {
      level: 'warn',
      timestamp: true,
    },
    dns: {
      servers: [
        {
          type: 'https',
          tag: 'dns-remote',
          server: dohIp,
          server_port: 443,
          path: '/dns-query',
          detour: 'proxy-active',
        },
        {
          type: 'https',
          tag: 'dns-ai',
          server: '1.1.1.1',
          server_port: 443,
          path: '/dns-query',
          detour: 'proxy-ai',
        },
        {
          type: 'https',
          tag: 'dns-ai-probe',
          server: '1.1.1.1',
          server_port: 443,
          path: '/dns-query',
          detour: 'proxy-ai-probe',
        },
        {
          type: 'udp',
          tag: 'dns-direct',
          server: '77.88.8.8',
          server_port: 53,
        },
      ],
      rules: dnsRules,
      final: 'dns-remote',
      strategy: 'prefer_ipv4',
      independent_cache: true,
    },
    ...(endpoints.length > 0 ? { endpoints } : {}),
    inbounds: [
      {
        type: 'mixed',
        tag: 'mixed-in',
        listen: '127.0.0.1',
        listen_port: localSocksPort,
      },
      {
        type: 'mixed',
        tag: 'ai-probe-in',
        listen: '127.0.0.1',
        listen_port: aiProbePort,
      },
    ],
    outbounds: [
      selectorGroup,
      aiSelectorGroup,
      aiProbeSelectorGroup,
      urlTestGroup,
      ...outbounds,
      {
        type: 'direct',
        tag: 'direct',
      },
    ],
    route: {
      default_domain_resolver: 'dns-direct',
      rules: routeRules,
      final: 'proxy-active',
    },
    experimental: {
      clash_api: {
        external_controller: `127.0.0.1:${clashApiPort}`,
      },
    },
  };
}
