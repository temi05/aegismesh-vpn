// Генератор конфигураций ядра sing-box (спецификация 1.12+) для Десктопа и Мобильных устройств (iOS/Android)
import {
  AI_UNSUPPORTED_COUNTRY_CODES,
  collectAiRoutingDomains,
  collectFastMediaBypassDomains,
  computeNodeAiRank,
  inferCountryHintFromNode,
  pickBestStickyAiNode,
} from '../shared/aiRouting';
import type { AppSettings, DnsProviderId, VpnNode } from '../shared/types';

interface DohUpstreamSpec {
  server: string;
  port: number;
  path: string;
  isDomain: boolean;
  label: string;
}

export function getDohSpec(
  provider: DnsProviderId,
  customUrl: string,
  blockAds: boolean
): DohUpstreamSpec {
  if (blockAds && provider !== 'custom') {
    if (provider === 'adguard') {
      return {
        server: '94.140.14.14',
        port: 443,
        path: '/dns-query',
        isDomain: false,
        label: 'AdGuard DoH (Блокировка рекламы и трекеров)',
      };
    }
  }

  switch (provider) {
    case 'quad9':
      return {
        server: '9.9.9.9',
        port: 443,
        path: '/dns-query',
        isDomain: false,
        label: 'Quad9 Security DoH (Защита от вредоносных доменов)',
      };
    case 'adguard':
      return {
        server: '94.140.14.14',
        port: 443,
        path: '/dns-query',
        isDomain: false,
        label: 'AdGuard DoH (Фильтрация рекламы и слежки)',
      };
    case 'google':
      return {
        server: '8.8.8.8',
        port: 443,
        path: '/dns-query',
        isDomain: false,
        label: 'Google Public DoH (8.8.8.8)',
      };
    case 'custom': {
      try {
        const parsed = new URL(customUrl || 'https://1.1.1.1/dns-query');
        const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(parsed.hostname);
        return {
          server: parsed.hostname,
          port: parsed.port ? Number(parsed.port) : 443,
          path: parsed.pathname || '/dns-query',
          isDomain: !isIp,
          label: `Custom DoH (${parsed.hostname})`,
        };
      } catch {
        return {
          server: '1.1.1.1',
          port: 443,
          path: '/dns-query',
          isDomain: false,
          label: 'Cloudflare DoH (1.1.1.1)',
        };
      }
    }
    case 'cloudflare':
    default:
      return {
        server: '1.1.1.1',
        port: 443,
        path: '/dns-query',
        isDomain: false,
        label: 'Cloudflare Privacy DoH (1.1.1.1)',
      };
  }
}

function buildTransportBlock(node: VpnNode): Record<string, unknown> | undefined {
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

function buildTlsBlock(node: VpnNode): Record<string, unknown> | undefined {
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

// Конвертация VpnNode в outbound или WireGuard endpoint для sing-box 1.12+
export function convertNodeToSingboxUnit(
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
    if (node.wgPreSharedKey) {
      peer.pre_shared_key = node.wgPreSharedKey;
    }
    if (node.wgReserved && node.wgReserved.length === 3) {
      peer.reserved = node.wgReserved;
    }

    return {
      kind: 'endpoint',
      config: {
        type: 'wireguard',
        tag,
        system: false,
        mtu: node.wgMtu || 1408,
        address:
          node.wgLocalAddress && node.wgLocalAddress.length > 0
            ? node.wgLocalAddress
            : ['10.7.0.2/32'],
        private_key: node.wgPrivateKey || '',
        peers: [peer],
      },
    };
  }

  const transport = buildTransportBlock(node);
  const tls = buildTlsBlock(node);

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
            ? {
                obfs: {
                  type: 'salamander',
                  password: node.obfsPassword,
                },
              }
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

// Очистка белого списка доменов для маршрутизации Split Tunneling
export function extractSplitTunnelDomains(rawList: string[]): {
  exactDomains: string[];
  domainSuffixes: string[];
} {
  const exactDomains: string[] = [];
  const domainSuffixes: string[] = [];

  for (const raw of rawList) {
    const item = raw.trim().toLowerCase();
    if (!item) continue;
    if (item.startsWith('*.')) {
      const suffix = item.slice(1); // ".local" или ".bank.kz"
      if (suffix.length > 1) domainSuffixes.push(suffix);
    } else if (item.startsWith('.')) {
      if (item.length > 1) domainSuffixes.push(item);
    } else {
      exactDomains.push(item);
      if (item.includes('.')) {
        domainSuffixes.push(`.${item}`);
      }
    }
  }

  return {
    exactDomains: Array.from(new Set(exactDomains)),
    domainSuffixes: Array.from(new Set(domainSuffixes)),
  };
}

export interface DesktopSingboxBuildOptions {
  nodes: VpnNode[];
  activeNodeId: string;
  activeAiNodeId?: string | null;
  settings: AppSettings;
  internalMixedPort: number;
  aiProbePort?: number;
  clashApiPort: number;
  clashApiSecret: string;
  enableTun: boolean;
}

// Сборка полной конфигурации sing-box 1.12+ для Десктопа (с горячим переключением Clash API и шлюзом Нейросетей proxy-ai)
export function buildDesktopSingboxConfig(
  opts: DesktopSingboxBuildOptions
): Record<string, unknown> {
  const enabledNodes = opts.nodes.filter((n) => n.enabled);
  if (enabledNodes.length === 0) {
    throw new Error('Нет доступных включённых VPN-серверов для генерации конфигурации');
  }

  const outbounds: Array<Record<string, unknown>> = [];
  const endpoints: Array<Record<string, unknown>> = [];
  const nodeTags: string[] = [];
  let activeTag = '';
  let activeAiTag = '';

  const chosenAiNode = pickBestStickyAiNode({
    nodes: enabledNodes,
    currentAiNodeId: opts.activeAiNodeId,
    preferredAiNodeId: opts.settings.preferredAiNodeId,
    fallbackActiveNodeId: opts.activeNodeId,
  });

  const foreignAiNodes = enabledNodes.filter((n) => {
    const c = inferCountryHintFromNode(n);
    return !(c && AI_UNSUPPORTED_COUNTRY_CODES.has(c)) && n.aiStatus !== 'blocked';
  });
  const orderedAiSelectorNodes = (foreignAiNodes.length > 0 ? foreignAiNodes : enabledNodes)
    .slice()
    .sort((a, b) => computeNodeAiRank(b) - computeNodeAiRank(a) || a.priority - b.priority);
  const cleanAiSelectorTags = orderedAiSelectorNodes.map((n) => `node-${n.id}`);

  for (const node of enabledNodes) {
    const tag = `node-${node.id}`;
    nodeTags.push(tag);
    if (node.id === opts.activeNodeId) {
      activeTag = tag;
    }
    if (
      (chosenAiNode && node.id === chosenAiNode.id) ||
      (!chosenAiNode && opts.activeAiNodeId && node.id === opts.activeAiNodeId)
    ) {
      activeAiTag = tag;
    }
    const unit = convertNodeToSingboxUnit(node, tag);
    if (unit.kind === 'endpoint') {
      endpoints.push(unit.config);
    } else {
      outbounds.push(unit.config);
    }
  }

  if (!activeTag) {
    activeTag = nodeTags[0];
  }
  if (!activeAiTag) {
    activeAiTag = cleanAiSelectorTags[0] || activeTag;
  }

  // Группа автозамены urltest + главный селектор proxy-active + липкий ИИ-шлюз proxy-ai
  const selectorGroup: Record<string, unknown> = {
    type: 'selector',
    tag: 'proxy-active',
    outbounds: ['auto-failover', ...nodeTags],
    default: activeTag,
    interrupt_exist_connections: true,
  };

  const aiSelectorOutbounds = Array.from(
    new Set([activeAiTag, ...cleanAiSelectorTags, ...nodeTags])
  ).filter(Boolean);
  const aiSelectorGroup: Record<string, unknown> = {
    type: 'selector',
    tag: 'proxy-ai',
    outbounds: aiSelectorOutbounds,
    default: activeAiTag,
    interrupt_exist_connections: true,
  };

  const aiProbeSelectorGroup: Record<string, unknown> = {
    type: 'selector',
    tag: 'proxy-ai-probe',
    outbounds: [...nodeTags],
    default: activeAiTag,
    interrupt_exist_connections: true,
  };

  const urlTestGroup: Record<string, unknown> = {
    type: 'urltest',
    tag: 'auto-failover',
    outbounds: [...nodeTags],
    url: 'http://connectivitycheck.gstatic.com/generate_204',
    interval: `${Math.max(10, opts.settings.healthCheckIntervalSec * 2)}s`,
    tolerance: 80,
    interrupt_exist_connections: true,
  };

  const doh = getDohSpec(
    opts.settings.dnsProvider,
    opts.settings.customDohUrl,
    opts.settings.blockAdsAndTrackers
  );

  const remoteDnsServer: Record<string, unknown> = {
    type: 'https',
    tag: 'dns-remote',
    server: doh.server,
    server_port: doh.port,
    path: doh.path,
    detour: 'proxy-active',
    ...(doh.isDomain ? { domain_resolver: 'dns-direct' } : {}),
  };

  const aiDnsServer: Record<string, unknown> = {
    type: 'https',
    tag: 'dns-ai',
    server: '1.1.1.1',
    server_port: 443,
    path: '/dns-query',
    detour: 'proxy-ai',
  };

  const aiProbeDnsServer: Record<string, unknown> = {
    type: 'https',
    tag: 'dns-ai-probe',
    server: '1.1.1.1',
    server_port: 443,
    path: '/dns-query',
    detour: 'proxy-ai-probe',
  };

  const effectiveAiProbePort = opts.aiProbePort ?? 20809;
  const inbounds: Array<Record<string, unknown>> = [
    {
      type: 'mixed',
      tag: 'mixed-in',
      listen: '127.0.0.1',
      listen_port: opts.internalMixedPort,
    },
  ];

  if (effectiveAiProbePort > 0) {
    inbounds.push({
      type: 'mixed',
      tag: 'ai-probe-in',
      listen: '127.0.0.1',
      listen_port: effectiveAiProbePort,
    });
  }

  if (opts.enableTun) {
    inbounds.push({
      type: 'tun',
      tag: 'tun-in',
      interface_name: 'AegisMeshTunnel',
      address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
      mtu: 1400,
      auto_route: true,
      strict_route: true,
      stack: 'system',
    });
  }

  const routeRules: Array<Record<string, unknown>> = [
    {
      action: 'sniff',
    },
    {
      protocol: 'dns',
      action: 'hijack-dns',
    },
  ];

  const dnsRules: Array<Record<string, unknown>> = [];

  if (effectiveAiProbePort > 0) {
    routeRules.push({
      inbound: ['ai-probe-in'],
      outbound: 'proxy-ai-probe',
    });
    dnsRules.push({
      inbound: ['ai-probe-in'],
      server: 'dns-ai-probe',
    });
  }

  if (opts.settings.bypassPrivateLan) {
    routeRules.push({
      ip_is_private: true,
      outbound: 'direct',
    });
  }

  if (opts.settings.aiRoutingEnabled !== false) {
    const clientInbounds = opts.enableTun ? ['mixed-in', 'tun-in'] : ['mixed-in'];
    routeRules.push({
      inbound: clientInbounds,
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
    const { exactDomains, domainSuffixes } = extractSplitTunnelDomains(
      opts.settings.bypassDomains
    );
    const domainRule: Record<string, unknown> = {};
    if (exactDomains.length > 0) domainRule.domain = exactDomains;
    if (domainSuffixes.length > 0) domainRule.domain_suffix = domainSuffixes;

    if (Object.keys(domainRule).length > 0) {
      routeRules.push({
        ...domainRule,
        outbound: 'direct',
      });
      dnsRules.push({
        ...domainRule,
        server: 'dns-direct',
      });
    }
  }

  return {
    log: {
      level: 'warn',
      timestamp: true,
    },
    dns: {
      servers: [
        remoteDnsServer,
        aiDnsServer,
        aiProbeDnsServer,
        {
          type: 'local',
          tag: 'dns-direct',
        },
      ],
      rules: dnsRules,
      final: 'dns-remote',
      independent_cache: true,
    },
    ...(endpoints.length > 0 ? { endpoints } : {}),
    inbounds,
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
      auto_detect_interface: true,
      rules: routeRules,
      final: 'proxy-active',
    },
    experimental: {
      clash_api: {
        external_controller: `127.0.0.1:${opts.clashApiPort}`,
        secret: opts.clashApiSecret,
      },
    },
  };
}

// Сборка автономного мобильного профиля sing-box 1.12+ (для iOS и Android с встроенным Auto-Failover!)
export function buildMobileAutonomousSingboxProfile(
  nodes: VpnNode[],
  settings: AppSettings
): Record<string, unknown> {
  const usableNodes = nodes
    .filter((n) => n.enabled && !n.isTestStand)
    .sort((a, b) => a.priority - b.priority);

  const outbounds: Array<Record<string, unknown>> = [];
  const endpoints: Array<Record<string, unknown>> = [];
  const tags: string[] = [];

  for (const node of usableNodes) {
    const cleanLabel = `${node.priority}. ${node.name}`;
    tags.push(cleanLabel);
    const unit = convertNodeToSingboxUnit(node, cleanLabel);
    if (unit.kind === 'endpoint') {
      endpoints.push(unit.config);
    } else {
      outbounds.push(unit.config);
    }
  }

  const doh = getDohSpec(
    settings.dnsProvider,
    settings.customDohUrl,
    settings.blockAdsAndTrackers
  );

  const routeRules: Array<Record<string, unknown>> = [
    { action: 'sniff' },
    { protocol: 'dns', action: 'hijack-dns' },
    { ip_is_private: true, outbound: 'direct' },
  ];

  const dnsRules: Array<Record<string, unknown>> = [];

  if (settings.splitTunnelingEnabled && settings.bypassDomains.length > 0) {
    const { exactDomains, domainSuffixes } = extractSplitTunnelDomains(
      settings.bypassDomains
    );
    const domainRule: Record<string, unknown> = {};
    if (exactDomains.length > 0) domainRule.domain = exactDomains;
    if (domainSuffixes.length > 0) domainRule.domain_suffix = domainSuffixes;
    if (Object.keys(domainRule).length > 0) {
      routeRules.push({ ...domainRule, outbound: 'direct' });
      dnsRules.push({ ...domainRule, server: 'dns-direct' });
    }
  }

  const topGroupTag = 'AegisMesh Auto-Failover';
  const manualSelectTag = 'Выбор сервера';

  const mobileOutbounds: Array<Record<string, unknown>> =
    tags.length > 0
      ? [
          {
            type: 'urltest',
            tag: topGroupTag,
            outbounds: tags,
            url: 'https://cp.cloudflare.com/generate_204',
            interval: `${Math.max(15, settings.healthCheckIntervalSec * 2)}s`,
            tolerance: 60,
            interrupt_exist_connections: true,
          },
          {
            type: 'selector',
            tag: manualSelectTag,
            outbounds: [topGroupTag, ...tags],
            default: topGroupTag,
          },
          ...outbounds,
          { type: 'direct', tag: 'direct' },
        ]
      : [{ type: 'direct', tag: 'direct' }];

  return {
    log: { level: 'warn' },
    dns: {
      servers: [
        {
          type: 'https',
          tag: 'dns-remote',
          server: doh.server,
          server_port: doh.port,
          path: doh.path,
          detour: tags.length > 0 ? manualSelectTag : 'direct',
          ...(doh.isDomain ? { domain_resolver: 'dns-direct' } : {}),
        },
        {
          type: 'local',
          tag: 'dns-direct',
        },
      ],
      rules: dnsRules,
      final: 'dns-remote',
    },
    ...(endpoints.length > 0 ? { endpoints } : {}),
    inbounds: [
      {
        type: 'tun',
        tag: 'tun-in',
        address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
        mtu: 1400,
        auto_route: true,
        strict_route: true,
      },
    ],
    outbounds: mobileOutbounds,
    route: {
      default_domain_resolver: 'dns-direct',
      auto_detect_interface: true,
      rules: routeRules,
      final: tags.length > 0 ? manualSelectTag : 'direct',
    },
  };
}
