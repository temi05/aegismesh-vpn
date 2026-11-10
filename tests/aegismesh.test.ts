// Комплексные модульные и интеграционные автотесты AegisMesh VPN (Vitest)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { fetchViaUpstream } from '../src/backend/proxyConnector';
import { DEFAULT_APP_SETTINGS, SecureVault } from '../src/backend/secureVault';
import {
  buildDesktopSingboxConfig,
  buildMobileAutonomousSingboxProfile,
} from '../src/backend/singboxConfig';
import { VpnEngine } from '../src/backend/vpnEngine';
import {
  buildDiversifiedFailoverBatch,
  canTriggerSelfHealingRefresh,
  classifyAndroidAppCategory,
  detectZombieTunnelStall,
  isSubscriptionDueForAutoRefresh,
  shouldPreemptivelySwitchNode,
  updateNodeSmartMetrics,
} from '../src/shared/smartFailover';
import { isValidHost, parseVpnImportPayload } from '../src/shared/uriParser';

const tempDirs: string[] = [];
function makeTempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()!;
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // Игнорируем блокировку временной папки ОС
    }
  }
});

describe('1. Универсальный парсер протоколов и подписок (uriParser)', () => {
  it('корректно разбирает VLESS (Reality), VMess (Base64 JSON), Shadowsocks, Trojan, Hysteria2 и TUIC', () => {
    const vmessPayload = Buffer.from(
      JSON.stringify({
        v: '2',
        ps: '🇳🇱 Амстердам VMess',
        add: 'nl.aegismesh.example',
        port: '8443',
        id: '22222222-3333-4444-5555-666666666666',
        aid: '0',
        scy: 'auto',
        net: 'ws',
        path: '/ws-tunnel',
        host: 'cdn.nl.example',
        tls: 'tls',
        sni: 'cdn.nl.example',
      }),
      'utf-8'
    ).toString('base64');

    const ssUser = Buffer.from('2022-blake3-aes-128-gcm:superSecretKey', 'utf-8').toString('base64');

    const multiInput = [
      'vless://11111111-2222-3333-4444-555555555555@de.reality.example:443?security=reality&encryption=none&pbk=PubKeyReality123&sid=a1b2c3d4&sni=www.microsoft.com&type=tcp&flow=xtls-rprx-vision&fp=chrome#🇩🇪%20Франкфурт%20Reality',
      `vmess://${vmessPayload}`,
      `ss://${ssUser}@fi.ss.example:8388#🇫🇮%20Хельсинки%20SS`,
      'trojan://myTrojanPass@tr.example.com:443?security=tls&sni=tr.example.com&type=grpc&serviceName=grpc-tun#🇹🇷%20Стамбул%20Trojan',
      'hysteria2://hy2pass@se.hy2.example:443?sni=se.hy2.example&obfs=salamander&obfs-password=obfspass&upmbps=100&downmbps=300#🇸🇪%20Стокгольм%20Hy2',
      'tuic://99999999-8888-7777-6666-555555555555:tuicSecret@jp.tuic.example:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3#🇯🇵%20Токио%20TUIC',
    ].join('\n');

    const result = parseVpnImportPayload(multiInput);
    expect(result.errors).toEqual([]);
    expect(result.nodes).toHaveLength(6);

    const [vless, vmess, ss, trojan, hy2, tuic] = result.nodes;
    expect(vless.protocol).toBe('vless');
    expect(vless.tls).toBe('reality');
    expect(vless.realityPublicKey).toBe('PubKeyReality123');
    expect(vless.realityShortId).toBe('a1b2c3d4');
    expect(vless.sni).toBe('www.microsoft.com');
    expect(vless.countryHint).toBe('DE');

    expect(vmess.protocol).toBe('vmess');
    expect(vmess.transport).toBe('ws');
    expect(vmess.wsPath).toBe('/ws-tunnel');
    expect(vmess.countryHint).toBe('NL');

    expect(ss.protocol).toBe('shadowsocks');
    expect(ss.method).toBe('2022-blake3-aes-128-gcm');
    expect(ss.password).toBe('superSecretKey');

    expect(trojan.protocol).toBe('trojan');
    expect(trojan.transport).toBe('grpc');
    expect(trojan.grpcServiceName).toBe('grpc-tun');

    expect(hy2.protocol).toBe('hysteria2');
    expect(hy2.obfsType).toBe('salamander');
    expect(hy2.upMbps).toBe(100);

    expect(tuic.protocol).toBe('tuic');
    expect(tuic.congestionControl).toBe('bbr');
    expect(tuic.alpn).toEqual(['h3']);
  });

  it('разбирает классический конфиг WireGuard (.conf), Base64-подписку и блокирует опасные строки', () => {
    const wgConf = `
      [Interface]
      PrivateKey = WG_PRIVATE_KEY_BASE64_EXAMPLE
      Address = 10.66.66.2/32, fd42:42:42::2/128
      MTU = 1420

      [Peer]
      PublicKey = WG_PUBLIC_KEY_BASE64_EXAMPLE
      PreSharedKey = WG_PSK_EXAMPLE
      Endpoint = wg.frankfurt.example:51820
      AllowedIPs = 0.0.0.0/0, ::/0
    `;
    const wgRes = parseVpnImportPayload(wgConf, 1, undefined, 'DE WireGuard');
    expect(wgRes.errors).toHaveLength(0);
    expect(wgRes.nodes[0].protocol).toBe('wireguard');
    expect(wgRes.nodes[0].wgPrivateKey).toBe('WG_PRIVATE_KEY_BASE64_EXAMPLE');
    expect(wgRes.nodes[0].wgPublicKey).toBe('WG_PUBLIC_KEY_BASE64_EXAMPLE');
    expect(wgRes.nodes[0].port).toBe(51820);

    // Base64-кодированная подписка из двух ключей
    const rawSub = [
      'vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443?security=tls#Node1',
      'trojan://secretPass@5.6.7.8:443?security=tls#Node2',
    ].join('\n');
    const b64Sub = Buffer.from(rawSub, 'utf-8').toString('base64');
    const subRes = parseVpnImportPayload(b64Sub);
    expect(subRes.nodes).toHaveLength(2);
    expect(subRes.nodes[0].priority).toBe(1);
    expect(subRes.nodes[1].priority).toBe(2);

    // Защита от некорректных ссылок и командных инъекций в хосте
    expect(isValidHost('evil.com; rm -rf /')).toBe(false);
    expect(isValidHost('valid-node.example.com')).toBe(true);
    const badRes = parseVpnImportPayload('unknown://broken_link\nvless://@invalid:99999');
    expect(badRes.nodes).toHaveLength(0);
    expect(badRes.errors.length).toBeGreaterThanOrEqual(2);
  });
});

describe('2. Криптографический сейф SecureVault (AES-256-GCM + scrypt)', () => {
  it('шифрует узлы на диске, поддерживает установку PIN-кода, блокировку и защиту от неверного PIN', () => {
    const dir = makeTempDir('aegis-vault-');
    const vault = new SecureVault(dir);

    const parsed = parseVpnImportPayload(
      'vless://11111111-2222-3333-4444-555555555555@de.example.com:443?security=tls#DE-Vault'
    );
    const initialData = vault.getDefaultData();
    initialData.nodes = parsed.nodes;
    vault.save(initialData);

    // Повторное чтение без PIN
    const vaultReloaded = new SecureVault(dir);
    expect(vaultReloaded.isLocked()).toBe(false);
    expect(vaultReloaded.load().nodes).toHaveLength(1);

    // Устанавливаем мастер-PIN
    vaultReloaded.setPin('7391', initialData);
    expect(vaultReloaded.hasPin()).toBe(true);

    // Новый экземпляр должен быть заблокирован до ввода PIN
    const lockedVault = new SecureVault(dir);
    expect(lockedVault.hasPin()).toBe(true);
    expect(lockedVault.isLocked()).toBe(true);
    expect(() => lockedVault.load()).toThrow(/VAULT_LOCKED/);
    expect(() => lockedVault.unlock('0000')).toThrow(/Неверный PIN-код/);

    // Успешная разблокировка верным PIN-кодом
    const unlocked = lockedVault.unlock('7391');
    expect(lockedVault.isLocked()).toBe(false);
    expect(unlocked.nodes).toHaveLength(1);
    expect(unlocked.nodes[0].server).toBe('de.example.com');
  });
});

describe('3. Генератор конфигураций sing-box 1.12+ (Десктоп + Мобильный профиль)', () => {
  it('формирует Split Tunneling, DoH DNS, группу urltest и WireGuard endpoints', () => {
    const parsed = parseVpnImportPayload(
      [
        'vless://11111111-2222-3333-4444-555555555555@de.example.com:443?security=reality&pbk=PK1&sid=ab12&sni=yahoo.com#DE-Reality',
        'wireguard://WG_PRIV@198.51.100.10:51820?publickey=WG_PUB&address=10.7.0.2/32#NL-WireGuard',
      ].join('\n')
    );

    const desktopCfg = buildDesktopSingboxConfig({
      nodes: parsed.nodes,
      activeNodeId: parsed.nodes[0].id,
      settings: {
        ...DEFAULT_APP_SETTINGS,
        dnsProvider: 'adguard',
        splitTunnelingEnabled: true,
        bypassDomains: ['gosuslugi.ru', '*.kaspi.kz'],
      },
      internalMixedPort: 20808,
      clashApiPort: 20809,
      clashApiSecret: 'test-secret',
      enableTun: true,
    });

    // Проверка WireGuard endpoints по спецификации sing-box 1.12+
    const endpoints = desktopCfg.endpoints as Array<Record<string, unknown>>;
    expect(endpoints).toHaveLength(1);
    expect(endpoints[0].type).toBe('wireguard');

    // Проверка группы urltest и TUN inbound
    const outbounds = desktopCfg.outbounds as Array<Record<string, unknown>>;
    expect(outbounds.some((o) => o.type === 'urltest' && o.tag === 'auto-failover')).toBe(true);
    const inbounds = desktopCfg.inbounds as Array<Record<string, unknown>>;
    expect(inbounds.some((i) => i.type === 'tun')).toBe(true);

    // Проверка DoH DNS и правил Split Tunneling
    const dns = desktopCfg.dns as { servers: Array<Record<string, unknown>>; rules: unknown[] };
    expect(dns.servers[0].server).toBe('94.140.14.14');
    expect(dns.rules.length).toBeGreaterThan(0);

    // Проверка автономного мобильного профиля (iOS/Android)
    const mobileCfg = buildMobileAutonomousSingboxProfile(parsed.nodes, DEFAULT_APP_SETTINGS);
    const mobOutbounds = mobileCfg.outbounds as Array<Record<string, unknown>>;
    expect(
      mobOutbounds.some((o) => o.type === 'urltest' && o.tag === 'AegisMesh Auto-Failover')
    ).toBe(true);
  });
});

describe('4. Боевой интеграционный тест: Auto-Failover (1 ➔ 2 ➔ 3) и Kill Switch', () => {
  it('автоматически переключает трафик по каскаду 1 ➔ 2 ➔ 3 при падении серверов и блокирует утечки IP через Kill Switch', async () => {
    const dir = makeTempDir('aegis-engine-');
    const engine = new VpnEngine(dir);

    try {
      await engine.updateSettings({
        localProxyPort: 0, // Динамический свободный порт для изоляции теста
        failoverMode: 'strict_cascade',
        killSwitchEnabled: true,
      });

      // 1. Запускаем локальный кластер из 3 серверов (#1 Франкфурт, #2 Амстердам, #3 Хельсинки)
      const standSnap = await engine.startTestStand();
      expect(standSnap.testStandRunning).toBe(true);
      expect(standSnap.nodes.map((n) => n.id)).toEqual([
        'test_node_1',
        'test_node_2',
        'test_node_3',
      ]);

      // 2. Подключаемся и проверяем, что активен узел #1 (Франкфурт) и трафик маскируется
      const connectedSnap = await engine.connect();
      expect(connectedSnap.connectionState).toBe('connected');
      expect(connectedSnap.activeNodeId).toBe('test_node_1');

      const audit1 = await engine.runCyberAudit();
      expect(audit1.ipMasked).toBe(true);
      expect(audit1.tunnelIp).toBe('185.220.101.41');

      // 3. Отключаем сервер #1 ➔ проверяем мгновенное переключение на сервер #2 (Амстердам)
      const afterFail1 = await engine.setTestNodeOnline('test_node_1', false);
      expect(afterFail1.connectionState).toBe('connected');
      expect(afterFail1.activeNodeId).toBe('test_node_2');
      expect(afterFail1.failoverSwitchCount).toBe(1);

      const audit2 = await engine.runCyberAudit();
      expect(audit2.tunnelIp).toBe('94.142.241.112');

      // 4. Отключаем сервер #2 ➔ проверяем мгновенное переключение на сервер #3 (Хельсинки)
      const afterFail2 = await engine.setTestNodeOnline('test_node_2', false);
      expect(afterFail2.connectionState).toBe('connected');
      expect(afterFail2.activeNodeId).toBe('test_node_3');
      expect(afterFail2.failoverSwitchCount).toBe(2);

      const audit3 = await engine.runCyberAudit();
      expect(audit3.tunnelIp).toBe('65.109.88.19');

      // 5. Отключаем последний сервер #3 ➔ должен сработать Kill Switch (503 без утечки реального IP)
      const afterFail3 = await engine.setTestNodeOnline('test_node_3', false);
      expect(afterFail3.connectionState).toBe('killswitch_locked');
      expect(afterFail3.killSwitchBlocking).toBe(true);

      const guardPort = engine.getGuardProxyPort();
      const blockedResp = await fetchViaUpstream(
        'http://example.com/sensitive-check',
        { protocol: 'http', host: '127.0.0.1', port: guardPort },
        3000
      );
      expect(blockedResp.statusCode).toBe(503);
      expect(blockedResp.body).toContain('Kill Switch');
      expect(engine.getBlockedLeakAttempts()).toBeGreaterThanOrEqual(1);

      // 6. Восстанавливаем сервер #1
      const recoveredSnap = await engine.setTestNodeOnline('test_node_1', true);
      const node1 = recoveredSnap.nodes.find((n) => n.id === 'test_node_1');
      expect(node1?.status).toBe('standby');
    } finally {
      await engine.shutdown();
    }
  });
});

describe('5. Нативный мобильный Android VPN-контроллер (0 выдуманных серверов + каскад пользователя)', () => {
  it('стартует с чистым списком (0 серверов) и строит автозамену строго из добавленных пользователем VPN', async () => {
    const { handleMobileStandaloneCall } = await import(
      '../src/renderer/mobileStandaloneFallback'
    );
    const { buildAndroidEmbeddedSingboxConfig } = await import(
      '../src/shared/androidSingboxConfig'
    );

    const initSnap = (await handleMobileStandaloneCall('/api/state')) as {
      connectionState: string;
      nodes: Array<{ id: string; name: string; priority: number }>;
    };
    expect(initSnap.connectionState).toBe('disconnected');
    expect(initSnap.nodes).toHaveLength(0);

    // Попытка подключения без добавленных серверов должна возвращать честную ошибку, а не фейковый стенд
    await expect(handleMobileStandaloneCall('/api/connect')).rejects.toThrow(
      /Добавьте .*VPN-ключ/
    );

    // Пользователь добавляет свои собственные 2 VPN-ключа
    const userKeys = [
      'vless://11111111-2222-3333-4444-555555555555@my-own-vpn1.org:443?security=reality&pbk=PKUser1&sid=0102&sni=cloudflare.com#МойЛичныйСервер_1',
      'hysteria2://myPass2@my-own-vpn2.org:8443/?sni=my-own-vpn2.org#МойРезервныйСервер_2',
    ].join('\n');

    const imported = (await handleMobileStandaloneCall('/api/import', {
      text: userKeys,
    })) as {
      snapshot: Parameters<typeof buildAndroidEmbeddedSingboxConfig>[0]['nodes'] extends infer N
        ? { nodes: N; settings: Parameters<typeof buildAndroidEmbeddedSingboxConfig>[0]['settings'] }
        : never;
    };

    expect(imported.snapshot.nodes).toHaveLength(2);
    expect(imported.snapshot.nodes[0].name).toBe('МойЛичныйСервер_1');
    expect(imported.snapshot.nodes[0].priority).toBe(1);
    expect(imported.snapshot.nodes[1].name).toBe('МойРезервныйСервер_2');
    expect(imported.snapshot.nodes[1].priority).toBe(2);

    // Проверяем Android sing-box конфиг: только серверы пользователя и без auto_detect_interface
    const androidCfg = buildAndroidEmbeddedSingboxConfig({
      nodes: imported.snapshot.nodes,
      activeNodeId: imported.snapshot.nodes[0].id,
      settings: imported.snapshot.settings,
    });

    const routeBlock = androidCfg.route as Record<string, unknown>;
    expect(routeBlock.auto_detect_interface).toBeUndefined();

    const outbounds = androidCfg.outbounds as Array<Record<string, unknown>>;
    const urltest = outbounds.find((o) => o.type === 'urltest') as { outbounds: string[] };
    expect(urltest.outbounds).toEqual([
      `node-${imported.snapshot.nodes[0].id}`,
      `node-${imported.snapshot.nodes[1].id}`,
    ]);
  });
});

describe('6. AegisMesh VPN v2: Защита от 0.0.0.0:1 заглушек Remnawave, HWID-метаданные и мосты внешних клиентов', () => {
  it('отфильтровывает фейковые инфо-заглушки 0.0.0.0:1 в infoMessages, разбирает sing-box JSON и поддерживает локальные мосты 127.0.0.1', async () => {
    const {
      createDefaultExternalClientBridges,
      externalBridgeToVpnNode,
      generateValidHwid,
      isSyntheticDummyNode,
      parseSubscriptionResponseHeaders,
    } = await import('../src/shared/subscriptionMeta');
    const { buildAndroidEmbeddedSingboxConfig } = await import(
      '../src/shared/androidSingboxConfig'
    );

    // 1. Проверка строгого формата HWID для Remnawave v2.7+/v3+
    const hwid = generateValidHwid();
    expect(hwid).toHaveLength(32);
    expect(/^[A-F0-9]{32}$/.test(hwid)).toBe(true);

    // 2. Реальный кейс со скриншота пользователя: 3 инфо-заглушки 0.0.0.0:1 + 1 настоящий сервер
    const remnawaveMix = [
      'vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?type=tcp#❌%20Приложение%20не%20поддерживает',
      'vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?type=tcp#⭐%20Рекомендованные:%20Happ,',
      'vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?type=tcp#Throne,%20ShadowRocket',
      'vless://11111111-2222-3333-4444-555555555555@nl-real.provider.org:443?security=reality&pbk=RealKey123&sid=abcd&sni=cloudflare.com#🇳🇱%20Нидерланды%20#1',
    ].join('\n');

    const parsedMix = parseVpnImportPayload(Buffer.from(remnawaveMix, 'utf-8').toString('base64'));
    expect(parsedMix.nodes).toHaveLength(1);
    expect(parsedMix.nodes[0].server).toBe('nl-real.provider.org');
    expect(parsedMix.filteredDummyCount).toBe(3);
    expect(parsedMix.infoMessages).toHaveLength(3);
    expect(parsedMix.infoMessages?.[1]).toContain('Happ');

    // 3. Разбор заголовков подписки (subscription-userinfo + base64 profile-title)
    const titleB64 = Buffer.from('Мой Основной VPN', 'utf-8').toString('base64');
    const hdrMeta = parseSubscriptionResponseHeaders({
      'Profile-Title': `base64:${titleB64}`,
      'Subscription-Userinfo': 'upload=1073741824; download=4294967296; total=53687091200; expire=1893456000',
      'Profile-Update-Interval': '6',
    });
    expect(hdrMeta.profileTitle).toBe('Мой Основной VPN');
    expect(hdrMeta.usedBytes).toBe(5368709120);
    expect(hdrMeta.totalBytes).toBe(53687091200);
    expect(hdrMeta.expireUnix).toBe(1893456000);
    expect(hdrMeta.autoUpdateHours).toBe(6);

    // 4. Разбор JSON-профиля sing-box outbounds (ответ панели для Throne / sing-box)
    const singboxProfileJson = JSON.stringify({
      outbounds: [
        { type: 'selector', tag: 'proxy', outbounds: ['de-1'] },
        {
          type: 'vless',
          tag: '🇩🇪 Германия JSON',
          server: 'de-json.provider.org',
          server_port: 443,
          uuid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
          flow: 'xtls-rprx-vision',
          tls: {
            enabled: true,
            server_name: 'microsoft.com',
            reality: { enabled: true, public_key: 'PK_JSON', short_id: '01ab' },
          },
        },
        { type: 'direct', tag: 'direct' },
      ],
    });
    const parsedJson = parseVpnImportPayload(singboxProfileJson);
    expect(parsedJson.nodes).toHaveLength(1);
    expect(parsedJson.nodes[0].name).toBe('🇩🇪 Германия JSON');
    expect(parsedJson.nodes[0].tls).toBe('reality');
    expect(parsedJson.nodes[0].realityPublicKey).toBe('PK_JSON');

    // 5. Мост к внешнему VPN-клиенту (Happ / v2rayNG на 127.0.0.1:10808) не считается заглушкой и работает в sing-box
    const bridges = createDefaultExternalClientBridges();
    const happBridge = { ...bridges[0], enabledInFailover: true, detectedRunning: true, latencyMs: 3 };
    const bridgeNode = externalBridgeToVpnNode(happBridge, 2);
    expect(isSyntheticDummyNode(bridgeNode)).toBe(false);

    const multiVpnAndroidCfg = buildAndroidEmbeddedSingboxConfig({
      nodes: [parsedMix.nodes[0], bridgeNode],
      activeNodeId: parsedMix.nodes[0].id,
      settings: DEFAULT_APP_SETTINGS,
    });
    const outs = multiVpnAndroidCfg.outbounds as Array<Record<string, unknown>>;
    expect(outs.some((o) => o.type === 'socks' && o.server === '127.0.0.1' && o.server_port === 10808)).toBe(true);
  });
});


describe('7. AegisMesh VPN v3.0: Умная Автозамена v3 (Smart Score, диверсифицированная гонка, DPI-зомби, автообновление и Per-App VPN)', () => {
  it('считает Smart Score 0-100, собирает гонку из разных провайдеров, ловит зомби-туннели и классифицирует приложения', () => {
    const parsed = parseVpnImportPayload(
      [
        'vless://11111111-2222-3333-4444-555555555555@sub1-a.example.org:443?security=tls#Sub1-A',
        'vless://11111111-2222-3333-4444-555555555555@sub1-b.example.org:443?security=tls#Sub1-B',
        'vless://11111111-2222-3333-4444-555555555555@sub1-c.example.org:443?security=tls#Sub1-C',
        'vless://11111111-2222-3333-4444-555555555555@sub2-a.example.org:443?security=tls#Sub2-A',
        'socks5://127.0.0.1:10808#Happ-Bridge',
      ].join('\n')
    );

    const [s1a, s1b, s1c, s2a, bridge] = parsed.nodes;
    s1a.subscriptionId = 'sub_1';
    s1b.subscriptionId = 'sub_1';
    s1c.subscriptionId = 'sub_1';
    s2a.subscriptionId = 'sub_2';
    bridge.isExternalClientBridge = true;

    // 1. Smart Score учитывает задержку, джиттер и пропускную способность
    const fastScore = updateNodeSmartMetrics(s2a, 38, 18000);
    const chokedScore = updateNodeSmartMetrics(s1a, 240, 180); // задушенная скорость < 350 Кбит/с
    expect(fastScore).toBeGreaterThan(85);
    expect(chokedScore).toBeLessThan(fastScore - 30);

    // 2. Диверсифицированная параллельная гонка берёт кандидатов из РАЗНЫХ провайдеров, а не застревает в одной подписке
    const batch = buildDiversifiedFailoverBatch(parsed.nodes, null, 3);
    const groupsInFirstThree = new Set(
      batch.map((n) => (n.isExternalClientBridge ? 'bridge' : n.subscriptionId))
    );
    expect(groupsInFirstThree.size).toBe(3);

    // 3. Анти-флаппинг блокирует лишний прыжок во время паузы охлаждения и разрешает после неё
    const now = 100_000;
    expect(
      shouldPreemptivelySwitchNode({
        activeNode: s1a,
        challengerNode: s2a,
        lastSwitchAtMs: now - 3000, // прошло всего 3 сек (< 15 сек cooldown)
        now,
      })
    ).toBe(false);
    expect(
      shouldPreemptivelySwitchNode({
        activeNode: s1a,
        challengerNode: s2a,
        lastSwitchAtMs: now - 25000, // пауза прошла, преимущество огромное
        now,
      })
    ).toBe(true);

    // 4. Детектор DPI-заморозки (Zombie Tunnel Stall)
    expect(
      detectZombieTunnelStall({
        prevTxPackets: 100,
        currTxPackets: 122,
        prevRxBytes: 50000,
        currRxBytes: 50000,
      })
    ).toBe(true);
    expect(
      detectZombieTunnelStall({
        prevTxPackets: 100,
        currTxPackets: 122,
        prevRxBytes: 50000,
        currRxBytes: 84000,
      })
    ).toBe(false);

    // 5. Расписание автообновления и 15-минутный предохранитель самоисцеления подписок
    const subObj = {
      id: 'sub_1',
      name: 'Main VPN',
      url: 'https://sub.example.org/token',
      lastUpdatedAt: now - 7 * 3600 * 1000,
      nodeCount: 5,
      autoUpdateHours: 6,
    };
    expect(isSubscriptionDueForAutoRefresh(subObj, 12, now)).toBe(true);
    expect(canTriggerSelfHealingRefresh(subObj, now - 5 * 60 * 1000, now)).toBe(false);
    expect(canTriggerSelfHealingRefresh(subObj, now - 20 * 60 * 1000, now)).toBe(true);

    // 6. Категоризация приложений для Per-App VPN пресетов
    expect(classifyAndroidAppCategory('ru.sberbankmobile', 'СберБанк')).toBe('bank_gov');
    expect(classifyAndroidAppCategory('com.google.android.youtube', 'YouTube')).toBe('video_music');
    expect(classifyAndroidAppCategory('org.telegram.messenger', 'Telegram')).toBe('social_media');
    expect(classifyAndroidAppCategory('com.android.chrome', 'Chrome')).toBe('browser');
  });
});

describe('8. AegisMesh VPN v3.1: Умный шлюз Нейросетей (Gemini/ChatGPT/Grok) + QUIC/HY2 и Авто-реабилитация карантина', () => {
  it('изолирует трафик и DNS нейросетей в Sticky AI Tunnel (proxy-ai), корректно определяет мосты [HY2 через РФ] и сам возвращает серверы из карантина', async () => {
    const {
      collectAiRoutingDomains,
      evaluateAiProbeResult,
      inferCountryHintFromNode,
      pickBestStickyAiNode,
    } = await import('../src/shared/aiRouting');
    const { buildAndroidEmbeddedSingboxConfig } = await import(
      '../src/shared/androidSingboxConfig'
    );
    const {
      isUdpBasedVpnProtocol,
      markNodeTemporarilyUnavailable,
      releaseExpiredUnavailableNodes,
    } = await import('../src/shared/smartFailover');

    // 1. Покрытие доменов Google Gemini (включая мобильные gRPC эндпоинты Android-приложения), ChatGPT и Grok без YouTube googlevideo.com
    const aiDomains = collectAiRoutingDomains({
      aiRoutingEnabled: true,
      aiServices: ['gemini', 'chatgpt', 'grok'],
      aiIncludeGoogleAccountSession: true,
    });
    expect(aiDomains.exactDomains).toContain('gemini.google.com');
    expect(aiDomains.exactDomains).toContain('robinfrontend-pa.googleapis.com');
    expect(aiDomains.exactDomains).toContain('proactivebackend-pa.googleapis.com');
    expect(aiDomains.exactDomains).toContain('chatgpt.com');
    expect(aiDomains.exactDomains).toContain('grok.com');
    expect(aiDomains.exactDomains).not.toContain('googlevideo.com');

    // 2. Распознавание транзитных серверов со скриншота («🇳🇱 Нидерланды 🐇 [HY2 через РФ]» и без флага «Нидерланды [HY2 через РФ]») -> строго NL, а не RU!
    expect(
      inferCountryHintFromNode({ name: '🇳🇱 Нидерланды 🐇 [HY2 через РФ]' })
    ).toBe('NL');
    expect(
      inferCountryHintFromNode({ name: 'Нидерланды [HY2 через РФ]' })
    ).toBe('NL');
    expect(
      inferCountryHintFromNode({ name: '🇫🇮 Финляндия 🐇 [HY2 через РФ]' })
    ).toBe('FI');

    // 3. Честная оценка AI-пробы: редирект Gemini на /faq блокируется, а чистый 200 OK в NL получает статус ok и выбирается Sticky AI-шлюзом
    const parsed = parseVpnImportPayload(
      [
        'vless://11111111-2222-3333-4444-555555555555@ru-fast.example.org:443?security=tls#🇷🇺 Москва Быстрый',
        'hysteria2://hy2pass@wolverine.example.xyz:4443/?sni=wolverine.example.xyz#🇳🇱 Нидерланды 🐇 [HY2]',
        'hysteria2://hy2pass@fi-bridge.example.xyz:5443/?sni=fi-bridge.example.xyz#🇫🇮 Финляндия 🐇 [HY2 через РФ]',
      ].join('\n')
    );
    const [ruNode, nlHy2Node, fiHy2Node] = parsed.nodes;

    evaluateAiProbeResult(ruNode, {
      reachable: true,
      exitCountry: 'RU',
      geminiStatus: 302,
      geminiLocation: 'https://gemini.google.com/faq',
      chatgptStatus: 403,
      grokStatus: 403,
      latencyMs: 25,
    });
    expect(ruNode.aiStatus).toBe('blocked');
    expect(ruNode.aiGeminiOk).toBe(false);

    evaluateAiProbeResult(nlHy2Node, {
      reachable: true,
      exitCountry: 'NL',
      geminiStatus: 200,
      geminiLocation: '',
      chatgptStatus: 200,
      grokStatus: 200,
      latencyMs: 58,
    });
    expect(nlHy2Node.aiStatus).toBe('ok');
    expect(nlHy2Node.aiGeminiOk).toBe(true);

    // Sticky AI выбирает NL [HY2] для нейросетей, даже когда основной VPN подключён к быстрому RU-серверу!
    const stickyAi = pickBestStickyAiNode({
      nodes: parsed.nodes,
      currentAiNodeId: null,
      fallbackActiveNodeId: ruNode.id,
    });
    expect(stickyAi?.id).toBe(nlHy2Node.id);

    // 4. Генерация Android sing-box конфига: параллельный селектор proxy-ai (interrupt_exist_connections: true для сброса старых gRPC/H2 сокетов при смене ИИ), порт 20809 и dns-ai
    const androidCfg = buildAndroidEmbeddedSingboxConfig({
      nodes: parsed.nodes,
      activeNodeId: ruNode.id,
      activeAiNodeId: nlHy2Node.id,
      settings: DEFAULT_APP_SETTINGS,
    });
    const outbounds = androidCfg.outbounds as Array<Record<string, unknown>>;
    const proxyAi = outbounds.find((o) => o.tag === 'proxy-ai');
    expect(proxyAi).toBeDefined();
    expect(proxyAi?.default).toBe(`node-${nlHy2Node.id}`);
    expect(proxyAi?.interrupt_exist_connections).toBe(true);

    const inbounds = androidCfg.inbounds as Array<Record<string, unknown>>;
    expect(inbounds.some((i) => i.tag === 'ai-probe-in' && i.listen_port === 20809)).toBe(true);
    const dnsBlock = androidCfg.dns as { servers: Array<Record<string, unknown>> };
    expect(dnsBlock.servers.some((s) => s.tag === 'dns-ai' && s.detour === 'proxy-ai')).toBe(true);

    // 5. Защита UDP/QUIC протоколов (Hysteria2 / TUIC / WireGuard) от ложного TCP-бана + автовозврат серверов из карантина
    expect(isUdpBasedVpnProtocol('hysteria2')).toBe(true);
    expect(isUdpBasedVpnProtocol('tuic')).toBe(true);
    expect(isUdpBasedVpnProtocol('wireguard')).toBe(true);
    expect(isUdpBasedVpnProtocol('vless')).toBe(false);

    // Старая ложная TCP-ошибка на [HY2] мгновенно очищается
    fiHy2Node.status = 'down';
    fiHy2Node.lastError =
      'failed to connect to ru.nextdump.example.xyz/82.202.157.79 (port 4443) after 3200ms';
    const cleanedTcpFalsePositive = releaseExpiredUnavailableNodes([fiHy2Node], 100_000, false);
    expect(cleanedTcpFalsePositive).toBe(1);
    expect(fiHy2Node.status).toBe('standby');
    expect(fiHy2Node.lastError).toBeUndefined();

    // Временный карантин автоматически снимается по истечении таймера (например, 45 сек)
    markNodeTemporarilyUnavailable(ruNode, 'Временный сбой', 45, 200_000);
    expect(ruNode.status).toBe('quarantined');
    expect(ruNode.quarantinedUntil).toBe(245_000);
    expect(releaseExpiredUnavailableNodes([ruNode, nlHy2Node], 220_000, false)).toBe(0);
    expect(ruNode.status).toBe('quarantined');
    expect(releaseExpiredUnavailableNodes([ruNode, nlHy2Node], 246_000, false)).toBe(1);
    expect(ruNode.status).toBe('standby');
    expect(ruNode.quarantinedUntil).toBeNull();

    // Mass-Offline Guard: если пропала связь и ВСЕ серверы разом попали в карантин, система сама возвращает их в строй
    markNodeTemporarilyUnavailable(ruNode, 'Нет сети', 45, 300_000);
    markNodeTemporarilyUnavailable(nlHy2Node, 'Нет сети', 45, 300_000);
    markNodeTemporarilyUnavailable(fiHy2Node, 'Нет сети', 45, 300_000);
    const guardReleased = releaseExpiredUnavailableNodes(parsed.nodes, 305_000, true);
    expect(guardReleased).toBe(3);
    expect(parsed.nodes.every((n) => n.status === 'standby')).toBe(true);
  });
});

describe('9. AegisMesh VPN v3.2: Глубокая проверка Google GeoIP (sw.js_data / WIZ), защита от YouTube-RU серверов и изоляция QUIC/HTTP2 для Gemini', () => {
  it('распознаёт серверы NL/FI с Google GeoIP = RU («YouTube без рекламы»), переключает proxy-ai на чистый сервер из другой подписки (VPNUS) и исключает утечку региона Google через QUIC/HTTP2', async () => {
    const {
      buildAiScanCandidateQueue,
      collectAiRoutingDomains,
      collectFastMediaBypassDomains,
      evaluateAiProbeResult,
      parseGoogleSwJsCountry,
      parseGoogleWizHtmlSignals,
      pickBestStickyAiNode,
    } = await import('../src/shared/aiRouting');
    const { buildAndroidEmbeddedSingboxConfig } = await import(
      '../src/shared/androidSingboxConfig'
    );

    // 1. Точное извлечение истинного региона Google GFE из youtube.com/sw.js_data и WIZ_global_data
    const realSwPayload = `)]}'\n[["yt.sw.adr",null,[[["ru","RU",null,"147.90.250.41",null,null,[[2]]]]]]`;
    expect(parseGoogleSwJsCountry(realSwPayload)).toBe('RU');

    const cleanUsSwPayload = `)]}'\n[["yt.sw.adr",null,[[["en","US",null,"38.180.12.55",null,null,[[2]]]]]]`;
    expect(parseGoogleSwJsCountry(cleanUsSwPayload)).toBe('US');

    const wizBlockedHtml = `<script>window.WIZ_global_data = {"cfb2h":"boq_bard",null,"RUS","45631641":false};</script><div>Gemini isn't currently supported in your country</div>`;
    const wizRes = parseGoogleWizHtmlSignals(wizBlockedHtml);
    expect(wizRes.googleCountryIso2).toBe('RU');
    expect(wizRes.wizGeminiAllowed).toBe(false);
    expect(wizRes.hasUnsupportedBanner).toBe(true);

    // 2. Сценарий пользователя: Подписка 1 («Моя подписка» friedshrimp.xyz — Cloudflare=NL, но Google=RU!) + Подписка 2 («VPNUS» — чистый US)
    const sub1 = parseVpnImportPayload(
      [
        'hysteria2://pass@wolverine.friedshrimp.xyz:4443/?sni=wolverine.friedshrimp.xyz#🇳🇱 Нидерланды 🐇 [HY2]',
        'hysteria2://pass@fi.friedshrimp.xyz:4443/?sni=fi.friedshrimp.xyz#🇫🇮 Финляндия 🐇 [HY2 через РФ]',
      ].join('\n'),
      1,
      'sub_shrimp'
    );
    const sub2 = parseVpnImportPayload(
      'vless://99999999-2222-3333-4444-555555555555@us-clean.vpnus.org:443?security=tls&sni=us-clean.vpnus.org#🇺🇸 США Нью-Йорк (VPNUS)',
      3,
      'sub_vpnus'
    );
    const [fakeNlNode, fakeFiNode] = sub1.nodes;
    const [cleanUsNode] = sub2.nodes;

    // Умная Round-Robin очередь чередует подписки, сразу захватывая VPNUS вторым кандидатом вместо застревания в первой подписке!
    const scanQueue = buildAiScanCandidateQueue({
      nodes: [...sub1.nodes, ...sub2.nodes],
    });
    expect(scanQueue.map((n) => n.id)).toContain(cleanUsNode.id);
    expect(scanQueue.findIndex((n) => n.id === cleanUsNode.id)).toBeLessThanOrEqual(1);

    // Оценка обманчивого NL-сервера: Cloudflare loc=NL и ChatGPT/Grok 200 OK, НО Google sw.js_data = RU -> СТРОГИЙ БЛОК для Gemini!
    evaluateAiProbeResult(
      fakeNlNode,
      {
        reachable: true,
        exitCountry: 'NL',
        googleCountry: 'RU',
        geminiStatus: 200,
        geminiHtmlAllowed: false,
        chatgptStatus: 200,
        grokStatus: 200,
        latencyMs: 48,
      },
      ['gemini', 'chatgpt', 'grok']
    );
    expect(fakeNlNode.aiStatus).toBe('blocked');
    expect(fakeNlNode.aiGeminiOk).toBe(false);
    expect(fakeNlNode.aiExitCountry).toBe('RU');
    expect(fakeNlNode.aiBlockReason).toContain('Google');

    evaluateAiProbeResult(
      fakeFiNode,
      {
        reachable: true,
        exitCountry: 'FI',
        googleCountry: 'RU',
        geminiStatus: 302,
        geminiLocation: 'https://gemini.google.com/faq',
        chatgptStatus: 200,
        grokStatus: 200,
        latencyMs: 52,
      },
      ['gemini', 'chatgpt', 'grok']
    );
    expect(fakeFiNode.aiStatus).toBe('blocked');

    // Чистый US-сервер из подписки VPNUS проходит базу Google (googleCountry: 'US') и получает AI OK!
    evaluateAiProbeResult(
      cleanUsNode,
      {
        reachable: true,
        exitCountry: 'US',
        googleCountry: 'US',
        geminiStatus: 200,
        geminiHtmlAllowed: true,
        chatgptStatus: 200,
        grokStatus: 200,
        latencyMs: 115,
      },
      ['gemini', 'chatgpt', 'grok']
    );
    expect(cleanUsNode.aiStatus).toBe('ok');
    expect(cleanUsNode.aiGeminiOk).toBe(true);
    expect(cleanUsNode.aiExitCountry).toBe('US');

    const chosenAi = pickBestStickyAiNode({
      nodes: [...sub1.nodes, ...sub2.nodes],
      currentAiNodeId: fakeNlNode.id,
      fallbackActiveNodeId: fakeNlNode.id,
    });
    expect(chosenAi?.id).toBe(cleanUsNode.id);

    // 3. Проверка маршрутизации sing-box v3.2:
    // - aiExtraCandidateNodes позволяет proxy-ai использовать cleanUsNode, даже если для основного VPN активна только sub1
    // - UDP:443 на mixed-in отклоняется (перевод клиентского QUIC на TCP 443 для 100% TLS SNI и исключения HTTP/3 утечки)
    // - googlevideo.com / youtube.com идут в быстрый proxy-active СТРОГО ДО того, как весь контур google.com / googleapis.com уходит в proxy-ai!
    const fastMedia = collectFastMediaBypassDomains();
    expect(fastMedia.exactDomains).toContain('googlevideo.com');
    expect(fastMedia.exactDomains).toContain('youtube.com');

    const aiDomains = collectAiRoutingDomains({
      aiRoutingEnabled: true,
      aiServices: ['gemini', 'chatgpt', 'grok'],
      aiIncludeGoogleAccountSession: true,
    });
    expect(aiDomains.exactDomains).toContain('google.com');
    expect(aiDomains.exactDomains).toContain('googleapis.com');
    expect(aiDomains.exactDomains).toContain('embeddedassistant.googleapis.com');
    expect(aiDomains.exactDomains).toContain('footprints-pa.googleapis.com');

    const cfg = buildAndroidEmbeddedSingboxConfig({
      nodes: sub1.nodes,
      aiExtraCandidateNodes: [...sub1.nodes, ...sub2.nodes],
      activeNodeId: fakeNlNode.id,
      activeAiNodeId: cleanUsNode.id,
      settings: DEFAULT_APP_SETTINGS,
    });

    const outbounds = cfg.outbounds as Array<Record<string, unknown>>;
    const proxyActive = outbounds.find((o) => o.tag === 'proxy-active') as { outbounds: string[] };
    const proxyAi = outbounds.find((o) => o.tag === 'proxy-ai') as {
      outbounds: string[];
      default: string;
      interrupt_exist_connections: boolean;
    };
    expect(proxyActive.outbounds).not.toContain(`node-${cleanUsNode.id}`);
    expect(proxyAi.outbounds).toContain(`node-${cleanUsNode.id}`);
    expect(proxyAi.default).toBe(`node-${cleanUsNode.id}`);
    expect(proxyAi.interrupt_exist_connections).toBe(true);

    const routeRules = (cfg.route as { rules: Array<Record<string, unknown>> }).rules;
    const quicRejectIdx = routeRules.findIndex(
      (r) =>
        r.action === 'reject' &&
        Array.isArray(r.network) &&
        r.network.includes('udp') &&
        Array.isArray(r.port) &&
        r.port.includes(443)
    );
    const youtubeFastIdx = routeRules.findIndex(
      (r) =>
        r.outbound === 'proxy-active' &&
        Array.isArray(r.domain) &&
        r.domain.includes('googlevideo.com')
    );
    const aiRouteIdx = routeRules.findIndex(
      (r) =>
        r.outbound === 'proxy-ai' &&
        Array.isArray(r.domain) &&
        r.domain.includes('gemini.google.com')
    );

    expect(quicRejectIdx).toBeGreaterThanOrEqual(0);
    expect(youtubeFastIdx).toBeGreaterThanOrEqual(0);
    expect(aiRouteIdx).toBeGreaterThan(youtubeFastIdx);
  });
});

describe('10. AegisMesh VPN v3.3: Защита мобильного интернета (LTE / 4G / 5G), приоритет LTE и [через РФ] серверов, DNS 77.88.8.8 + prefer_ipv4', () => {
  it('распознаёт LTE и [через РФ] серверы, ставит их в приоритет на мобильной сети и настраивает sing-box с Яндекс DNS (77.88.8.8), prefer_ipv4 и проверкой через gstatic', async () => {
    const {
      buildDiversifiedFailoverBatch,
      isMobileCarrierFriendlyNode,
      rankCandidatesSmart,
    } = await import('../src/shared/smartFailover');
    const { buildAndroidEmbeddedSingboxConfig } = await import(
      '../src/shared/androidSingboxConfig'
    );

    const parsed = parseVpnImportPayload(
      [
        'hysteria2://pass@wolverine.friedshrimp.xyz:4443/?sni=wolverine.friedshrimp.xyz#🇳🇱 Нидерланды 🐇 [HY2]',
        'hysteria2://pass@ru.wolverine.friedshrimp.xyz:5443/?sni=ru.wolverine.friedshrimp.xyz#🇳🇱 Нидерланды 🐇 [HY2 через РФ]',
        'vless://11111111-2222-3333-4444-555555555555@lte-fi.vpnus.org:443?security=reality&sni=yahoo.com&pbk=abc#🇫🇮 LTE #1 (VPNUS)',
      ].join('\n'),
      1,
      'sub_mobile_test'
    );
    const [directNl, relayRuNl, lteFi] = parsed.nodes;
    directNl.subscriptionId = 'sub_1';
    relayRuNl.subscriptionId = 'sub_1';
    lteFi.subscriptionId = 'sub_2';

    // 1. Точное распознавание мобильно-устойчивых узлов (LTE / 4G / через РФ / ru.* / VLESS Reality)
    expect(isMobileCarrierFriendlyNode(directNl)).toBe(false);
    expect(isMobileCarrierFriendlyNode(relayRuNl)).toBe(true);
    expect(isMobileCarrierFriendlyNode(lteFi)).toBe(true);

    // 2. Ранжирование и диверсифицированный батч на мобильной сети (preferMobileFriendly = true)
    // гарантированно ставят LTE #1 и [HY2 через РФ] выше обычного прямого зарубежного узла
    const rankedMobile = rankCandidatesSmart(parsed.nodes, null, Date.now(), true);
    expect(rankedMobile[0].id).not.toBe(directNl.id);
    expect([relayRuNl.id, lteFi.id]).toContain(rankedMobile[0].id);
    expect([relayRuNl.id, lteFi.id]).toContain(rankedMobile[1].id);

    const batchMobile = buildDiversifiedFailoverBatch(parsed.nodes, null, 2, Date.now(), true);
    expect(batchMobile.map((n) => n.id)).toContain(lteFi.id);
    expect(batchMobile.map((n) => n.id)).toContain(relayRuNl.id);

    // 3. Проверка конфигурации sing-box v3.3 для мобильных сетей РФ:
    // - dns.strategy = 'prefer_ipv4' (защита от сломанного IPv6 на LTE)
    // - dns-direct = '77.88.8.8' (Яндекс DNS вместо блокируемого операторами 1.1.1.1:53)
    // - urltest 'auto-failover' использует 'http://connectivitycheck.gstatic.com/generate_204' вместо блокируемого ТСПУ cp.cloudflare.com
    const cfg = buildAndroidEmbeddedSingboxConfig({
      nodes: parsed.nodes,
      activeNodeId: lteFi.id,
      settings: DEFAULT_APP_SETTINGS,
    });
    const dns = cfg.dns as {
      strategy: string;
      servers: Array<Record<string, unknown>>;
    };
    expect(dns.strategy).toBe('prefer_ipv4');
    const dnsDirect = dns.servers.find((s) => s.tag === 'dns-direct');
    expect(dnsDirect?.server).toBe('77.88.8.8');

    const outbounds = cfg.outbounds as Array<Record<string, unknown>>;
    const autoFailover = outbounds.find((o) => o.tag === 'auto-failover');
    expect(autoFailover?.url).toBe('http://connectivitycheck.gstatic.com/generate_204');
  });
});

describe('11. AegisMesh VPN v3.4: Интеллектуальный роуминг Wi-Fi ⇄ LTE, раздельная память лучших серверов по сетям и адаптивный сброс карантина при смене сети', () => {
  it('ведёт раздельный рейтинг Wi-Fi vs LTE, мгновенно выбирает запомненного чемпиона сети при роуминге и снимает карантин прошлой сети', async () => {
    const {
      markNodeTemporarilyUnavailable,
      pickRememberedNetworkChampion,
      rankCandidatesSmart,
      releaseQuarantineForNetworkShift,
      updateNodeSmartMetrics,
    } = await import('../src/shared/smartFailover');

    const parsed = parseVpnImportPayload(
      [
        'hysteria2://pass@wolverine.friedshrimp.xyz:4443/?sni=wolverine.friedshrimp.xyz#🇳🇱 Нидерланды 🐇 [HY2]',
        'vless://11111111-2222-3333-4444-555555555555@lte-fi.vpnus.org:443?security=reality&sni=yahoo.com&pbk=abc#🇫🇮 LTE #1 (VPNUS)',
      ].join('\n'),
      1,
      'sub_roaming_v34'
    );
    const [wifiFastHy2, lteRealityFi] = parsed.nodes;

    // 1. На домашнем Wi-Fi прямой HY2-сервер работает идеально (42 мс), а на LTE падает из-за ТСПУ оператора
    updateNodeSmartMetrics(wifiFastHy2, 42, 45000, 'wifi');
    expect(wifiFastHy2.wifiEmaLatencyMs).toBe(42);
    expect(wifiFastHy2.wifiScore).toBeGreaterThanOrEqual(85);
    expect(wifiFastHy2.lastSuccessNetwork).toBe('wifi');

    // Сбой на LTE ухудшает cellularScore, но НЕ портит домашний wifiScore!
    const savedWifiScore = wifiFastHy2.wifiScore!;
    updateNodeSmartMetrics(wifiFastHy2, null, undefined, 'cellular');
    expect(wifiFastHy2.wifiScore).toBe(savedWifiScore);
    expect(wifiFastHy2.cellularScore).toBeLessThan(savedWifiScore);

    // 2. На LTE отлично работает VLESS Reality (LTE #1)
    updateNodeSmartMetrics(lteRealityFi, 78, 18000, 'cellular');
    expect(lteRealityFi.cellularEmaLatencyMs).toBe(78);
    expect(lteRealityFi.cellularScore).toBeGreaterThanOrEqual(80);
    expect(lteRealityFi.lastSuccessNetwork).toBe('cellular');

    // 3. Выбор запомненного чемпиона для каждой сети (Zero-Drop Handover)
    const now = Date.now();
    const chosenForWifi = pickRememberedNetworkChampion(
      parsed.nodes,
      'wifi',
      wifiFastHy2.id,
      now
    );
    expect(chosenForWifi?.id).toBe(wifiFastHy2.id);

    const chosenForCellular = pickRememberedNetworkChampion(
      parsed.nodes,
      'cellular',
      lteRealityFi.id,
      now
    );
    expect(chosenForCellular?.id).toBe(lteRealityFi.id);

    // При ранжировании на Wi-Fi побеждает прямой HY2, а на LTE — LTE #1 (Reality)
    const rankedOnWifi = rankCandidatesSmart(parsed.nodes, null, now, false);
    expect(rankedOnWifi[0].id).toBe(wifiFastHy2.id);

    const rankedOnCellular = rankCandidatesSmart(parsed.nodes, null, now, true);
    expect(rankedOnCellular[0].id).toBe(lteRealityFi.id);

    // 4. Если узел попал в карантин на Wi-Fi, при переходе на LTE его карантин мгновенно снимается!
    markNodeTemporarilyUnavailable(lteRealityFi, 'Таймаут на домашнем роутере', 45, now, 'wifi');
    expect(lteRealityFi.quarantinedOnNetwork).toBe('wifi');
    expect(lteRealityFi.quarantinedUntil).toBeGreaterThan(now);

    const releasedCount = releaseQuarantineForNetworkShift(parsed.nodes, 'cellular');
    expect(releasedCount).toBe(1);
    expect(lteRealityFi.quarantinedUntil).toBeNull();
    expect(lteRealityFi.consecutiveFailures).toBe(0);
  });
});

describe('12. AegisMesh VPN v3.5 «Адский стресс-стенд»: 240 враждебных серверов (РФ, [через РФ], LTE #1, YouTube-RU, карантин, флаппинг) против ИИ-шлюза и роуминга', () => {
  it('из 240 серверов (237 РФ/релеи/LTE/битые и только 3 чистых в конце списка) безошибочно изолирует proxy-ai от РФ на холодном старте, при сканировании, ручном переборе и шторме Wi-Fi ⇄ LTE', async () => {
    const {
      AI_UNSUPPORTED_COUNTRY_CODES,
      buildAiScanCandidateQueue,
      computeNodeAiRank,
      evaluateAiProbeResult,
      inferCountryHintFromNode,
      isSuspiciousAiCandidateNode,
      pickBestStickyAiNode,
      pickNextAiNodeForManualCycle,
    } = await import('../src/shared/aiRouting');
    const { buildAndroidEmbeddedSingboxConfig } = await import(
      '../src/shared/androidSingboxConfig'
    );
    const { buildDesktopSingboxConfig } = await import('../src/backend/singboxConfig');
    const {
      markNodeTemporarilyUnavailable,
      pickRememberedNetworkChampion,
      releaseExpiredUnavailableNodes,
      releaseQuarantineForNetworkShift,
      updateNodeSmartMetrics,
    } = await import('../src/shared/smartFailover');

    const linesSub1: string[] = [];
    const linesSub2: string[] = [];
    const linesSub3: string[] = [];

    // 1. 60 явно российских и белорусских серверов (с минимальным пингом 12 мс)
    for (let i = 1; i <= 25; i++) {
      linesSub1.push(
        `vless://11111111-1111-1111-1111-111111111111@msk-${i}.provider.ru:443?security=tls&sni=msk-${i}.provider.ru#🇷🇺 Москва Скоростной #${i}`
      );
    }
    for (let i = 1; i <= 20; i++) {
      linesSub1.push(
        `vless://11111111-1111-1111-1111-111111111111@spb-${i}.provider.su:443?security=tls&sni=spb-${i}.provider.su#Россия Санкт-Петербург #${i}`
      );
    }
    for (let i = 1; i <= 15; i++) {
      linesSub1.push(
        `vless://11111111-1111-1111-1111-111111111111@relay-${i}.example.com:443?security=tls#Мост РФ #${i}`
      );
    }

    // 2. 55 обманчивых российских релеев с иностранными флагами 🇳🇱/🇫🇮/🇩🇪 ([HY2 через РФ], [via RU], ru.wolverine...)
    for (let i = 1; i <= 30; i++) {
      linesSub1.push(
        `hysteria2://pass@ru.wolverine-${i}.friedshrimp.xyz:5443/?sni=ru.wolverine.friedshrimp.xyz#🇳🇱 Нидерланды 🐇 [HY2 через РФ] #${i}`
      );
    }
    for (let i = 1; i <= 25; i++) {
      linesSub2.push(
        `hysteria2://pass@ru.nextdump-${i}.friedshrimp.xyz:4443/?sni=ru.nextdump.friedshrimp.xyz#🇫🇮 Финляндия 🐇 [HY2 через РФ] #${i}`
      );
    }

    // 3. 40 мобильных обходных серверов (🇫🇮 LTE #1, Обход МТС/МегаФон/Билайн, Вайт-лист) с иностранными флагами
    for (let i = 1; i <= 25; i++) {
      linesSub2.push(
        `vless://22222222-2222-2222-2222-222222222222@lte-${i}.vpnus.org:443?security=reality&sni=yahoo.com&pbk=abc#🇫🇮 LTE #${i} (VPNUS)`
      );
    }
    for (let i = 1; i <= 15; i++) {
      linesSub2.push(
        `vless://22222222-2222-2222-2222-222222222222@white-${i}.carrier.net:443?security=reality&sni=vk.com&pbk=abc#🇩🇪 4G Обход Вайт #${i}`
      );
    }

    // 4. 30 серверов «YouTube без рекламы» (Cloudflare=NL, но Google=RU!)
    for (let i = 1; i <= 30; i++) {
      linesSub2.push(
        `hysteria2://pass@yt-${i}.friedshrimp.xyz:4443/?sni=yt.friedshrimp.xyz#🇳🇱 Нидерланды YouTube без рекламы #${i}`
      );
    }

    // Чистый сервер №1 спрятан на позиции #186
    linesSub2.push(
      `vless://88888888-1111-2222-3333-444444444441@de-frankfurt-direct.cleanvpn.net:443?security=tls&sni=de-frankfurt-direct.cleanvpn.net#🇩🇪 Германия Франкфурт Direct`
    );

    // 5. 35 мёртвых/карантинных и 17 флаппящих серверов в 3-й подписке
    for (let i = 1; i <= 35; i++) {
      linesSub3.push(
        `vless://33333333-3333-3333-3333-333333333333@dead-${i}.offline.org:443?security=tls#🇬🇧 Лондон Архив #${i}`
      );
    }
    for (let i = 1; i <= 17; i++) {
      linesSub3.push(
        `vless://44444444-4444-4444-4444-444444444444@flap-${i}.via-ru.org:443?security=tls#🇸🇪 Швеция [через РФ] #${i}`
      );
    }

    // Чистые серверы №2 и №3 спрятаны в самом конце (позиции #239 и #240)!
    linesSub3.push(
      `vless://88888888-1111-2222-3333-444444444442@us-nyc-direct.vpnus.org:443?security=tls&sni=us-nyc-direct.vpnus.org#🇺🇸 США Нью-Йорк (VPNUS)`
    );
    linesSub3.push(
      `vless://88888888-1111-2222-3333-444444444443@nl-ams-direct.vpnus.org:443?security=tls&sni=nl-ams-direct.vpnus.org#🇳🇱 Нидерланды Амстердам Direct (VPNUS)`
    );

    const parsed1 = parseVpnImportPayload(linesSub1.join('\n'), 1, 'sub_ru_heavy');
    const parsed2 = parseVpnImportPayload(linesSub2.join('\n'), 100, 'sub_lte_relays');
    const parsed3 = parseVpnImportPayload(linesSub3.join('\n'), 200, 'sub_vpnus_mixed');

    const allNodes = [...parsed1.nodes, ...parsed2.nodes, ...parsed3.nodes];
    expect(allNodes.length).toBe(240);

    const cleanNames = new Set([
      '🇩🇪 Германия Франкфурт Direct',
      '🇺🇸 США Нью-Йорк (VPNUS)',
      '🇳🇱 Нидерланды Амстердам Direct (VPNUS)',
    ]);
    const cleanNodes = allNodes.filter((n) => cleanNames.has(n.name));
    expect(cleanNodes.length).toBe(3);
    const cleanIds = new Set(cleanNodes.map((n) => n.id));

    const now = 1_000_000;
    // Задаём провокационные метрики:
    // - всем РФ, [через РФ] и LTE серверам ставим сверхнизкий пинг 12–18 мс и высокий smartScore = 98!
    // - чистым серверам US/DE/NL ставим реальный трансатлантический/европейский пинг 115–145 мс и smartScore = 76!
    // - 35 архивным серверам ставим карантин
    for (const node of allNodes) {
      if (node.name.includes('Архив')) {
        markNodeTemporarilyUnavailable(node, 'Connection refused', 60, now, 'wifi');
      } else if (cleanIds.has(node.id)) {
        node.latencyMs = 128;
        node.emaLatencyMs = 128;
        node.smartScore = 76;
      } else {
        node.latencyMs = 14;
        node.emaLatencyMs = 14;
        node.smartScore = 98;
      }
    }

    // ЭТАП 1: Криминалистика распознавания стран и подозрительных релеев
    const mskNode = allNodes.find((n) => n.name.includes('Москва Скоростной #1'))!;
    const spbNode = allNodes.find((n) => n.name.includes('Санкт-Петербург #1'))!;
    const bridgeRuNode = allNodes.find((n) => n.name.includes('Мост РФ #1'))!;
    const relayNlViaRu = allNodes.find((n) => n.name.includes('[HY2 через РФ] #1'))!;
    const lteFiNode = allNodes.find((n) => n.name.includes('🇫🇮 LTE #1'))!;
    const ytNoAdsNode = allNodes.find((n) => n.name.includes('YouTube без рекламы #1'))!;

    expect(inferCountryHintFromNode(mskNode)).toBe('RU');
    expect(inferCountryHintFromNode(spbNode)).toBe('RU');
    expect(inferCountryHintFromNode(bridgeRuNode)).toBe('RU');
    expect(AI_UNSUPPORTED_COUNTRY_CODES.has(inferCountryHintFromNode(mskNode)!)).toBe(true);
    expect(AI_UNSUPPORTED_COUNTRY_CODES.has(inferCountryHintFromNode(bridgeRuNode)!)).toBe(true);

    expect(isSuspiciousAiCandidateNode(relayNlViaRu)).toBe(true);
    expect(isSuspiciousAiCandidateNode(lteFiNode)).toBe(true);
    expect(isSuspiciousAiCandidateNode(ytNoAdsNode)).toBe(true);
    for (const clean of cleanNodes) {
      expect(isSuspiciousAiCandidateNode(clean)).toBe(false);
      expect(computeNodeAiRank(clean)).toBeGreaterThan(computeNodeAiRank(relayNlViaRu));
      expect(computeNodeAiRank(clean)).toBeGreaterThan(computeNodeAiRank(lteFiNode));
      expect(computeNodeAiRank(clean)).toBeGreaterThan(computeNodeAiRank(mskNode));
    }

    // ЭТАП 2: Холодный старт (0 проверенных узлов!) при активном российском или LTE-сервере в основном VPN
    // Даже когда основной VPN подключён к «🇷🇺 Москва Скоростной #1» или «🇫🇮 LTE #1 (14 мс)»,
    // шлюз ИИ обязан МГНОВЕННО выбрать один из 3 чистых зарубежных серверов (позиции #186, #239, #240)!
    const coldStartPicked = pickBestStickyAiNode({
      nodes: allNodes,
      currentAiNodeId: relayNlViaRu.id, // даже если с прошлого запуска залип релей [через РФ]!
      preferredAiNodeId: mskNode.id, // даже если в настройках ошибочно сохранён РФ-узел!
      fallbackActiveNodeId: mskNode.id,
    });
    expect(coldStartPicked).not.toBeNull();
    expect(cleanIds.has(coldStartPicked!.id)).toBe(true);

    // Проверяем генерацию конфига sing-box (Android + Desktop) на холодном старте, когда передан ошибочный activeAiNodeId = РФ
    const androidCfgCold = buildAndroidEmbeddedSingboxConfig({
      nodes: parsed1.nodes, // в основной подписке ТОЛЬКО РФ и [через РФ]!
      aiExtraCandidateNodes: allNodes,
      activeNodeId: mskNode.id,
      activeAiNodeId: mskNode.id, // провокация: передаём РФ-сервер как activeAiNodeId
      settings: DEFAULT_APP_SETTINGS,
    });
    const outboundsCold = androidCfgCold.outbounds as Array<Record<string, unknown>>;
    const proxyAiCold = outboundsCold.find((o) => o.tag === 'proxy-ai') as {
      default: string;
      outbounds: string[];
    };
    expect(cleanIds.has(proxyAiCold.default.replace(/^node-/, ''))).toBe(true);
    expect(proxyAiCold.outbounds).not.toContain('auto-failover');
    // Первыми в списке proxy-ai.outbounds идут чистые серверы, а не РФ
    expect(cleanIds.has(proxyAiCold.outbounds[0].replace(/^node-/, ''))).toBe(true);

    // ЭТАП 3: Проверка отсутствия DNS-утечки на тестовом порту ai-probe-in (127.0.0.1:20809)
    const dnsCold = androidCfgCold.dns as {
      servers: Array<Record<string, unknown>>;
      rules: Array<Record<string, unknown>>;
    };
    const dnsAiProbeServer = dnsCold.servers.find((s) => s.tag === 'dns-ai-probe');
    expect(dnsAiProbeServer).toBeDefined();
    expect(dnsAiProbeServer?.detour).toBe('proxy-ai-probe');
    // Правило для ai-probe-in ОБЯЗАНО стоять под индексом 0 (раньше правила youtube.com -> dns-remote)!
    expect(dnsCold.rules[0]).toEqual({
      inbound: ['ai-probe-in'],
      server: 'dns-ai-probe',
    });

    const desktopCfgCold = buildDesktopSingboxConfig({
      nodes: allNodes,
      activeNodeId: mskNode.id,
      activeAiNodeId: relayNlViaRu.id,
      settings: DEFAULT_APP_SETTINGS,
      internalMixedPort: 20808,
      clashApiPort: 20810,
      clashApiSecret: 'test-secret',
      aiProbePort: 20809,
      enableTun: false,
    });
    const desktopDns = desktopCfgCold.dns as { rules: Array<Record<string, unknown>> };
    expect(desktopDns.rules[0]).toEqual({
      inbound: ['ai-probe-in'],
      server: 'dns-ai-probe',
    });

    // ЭТАП 4: Очередь ИИ-сканера (buildAiScanCandidateQueue) на 240 серверах
    // Все 3 чистых сервера обязаны попасть в ТОП-5 очереди сканирования, несмотря на 237 мусорных узлов перед ними!
    const scanQueue = buildAiScanCandidateQueue({
      nodes: allNodes,
      currentAiNodeId: relayNlViaRu.id,
      preferredAiNodeId: mskNode.id,
    });
    const top5Ids = new Set(scanQueue.slice(0, 5).map((n) => n.id));
    for (const clean of cleanNodes) {
      expect(top5Ids.has(clean.id)).toBe(true);
    }
    // Ни один явно российский или карантинный сервер не должен засорять очередь сканера
    expect(scanQueue.some((n) => inferCountryHintFromNode(n) === 'RU')).toBe(false);
    expect(scanQueue.some((n) => n.status === 'quarantined')).toBe(false);

    // ЭТАП 5: Жёсткая проверка evaluateAiProbeResult против обманчивых ответов ТСПУ и релеев
    // 5.1. Релей [HY2 через РФ]: YouTube sw.js_data отвалился по таймауту (googleCountry = null), а gemini.google.com вернул 302 редирект -> БЛОК!
    evaluateAiProbeResult(
      relayNlViaRu,
      {
        reachable: true,
        exitCountry: null,
        googleCountry: null,
        geminiStatus: 302,
        geminiLocation: 'https://accounts.google.com/ServiceLogin',
        chatgptStatus: 200,
        grokStatus: 200,
        latencyMs: 15,
      },
      ['gemini', 'chatgpt', 'grok']
    );
    expect(relayNlViaRu.aiStatus).toBe('blocked');

    // 5.2. Мобильный LTE #1 с финским флагом: вернул 200 на прокси-страницу, но googleCountry не подтверждён (null) -> БЛОК!
    evaluateAiProbeResult(
      lteFiNode,
      {
        reachable: true,
        exitCountry: 'FI',
        googleCountry: null,
        geminiStatus: 200,
        chatgptStatus: 200,
        grokStatus: 200,
        latencyMs: 18,
      },
      ['gemini', 'chatgpt', 'grok']
    );
    expect(lteFiNode.aiStatus).toBe('blocked');

    // 5.3. Сервер «YouTube без рекламы»: Cloudflare видит NL, но Google видит RU -> БЛОК!
    evaluateAiProbeResult(
      ytNoAdsNode,
      {
        reachable: true,
        exitCountry: 'NL',
        googleCountry: 'RU',
        geminiStatus: 200,
        chatgptStatus: 200,
        grokStatus: 200,
        latencyMs: 22,
      },
      ['gemini', 'chatgpt', 'grok']
    );
    expect(ytNoAdsNode.aiStatus).toBe('blocked');

    // 5.4. Три чистых сервера проходят полную проверку Google (DE, US, NL) -> ОК!
    const cleanCountries: Record<string, string> = {
      '🇩🇪 Германия Франкфурт Direct': 'DE',
      '🇺🇸 США Нью-Йорк (VPNUS)': 'US',
      '🇳🇱 Нидерланды Амстердам Direct (VPNUS)': 'NL',
    };
    for (const clean of cleanNodes) {
      const cc = cleanCountries[clean.name];
      evaluateAiProbeResult(
        clean,
        {
          reachable: true,
          exitCountry: cc,
          googleCountry: cc,
          geminiStatus: 200,
          geminiHtmlAllowed: true,
          chatgptStatus: 200,
          grokStatus: 200,
          latencyMs: 120,
        },
        ['gemini', 'chatgpt', 'grok']
      );
      expect(clean.aiStatus).toBe('ok');
    }

    // ЭТАП 6: 50 нажатий подряд «Сменить ИИ-сервер» (pickNextAiNodeForManualCycle)
    // Вращение происходит ТОЛЬКО между 3 проверенными чистыми серверами, ни разу не попадая на 237 российских/LTE/релейных!
    let currentAiId: string | null = cleanNodes[0].id;
    const visitedCleanIds = new Set<string>();
    for (let click = 0; click < 50; click++) {
      const nextNode = pickNextAiNodeForManualCycle(allNodes, currentAiId);
      expect(nextNode).not.toBeNull();
      expect(cleanIds.has(nextNode!.id)).toBe(true);
      expect(nextNode!.id).not.toBe(currentAiId);
      visitedCleanIds.add(nextNode!.id);
      currentAiId = nextNode!.id;
    }
    expect(visitedCleanIds.size).toBe(3);

    // ЭТАП 7: Шторм переключений физической сети (10 циклов Wi-Fi ⇄ LTE + Mass-Offline Guard)
    updateNodeSmartMetrics(relayNlViaRu, 16, 55000, 'wifi');
    updateNodeSmartMetrics(lteFiNode, 24, 28000, 'cellular');

    for (let cycle = 0; cycle < 10; cycle++) {
      const netType = cycle % 2 === 0 ? 'cellular' : 'wifi';
      releaseQuarantineForNetworkShift(allNodes, netType);
      const mainChamp = pickRememberedNetworkChampion(allNodes, netType, null, now + cycle * 1000);
      expect(mainChamp).not.toBeNull();
      // Основной VPN на LTE выбирает LTE #1, а на Wi-Fi — быстрый HY2
      expect(mainChamp!.id).toBe(netType === 'cellular' ? lteFiNode.id : relayNlViaRu.id);

      // При этом ИИ-шлюз (proxy-ai) при любом основном сервере остаётся на 100% привязан к чистому US/DE/NL серверу!
      const stickyAi = pickBestStickyAiNode({
        nodes: allNodes,
        currentAiNodeId: currentAiId,
        fallbackActiveNodeId: mainChamp!.id,
      });
      expect(stickyAi).not.toBeNull();
      expect(cleanIds.has(stickyAi!.id)).toBe(true);
    }

    // Проверяем Mass-Offline Guard на 240 серверах (если при падении базовой станции все 240 узлов ушли в карантин — система мгновенно возвращает их в строй)
    for (const node of allNodes) {
      markNodeTemporarilyUnavailable(node, 'Обрыв радиоканала', 45, now + 50_000, 'cellular');
    }
    const massRecovered = releaseExpiredUnavailableNodes(allNodes, now + 51_000, true);
    expect(massRecovered).toBe(240);
  });
});
