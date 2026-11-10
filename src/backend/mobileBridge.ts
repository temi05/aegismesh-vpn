// Мобильный мост (iOS / Android): генерация автономного профиля с Auto-Failover и LAN Wi-Fi пульта
import crypto from 'node:crypto';
import os from 'node:os';
import type { AppSettings, MobileAccessInfo, VpnNode } from '../shared/types';
import { buildMobileAutonomousSingboxProfile } from './singboxConfig';

export function detectLanIpv4(): string {
  const nets = os.networkInterfaces();
  const candidates: string[] = [];

  for (const [ifName, list] of Object.entries(nets)) {
    if (!list) continue;
    const lowerName = ifName.toLowerCase();
    // Пропускаем виртуальные интерфейсы TUN, WSL, Docker и Hyper-V
    if (
      lowerName.includes('aegismeshtunnel') ||
      lowerName.includes('tun') ||
      lowerName.includes('wsl') ||
      lowerName.includes('vethernet') ||
      lowerName.includes('docker') ||
      lowerName.includes('loopback')
    ) {
      continue;
    }

    for (const addr of list) {
      if (addr.family === 'IPv4' && !addr.internal) {
        if (addr.address.startsWith('192.168.') || addr.address.startsWith('10.')) {
          return addr.address;
        }
        candidates.push(addr.address);
      }
    }
  }

  return candidates[0] || '127.0.0.1';
}

export class MobileBridgeManager {
  private accessToken: string;

  constructor() {
    this.accessToken = crypto.randomBytes(12).toString('hex');
  }

  public getAccessToken(): string {
    return this.accessToken;
  }

  public rotateAccessToken(): string {
    this.accessToken = crypto.randomBytes(12).toString('hex');
    return this.accessToken;
  }

  public validateToken(token?: string | null): boolean {
    if (!token) return false;
    const a = Buffer.from(token);
    const b = Buffer.from(this.accessToken);
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }

  public buildMobileAccessInfo(params: {
    nodes: VpnNode[];
    settings: AppSettings;
    apiServerPort: number;
  }): MobileAccessInfo {
    const lanIp = detectLanIpv4();
    const usableNodes = params.nodes.filter((n) => n.enabled && !n.isTestStand);
    const profileObj = buildMobileAutonomousSingboxProfile(params.nodes, params.settings);
    const singboxProfileJson = JSON.stringify(profileObj, null, 2);

    const remoteProfileUrl = `http://${lanIp}:${params.apiServerPort}/api/mobile/singbox-profile.json?token=${this.accessToken}`;
    const singboxDeepLink = `sing-box://import-remote-profile?url=${encodeURIComponent(
      remoteProfileUrl
    )}#AegisMesh_AutoFailover`;

    const remoteWebUrl = `http://${lanIp}:${params.apiServerPort}/?token=${this.accessToken}`;
    const lanProxyAddress = `${lanIp}:${params.settings.localProxyPort}`;

    return {
      lanIp,
      remoteWebUrl,
      lanProxyAddress,
      accessToken: this.accessToken,
      singboxProfileJson,
      singboxDeepLink,
      nodeCount: usableNodes.length,
    };
  }
}
