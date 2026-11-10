// Криптографическое сейф-хранилище ключей и настроек (AES-256-GCM + scrypt)
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type {
  AppSettings,
  ExternalVpnClientBridge,
  SubscriptionSource,
  VpnNode,
} from '../shared/types';
import { isSyntheticDummyNode } from '../shared/subscriptionMeta';

export interface VaultPlainData {
  nodes: VpnNode[];
  subscriptions: SubscriptionSource[];
  settings: AppSettings;
  manualGroupEnabledInFailover?: boolean;
  externalClients?: ExternalVpnClientBridge[];
  deviceHwid?: string;
}

interface EncryptedVaultEnvelope {
  version: 1;
  hasPin: boolean;
  saltHex: string;
  ivHex: string;
  authTagHex: string;
  ciphertextBase64: string;
}

export const DEFAULT_APP_SETTINGS: AppSettings = {
  failoverMode: 'smart_fastest',
  healthCheckIntervalSec: 6,
  maxLatencyThresholdMs: 1400,
  failureThreshold: 2,
  quarantineDurationSec: 30,
  killSwitchEnabled: true,
  connectionMode: 'proxy_only',
  localProxyPort: 10808,
  allowLanGateway: false,
  dnsProvider: 'cloudflare',
  customDohUrl: 'https://1.1.1.1/dns-query',
  blockAdsAndTrackers: true,
  splitTunnelingEnabled: true,
  bypassDomains: [
    'localhost',
    '*.local',
    'gosuslugi.ru',
    'egov.kz',
    'kaspi.kz',
    'sberbank.ru',
    'tbank.ru',
  ],
  bypassPrivateLan: true,
  perAppMode: 'all',
  perAppPackages: [],
  autoRefreshSubscriptions: true,
  defaultAutoUpdateHours: 12,
  speedFailoverEnabled: true,
  minThroughputKbps: 350,
  zombieCheckEnabled: true,
  antiFlapEnabled: true,
  aiRoutingEnabled: true,
  aiRoutingMode: 'parallel_ai_tunnel',
  aiServices: ['gemini', 'chatgpt', 'grok', 'claude_other'],
  aiIncludeGoogleAccountSession: true,
  aiIncludeXForGrok: false,
  aiCustomDomains: [],
  preferredAiNodeId: null,
  seamlessRoamingEnabled: true,
  networkProfileAutoSwitchEnabled: true,
  bestWifiNodeId: null,
  bestCellularNodeId: null,
  adaptiveMobileMtu: true,
};

export class SecureVault {
  private readonly vaultDir: string;
  private readonly vaultFile: string;
  private readonly machineSecretFile: string;
  private activePin: string | null = null;
  private hasPinConfigured = false;
  private locked = false;

  constructor(storageDir: string) {
    this.vaultDir = storageDir;
    this.vaultFile = path.join(storageDir, 'vault.enc.json');
    this.machineSecretFile = path.join(storageDir, 'device.key');
    fs.mkdirSync(this.vaultDir, { recursive: true });
    this.inspectEnvelopeMeta();
  }

  private getOrCreateMachineSecret(): string {
    if (fs.existsSync(this.machineSecretFile)) {
      return fs.readFileSync(this.machineSecretFile, 'utf-8').trim();
    }
    const randomKey = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(this.machineSecretFile, randomKey, { encoding: 'utf-8', mode: 0o600 });
    return randomKey;
  }

  private deriveKey(salt: Buffer, pin: string | null): Buffer {
    const machineKey = this.getOrCreateMachineSecret();
    const userContext = `${os.hostname()}::${os.userInfo().username}`;
    const secretMaterial = `${machineKey}::${userContext}::${pin ?? 'NO_PIN'}`;
    return crypto.scryptSync(secretMaterial, salt, 32, { N: 16384, r: 8, p: 1 });
  }

  private inspectEnvelopeMeta(): void {
    if (!fs.existsSync(this.vaultFile)) {
      this.hasPinConfigured = false;
      this.locked = false;
      return;
    }
    try {
      const raw = JSON.parse(fs.readFileSync(this.vaultFile, 'utf-8')) as EncryptedVaultEnvelope;
      this.hasPinConfigured = Boolean(raw.hasPin);
      this.locked = this.hasPinConfigured && this.activePin === null;
    } catch {
      this.hasPinConfigured = false;
      this.locked = false;
    }
  }

  public isLocked(): boolean {
    return this.locked;
  }

  public hasPin(): boolean {
    return this.hasPinConfigured;
  }

  // Разблокировка сейфа с помощью пользовательского PIN/мастер-пароля
  public unlock(pin: string): VaultPlainData {
    if (!fs.existsSync(this.vaultFile)) {
      this.activePin = pin;
      this.locked = false;
      return this.getDefaultData();
    }
    const envelope = JSON.parse(
      fs.readFileSync(this.vaultFile, 'utf-8')
    ) as EncryptedVaultEnvelope;
    const decrypted = this.decryptEnvelope(envelope, pin);
    this.activePin = pin;
    this.locked = false;
    return decrypted;
  }

  // Установка или снятие PIN-кода с немедленным перешифрованием сейфа
  public setPin(newPin: string | null, currentData: VaultPlainData): void {
    const cleanPin = newPin && newPin.trim().length > 0 ? newPin.trim() : null;
    this.activePin = cleanPin;
    this.hasPinConfigured = cleanPin !== null;
    this.locked = false;
    this.save(currentData);
  }

  public lock(): void {
    if (this.hasPinConfigured) {
      this.activePin = null;
      this.locked = true;
    }
  }

  public getDefaultData(): VaultPlainData {
    return {
      nodes: [],
      subscriptions: [],
      settings: {
        ...DEFAULT_APP_SETTINGS,
        bypassDomains: [...DEFAULT_APP_SETTINGS.bypassDomains],
      },
    };
  }

  public load(): VaultPlainData {
    if (!fs.existsSync(this.vaultFile)) {
      const initial = this.getDefaultData();
      this.save(initial);
      return initial;
    }

    const envelope = JSON.parse(
      fs.readFileSync(this.vaultFile, 'utf-8')
    ) as EncryptedVaultEnvelope;

    if (envelope.hasPin && this.activePin === null) {
      this.hasPinConfigured = true;
      this.locked = true;
      throw new Error('VAULT_LOCKED: Сейф защищён PIN-кодом. Разблокируйте его для доступа.');
    }

    return this.decryptEnvelope(envelope, envelope.hasPin ? this.activePin : null);
  }

  private decryptEnvelope(
    envelope: EncryptedVaultEnvelope,
    pin: string | null
  ): VaultPlainData {
    const salt = Buffer.from(envelope.saltHex, 'hex');
    const iv = Buffer.from(envelope.ivHex, 'hex');
    const authTag = Buffer.from(envelope.authTagHex, 'hex');
    const ciphertext = Buffer.from(envelope.ciphertextBase64, 'base64');

    const key = this.deriveKey(salt, pin);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    let decrypted: Buffer;
    try {
      decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      throw new Error('Неверный PIN-код или повреждена целостность зашифрованного сейфа');
    }

    const parsed = JSON.parse(decrypted.toString('utf-8')) as Partial<VaultPlainData>;
    const sanitizedNodes = (parsed.nodes ?? [])
      .filter((n) => !n.isExternalClientBridge && !isSyntheticDummyNode(n))
      .map((n, index) => ({
        ...n,
        priority: typeof n.priority === 'number' ? n.priority : index + 1,
        status: 'idle' as const,
        consecutiveFailures: 0,
        quarantinedUntil: null,
      }));

    return {
      nodes: sanitizedNodes,
      subscriptions: parsed.subscriptions ?? [],
      settings: {
        ...DEFAULT_APP_SETTINGS,
        ...(parsed.settings ?? {}),
      },
      manualGroupEnabledInFailover:
        parsed.manualGroupEnabledInFailover !== undefined
          ? Boolean(parsed.manualGroupEnabledInFailover)
          : true,
      externalClients: Array.isArray(parsed.externalClients)
        ? parsed.externalClients
        : undefined,
      deviceHwid: parsed.deviceHwid,
    };
  }

  public save(data: VaultPlainData): void {
    if (this.locked) {
      throw new Error('Невозможно сохранить данные, пока сейф заблокирован');
    }

    // Не сохраняем временные узлы тестового стенда, виртуальные мосты и 0.0.0.0:1 заглушки на диск
    const persistentData: VaultPlainData = {
      nodes: data.nodes
        .filter((n) => !n.isTestStand && !n.isExternalClientBridge && !isSyntheticDummyNode(n))
        .map((n) => ({
          ...n,
          status: 'idle',
          consecutiveFailures: 0,
          quarantinedUntil: null,
        })),
      subscriptions: data.subscriptions,
      settings: data.settings,
      manualGroupEnabledInFailover: data.manualGroupEnabledInFailover ?? true,
      externalClients: data.externalClients,
      deviceHwid: data.deviceHwid,
    };

    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const pinToUse = this.hasPinConfigured ? this.activePin : null;
    const key = this.deriveKey(salt, pinToUse);

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const plaintext = Buffer.from(JSON.stringify(persistentData), 'utf-8');
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const envelope: EncryptedVaultEnvelope = {
      version: 1,
      hasPin: this.hasPinConfigured,
      saltHex: salt.toString('hex'),
      ivHex: iv.toString('hex'),
      authTagHex: authTag.toString('hex'),
      ciphertextBase64: ciphertext.toString('base64'),
    };

    const tmpFile = `${this.vaultFile}.tmp`;
    fs.writeFileSync(tmpFile, JSON.stringify(envelope, null, 2), {
      encoding: 'utf-8',
      mode: 0o600,
    });
    fs.renameSync(tmpFile, this.vaultFile);
  }
}
