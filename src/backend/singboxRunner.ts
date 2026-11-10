// Менеджер дочернего процесса sing-box и горячего переключения узлов через Clash API
import { spawn, type ChildProcess } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import type { AppSettings, VpnNode } from '../shared/types';
import { buildDesktopSingboxConfig } from './singboxConfig';

export function allocateFreeTcpPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

export class SingboxProcessRunner {
  private proc: ChildProcess | null = null;
  private internalMixedPort = 0;
  private aiProbePort = 0;
  private clashApiPort = 0;
  private readonly clashSecret = crypto.randomBytes(12).toString('hex');
  private readonly runtimeDir: string;

  constructor(storageRootDir: string) {
    this.runtimeDir = path.join(storageRootDir, 'runtime');
    fs.mkdirSync(this.runtimeDir, { recursive: true });
  }

  public isRunning(): boolean {
    return this.proc !== null && this.proc.exitCode === null && !this.proc.killed;
  }

  public getInternalMixedPort(): number {
    return this.internalMixedPort;
  }

  public getAiProbePort(): number {
    return this.aiProbePort;
  }

  public async start(params: {
    binaryPath: string;
    nodes: VpnNode[];
    activeNodeId: string;
    activeAiNodeId?: string | null;
    settings: AppSettings;
    enableTun: boolean;
    onCrash?: (reason: string) => void;
  }): Promise<number> {
    await this.stop();

    this.internalMixedPort = await allocateFreeTcpPort();
    this.aiProbePort = await allocateFreeTcpPort();
    this.clashApiPort = await allocateFreeTcpPort();

    const cfg = buildDesktopSingboxConfig({
      nodes: params.nodes,
      activeNodeId: params.activeNodeId,
      activeAiNodeId: params.activeAiNodeId,
      settings: params.settings,
      internalMixedPort: this.internalMixedPort,
      aiProbePort: this.aiProbePort,
      clashApiPort: this.clashApiPort,
      clashApiSecret: this.clashSecret,
      enableTun: params.enableTun,
    });

    const configPath = path.join(this.runtimeDir, 'active-singbox.json');
    fs.writeFileSync(configPath, JSON.stringify(cfg, null, 2), {
      encoding: 'utf-8',
      mode: 0o600,
    });

    const child = spawn(params.binaryPath, ['run', '-c', configPath], {
      cwd: this.runtimeDir,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    this.proc = child;
    let stderrTail = '';

    child.stderr?.on('data', (chunk: Buffer) => {
      stderrTail = `${stderrTail}${chunk.toString('utf-8')}`.slice(-800);
    });

    child.once('exit', (code) => {
      if (this.proc === child) {
        this.proc = null;
        params.onCrash?.(
          `Процесс sing-box завершился (код ${code ?? 'null'}): ${stderrTail.trim()}`
        );
      }
    });

    // Ожидаем открытия локального порта mixed-in
    const ready = await this.waitForLocalPort(this.internalMixedPort, 4000);
    if (!ready) {
      await this.stop();
      throw new Error(
        `Не удалось запустить туннель sing-box: ${stderrTail.trim() || 'порт не открылся'}`
      );
    }

    return this.internalMixedPort;
  }

  public async switchSelectorOutbound(
    selectorGroup: 'proxy-active' | 'proxy-ai' | 'proxy-ai-probe',
    nodeId: string
  ): Promise<boolean> {
    if (!this.isRunning() || !this.clashApiPort) return false;
    const targetTag = `node-${nodeId}`;
    const body = JSON.stringify({ name: targetTag });

    return new Promise((resolve) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port: this.clashApiPort,
          path: `/proxies/${encodeURIComponent(selectorGroup)}`,
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body),
            Authorization: `Bearer ${this.clashSecret}`,
          },
          timeout: 2500,
        },
        (res) => {
          res.resume();
          resolve(res.statusCode === 204 || res.statusCode === 200);
        }
      );
      req.on('error', () => resolve(false));
      req.on('timeout', () => {
        req.destroy();
        resolve(false);
      });
      req.write(body);
      req.end();
    });
  }

  public async switchActiveOutbound(nodeId: string): Promise<boolean> {
    return this.switchSelectorOutbound('proxy-active', nodeId);
  }

  // Сквозная проверка любого узла (включая UDP/QUIC Hysteria2, TUIC и WireGuard) через Clash API ядра sing-box
  public async probeOutboundDelay(
    nodeId: string,
    timeoutMs = 3500
  ): Promise<number | null> {
    if (!this.isRunning() || !this.clashApiPort) return null;
    const targetTag = `node-${nodeId}`;
    const testUrl = encodeURIComponent('http://cp.cloudflare.com/generate_204');
    const cleanTimeout = Math.max(800, Math.round(timeoutMs));

    return new Promise((resolve) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port: this.clashApiPort,
          path: `/proxies/${encodeURIComponent(targetTag)}/delay?url=${testUrl}&timeout=${cleanTimeout}`,
          method: 'GET',
          headers: {
            Accept: 'application/json',
            Authorization: `Bearer ${this.clashSecret}`,
          },
          timeout: cleanTimeout + 600,
        },
        (res) => {
          let raw = '';
          res.setEncoding('utf-8');
          res.on('data', (chunk) => {
            raw += chunk;
          });
          res.on('end', () => {
            try {
              const parsed = JSON.parse(raw) as { delay?: number };
              if (res.statusCode === 200 && typeof parsed.delay === 'number' && parsed.delay > 0) {
                resolve(Math.round(parsed.delay));
                return;
              }
            } catch {
              // Игнорируем ошибку JSON
            }
            resolve(null);
          });
        }
      );
      req.on('error', () => resolve(null));
      req.on('timeout', () => {
        req.destroy();
        resolve(null);
      });
      req.end();
    });
  }

  public async stop(): Promise<void> {
    if (!this.proc) return;
    const child = this.proc;
    this.proc = null;
    this.internalMixedPort = 0;

    if (child.exitCode === null && !child.killed) {
      child.kill();
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          try {
            child.kill('SIGKILL');
          } catch {
            // Игнорируем
          }
          resolve();
        }, 1200);
        child.once('exit', () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
  }

  private async waitForLocalPort(port: number, timeoutMs: number): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (!this.isRunning()) return false;
      const open = await new Promise<boolean>((resolve) => {
        const s = net.connect(port, '127.0.0.1');
        s.setTimeout(300);
        s.once('connect', () => {
          s.destroy();
          resolve(true);
        });
        s.once('error', () => {
          s.destroy();
          resolve(false);
        });
        s.once('timeout', () => {
          s.destroy();
          resolve(false);
        });
      });
      if (open) return true;
      await new Promise((r) => setTimeout(r, 120));
    }
    return false;
  }
}
