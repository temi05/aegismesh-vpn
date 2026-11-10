// HTTP API сервер для управления движком из браузера, мобильного Wi-Fi пульта и раздачи sing-box профиля по QR
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import type { AppSettings } from '../shared/types';
import type { VpnEngine } from './vpnEngine';

export class LocalApiServer {
  private server: http.Server | null = null;
  private boundPort = 18940;
  private readonly engine: VpnEngine;
  private readonly staticDistDir?: string;

  constructor(engine: VpnEngine, staticDistDir?: string) {
    this.engine = engine;
    this.staticDistDir = staticDistDir;
  }

  public getPort(): number {
    return this.boundPort;
  }

  public async start(preferredPort = 18940): Promise<number> {
    if (this.server && this.server.listening) return this.boundPort;

    return new Promise((resolve) => {
      const srv = http.createServer((req, res) => {
        void this.handleRequest(req, res);
      });

      const tryListen = (portToTry: number) => {
        srv.once('error', () => {
          tryListen(0);
        });
        srv.listen(portToTry, '0.0.0.0', () => {
          this.server = srv;
          const addr = srv.address();
          this.boundPort =
            typeof addr === 'object' && addr ? addr.port : preferredPort;
          this.engine.setApiServerPort(this.boundPort);
          resolve(this.boundPort);
        });
      };

      tryListen(preferredPort);
    });
  }

  public async stop(): Promise<void> {
    if (!this.server) return;
    const srv = this.server;
    this.server = null;
    await new Promise<void>((res) => srv.close(() => res()));
  }

  private sendJson(res: http.ServerResponse, status: number, payload: unknown): void {
    const body = JSON.stringify(payload);
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Aegis-Token',
    });
    res.end(body);
  }

  private readJsonBody<T>(req: http.IncomingMessage): Promise<T> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf-8').trim();
        if (!raw) {
          resolve({} as T);
          return;
        }
        try {
          resolve(JSON.parse(raw) as T);
        } catch (e) {
          reject(e);
        }
      });
      req.on('error', reject);
    });
  }

  private isLocalhostRequest(req: http.IncomingMessage): boolean {
    const remote = req.socket.remoteAddress || '';
    return (
      remote === '127.0.0.1' ||
      remote === '::1' ||
      remote === '::ffff:127.0.0.1'
    );
  }

  private async handleRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse
  ): Promise<void> {
    if (req.method === 'OPTIONS') {
      this.sendJson(res, 200, { ok: true });
      return;
    }

    const parsedUrl = new URL(req.url || '/', 'http://127.0.0.1');
    const pathname = parsedUrl.pathname;

    // Раздача готового автономного мобильного профиля sing-box по QR-ссылке
    if (pathname === '/api/mobile/singbox-profile.json') {
      const token = parsedUrl.searchParams.get('token');
      if (!this.isLocalhostRequest(req) && !this.engine.validateMobileToken(token)) {
        this.sendJson(res, 403, { error: 'Неверный токен доступа мобильного профиля' });
        return;
      }
      const info = this.engine.getMobileAccessInfo();
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': 'attachment; filename="aegismesh-mobile-failover.json"',
      });
      res.end(info.singboxProfileJson);
      return;
    }

    if (pathname.startsWith('/api/')) {
      // Для внешних запросов по Wi-Fi проверяем токен безопасности
      const headerToken = String(req.headers['x-aegis-token'] || '');
      const queryToken = parsedUrl.searchParams.get('token') || '';
      if (
        !this.isLocalhostRequest(req) &&
        !this.engine.validateMobileToken(headerToken || queryToken)
      ) {
        this.sendJson(res, 401, {
          error: 'Требуется токен авторизации Мобильного пульта (отсканируйте QR-код на ПК)',
        });
        return;
      }

      try {
        if (pathname === '/api/state' && req.method === 'GET') {
          this.sendJson(res, 200, this.engine.getSnapshot());
          return;
        }
        if (pathname === '/api/mobile-info' && req.method === 'GET') {
          this.sendJson(res, 200, this.engine.getMobileAccessInfo());
          return;
        }
        if (pathname === '/api/connect' && req.method === 'POST') {
          const b = await this.readJsonBody<{ nodeId?: string }>(req);
          this.sendJson(res, 200, await this.engine.connect(b.nodeId));
          return;
        }
        if (pathname === '/api/disconnect' && req.method === 'POST') {
          this.sendJson(res, 200, await this.engine.disconnect());
          return;
        }
        if (pathname === '/api/switch-node' && req.method === 'POST') {
          const b = await this.readJsonBody<{ nodeId: string }>(req);
          this.sendJson(res, 200, await this.engine.switchToNodeManual(b.nodeId));
          return;
        }
        if (pathname === '/api/ping-all' && req.method === 'POST') {
          this.sendJson(res, 200, await this.engine.pingAllNodes());
          return;
        }
        if (pathname === '/api/recover-unavailable' && req.method === 'POST') {
          this.sendJson(res, 200, await this.engine.recoverUnavailableNodes());
          return;
        }
        if (pathname === '/api/network/rebind' && req.method === 'POST') {
          this.sendJson(res, 200, await this.engine.rebindNetwork());
          return;
        }
        if (pathname === '/api/node/probe' && req.method === 'POST') {
          const b = await this.readJsonBody<{ nodeId: string }>(req);
          this.sendJson(res, 200, await this.engine.probeNodeById(b.nodeId));
          return;
        }
        if (pathname === '/api/smart-optimize' && req.method === 'POST') {
          this.sendJson(res, 200, await this.engine.smartOptimize());
          return;
        }
        if (pathname === '/api/ai/scan' && req.method === 'POST') {
          this.sendJson(res, 200, await this.engine.scanAiCompatibility());
          return;
        }
        if (pathname === '/api/ai/switch' && req.method === 'POST') {
          const b = await this.readJsonBody<{ nodeId?: string }>(req);
          this.sendJson(res, 200, await this.engine.switchAiGatewayNode(b.nodeId));
          return;
        }
        if (pathname === '/api/installed-apps' && req.method === 'POST') {
          this.sendJson(res, 200, this.engine.getSnapshot());
          return;
        }
        if (pathname === '/api/import' && req.method === 'POST') {
          const b = await this.readJsonBody<{ text: string }>(req);
          const result = this.engine.importNodesFromText(b.text || '');
          this.sendJson(res, 200, {
            result,
            snapshot: this.engine.getSnapshot(),
          });
          return;
        }
        if (pathname === '/api/subscription/add' && req.method === 'POST') {
          const b = await this.readJsonBody<{ name: string; url: string }>(req);
          this.sendJson(
            res,
            200,
            await this.engine.addSubscriptionUrl(b.name || '', b.url || '')
          );
          return;
        }
        if (pathname === '/api/subscription/delete' && req.method === 'POST') {
          const b = await this.readJsonBody<{ id: string }>(req);
          this.sendJson(res, 200, this.engine.deleteSubscription(b.id));
          return;
        }
        if (pathname === '/api/subscription/refresh' && req.method === 'POST') {
          const b = await this.readJsonBody<{ id: string }>(req);
          this.sendJson(res, 200, await this.engine.refreshSubscription(b.id));
          return;
        }
        if (pathname === '/api/subscription/toggle-failover' && req.method === 'POST') {
          const b = await this.readJsonBody<{ id: string; enabled: boolean }>(req);
          this.sendJson(
            res,
            200,
            this.engine.toggleSubscriptionFailover(b.id, Boolean(b.enabled))
          );
          return;
        }
        if (pathname === '/api/manual-group/toggle-failover' && req.method === 'POST') {
          const b = await this.readJsonBody<{ enabled: boolean }>(req);
          this.sendJson(
            res,
            200,
            this.engine.toggleManualGroupFailover(Boolean(b.enabled))
          );
          return;
        }
        if (pathname === '/api/external-clients/scan' && req.method === 'POST') {
          this.sendJson(res, 200, await this.engine.scanExternalClients());
          return;
        }
        if (pathname === '/api/external-clients/toggle' && req.method === 'POST') {
          const b = await this.readJsonBody<{ id: string; enabled: boolean }>(req);
          this.sendJson(
            res,
            200,
            await this.engine.toggleExternalClient(b.id, Boolean(b.enabled))
          );
          return;
        }
        if (pathname === '/api/external-clients/add-custom' && req.method === 'POST') {
          const b = await this.readJsonBody<{
            clientName: string;
            protocol: 'socks' | 'http';
            port: number;
          }>(req);
          this.sendJson(
            res,
            200,
            await this.engine.addCustomExternalClient(
              b.clientName || '',
              b.protocol || 'socks',
              Number(b.port)
            )
          );
          return;
        }
        if (pathname === '/api/failover-banner/dismiss' && req.method === 'POST') {
          this.sendJson(res, 200, this.engine.dismissFailoverBanner());
          return;
        }
        if (
          (pathname === '/api/emergency-app/select' ||
            pathname === '/api/emergency-app/launch') &&
          req.method === 'POST'
        ) {
          this.sendJson(res, 200, this.engine.getSnapshot());
          return;
        }
        if (pathname === '/api/node/delete' && req.method === 'POST') {
          const b = await this.readJsonBody<{ nodeId: string }>(req);
          this.sendJson(res, 200, this.engine.deleteNode(b.nodeId));
          return;
        }
        if (pathname === '/api/node/toggle' && req.method === 'POST') {
          const b = await this.readJsonBody<{ nodeId: string; enabled: boolean }>(req);
          this.sendJson(
            res,
            200,
            this.engine.toggleNodeEnabled(b.nodeId, Boolean(b.enabled))
          );
          return;
        }
        if (pathname === '/api/node/priority' && req.method === 'POST') {
          const b = await this.readJsonBody<{
            nodeId: string;
            direction: 'up' | 'down';
          }>(req);
          this.sendJson(
            res,
            200,
            this.engine.moveNodePriority(b.nodeId, b.direction)
          );
          return;
        }
        if (pathname === '/api/settings' && req.method === 'POST') {
          const b = await this.readJsonBody<Partial<AppSettings>>(req);
          this.sendJson(res, 200, await this.engine.updateSettings(b));
          return;
        }
        if (pathname === '/api/vault/unlock' && req.method === 'POST') {
          const b = await this.readJsonBody<{ pin: string }>(req);
          this.sendJson(res, 200, this.engine.unlockVaultWithPin(b.pin || ''));
          return;
        }
        if (pathname === '/api/vault/pin' && req.method === 'POST') {
          const b = await this.readJsonBody<{ pin: string | null }>(req);
          this.sendJson(res, 200, this.engine.setVaultPin(b.pin));
          return;
        }
        if (pathname === '/api/test-stand/start' && req.method === 'POST') {
          this.sendJson(res, 200, await this.engine.startTestStand());
          return;
        }
        if (pathname === '/api/test-stand/stop' && req.method === 'POST') {
          this.sendJson(res, 200, await this.engine.stopTestStand());
          return;
        }
        if (pathname === '/api/test-stand/node-online' && req.method === 'POST') {
          const b = await this.readJsonBody<{ nodeId: string; online: boolean }>(req);
          this.sendJson(
            res,
            200,
            await this.engine.setTestNodeOnline(b.nodeId, Boolean(b.online))
          );
          return;
        }
        if (pathname === '/api/test-stand/node-delay' && req.method === 'POST') {
          const b = await this.readJsonBody<{ nodeId: string; delayMs: number }>(req);
          this.sendJson(
            res,
            200,
            await this.engine.setTestNodeDelay(b.nodeId, Number(b.delayMs || 0))
          );
          return;
        }
        if (pathname === '/api/audit' && req.method === 'POST') {
          const report = await this.engine.runCyberAudit();
          this.sendJson(res, 200, {
            report,
            snapshot: this.engine.getSnapshot(),
          });
          return;
        }
        if (pathname === '/api/core/install' && req.method === 'POST') {
          this.sendJson(res, 200, await this.engine.installSingboxCore());
          return;
        }

        this.sendJson(res, 404, { error: 'Неизвестный API маршрут' });
      } catch (err) {
        this.sendJson(res, 400, {
          error: err instanceof Error ? err.message : 'Ошибка выполнения операции',
        });
      }
      return;
    }

    // Если подключён телефон по Wi-Fi — отдаём скомпилированный интерфейс из dist/renderer
    if (this.staticDistDir && fs.existsSync(this.staticDistDir)) {
      const rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
      const safePath = path.normalize(path.join(this.staticDistDir, rel));
      if (
        safePath.startsWith(this.staticDistDir) &&
        fs.existsSync(safePath) &&
        fs.statSync(safePath).isFile()
      ) {
        const ext = path.extname(safePath).toLowerCase();
        const mime =
          ext === '.html'
            ? 'text/html; charset=utf-8'
            : ext === '.js'
              ? 'application/javascript; charset=utf-8'
              : ext === '.css'
                ? 'text/css; charset=utf-8'
                : ext === '.json'
                  ? 'application/json; charset=utf-8'
                  : 'application/octet-stream';
        res.writeHead(200, { 'Content-Type': mime });
        fs.createReadStream(safePath).pipe(res);
        return;
      }
    }

    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('AegisMesh VPN Local API Server Active');
  }
}
