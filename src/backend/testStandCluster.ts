// Встроенный локальный кластер из 3 реальных прокси-узлов для боевой проверки каскадной автозамены (1 -> 2 -> 3)
import http from 'node:http';
import net from 'node:net';
import type { VpnNode } from '../shared/types';

interface SimProxyInstance {
  id: string;
  name: string;
  countryHint: string;
  simulatedIp: string;
  artificialDelayMs: number;
  online: boolean;
  port: number;
  server: http.Server | null;
  sockets: Set<net.Socket>;
}

export class TestStandCluster {
  private nodes: SimProxyInstance[] = [];
  private healthTargetServer: http.Server | null = null;
  private healthTargetPort = 0;
  private running = false;

  public isRunning(): boolean {
    return this.running;
  }

  public getHealthCheckUrl(): string | null {
    if (!this.running || !this.healthTargetPort) return null;
    return `http://127.0.0.1:${this.healthTargetPort}/generate_204`;
  }

  public getEchoIdentityUrl(): string | null {
    if (!this.running || !this.healthTargetPort) return null;
    return `http://127.0.0.1:${this.healthTargetPort}/whoami`;
  }

  public async start(): Promise<VpnNode[]> {
    if (this.running) {
      return this.toVpnNodes();
    }

    // 1. Локальный проверочный эндпоинт (имитирует generate_204 и возврат выходного IP узла)
    await new Promise<void>((resolve, reject) => {
      const srv = http.createServer((req, res) => {
        if (req.url?.startsWith('/generate_204')) {
          res.writeHead(204, {
            'X-Vpn-Exit-Node': String(req.headers['x-aegis-sim-ip'] || 'direct'),
          });
          res.end();
          return;
        }
        if (req.url?.startsWith('/whoami')) {
          const exitIp = String(req.headers['x-aegis-sim-ip'] || '127.0.0.1 (Direct)');
          const exitCountry = String(req.headers['x-aegis-sim-country'] || 'LOC');
          const exitNode = decodeURIComponent(
            String(req.headers['x-aegis-sim-node'] || 'Direct')
          );
          res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(
            JSON.stringify({
              ip: exitIp,
              country: exitCountry,
              org: `AegisMesh TestCluster (${exitNode})`,
            })
          );
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('AegisMesh Test Target OK');
      });
      srv.once('error', reject);
      srv.listen(0, '127.0.0.1', () => {
        this.healthTargetServer = srv;
        const addr = srv.address();
        this.healthTargetPort = typeof addr === 'object' && addr ? addr.port : 0;
        resolve();
      });
    });

    // 2. Поднимаем 3 независимых HTTP/CONNECT прокси-узла с разными задержками и виртуальными выходными IP
    const specs: Array<{
      id: string;
      name: string;
      countryHint: string;
      simulatedIp: string;
      delay: number;
    }> = [
      {
        id: 'test_node_1',
        name: '🇩🇪 Франкфурт #1 [Тест-узел]',
        countryHint: 'DE',
        simulatedIp: '185.220.101.41',
        delay: 18,
      },
      {
        id: 'test_node_2',
        name: '🇳🇱 Амстердам #2 [Тест-узел]',
        countryHint: 'NL',
        simulatedIp: '94.142.241.112',
        delay: 46,
      },
      {
        id: 'test_node_3',
        name: '🇫🇮 Хельсинки #3 [Тест-узел]',
        countryHint: 'FI',
        simulatedIp: '65.109.88.19',
        delay: 78,
      },
    ];

    this.nodes = [];
    for (const spec of specs) {
      const inst: SimProxyInstance = {
        id: spec.id,
        name: spec.name,
        countryHint: spec.countryHint,
        simulatedIp: spec.simulatedIp,
        artificialDelayMs: spec.delay,
        online: true,
        port: 0,
        server: null,
        sockets: new Set(),
      };
      await this.startNodeServer(inst);
      this.nodes.push(inst);
    }

    this.running = true;
    return this.toVpnNodes();
  }

  private async startNodeServer(inst: SimProxyInstance): Promise<void> {
    if (inst.server && inst.server.listening) return;

    await new Promise<void>((resolve, reject) => {
      const srv = http.createServer((req, res) => {
        if (!inst.online) {
          req.socket.destroy();
          return;
        }
        setTimeout(() => {
          if (!inst.online) {
            req.socket.destroy();
            return;
          }
          let targetUrl: URL;
          try {
            targetUrl = new URL(req.url || '');
          } catch {
            res.writeHead(400);
            res.end('Invalid proxy URL');
            return;
          }

          const outHeaders: http.OutgoingHttpHeaders = {
            ...req.headers,
            host: targetUrl.host,
            'x-aegis-sim-ip': inst.simulatedIp,
            'x-aegis-sim-country': inst.countryHint,
            'x-aegis-sim-node': encodeURIComponent(inst.name),
          };

          const fwd = http.request(
            {
              host: targetUrl.hostname,
              port: targetUrl.port ? Number(targetUrl.port) : 80,
              method: req.method,
              path: `${targetUrl.pathname}${targetUrl.search}`,
              headers: outHeaders,
              timeout: 8000,
            },
            (fwdRes) => {
              res.writeHead(fwdRes.statusCode ?? 502, fwdRes.headers);
              fwdRes.pipe(res);
            }
          );
          fwd.on('error', (err) => {
            if (!res.headersSent) res.writeHead(502);
            res.end(err.message);
          });
          req.pipe(fwd);
        }, inst.artificialDelayMs);
      });

      srv.on('connect', (req, clientSocket, head) => {
        const sock = clientSocket as net.Socket;
        if (!inst.online) {
          sock.destroy();
          return;
        }
        setTimeout(() => {
          if (!inst.online) {
            sock.destroy();
            return;
          }
          try {
            const parsed = new URL(`http://${req.url}`);
            const remote = net.connect(
              parsed.port ? Number(parsed.port) : 443,
              parsed.hostname,
              () => {
                sock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
                if (head.length > 0) remote.write(head);
                remote.pipe(sock);
                sock.pipe(remote);
              }
            );
            remote.on('error', () => sock.destroy());
            sock.on('error', () => remote.destroy());
          } catch {
            sock.destroy();
          }
        }, inst.artificialDelayMs);
      });

      srv.on('connection', (s) => {
        inst.sockets.add(s);
        s.once('close', () => inst.sockets.delete(s));
        if (!inst.online) {
          s.destroy();
        }
      });

      srv.once('error', reject);
      srv.listen(inst.port || 0, '127.0.0.1', () => {
        inst.server = srv;
        const addr = srv.address();
        inst.port = typeof addr === 'object' && addr ? addr.port : inst.port;
        inst.online = true;
        resolve();
      });
    });
  }

  // Реальное отключение («падение») конкретного узла с закрытием его слушающего порта!
  public async setNodeOnline(nodeId: string, online: boolean): Promise<boolean> {
    const inst = this.nodes.find((n) => n.id === nodeId);
    if (!inst) return false;

    if (!online) {
      inst.online = false;
      for (const s of inst.sockets) {
        s.destroy();
      }
      inst.sockets.clear();
      if (inst.server) {
        const srv = inst.server;
        inst.server = null;
        await new Promise<void>((res) => srv.close(() => res()));
      }
      return true;
    }

    inst.online = true;
    await this.startNodeServer(inst);
    return true;
  }

  // Установка искусственной задержки (например 2200 мс для проверки переключения при лагах!)
  public setNodeDelay(nodeId: string, delayMs: number): boolean {
    const inst = this.nodes.find((n) => n.id === nodeId);
    if (!inst) return false;
    inst.artificialDelayMs = Math.max(0, delayMs);
    return true;
  }

  public isNodeOnline(nodeId: string): boolean {
    const inst = this.nodes.find((n) => n.id === nodeId);
    return inst ? inst.online : false;
  }

  public toVpnNodes(startingPriority = 1): VpnNode[] {
    return this.nodes.map((inst, idx) => ({
      id: inst.id,
      name: inst.name,
      protocol: 'http',
      server: '127.0.0.1',
      port: inst.port,
      enabled: true,
      priority: startingPriority + idx,
      countryHint: inst.countryHint,
      isTestStand: true,
      status: inst.online ? 'standby' : 'down',
      latencyMs: inst.online ? inst.artificialDelayMs : null,
      lastCheckedAt: Date.now(),
      consecutiveFailures: 0,
      quarantinedUntil: null,
    }));
  }

  public async stop(): Promise<void> {
    for (const inst of this.nodes) {
      inst.online = false;
      for (const s of inst.sockets) s.destroy();
      inst.sockets.clear();
      if (inst.server) {
        const srv = inst.server;
        inst.server = null;
        await new Promise<void>((res) => srv.close(() => res()));
      }
    }
    this.nodes = [];

    if (this.healthTargetServer) {
      const hSrv = this.healthTargetServer;
      this.healthTargetServer = null;
      await new Promise<void>((res) => hSrv.close(() => res()));
    }
    this.healthTargetPort = 0;
    this.running = false;
  }
}
