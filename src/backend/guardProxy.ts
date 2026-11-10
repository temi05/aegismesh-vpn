// Локальный защитный шлюз GuardProxy: Kill Switch (0 утечек IP при переключении) + Split Tunneling
import http from 'node:http';
import net from 'node:net';
import { openTunnelThroughUpstream, type UpstreamEndpoint } from './proxyConnector';

export interface GuardProxyOptions {
  onUpstreamFailure?: (errorMessage: string) => void;
}

export function isPrivateIpAddress(host: string): boolean {
  const clean = host.trim().toLowerCase();
  if (clean === 'localhost' || clean === '::1' || clean === '[::1]') return true;
  const m = clean.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  if (a === 127 || a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  return false;
}

export function shouldBypassHost(
  host: string,
  splitTunnelingEnabled: boolean,
  bypassDomains: string[],
  bypassPrivateLan: boolean
): boolean {
  const cleanHost = host
    .trim()
    .toLowerCase()
    .replace(/:\d+$/, '')
    .replace(/^\[|\]$/g, '');

  if (!cleanHost) return false;
  if (bypassPrivateLan && isPrivateIpAddress(cleanHost)) return true;
  if (!splitTunnelingEnabled) return false;

  for (const rawPattern of bypassDomains) {
    const pat = rawPattern.trim().toLowerCase();
    if (!pat) continue;
    if (pat.startsWith('*.')) {
      const suffix = pat.slice(2);
      if (cleanHost === suffix || cleanHost.endsWith(`.${suffix}`)) return true;
    } else if (pat.startsWith('.')) {
      const suffix = pat.slice(1);
      if (cleanHost === suffix || cleanHost.endsWith(`.${suffix}`)) return true;
    } else if (cleanHost === pat || cleanHost.endsWith(`.${pat}`)) {
      return true;
    }
  }
  return false;
}

export class GuardProxy {
  private server: http.Server | null = null;
  private activePort = 0;
  private activeHost = '127.0.0.1';
  private upstream: UpstreamEndpoint | null = null;
  private killSwitchBlocking = false;
  private splitTunnelingEnabled = true;
  private bypassDomains: string[] = [];
  private bypassPrivateLan = true;
  private blockedLeakAttempts = 0;
  private readonly activeSockets = new Set<net.Socket>();
  private readonly opts: GuardProxyOptions;

  constructor(opts: GuardProxyOptions = {}) {
    this.opts = opts;
  }

  public setRoutingPolicy(params: {
    upstream: UpstreamEndpoint | null;
    killSwitchBlocking: boolean;
    splitTunnelingEnabled: boolean;
    bypassDomains: string[];
    bypassPrivateLan: boolean;
  }): void {
    this.upstream = params.upstream;
    this.killSwitchBlocking = params.killSwitchBlocking;
    this.splitTunnelingEnabled = params.splitTunnelingEnabled;
    this.bypassDomains = [...params.bypassDomains];
    this.bypassPrivateLan = params.bypassPrivateLan;
  }

  public getBlockedLeakAttempts(): number {
    return this.blockedLeakAttempts;
  }

  public getBoundPort(): number {
    return this.activePort;
  }

  public isRunning(): boolean {
    return this.server !== null && this.server.listening;
  }

  public async start(port: number, allowLan: boolean): Promise<number> {
    const desiredHost = allowLan ? '0.0.0.0' : '127.0.0.1';
    if (
      this.server &&
      this.server.listening &&
      this.activePort === port &&
      this.activeHost === desiredHost
    ) {
      return this.activePort;
    }

    await this.stop();

    return new Promise((resolve, reject) => {
      const srv = http.createServer((req, res) => this.handleHttpRequest(req, res));
      srv.on('connect', (req, clientSocket, head) =>
        this.handleConnect(req, clientSocket as net.Socket, head)
      );
      srv.on('connection', (sock) => {
        this.activeSockets.add(sock);
        sock.once('close', () => this.activeSockets.delete(sock));
      });

      srv.once('error', (err) => {
        reject(err);
      });

      srv.listen(port, desiredHost, () => {
        this.server = srv;
        this.activeHost = desiredHost;
        const addr = srv.address();
        this.activePort = typeof addr === 'object' && addr ? addr.port : port;
        resolve(this.activePort);
      });
    });
  }

  public async stop(): Promise<void> {
    for (const sock of this.activeSockets) {
      sock.destroy();
    }
    this.activeSockets.clear();

    if (!this.server) return;
    const srv = this.server;
    this.server = null;
    this.activePort = 0;

    await new Promise<void>((resolve) => {
      srv.close(() => resolve());
    });
  }

  private isBypassed(hostname: string): boolean {
    return shouldBypassHost(
      hostname,
      this.splitTunnelingEnabled,
      this.bypassDomains,
      this.bypassPrivateLan
    );
  }

  private handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const rawUrl = req.url || '/';
    let parsedUrl: URL;
    try {
      parsedUrl = rawUrl.startsWith('http')
        ? new URL(rawUrl)
        : new URL(`http://${req.headers.host || 'localhost'}${rawUrl}`);
    } catch {
      res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('AegisMesh GuardProxy: Некорректный URL запроса');
      return;
    }

    const targetHost = parsedUrl.hostname;
    const targetPort = parsedUrl.port ? Number(parsedUrl.port) : 80;
    const isTunnelProbe =
      parsedUrl.pathname.startsWith('/whoami') ||
      parsedUrl.pathname.startsWith('/generate_204');
    const bypass = !isTunnelProbe && this.isBypassed(targetHost);

    // Если активен Kill Switch и домен НЕ в белом списке — блокируем утечку реального IP!
    if (!bypass && (this.killSwitchBlocking || !this.upstream)) {
      this.blockedLeakAttempts += 1;
      res.writeHead(503, {
        'Content-Type': 'text/plain; charset=utf-8',
        'X-AegisMesh-KillSwitch': 'ENGAGED',
      });
      res.end(
        'AegisMesh Kill Switch: Трафик защищён и временно заблокирован на время автозамены VPN-сервера (утечка реального IP предотвращена).'
      );
      return;
    }

    if (bypass) {
      // Прямой маршрут (Split Tunneling)
      const directReq = http.request(
        {
          host: targetHost,
          port: targetPort,
          method: req.method,
          path: `${parsedUrl.pathname}${parsedUrl.search}`,
          headers: { ...req.headers, host: parsedUrl.host },
          timeout: 12000,
        },
        (directRes) => {
          res.writeHead(directRes.statusCode ?? 502, directRes.headers);
          directRes.pipe(res);
        }
      );
      directReq.on('error', (err) => {
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
        }
        res.end(`Ошибка прямого соединения: ${err.message}`);
      });
      req.pipe(directReq);
      return;
    }

    const currentUpstream = this.upstream!;

    if (currentUpstream.protocol === 'http') {
      const fwdHeaders: http.OutgoingHttpHeaders = { ...req.headers };
      if (currentUpstream.username !== undefined) {
        fwdHeaders['proxy-authorization'] = `Basic ${Buffer.from(
          `${currentUpstream.username}:${currentUpstream.password ?? ''}`
        ).toString('base64')}`;
      }

      const proxyReq = http.request(
        {
          host: currentUpstream.host,
          port: currentUpstream.port,
          method: req.method,
          path: parsedUrl.toString(),
          headers: fwdHeaders,
          timeout: 12000,
        },
        (proxyRes) => {
          res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
          proxyRes.pipe(res);
        }
      );

      proxyReq.on('error', (err) => {
        this.opts.onUpstreamFailure?.(err.message);
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
        }
        res.end(`AegisMesh: Сбой текущего VPN-узла (${err.message}). Запущена автозамена...`);
      });

      req.pipe(proxyReq);
      return;
    }

    // Если апстрим SOCKS5 — открываем туннель к целевому веб-серверу
    openTunnelThroughUpstream(currentUpstream, targetHost, targetPort, 9000)
      .then((tunnelSock) => {
        const proxyReq = http.request(
          {
            host: targetHost,
            port: targetPort,
            method: req.method,
            path: `${parsedUrl.pathname}${parsedUrl.search}`,
            headers: { ...req.headers, host: parsedUrl.host },
            createConnection: () => tunnelSock,
          },
          (proxyRes) => {
            res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
            proxyRes.pipe(res);
          }
        );
        proxyReq.on('error', (err) => {
          tunnelSock.destroy();
          this.opts.onUpstreamFailure?.(err.message);
          if (!res.headersSent) {
            res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
          }
          res.end(`Ошибка туннеля: ${err.message}`);
        });
        req.pipe(proxyReq);
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : 'Ошибка SOCKS5';
        this.opts.onUpstreamFailure?.(msg);
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
        }
        res.end(`AegisMesh: Сбой VPN-узла (${msg}). Переключение...`);
      });
  }

  private handleConnect(
    req: http.IncomingMessage,
    clientSocket: net.Socket,
    head: Buffer
  ): void {
    const authority = req.url || '';
    let targetHost = '';
    let targetPort = 443;

    try {
      const parsed = new URL(`http://${authority}`);
      targetHost = parsed.hostname;
      targetPort = parsed.port ? Number(parsed.port) : 443;
    } catch {
      clientSocket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
      clientSocket.destroy();
      return;
    }

    const bypass = this.isBypassed(targetHost);

    if (!bypass && (this.killSwitchBlocking || !this.upstream)) {
      this.blockedLeakAttempts += 1;
      clientSocket.write(
        'HTTP/1.1 503 Service Unavailable\r\nX-AegisMesh-KillSwitch: ENGAGED\r\n\r\n'
      );
      clientSocket.destroy();
      return;
    }

    if (bypass) {
      const cleanHost =
        targetHost.startsWith('[') && targetHost.endsWith(']')
          ? targetHost.slice(1, -1)
          : targetHost;
      const directSock = net.connect(targetPort, cleanHost, () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head.length > 0) directSock.write(head);
        directSock.pipe(clientSocket);
        clientSocket.pipe(directSock);
      });
      directSock.on('error', () => clientSocket.destroy());
      clientSocket.on('error', () => directSock.destroy());
      return;
    }

    const currentUpstream = this.upstream!;
    openTunnelThroughUpstream(currentUpstream, targetHost, targetPort, 9000)
      .then((remoteSock) => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head.length > 0) remoteSock.write(head);
        remoteSock.pipe(clientSocket);
        clientSocket.pipe(remoteSock);
        remoteSock.on('error', () => clientSocket.destroy());
        clientSocket.on('error', () => remoteSock.destroy());
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : 'Ошибка CONNECT апстрима';
        this.opts.onUpstreamFailure?.(msg);
        if (!clientSocket.destroyed) {
          clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
          clientSocket.destroy();
        }
      });
  }
}
