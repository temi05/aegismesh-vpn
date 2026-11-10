// Низкоуровневый коннектор SOCKS5 / HTTP CONNECT и HTTP(S) клиент сквозь туннель
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';

export interface UpstreamEndpoint {
  protocol: 'http' | 'socks';
  host: string;
  port: number;
  username?: string;
  password?: string;
}

// Установка TCP-туннеля к targetHost:targetPort через HTTP CONNECT или SOCKS5 апстрим
export function openTunnelThroughUpstream(
  upstream: UpstreamEndpoint,
  targetHost: string,
  targetPort: number,
  timeoutMs = 7000
): Promise<net.Socket> {
  if (upstream.protocol === 'socks') {
    return openSocks5Tunnel(upstream, targetHost, targetPort, timeoutMs);
  }
  return openHttpConnectTunnel(upstream, targetHost, targetPort, timeoutMs);
}

function openHttpConnectTunnel(
  upstream: UpstreamEndpoint,
  targetHost: string,
  targetPort: number,
  timeoutMs: number
): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(upstream.port, upstream.host);
    let settled = false;

    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(err);
    };

    socket.setTimeout(timeoutMs, () => fail(new Error('Таймаут HTTP CONNECT апстрима')));
    socket.once('error', fail);

    socket.once('connect', () => {
      const authHeader =
        upstream.username !== undefined
          ? `Proxy-Authorization: Basic ${Buffer.from(
              `${upstream.username}:${upstream.password ?? ''}`
            ).toString('base64')}\r\n`
          : '';
      const hostBracketed =
        targetHost.includes(':') && !targetHost.startsWith('[')
          ? `[${targetHost}]`
          : targetHost;
      const reqStr =
        `CONNECT ${hostBracketed}:${targetPort} HTTP/1.1\r\n` +
        `Host: ${hostBracketed}:${targetPort}\r\n` +
        authHeader +
        `Proxy-Connection: Keep-Alive\r\n\r\n`;

      socket.write(reqStr);

      let headerBuf = Buffer.alloc(0);
      const onData = (chunk: Buffer) => {
        headerBuf = Buffer.concat([headerBuf, chunk]);
        const endIdx = headerBuf.indexOf('\r\n\r\n');
        if (endIdx === -1) {
          if (headerBuf.length > 16384) {
            socket.off('data', onData);
            fail(new Error('Слишком большой заголовок ответа от прокси'));
          }
          return;
        }
        socket.off('data', onData);
        const headText = headerBuf.subarray(0, endIdx).toString('latin1');
        const statusLine = headText.split('\r\n')[0] || '';
        const match = statusLine.match(/^HTTP\/1\.[01]\s+(\d{3})/);
        const code = match ? Number(match[1]) : 0;
        if (code !== 200) {
          fail(new Error(`Апстрим отклонил CONNECT: ${statusLine}`));
          return;
        }
        const leftover = headerBuf.subarray(endIdx + 4);
        settled = true;
        socket.setTimeout(0);
        socket.removeListener('error', fail);
        if (leftover.length > 0) {
          socket.unshift(leftover);
        }
        resolve(socket);
      };

      socket.on('data', onData);
    });
  });
}

function openSocks5Tunnel(
  upstream: UpstreamEndpoint,
  targetHost: string,
  targetPort: number,
  timeoutMs: number
): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(upstream.port, upstream.host);
    let settled = false;

    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(err);
    };

    socket.setTimeout(timeoutMs, () => fail(new Error('Таймаут SOCKS5 апстрима')));
    socket.once('error', fail);

    const readBytes = (minLen: number): Promise<Buffer> =>
      new Promise((resRead) => {
        let acc = Buffer.alloc(0);
        const onChunk = (c: Buffer) => {
          acc = Buffer.concat([acc, c]);
          if (acc.length >= minLen) {
            socket.off('data', onChunk);
            resRead(acc);
          }
        };
        socket.on('data', onChunk);
      });

    socket.once('connect', async () => {
      try {
        const useAuth = Boolean(upstream.username);
        // 1. Greeting
        socket.write(
          useAuth ? Buffer.from([0x05, 0x02, 0x00, 0x02]) : Buffer.from([0x05, 0x01, 0x00])
        );
        const greetResp = await readBytes(2);
        if (greetResp[0] !== 0x05) {
          throw new Error('Некорректный ответ SOCKS5 сервера');
        }
        if (greetResp[1] === 0x02) {
          const uBuf = Buffer.from(upstream.username || '', 'utf-8');
          const pBuf = Buffer.from(upstream.password || '', 'utf-8');
          const authPkt = Buffer.concat([
            Buffer.from([0x01, uBuf.length]),
            uBuf,
            Buffer.from([pBuf.length]),
            pBuf,
          ]);
          socket.write(authPkt);
          const authResp = await readBytes(2);
          if (authResp[1] !== 0x00) {
            throw new Error('Ошибка авторизации SOCKS5');
          }
        } else if (greetResp[1] !== 0x00) {
          throw new Error('SOCKS5 сервер не поддержал предложенные методы аутентификации');
        }

        // 2. CONNECT запрос (домен или IPv4)
        const ipv4Match = targetHost.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
        let addrPart: Buffer;
        if (ipv4Match) {
          addrPart = Buffer.from([
            0x01,
            Number(ipv4Match[1]),
            Number(ipv4Match[2]),
            Number(ipv4Match[3]),
            Number(ipv4Match[4]),
          ]);
        } else {
          const cleanHost =
            targetHost.startsWith('[') && targetHost.endsWith(']')
              ? targetHost.slice(1, -1)
              : targetHost;
          const domainBuf = Buffer.from(cleanHost, 'utf-8');
          addrPart = Buffer.concat([Buffer.from([0x03, domainBuf.length]), domainBuf]);
        }

        const portBuf = Buffer.alloc(2);
        portBuf.writeUInt16BE(targetPort, 0);
        socket.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), addrPart, portBuf]));

        const connHead = await readBytes(4);
        if (connHead[0] !== 0x05 || connHead[1] !== 0x00) {
          throw new Error(`SOCKS5 ошибка соединения (код ${connHead[1]})`);
        }

        const atyp = connHead[3];
        let totalExpected = 4;
        if (atyp === 0x01) {
          totalExpected = 4 + 4 + 2;
        } else if (atyp === 0x04) {
          totalExpected = 4 + 16 + 2;
        } else if (atyp === 0x03) {
          const withLen = connHead.length >= 5 ? connHead : Buffer.concat([connHead, await readBytes(5 - connHead.length)]);
          totalExpected = 5 + withLen[4] + 2;
          if (withLen.length < totalExpected) {
            const rest = await readBytes(totalExpected - withLen.length);
            const full = Buffer.concat([withLen, rest]);
            if (full.length > totalExpected) {
              socket.unshift(full.subarray(totalExpected));
            }
          } else if (withLen.length > totalExpected) {
            socket.unshift(withLen.subarray(totalExpected));
          }
          settled = true;
          socket.setTimeout(0);
          socket.removeListener('error', fail);
          resolve(socket);
          return;
        }

        if (connHead.length < totalExpected) {
          const rest = await readBytes(totalExpected - connHead.length);
          const full = Buffer.concat([connHead, rest]);
          if (full.length > totalExpected) {
            socket.unshift(full.subarray(totalExpected));
          }
        } else if (connHead.length > totalExpected) {
          socket.unshift(connHead.subarray(totalExpected));
        }

        settled = true;
        socket.setTimeout(0);
        socket.removeListener('error', fail);
        resolve(socket);
      } catch (e) {
        fail(e instanceof Error ? e : new Error('Ошибка рукопожатия SOCKS5'));
      }
    });
  });
}

// Выполнение HTTP/HTTPS GET запроса через указанный прокси-апстрим (для Health-Check и Кибердиагностики)
export async function fetchViaUpstream(
  urlStr: string,
  upstream: UpstreamEndpoint | null,
  timeoutMs = 6000
): Promise<{ statusCode: number; body: string; elapsedMs: number; location?: string }> {
  const startedAt = performance.now();
  const parsed = new URL(urlStr);
  const isHttps = parsed.protocol === 'https:';
  const targetPort = parsed.port ? Number(parsed.port) : isHttps ? 443 : 80;
  const targetHost = parsed.hostname;

  if (!upstream) {
    return new Promise((resolve, reject) => {
      const lib = isHttps ? https : http;
      const req = lib.get(
        urlStr,
        {
          headers: { 'User-Agent': 'AegisMesh-Diagnostic/1.0', Connection: 'close' },
          timeout: timeoutMs,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => {
            resolve({
              statusCode: res.statusCode ?? 0,
              body: Buffer.concat(chunks).toString('utf-8'),
              elapsedMs: Math.round(performance.now() - startedAt),
            });
          });
        }
      );
      req.on('error', reject);
      req.on('timeout', () => req.destroy(new Error('Таймаут прямого запроса')));
    });
  }

  // Для обычного HTTP запроса через HTTP-прокси можно отправить абсолютный URI напрямую без CONNECT
  if (!isHttps && upstream.protocol === 'http') {
    return new Promise((resolve, reject) => {
      const headers: Record<string, string> = {
        Host: parsed.host,
        'User-Agent': 'AegisMesh-Watchdog/1.0',
        Connection: 'close',
      };
      if (upstream.username !== undefined) {
        headers['Proxy-Authorization'] = `Basic ${Buffer.from(
          `${upstream.username}:${upstream.password ?? ''}`
        ).toString('base64')}`;
      }
      const req = http.request(
        {
          host: upstream.host,
          port: upstream.port,
          method: 'GET',
          path: urlStr,
          headers,
          timeout: timeoutMs,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => {
            resolve({
              statusCode: res.statusCode ?? 0,
              body: Buffer.concat(chunks).toString('utf-8'),
              elapsedMs: Math.round(performance.now() - startedAt),
            });
          });
        }
      );
      req.on('error', reject);
      req.on('timeout', () => req.destroy(new Error('Таймаут HTTP прокси-запроса')));
      req.end();
    });
  }

  // Для HTTPS или SOCKS5 прокладываем TCP туннель к целевому хосту
  const rawSocket = await openTunnelThroughUpstream(
    upstream,
    targetHost,
    targetPort,
    timeoutMs
  );

  const transportSocket: net.Socket | tls.TLSSocket = isHttps
    ? tls.connect({
        socket: rawSocket,
        servername: targetHost,
      })
    : rawSocket;

  return new Promise((resolve, reject) => {
    const req = (isHttps ? https : http).request(
      {
        host: targetHost,
        port: targetPort,
        path: `${parsed.pathname}${parsed.search}`,
        method: 'GET',
        headers: {
          Host: parsed.host,
          'User-Agent': 'AegisMesh-Watchdog/1.0',
          Connection: 'close',
        },
        createConnection: () => transportSocket,
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          transportSocket.destroy();
          resolve({
            statusCode: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString('utf-8'),
            elapsedMs: Math.round(performance.now() - startedAt),
            location: typeof res.headers.location === 'string' ? res.headers.location : undefined,
          });
        });
      }
    );

    req.on('error', (err) => {
      transportSocket.destroy();
      reject(err);
    });
    req.on('timeout', () => {
      req.destroy(new Error('Таймаут чтения внутри туннеля'));
    });
    req.end();
  });
}

// Быстрый TCP пинг сервера (возвращает время рукопожатия в мс)
export function measureTcpLatency(
  host: string,
  port: number,
  timeoutMs = 3500
): Promise<number> {
  return new Promise((resolve, reject) => {
    const start = performance.now();
    const cleanHost =
      host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
    const sock = net.connect(port, cleanHost);
    let done = false;

    const finishErr = (err: Error) => {
      if (done) return;
      done = true;
      sock.destroy();
      reject(err);
    };

    sock.setTimeout(timeoutMs, () => finishErr(new Error('Таймаут TCP соединения')));
    sock.once('error', finishErr);
    sock.once('connect', () => {
      if (done) return;
      done = true;
      const ms = Math.max(1, Math.round(performance.now() - start));
      sock.destroy();
      resolve(ms);
    });
  });
}

// Прямой HTTP/HTTPS запрос с кастомными заголовками (Shadowrocket/v2rayNG/Throne + x-hwid),
// поддержкой редиректов (301/302/307/308) и захватом заголовков ответа подписки
export async function fetchDirectWithHeaders(
  urlStr: string,
  headers: Record<string, string>,
  timeoutMs = 10000,
  maxRedirects = 3
): Promise<{
  statusCode: number;
  body: string;
  headers: Record<string, string | undefined>;
  elapsedMs: number;
}> {
  const startedAt = performance.now();

  const doRequest = (
    currentUrl: string,
    redirectsLeft: number
  ): Promise<{
    statusCode: number;
    body: string;
    headers: Record<string, string | undefined>;
    elapsedMs: number;
  }> =>
    new Promise((resolve, reject) => {
      let parsed: URL;
      try {
        parsed = new URL(currentUrl);
      } catch (err) {
        reject(err);
        return;
      }
      const isHttps = parsed.protocol === 'https:';
      const lib = isHttps ? https : http;
      const req = lib.get(
        currentUrl,
        {
          headers: {
            ...headers,
            Connection: 'close',
          },
          timeout: timeoutMs,
        },
        (res) => {
          const code = res.statusCode ?? 0;
          const loc = res.headers.location;
          if (
            redirectsLeft > 0 &&
            loc &&
            (code === 301 || code === 302 || code === 303 || code === 307 || code === 308)
          ) {
            res.resume();
            const nextUrl = new URL(loc, currentUrl).toString();
            doRequest(nextUrl, redirectsLeft - 1).then(resolve, reject);
            return;
          }

          const flatHeaders: Record<string, string | undefined> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (Array.isArray(v)) {
              flatHeaders[k.toLowerCase()] = v.join(', ');
            } else if (typeof v === 'string') {
              flatHeaders[k.toLowerCase()] = v;
            }
          }

          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => {
            resolve({
              statusCode: code,
              body: Buffer.concat(chunks).toString('utf-8'),
              headers: flatHeaders,
              elapsedMs: Math.round(performance.now() - startedAt),
            });
          });
        }
      );
      req.on('error', reject);
      req.on('timeout', () => req.destroy(new Error('Таймаут загрузки подписки')));
    });

  return doRequest(urlStr, maxRedirects);
}

// Быстрое сканирование локальных портов 127.0.0.1 для обнаружения запущенных сторонних VPN-клиентов
export async function scanLocalLoopbackPorts(
  ports: number[],
  timeoutMs = 260
): Promise<Array<{ port: number; open: boolean; latencyMs: number | null }>> {
  return Promise.all(
    ports.map(async (port) => {
      try {
        const ms = await measureTcpLatency('127.0.0.1', port, timeoutMs);
        return { port, open: true, latencyMs: ms };
      } catch {
        return { port, open: false, latencyMs: null };
      }
    })
  );
}
