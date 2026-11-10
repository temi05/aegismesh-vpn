// Вспомогательный скрипт запуска Electron в режиме разработки после готовности Vite (порт 5173)
import { spawn } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';

function waitForPort(port: number, timeoutMs = 20000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve) => {
    const attempt = () => {
      const sock = net.connect(port, '127.0.0.1');
      sock.setTimeout(500);
      sock.once('connect', () => {
        sock.destroy();
        resolve(true);
      });
      sock.once('error', () => {
        sock.destroy();
        if (Date.now() > deadline) resolve(false);
        else setTimeout(attempt, 250);
      });
      sock.once('timeout', () => {
        sock.destroy();
        if (Date.now() > deadline) resolve(false);
        else setTimeout(attempt, 250);
      });
    };
    attempt();
  });
}

async function run() {
  const ready = await waitForPort(5173);
  if (!ready) {
    console.error('Не удалось дождаться старта Vite на порту 5173');
    process.exit(1);
  }
  const electronBin = path.resolve(
    process.cwd(),
    'node_modules',
    '.bin',
    process.platform === 'win32' ? 'electron.cmd' : 'electron'
  );
  const mainEntry = path.resolve(process.cwd(), 'dist', 'electron', 'electron', 'main.js');
  const child = spawn(electronBin, [mainEntry], {
    stdio: 'inherit',
    env: { ...process.env, NODE_ENV: 'development' },
    shell: process.platform === 'win32',
  });
  child.on('exit', (code) => process.exit(code ?? 0));
}

void run();
