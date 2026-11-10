// Автономный запуск бэкенд-сервера AegisMesh VPN (для веб-режима, разработки и мобильного Wi-Fi пульта)
import path from 'node:path';
import { LocalApiServer } from './apiServer';
import { VpnEngine } from './vpnEngine';

const storageDir = path.resolve(process.cwd(), '.aegismesh-data');
const staticDir = path.resolve(process.cwd(), 'dist', 'renderer');

const engine = new VpnEngine(storageDir);
const apiServer = new LocalApiServer(engine, staticDir);

async function bootstrap() {
  const port = await apiServer.start(18940);
  console.log(`[AegisMesh VPN] Локальный сервер управления запущен: http://127.0.0.1:${port}`);
}

void bootstrap();

const gracefulExit = async () => {
  await apiServer.stop();
  await engine.shutdown();
  process.exit(0);
};

process.on('SIGINT', () => void gracefulExit());
process.on('SIGTERM', () => void gracefulExit());
