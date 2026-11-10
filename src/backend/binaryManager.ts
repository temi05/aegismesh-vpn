// Менеджер официального бинарного ядра sing-box (автозагрузка, валидация конфигов и проверка прав ОС)
import { execFile, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import type { CoreBinaryStatus } from '../shared/types';

interface GithubReleaseAsset {
  name: string;
  browser_download_url: string;
  size: number;
}

interface GithubReleaseInfo {
  tag_name: string;
  prerelease: boolean;
  assets: GithubReleaseAsset[];
}

export class BinaryManager {
  private readonly binDir: string;
  private readonly binaryPath: string;
  private downloading = false;
  private downloadProgress = 0;
  private lastError?: string;
  private cachedVersion: string | null = null;
  private readonly adminFlag: boolean;

  constructor(storageRootDir: string) {
    this.binDir = path.join(storageRootDir, 'bin');
    const exeName = process.platform === 'win32' ? 'sing-box.exe' : 'sing-box';
    this.binaryPath = path.join(this.binDir, exeName);
    fs.mkdirSync(this.binDir, { recursive: true });
    this.adminFlag = this.detectAdminPrivileges();
    this.refreshVersionSync();
  }

  private detectAdminPrivileges(): boolean {
    if (process.platform === 'win32') {
      const res = spawnSync('net', ['session'], { stdio: 'ignore', windowsHide: true });
      return res.status === 0;
    }
    return typeof process.getuid === 'function' ? process.getuid() === 0 : false;
  }

  public getBinaryPath(): string {
    return this.binaryPath;
  }

  public isInstalled(): boolean {
    return fs.existsSync(this.binaryPath);
  }

  public refreshVersionSync(): string | null {
    if (!this.isInstalled()) {
      this.cachedVersion = null;
      return null;
    }
    try {
      const res = spawnSync(this.binaryPath, ['version'], {
        encoding: 'utf-8',
        timeout: 4000,
        windowsHide: true,
      });
      if (res.status === 0 && res.stdout) {
        const firstLine = res.stdout.split(/\r?\n/)[0] || '';
        const match = firstLine.match(/sing-box version\s+([^\s]+)/i);
        this.cachedVersion = match ? match[1] : firstLine.trim();
        return this.cachedVersion;
      }
    } catch {
      this.cachedVersion = null;
    }
    return this.cachedVersion;
  }

  public getStatus(): CoreBinaryStatus {
    const installed = this.isInstalled();
    return {
      installed,
      version: installed ? this.cachedVersion ?? this.refreshVersionSync() : null,
      binaryPath: this.binaryPath,
      downloading: this.downloading,
      downloadProgress: this.downloadProgress,
      engineDriver: installed ? 'hybrid' : 'native-guard',
      isAdmin: this.adminFlag,
      error: this.lastError,
    };
  }

  // Валидация сгенерированного JSON через официальную команду `sing-box check -c`
  public validateConfigFile(configPath: string): Promise<{ valid: boolean; output: string }> {
    return new Promise((resolve) => {
      if (!this.isInstalled()) {
        resolve({
          valid: false,
          output: 'Ядро sing-box ещё не установлено в папку bin/',
        });
        return;
      }
      execFile(
        this.binaryPath,
        ['check', '-c', configPath],
        { timeout: 6000, windowsHide: true },
        (err, stdout, stderr) => {
          if (err) {
            resolve({
              valid: false,
              output: `${stderr || ''} ${stdout || ''} ${err.message}`.trim(),
            });
            return;
          }
          resolve({ valid: true, output: (stdout || stderr || 'OK').trim() });
        }
      );
    });
  }

  private httpsGetJson<T>(url: string): Promise<T> {
    return new Promise((resolve, reject) => {
      const req = https.get(
        url,
        {
          headers: {
            'User-Agent': 'AegisMesh-VPN-Client/1.0',
            Accept: 'application/vnd.github+json',
          },
          timeout: 15000,
        },
        (res) => {
          if (
            res.statusCode &&
            res.statusCode >= 300 &&
            res.statusCode < 400 &&
            res.headers.location
          ) {
            this.httpsGetJson<T>(res.headers.location).then(resolve).catch(reject);
            return;
          }
          if (res.statusCode !== 200) {
            reject(new Error(`Ошибка запроса релизов GitHub: HTTP ${res.statusCode}`));
            return;
          }
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => chunks.push(chunk));
          res.on('end', () => {
            try {
              const parsed = JSON.parse(Buffer.concat(chunks).toString('utf-8')) as T;
              resolve(parsed);
            } catch (e) {
              reject(e);
            }
          });
        }
      );
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy(new Error('Таймаут запроса к GitHub API'));
      });
    });
  }

  private downloadFile(
    url: string,
    destPath: string,
    onProgress?: (pct: number) => void
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      const req = https.get(
        url,
        {
          headers: { 'User-Agent': 'AegisMesh-VPN-Client/1.0' },
          timeout: 30000,
        },
        (res) => {
          if (
            res.statusCode &&
            res.statusCode >= 300 &&
            res.statusCode < 400 &&
            res.headers.location
          ) {
            this.downloadFile(res.headers.location, destPath, onProgress)
              .then(resolve)
              .catch(reject);
            return;
          }
          if (res.statusCode !== 200) {
            reject(new Error(`Ошибка загрузки файла ядра: HTTP ${res.statusCode}`));
            return;
          }

          const total = Number(res.headers['content-length'] || 0);
          let received = 0;
          const fileStream = fs.createWriteStream(destPath);

          res.on('data', (chunk: Buffer) => {
            received += chunk.length;
            if (total > 0 && onProgress) {
              onProgress(Math.min(95, Math.round((received / total) * 95)));
            }
          });

          res.pipe(fileStream);
          fileStream.on('finish', () => {
            fileStream.close(() => resolve());
          });
          fileStream.on('error', (err) => {
            fs.rmSync(destPath, { force: true });
            reject(err);
          });
        }
      );
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy(new Error('Таймаут скачивания архива sing-box'));
      });
    });
  }

  // Автоматическая установка последнего официального стабильного релиза SagerNet/sing-box
  public async ensureInstalled(onUpdate?: () => void): Promise<CoreBinaryStatus> {
    if (this.isInstalled()) {
      this.refreshVersionSync();
      return this.getStatus();
    }
    if (this.downloading) {
      return this.getStatus();
    }

    this.downloading = true;
    this.downloadProgress = 5;
    this.lastError = undefined;
    onUpdate?.();

    const tmpExtractDir = path.join(this.binDir, `_extract_${Date.now()}`);
    let archivePath = '';

    try {
      const release = await this.httpsGetJson<GithubReleaseInfo>(
        'https://api.github.com/repos/SagerNet/sing-box/releases/latest'
      );

      const arch = os.arch() === 'arm64' ? 'arm64' : 'amd64';
      const platformKey =
        process.platform === 'win32'
          ? `windows-${arch}.zip`
          : process.platform === 'darwin'
            ? `darwin-${arch}.tar.gz`
            : `linux-${arch}.tar.gz`;

      const asset = release.assets.find((a) => a.name.endsWith(platformKey));
      if (!asset) {
        throw new Error(`Не найден бинарный пакет под платформу ${platformKey}`);
      }

      archivePath = path.join(this.binDir, asset.name);
      await this.downloadFile(asset.browser_download_url, archivePath, (pct) => {
        this.downloadProgress = pct;
        onUpdate?.();
      });

      fs.mkdirSync(tmpExtractDir, { recursive: true });
      // Используем системный tar (встроен в Windows 10/11, macOS и Linux)
      const tarRes = spawnSync('tar', ['-xf', archivePath, '-C', tmpExtractDir], {
        windowsHide: true,
      });

      if (tarRes.status !== 0 && process.platform === 'win32') {
        // Резервный метод распаковки через PowerShell Expand-Archive
        const psRes = spawnSync(
          'powershell.exe',
          [
            '-NoProfile',
            '-Command',
            `Expand-Archive -LiteralPath '${archivePath}' -DestinationPath '${tmpExtractDir}' -Force`,
          ],
          { windowsHide: true }
        );
        if (psRes.status !== 0) {
          throw new Error('Не удалось распаковать архив sing-box');
        }
      }

      // Находим исполняемый файл внутри распакованной папки
      const targetExe = process.platform === 'win32' ? 'sing-box.exe' : 'sing-box';
      const foundPath = this.findFileRecursive(tmpExtractDir, targetExe);
      if (!foundPath) {
        throw new Error(`В архиве релиза не найден исполняемый файл ${targetExe}`);
      }

      fs.copyFileSync(foundPath, this.binaryPath);
      if (process.platform !== 'win32') {
        fs.chmodSync(this.binaryPath, 0o755);
      }

      this.downloadProgress = 100;
      this.refreshVersionSync();
    } catch (err) {
      this.lastError =
        err instanceof Error ? err.message : 'Неизвестная ошибка загрузки ядра sing-box';
    } finally {
      this.downloading = false;
      if (archivePath && fs.existsSync(archivePath)) {
        fs.rmSync(archivePath, { force: true });
      }
      if (fs.existsSync(tmpExtractDir)) {
        fs.rmSync(tmpExtractDir, { recursive: true, force: true });
      }
      onUpdate?.();
    }

    return this.getStatus();
  }

  private findFileRecursive(dir: string, targetName: string): string | null {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        const sub = this.findFileRecursive(full, targetName);
        if (sub) return sub;
      } else if (entry.name.toLowerCase() === targetName.toLowerCase()) {
        return full;
      }
    }
    return null;
  }
}
