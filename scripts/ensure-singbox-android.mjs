#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import zlib from 'node:zlib';
import https from 'node:https';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');

const SINGBOX_VERSION = '1.14.4';
const ARCHIVE_BASENAME = `sing-box-${SINGBOX_VERSION}-android-arm64`;
const ARCHIVE_ENTRY = `${ARCHIVE_BASENAME}/sing-box`;
const DOWNLOAD_URL = `https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/${ARCHIVE_BASENAME}.tar.gz`;

const TARGET_DIR = path.join(ROOT_DIR, 'android', 'app', 'src', 'main', 'jniLibs', 'arm64-v8a');
const TARGET_SO = path.join(TARGET_DIR, 'libsingbox.so');
const MIN_SIZE_BYTES = 10_000_000; // 10 MB

/**
 * Verifies that a file exists, exceeds 10 MB, and starts with ELF magic bytes (0x7f, 'E', 'L', 'F').
 */
function verifySingboxBinary(filePath) {
  if (!fs.existsSync(filePath)) {
    return { ok: false, reason: 'file does not exist' };
  }
  const stat = fs.statSync(filePath);
  if (stat.size <= MIN_SIZE_BYTES) {
    return { ok: false, reason: `file size ${stat.size} bytes <= ${MIN_SIZE_BYTES} bytes` };
  }
  const fd = fs.openSync(filePath, 'r');
  try {
    const magic = Buffer.alloc(4);
    const bytesRead = fs.readSync(fd, magic, 0, 4, 0);
    if (
      bytesRead < 4 ||
      magic[0] !== 0x7f ||
      magic[1] !== 0x45 || // 'E'
      magic[2] !== 0x4c || // 'L'
      magic[3] !== 0x46    // 'F'
    ) {
      return {
        ok: false,
        reason: `invalid ELF magic bytes: [${magic[0]}, ${magic[1]}, ${magic[2]}, ${magic[3]}]`,
      };
    }
  } finally {
    fs.closeSync(fd);
  }
  return { ok: true, size: stat.size };
}

/**
 * Downloads a URL to destFile, following up to maxRedirects HTTP 301/302/303/307/308 redirects.
 */
function downloadWithNodeRedirects(urlStr, destFile, maxRedirects = 8) {
  return new Promise((resolve, reject) => {
    const visit = (currentUrl, redirectsLeft) => {
      const parsed = new URL(currentUrl);
      const client = parsed.protocol === 'https:' ? https : http;
      const req = client.get(
        currentUrl,
        {
          headers: {
            'User-Agent': 'AegisMesh-VPN-Updater/3.6.0',
            Accept: 'application/octet-stream, */*',
          },
        },
        (res) => {
          const status = res.statusCode || 0;
          if ([301, 302, 303, 307, 308].includes(status) && res.headers.location) {
            res.resume();
            if (redirectsLeft <= 0) {
              reject(new Error(`Too many HTTP redirects while downloading ${urlStr}`));
              return;
            }
            const nextUrl = new URL(res.headers.location, currentUrl).toString();
            visit(nextUrl, redirectsLeft - 1);
            return;
          }
          if (status < 200 || status >= 300) {
            res.resume();
            reject(new Error(`HTTP ${status} while downloading ${currentUrl}`));
            return;
          }
          const out = fs.createWriteStream(destFile);
          res.pipe(out);
          out.on('finish', () => {
            out.close(() => resolve());
          });
          out.on('error', (err) => {
            res.destroy();
            reject(err);
          });
        }
      );
      req.on('error', reject);
      req.setTimeout(60_000, () => {
        req.destroy(new Error(`Timeout downloading ${currentUrl}`));
      });
    };
    visit(urlStr, maxRedirects);
  });
}

async function downloadArchive(urlStr, destFile) {
  try {
    await downloadWithNodeRedirects(urlStr, destFile);
    if (fs.existsSync(destFile) && fs.statSync(destFile).size > 1_000_000) {
      return;
    }
  } catch (nodeErr) {
    console.warn(`[ensure-singbox-android] Node HTTPS download attempt failed (${nodeErr.message}), trying curl fallback...`);
  }

  execFileSync('curl', ['-fsSL', '--retry', '3', '-o', destFile, urlStr], {
    stdio: 'inherit',
  });
}

/**
 * Extracts a single entry from a .tar.gz buffer using pure Node.js (POSIX ustar parser)
 * as a portable fallback if system tar is unavailable.
 */
function extractFromTarGzPureNode(tarGzPath, entryName, outputPath) {
  const compressed = fs.readFileSync(tarGzPath);
  const tarBuffer = zlib.gunzipSync(compressed);
  let offset = 0;

  while (offset + 512 <= tarBuffer.length) {
    const header = tarBuffer.subarray(offset, offset + 512);
    // Empty block indicates end of archive
    if (header.every((b) => b === 0)) {
      break;
    }

    const rawName = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/, '');
    const fullName = prefix ? `${prefix}/${rawName}` : rawName;
    const sizeOctal = header.subarray(124, 136).toString('utf8').replace(/\0.*$/, '').trim();
    const fileSize = parseInt(sizeOctal || '0', 8) || 0;

    const dataStart = offset + 512;
    const dataEnd = dataStart + fileSize;

    const normalizedFull = fullName.replace(/^\.\//, '');
    if (normalizedFull === entryName || normalizedFull.endsWith('/sing-box')) {
      fs.writeFileSync(outputPath, tarBuffer.subarray(dataStart, dataEnd));
      return true;
    }

    const paddedSize = Math.ceil(fileSize / 512) * 512;
    offset = dataStart + paddedSize;
  }

  return false;
}

async function main() {
  const existingCheck = verifySingboxBinary(TARGET_SO);
  if (existingCheck.ok) {
    fs.chmodSync(TARGET_SO, 0o755);
    console.log(
      `[ensure-singbox-android] Valid libsingbox.so already present (${existingCheck.size} bytes, ELF magic verified).`
    );
    return;
  }

  console.log(
    `[ensure-singbox-android] libsingbox.so missing or invalid (${existingCheck.reason}). Downloading sing-box v${SINGBOX_VERSION}...`
  );
  fs.mkdirSync(TARGET_DIR, { recursive: true });

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegismesh-singbox-'));
  const archivePath = path.join(tmpDir, `${ARCHIVE_BASENAME}.tar.gz`);

  try {
    await downloadArchive(DOWNLOAD_URL, archivePath);

    let extracted = false;
    try {
      execFileSync('tar', ['-xzf', archivePath, '-C', tmpDir, ARCHIVE_ENTRY], {
        stdio: 'inherit',
      });
      const extractedBin = path.join(tmpDir, ARCHIVE_BASENAME, 'sing-box');
      if (fs.existsSync(extractedBin)) {
        fs.copyFileSync(extractedBin, TARGET_SO);
        extracted = true;
      }
    } catch {
      // Fallback to pure Node tar.gz extractor
    }

    if (!extracted) {
      const ok = extractFromTarGzPureNode(archivePath, ARCHIVE_ENTRY, TARGET_SO);
      if (!ok) {
        throw new Error(`Entry ${ARCHIVE_ENTRY} not found inside ${archivePath}`);
      }
    }

    fs.chmodSync(TARGET_SO, 0o755);

    const postCheck = verifySingboxBinary(TARGET_SO);
    if (!postCheck.ok) {
      throw new Error(`Extracted libsingbox.so failed verification: ${postCheck.reason}`);
    }

    console.log(
      `[ensure-singbox-android] Successfully installed libsingbox.so (${postCheck.size} bytes, ELF 0x7f454c46, mode 0755).`
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(`[ensure-singbox-android] ERROR: ${err.message || err}`);
  process.exit(1);
});
