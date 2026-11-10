// Модуль проверки обновлений и версионирования AegisMesh VPN v3.6 (GitHub Releases + OTA APK)
import type { AppUpdateInfo } from './types';

export const APP_VERSION = '3.6.0';
export const GITHUB_REPO_SLUG = 'temi05/aegismesh-vpn';
export const GITHUB_RELEASES_LATEST_URL = `https://api.github.com/repos/${GITHUB_REPO_SLUG}/releases/latest`;
export const GITHUB_RELEASES_PAGE_URL = `https://github.com/${GITHUB_REPO_SLUG}/releases`;

/**
 * Нормализует строку версии SemVer: убирает префиксы `v`/`V`, пробелы и суффиксы сборки,
 * приводя к каноническому виду `major.minor.patch`.
 */
export function normalizeSemver(version: string): string {
  const cleaned = String(version ?? '')
    .trim()
    .replace(/^[vV]+\s*/, '');
  const match = cleaned.match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!match) {
    return cleaned || '0.0.0';
  }
  const major = Number.parseInt(match[1] || '0', 10) || 0;
  const minor = Number.parseInt(match[2] || '0', 10) || 0;
  const patch = Number.parseInt(match[3] || '0', 10) || 0;
  return `${major}.${minor}.${patch}`;
}

/**
 * Сравнивает две версии SemVer:
 * возвращает `-1`, если `a < b`; `0`, если `a == b`; `1`, если `a > b`.
 */
export function compareSemver(a: string, b: string): number {
  const partsA = normalizeSemver(a)
    .split('.')
    .map((n) => Number.parseInt(n, 10) || 0);
  const partsB = normalizeSemver(b)
    .split('.')
    .map((n) => Number.parseInt(n, 10) || 0);

  for (let i = 0; i < 3; i += 1) {
    const segA = partsA[i] ?? 0;
    const segB = partsB[i] ?? 0;
    if (segA < segB) return -1;
    if (segA > segB) return 1;
  }
  return 0;
}

/**
 * Проверяет, является ли версия-кандидат строго новее текущей установленной версии.
 */
export function isNewerSemver(currentVersion: string, candidateVersion: string): boolean {
  return compareSemver(currentVersion, candidateVersion) < 0;
}

/**
 * Создаёт начальное состояние информации об обновлении по умолчанию.
 */
export function createDefaultAppUpdateInfo(currentVersion = APP_VERSION): AppUpdateInfo {
  const normCurrent = normalizeSemver(currentVersion);
  return {
    currentVersion: normCurrent,
    latestVersion: normCurrent,
    updateAvailable: false,
    releaseTag: `v${normCurrent}`,
    releaseTitle: `AegisMesh VPN v${normCurrent}`,
    releaseNotes: '',
    publishedAt: null,
    htmlUrl: GITHUB_RELEASES_PAGE_URL,
    apkDownloadUrl: null,
    apkSizeBytes: null,
    desktopDownloadUrl: null,
    checkedAt: Date.now(),
    downloading: false,
    downloadProgress: 0,
    statusMessage: null,
    error: null,
  };
}

/**
 * Безопасно разбирает JSON-ответ GitHub API (`/releases/latest` или список `/releases`)
 * и формирует структуру `AppUpdateInfo` с прямыми ссылками на `.apk` и десктопный установщик.
 */
export function parseGitHubReleasePayload(
  rawPayload: unknown,
  currentVersion = APP_VERSION
): AppUpdateInfo {
  const normCurrent = normalizeSemver(currentVersion);
  let parsed: unknown = rawPayload;
  if (typeof rawPayload === 'string') {
    try {
      parsed = JSON.parse(rawPayload);
    } catch {
      parsed = null;
    }
  }

  let releaseObj: Record<string, unknown> | null = null;
  if (Array.isArray(parsed)) {
    const firstNonDraft = parsed.find(
      (item) =>
        item &&
        typeof item === 'object' &&
        (item as Record<string, unknown>).draft !== true
    ) as Record<string, unknown> | undefined;
    releaseObj =
      firstNonDraft ||
      (parsed[0] && typeof parsed[0] === 'object'
        ? (parsed[0] as Record<string, unknown>)
        : null);
  } else if (parsed && typeof parsed === 'object') {
    releaseObj = parsed as Record<string, unknown>;
  }

  if (!releaseObj) {
    return createDefaultAppUpdateInfo(normCurrent);
  }

  const tagName =
    typeof releaseObj.tag_name === 'string' ? releaseObj.tag_name.trim() : '';
  const rawTitle =
    typeof releaseObj.name === 'string' ? releaseObj.name.trim() : '';
  const candidateSemverSource = tagName || rawTitle || normCurrent;
  const latestVersion = /\d+\.\d+/.test(candidateSemverSource)
    ? normalizeSemver(candidateSemverSource)
    : normCurrent;

  const releaseTag = tagName || `v${latestVersion}`;
  const releaseTitle = rawTitle || `AegisMesh VPN ${releaseTag}`;
  const releaseNotes =
    typeof releaseObj.body === 'string' ? releaseObj.body.trim() : '';
  const publishedAt =
    typeof releaseObj.published_at === 'string' && releaseObj.published_at.trim()
      ? releaseObj.published_at.trim()
      : null;
  const htmlUrl =
    typeof releaseObj.html_url === 'string' && releaseObj.html_url.trim()
      ? releaseObj.html_url.trim()
      : GITHUB_RELEASES_PAGE_URL;

  let apkDownloadUrl: string | null = null;
  let apkSizeBytes: number | null = null;
  let desktopDownloadUrl: string | null = null;

  const assets = Array.isArray(releaseObj.assets)
    ? (releaseObj.assets as Array<Record<string, unknown>>)
    : [];

  for (const asset of assets) {
    if (!asset || typeof asset !== 'object') continue;
    const assetName = typeof asset.name === 'string' ? asset.name.trim() : '';
    const downloadUrl =
      typeof asset.browser_download_url === 'string'
        ? asset.browser_download_url.trim()
        : '';
    if (!downloadUrl) continue;

    if (
      !apkDownloadUrl &&
      (/\.apk$/i.test(assetName) || /\.apk(?:$|\?)/i.test(downloadUrl))
    ) {
      apkDownloadUrl = downloadUrl;
      apkSizeBytes =
        typeof asset.size === 'number' && asset.size > 0 ? asset.size : null;
      continue;
    }

    if (
      !desktopDownloadUrl &&
      /\.(exe|msi|zip|appimage|deb|dmg|tar\.gz)$/i.test(assetName || downloadUrl)
    ) {
      desktopDownloadUrl = downloadUrl;
    }
  }

  if (!apkDownloadUrl && tagName) {
    apkDownloadUrl = `https://github.com/${GITHUB_REPO_SLUG}/releases/download/${tagName}/AegisMesh-VPN.apk`;
  }

  if (!desktopDownloadUrl) {
    desktopDownloadUrl = htmlUrl;
  }

  const hasValidVersionSignal = Boolean(tagName || /\d+\.\d+/.test(rawTitle));
  const updateAvailable =
    hasValidVersionSignal && isNewerSemver(normCurrent, latestVersion);

  return {
    currentVersion: normCurrent,
    latestVersion,
    updateAvailable,
    releaseTag,
    releaseTitle,
    releaseNotes,
    publishedAt,
    htmlUrl,
    apkDownloadUrl,
    apkSizeBytes,
    desktopDownloadUrl,
    checkedAt: Date.now(),
    downloading: false,
    downloadProgress: 0,
    statusMessage: null,
    error: null,
  };
}
