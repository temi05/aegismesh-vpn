// Безопасное управление системным прокси Windows (WinINET / реестр) с гарантированным автосбросом
import { spawnSync } from 'node:child_process';

const REG_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';

export class WindowsSystemProxy {
  private appliedByUs = false;

  public enable(host: string, port: number, bypassDomains: string[]): boolean {
    if (process.platform !== 'win32') return false;

    const proxyServer = `${host}:${port}`;
    const overrideList = Array.from(
      new Set([
        'localhost',
        '127.*',
        '10.*',
        '192.168.*',
        ...bypassDomains.map((d) => d.trim()).filter(Boolean),
        '<local>',
      ])
    ).join(';');

    const r1 = spawnSync(
      'reg',
      ['add', REG_KEY, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '1', '/f'],
      { windowsHide: true }
    );
    const r2 = spawnSync(
      'reg',
      ['add', REG_KEY, '/v', 'ProxyServer', '/t', 'REG_SZ', '/d', proxyServer, '/f'],
      { windowsHide: true }
    );
    spawnSync(
      'reg',
      ['add', REG_KEY, '/v', 'ProxyOverride', '/t', 'REG_SZ', '/d', overrideList, '/f'],
      { windowsHide: true }
    );

    if (r1.status === 0 && r2.status === 0) {
      this.appliedByUs = true;
      this.notifyWinInet();
      return true;
    }
    return false;
  }

  public disable(): boolean {
    if (process.platform !== 'win32') return false;
    if (!this.appliedByUs) return true;

    const r = spawnSync(
      'reg',
      ['add', REG_KEY, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '0', '/f'],
      { windowsHide: true }
    );
    this.appliedByUs = false;
    this.notifyWinInet();
    return r.status === 0;
  }

  private notifyWinInet(): void {
    if (process.platform !== 'win32') return;
    // Мягкое уведомление WinINET об изменении настроек прокси без перезагрузки браузера
    const psCode =
      '$sig = \'[DllImport("wininet.dll", SetLastError = true)] public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);\'; ' +
      '$t = Add-Type -MemberDefinition $sig -Name WinInet -Namespace Aegis -PassThru; ' +
      '[void]$t::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0); ' +
      '[void]$t::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0);';

    spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', psCode], {
      timeout: 3000,
      windowsHide: true,
    });
  }
}
