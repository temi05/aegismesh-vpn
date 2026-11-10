# 🛡️ AegisMesh VPN v3.6

**Кибербезопасный мультипротокольный VPN-клиент (Windows Desktop + Android APK)** с тактическим каскадом автозамены серверов (`1 ➔ 2 ➔ 3`), аппаратным `Kill Switch`, выделенным **Умным шлюзом для Нейросетей** (`Google Gemini`, `ChatGPT`, `Grok`, `Claude`), анти-DPI маскировкой (`uTLS Chrome`, `Hysteria2 Port Hopping`, `xudp`), бесшовным роумингом сетей (`Wi-Fi 1 ⇄ Wi-Fi 2 ⇄ LTE`) и встроенным **автообновлением в 1 клик из GitHub Releases**.

---

## 🚀 Ключевые возможности

- **Тактический каскад Автозамены (`1 ➔ 2 ➔ 3`) и Smart Score (`0–100 ★`):**
  - Многоволновая параллельная гонка резервов (`Parallel Hedged Race`) между всеми подписками и протоколами (`VLESS Reality`, `Hysteria2 [HY2]`, `TUIC v5`, `WireGuard`, `VMess`, `Trojan`, `Shadowsocks`).
  - Анти-DPI усиление ядра `sing-box`: подмена TLS-отпечатка браузера **uTLS Chrome (`utls.fingerprint: "chrome"`)**, **Hysteria2 Port Hopping (`mport` / `server_ports` + `hop_interval`)** для обхода блокировки UDP-портов и **Full-Cone NAT (`packet_encoding: "xudp"`)** для звонков и игр.
  - Раздельная память лучших серверов для домашнего `🏠 Wi-Fi` и мобильного интернета `📶 LTE/4G/5G` с переключением за `≤ 1.5 сек`.
  - Автоматический 45-секундный карантин с экспоненциальным backoff, авто-реабилитацией и защитой от полного отключения (`Mass-Offline Guard`).
- **🤖 Выделенный Умный шлюз для Нейросетей (`proxy-ai` + `dns-ai`):**
  - Маршрутизирует трафик `Google Gemini`, `ChatGPT`, `Grok`, `Claude`, `Perplexity`, `Copilot` и `DeepSeek` через отдельный чистый зарубежный сервер, даже если основной VPN подключён к скоростному российскому узлу или мобильному релею `[через РФ]` / `LTE #1`.
  - **Защита голосового режима (`WebRTC / Voice AI Gateway`):** сохраняет работу `UDP` для `ChatGPT Advanced Voice (LiveKit)` и `Gemini Live` (`UDP:3478/5349/50000-65535`), блокируя только `UDP:443` (QUIC) для предотвращения утечки гео-сессии.
  - Глубокая двухконтурная проверка геолокации: сверяет регион в базе **Google GFE (`youtube.com/sw.js_data` + `WIZ_global_data`)** и **Cloudflare (`cdn-cgi/trace`)**, автоматически отсекая серверы «YouTube без рекламы» (`Cloudflare=NL`, но `Google=RU`) и транзитные релеи.
  - «Липкий» ИИ-туннель (`Sticky AI Tunnel`): не рвёт открытый голосовой или текстовый диалог с нейросетью при переключениях основного VPN.
- **🔄 Автообновление в 1 клик (`In-App Updater`) и GitHub Actions CI/CD:**
  - Встроенный модуль проверки и установки обновлений напрямую из `GitHub Releases` (`temi05/aegismesh-vpn/releases/latest`) с отображением `Release Notes` и нативной установкой свежего `AegisMesh-VPN.apk` через Android `FileProvider`.
  - Автоматический пайплайн **GitHub Actions CI/CD** (`.github/workflows/ci.yml`): при каждом `git push` и создании тега `v*` прогоняет все автотесты, загружает и верифицирует нативное ядро `libsingbox.so`, собирает подписанный `AegisMesh-VPN.apk` + `SHA-256` и публикует их в GitHub Releases.
- **📱 Нативное Android-ядро (`VpnService` + `libsingbox.so` + `hev-socks5-tunnel`):**
  - Сверхбыстрое переключение серверов (`~25 мс`) через `Clash API` без пересоздания `TUN`-интерфейса.
  - Бесшовный роуминг `Wi-Fi ⇄ LTE` (`ConnectivityManager.NetworkCallback` + `setUnderlyingNetworks` + адаптивный `MTU 1360/1400`).
  - Нативный сторож `24/7`, плитка быстрых настроек (`Quick Settings Tile`), виджет рабочего стола и пульт из 3 кнопок в шторке уведомлений (`🔄 Сменить VPN`, `🤖 Сменить ИИ`, `📴 Стоп`).
- **🔐 Криптографический сейф `SecureVault`:**
  - Шифрование всех ключей и подписок на диске по стандарту `AES-256-GCM + scrypt` с поддержкой персонального PIN-кода.

---

## 🧪 Автотесты и «Адский стресс-стенд»

В проекте реализовано **20 боевых тестовых наборов** (`tests/aegismesh.test.ts`), включая нагрузочный **«Адский стресс-стенд» на 240 враждебных серверов**, проверку анти-DPI конфигураций (`uTLS Chrome`, `Hysteria2 mport`, `xudp`), защиту `WebRTC/Voice AI` и тестирование `In-App Updater`:

```bash
npm test
```

---

## 🛠️ Сборка и запуск

### 1. Десктопная версия (Windows / Electron)
```bash
npm install
npm run build
npx electron .
```

### 2. Мобильная сборка Android (`.apk`)
```bash
npm run ensure:singbox-android
npm run build
npx cap sync android
cd android
.\gradlew.bat assembleDebug
```
> Примечание: команда `npm run ensure:singbox-android` (`scripts/ensure-singbox-android.mjs`) автоматически скачивает и проверяет по ELF-сигнатуре официальное нативное ядро `sing-box v1.14.4` (`android-arm64`) в `android/app/src/main/jniLibs/arm64-v8a/libsingbox.so`.

