# AegisMesh VPN — Stitch Architecture & Site Map

- **Stitch Project ID:** `16481386692824705431`
- **Design System Asset:** `assets/9dfefff40f19401693137a7ba8c672f3` (*Tactical Telemetry*)
- **Primary Screen ID:** `20a19dd22930443fb59920255ab7b8e5`

## 1. Визуальная концепция (Tactical Telemetry)
- **Базовый холст (`#070A0F`)** с миллиметровой тактической сеткой (`32px × 32px`, `rgba(142, 158, 181, 0.03)`).
- **Карточки узлов (`#0d131e` / `#161c27`)** с тонкими контурами `#3b4a3f` и направленным свечением активного щита (`#00F59B`), резервного узла (`#FFB020`), холодного резерва (`#00D2FF`) и аварийного Kill Switch (`#FF3B5C`).
- **Типографика:** `Space Grotesk` (структурные заголовки), `Manrope` (русскоязычный интерфейс), `JetBrains Mono` (IP-адреса, пинг, порты, шифры).

## 2. Карта экранов приложения
- [x] `ShieldCascadeView` — Тактический командный центр Bento 12-col (Центральный щит + Каскад `1 ➔ 2 ➔ 3` с анимированными кондуитами + Лабораторный стенд Auto-Failover + Правая колонка «Киберзащита и Модули», «Быстрый импорт ключа» и «Мобильный Мост QR»).
- [x] `NodesVaultView` — Полное управление своими VPN-ключами, подписками и приоритетами очереди.
- [x] `RoutingSecurityView` — Расширенные правила Split Tunneling, DoH DNS, ядро `sing-box` и PIN-код сейфа `AES-256-GCM`.
- [x] `DiagnosticsAuditView` — Сканер IP/DNS утечек и журнал переключений Failover.
- [x] `MobileBridgeView` — Автономный мобильный профиль `sing-box` по QR и Wi-Fi пульт.
