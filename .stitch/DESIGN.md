---
name: Tactical Telemetry
colors:
  surface: '#0d131e'
  surface-dim: '#0d131e'
  surface-bright: '#333946'
  surface-container-lowest: '#080e19'
  surface-container-low: '#161c27'
  surface-container: '#1a202b'
  surface-container-high: '#242a36'
  surface-container-highest: '#2f3541'
  on-surface: '#dde2f2'
  on-surface-variant: '#b9cbbd'
  inverse-surface: '#dde2f2'
  inverse-on-surface: '#2b303d'
  outline: '#849588'
  outline-variant: '#3b4a3f'
  surface-tint: '#00e38f'
  primary: '#cdffdc'
  on-primary: '#003920'
  primary-container: '#00f59b'
  on-primary-container: '#006b41'
  inverse-primary: '#006d42'
  secondary: '#a5e7ff'
  on-secondary: '#003543'
  secondary-container: '#00d2ff'
  on-secondary-container: '#00566a'
  tertiary: '#fff0f0'
  on-tertiary: '#68001a'
  tertiary-container: '#ffcacb'
  on-tertiary-container: '#bc0036'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#53ffab'
  primary-fixed-dim: '#00e38f'
  on-primary-fixed: '#002111'
  on-primary-fixed-variant: '#005231'
  secondary-fixed: '#b6ebff'
  secondary-fixed-dim: '#47d6ff'
  on-secondary-fixed: '#001f28'
  on-secondary-fixed-variant: '#004e60'
  tertiary-fixed: '#ffdada'
  tertiary-fixed-dim: '#ffb3b6'
  on-tertiary-fixed: '#40000c'
  on-tertiary-fixed-variant: '#920028'
  background: '#0d131e'
  on-background: '#dde2f2'
  surface-variant: '#2f3541'
typography:
  display-xl:
    fontFamily: Space Grotesk
    fontSize: 3rem
    fontWeight: '700'
    lineHeight: 3.5rem
    letterSpacing: -0.02em
  display-xl-mobile:
    fontFamily: Space Grotesk
    fontSize: 2rem
    fontWeight: '700'
    lineHeight: 2.5rem
    letterSpacing: -0.01em
  headline-lg:
    fontFamily: Space Grotesk
    fontSize: 2rem
    fontWeight: '600'
    lineHeight: 2.5rem
    letterSpacing: -0.01em
  headline-lg-mobile:
    fontFamily: Space Grotesk
    fontSize: 1.5rem
    fontWeight: '600'
    lineHeight: 2rem
    letterSpacing: '0'
  headline-md:
    fontFamily: Space Grotesk
    fontSize: 1.25rem
    fontWeight: '600'
    lineHeight: 1.75rem
    letterSpacing: 0.01em
  body-lg:
    fontFamily: Manrope
    fontSize: 1rem
    fontWeight: '500'
    lineHeight: 1.5rem
  body-md:
    fontFamily: Manrope
    fontSize: 0.875rem
    fontWeight: '400'
    lineHeight: 1.25rem
  body-sm:
    fontFamily: Manrope
    fontSize: 0.75rem
    fontWeight: '400'
    lineHeight: 1rem
  telemetry-lg:
    fontFamily: JetBrains Mono
    fontSize: 1.125rem
    fontWeight: '600'
    lineHeight: 1.5rem
    letterSpacing: -0.02em
  telemetry-md:
    fontFamily: JetBrains Mono
    fontSize: 0.875rem
    fontWeight: '500'
    lineHeight: 1.25rem
    letterSpacing: '0'
  telemetry-sm:
    fontFamily: JetBrains Mono
    fontSize: 0.75rem
    fontWeight: '400'
    lineHeight: 1rem
    letterSpacing: 0.04em
  badge-code:
    fontFamily: JetBrains Mono
    fontSize: 0.6875rem
    fontWeight: '700'
    lineHeight: 0.875rem
    letterSpacing: 0.06em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-desktop: 1.5rem
  margin: 1rem
  margin-desktop: 2rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1.25rem
  space-xl: 2rem
---

## Brand & Style

This design system targets elite cybersecurity analysts, systems engineers, and network privacy specialists who require instantaneous status comprehension and operational control. The aesthetic merges military avionics, mission-critical network ops (NOC), and high-fidelity cyber-defense dashboards.

The emotional signature is calculating, impregnable, and technologically dominant. It avoids consumer-grade minimalism in favor of structured data density, hard structural ergonomics, and reactive telemetry feedback. The visual style balances low-reflectance carbon surfaces with razor-sharp luminous accents, providing uncompromising visibility in low-light tactical environments.

## Colors

The chromatic palette is grounded in deeply stratified, low-noise dark surfaces calibrated to eliminate visual fatigue while elevating signal-to-noise ratio:

- **Surfaces & Voids:**
  - `canvas-dark`: `#070A0F` (Base void, structural viewport container)
  - `canvas-subtle`: `#0B1019` (Recessed wells, secondary toolbars)
  - `surface-card`: `#0E141F` (Primary analytical cards, control nodes)
  - `surface-elevated`: `#141D2D` (Floating inspector panels, popovers, active modal frames)
  - `border-tactical`: `rgba(142, 158, 181, 0.12)` (Standard grid delineations)
  - `border-active`: `rgba(0, 245, 155, 0.4)` (Active nodes and locked tunnels)

- **Chromatics & Signals:**
  - `primary` (Neon Emerald Shield): `#00F59B` — Verified handshake, active tunnel, zero packet loss, shielded status.
  - `secondary` (Cyber Cyan): `#00D2FF` — Routing traces, protocol relays, active peer-to-peer tunnels.
  - `warning` (Amber Cascade): `#FFB020` — Latency spikes, renegotiation phase, degraded node reliability.
  - `alert` (Crimson Kill Switch): `#FF3B5C` — Breached perimeter, kill switch engagement, packet drop fail-safe.

- **Data & Readout Text:**
  - `text-primary`: `#CAD6E8` (Headers, dynamic system values, critical logs)
  - `text-secondary`: `#8E9EB5` (Labels, field descriptions, protocol headers)
  - `text-dim`: `#4B5970` (Grid lines, inactive states, structural metadata)

## Typography

The typographical structure implements a disciplined three-tier stack:

1. **Structural Headers (`Space Grotesk`):** Delivers geometric precision and technical authority across navigation anchors and high-level metric sections.
2. **Operational Text (`Manrope`):** Optimized for high-density UI rendering, wide character aperture, and flawless Cyrillic and Latin multi-script support.
3. **Telemetry & Instrument Readouts (`JetBrains Mono`):** Applied to IP addresses, cryptographic hashes, network ping intervals, cipher suites, and telemetry data tables.

All uppercase telemetry labels utilize an expanded tracking scale (`+0.04em` to `+0.06em`) for rapid scanability during critical incidents.

## Layout & Spacing

This design system enforces a modular 12-column dynamic layout designed for multi-monitor workstations, modular cyber desks, and ruggedized touchpads:

- **Desktop (>= 1280px):** 12-column grid, `margin-desktop` (2rem / 32px), `gutter-desktop` (1.5rem / 24px). Accommodates concurrent operational views: telemetry sidebar, real-time node map, traffic waterfall, and diagnostics terminal.
- **Tablet / Split View (768px - 1279px):** 8-column layout, `gutter` (1rem / 16px). Secondary telemetry panels collapse into tabbed auxiliary drawers.
- **Mobile (< 768px):** 4-column layout, compact `margin` (1rem / 16px). Cards reflow into vertical operational stacks with persistent bottom-anchored Kill Switch and shield status controls.

Vertical rhythm follows a strict 4px/8px mathematical scale to preserve alignment with monospaced data blocks and compact readout panels.

## Elevation & Depth

Visual hierarchy uses hard tonal separation, high-precision hairline borders, and localized photon luminescence:

- **Base Layer (Surface Level 0):** `#070A0F` canvas void. Non-interactive backdrop containing ambient gridlines rendered at 4% opacity.
- **Node Tier (Surface Level 1):** `#0E141F` card surfaces paired with a razor-thin 1px border (`rgba(142, 158, 181, 0.12)`). Zero cast shadow; depth is strictly architectural.
- **Active Node Glow:** Interactive or active operational modules gain an inner ambient border wash and a targeted outer glow:
  - Shield Active: `box-shadow: 0 0 16px -2px rgba(0, 245, 155, 0.25), inset 0 0 12px rgba(0, 245, 155, 0.05)`
  - Alert / Kill Switch Triggered: `box-shadow: 0 0 20px -2px rgba(255, 59, 92, 0.35), inset 0 0 14px rgba(255, 59, 92, 0.08)`
- **Overlay & Modal Tier (Surface Level 2):** Floating diagnostics palettes at `#141D2D` utilizing a 1px border (`rgba(0, 210, 255, 0.3)`) and a deep, tight perimeter shadow: `box-shadow: 0 24px 48px -8px rgba(0, 0, 0, 0.85)`.

## Shapes

The interface embraces a low-radius, tactical geometry (`roundedness: 1`, base corner radius `0.25rem` / 4px). 

Sharp geometric profiles convey hardware reliability and software precision. Rounded corners never exceed `0.5rem` (8px), reserved exclusively for large view containers and security popovers. Telemetry tags, hex monitors, and status badges preserve a tight 2px to 4px edge profile, avoiding pill-shaped or consumer-styled geometries.

## Components

### Buttons & Operational Triggers
- **Primary / Shield Engage:** Surface in `#00F59B` with high-contrast text `#070A0F`. On hover, produces an intense emerald back-glow (`0 0 20px rgba(0, 245, 155, 0.4)`).
- **Tactical Secondary:** Transparent background, 1px border in `rgba(0, 210, 255, 0.4)`, text in `#CAD6E8`. Hover shifts border to `#00D2FF` and background to `rgba(0, 210, 255, 0.08)`.
- **Kill Switch (Emergency Terminate):** High-saturation crimson background `#FF3B5C` with text `#FFFFFF`. Features an active breathing pulse animation on its border (`rgba(255, 59, 92, 0.8)`) when arming or engaged.

### Monospace Telemetry Badges & Indicators
- Compact, high-density tags using `JetBrains Mono` (`badge-code`).
- Structure: 1px border with a 10% tinted background of the matching signal color (Emerald, Cyan, Amber, Crimson).
- Includes an inline 6px glowing indicator dot with CSS keyframe pulse for live connections (`ping < 18ms`, `AES-256-GCM`).

### Cards & Network Inspector Modules
- Background `#0E141F`, framed with a precise 1px border in `rgba(142, 158, 181, 0.12)`.
- Header bars within cards utilize `#0B1019` backgrounds with integrated protocol tags and node coordinate indicators.

### Data Inputs & Filter Fields
- Background `#070A0F`, text `#CAD6E8`, and placeholder `#4B5970`.
- Focus state instantly replaces subtle borders with a 1px `#00D2FF` border and a faint cyan inner glow. No heavy outlines or default browser rings.

### Checkboxes, Toggles & Radios
- Hard-edged, square toggles with a mechanical sliding track in `#0B1019`.
- Active state snaps to `#00F59B` (Protected) or `#00D2FF` (Routed), with monospaced `[ON]` / `[OFF]` state text indicators.

### Telemetry Graph Waterfalls & Ping Streams
- Sparklines and network load visualizers feature vector strokes in `#00F59B` and `#00D2FF` over subtle, low-opacity area gradients descending into `#070A0F`.
- Grid markers render in monospaced micro-labels (`telemetry-sm`) using `#4B5970`.