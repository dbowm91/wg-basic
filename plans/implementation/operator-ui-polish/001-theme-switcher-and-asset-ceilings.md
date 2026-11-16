# Operator UI polish M001 — Theme switcher and asset ceilings

Status: **ready**

Repository baseline: `0119227ae2849937a8921016fb42984838634e15`

Source roadmap: `plans/subsystems/operator-ui-polish-roadmap.md` M001

Canonical requirements and ADRs:

- `plans/adr/013-observability-metrics-and-telemetry-history.md` §2.6 (first-party assets)
- Maintainer decisions 2026-11-16: larger shell OK; no third-party assets where able
- `plans/subsystems/operator-parity-roadmap.md` §10 (dark mode was deferred; this roadmap owns it)

Primary work class: polish / infrastructure

Hard dependencies: none beyond maintainer ceiling decision (recorded in roadmap).

## Objective

Raise embedded asset ceilings so Phase 12 UI/auth work fits, and add a **System / Light / Dark** theme switcher that defaults to System (already partially implemented via CSS) with an explicit override and persistence.

## Explicit non-goals

- No visual redesign beyond what the switcher needs (M002).
- No sparklines (M003).
- No CDN fonts/icons/themes.
- No server-side theme preference schema (client `localStorage` is enough).

## Current repository evidence

- `app.css` already defines light tokens and `@media (prefers-color-scheme: dark)` overrides; `color-scheme: light dark`.
- No `[data-theme]` override, no switcher control, no JS theme boot.
- Ceilings: 48 KiB total / 28 KiB each; ~43.5 KiB used; `app.js` ~26.8 KiB.

## Invariants

- Default theme is System (`prefers-color-scheme`).
- Explicit Light/Dark set `data-theme` (or equivalent) on `documentElement` and persist in `localStorage`.
- Choosing System clears the override and follows OS changes (`matchMedia` listener).
- Enrollment page shares tokens and switcher behavior where practical without requiring auth.
- Inventory tests still enforce ceilings; no third-party absolute URLs in assets.

## Expected production changes

1. Raise ceilings to at least **128 KiB** total and **64 KiB** per asset (constants + tests + comment justifying reviewability bound).
2. Theme boot script inline or at top of `app.js` / enroll JS to avoid flash.
3. Accessible switcher control in the operator top bar (and enroll chrome if present).
4. CSS: explicit `[data-theme="light"]` / `[data-theme="dark"]` palettes; System continues to use media query when no data-theme.

## Ordered work packages

1. Ceiling constants + guard/inventory test updates.
2. CSS theme attribute support.
3. Switcher UI + persistence + enroll parity.
4. Assert no `https://` third-party asset references in embedded files (simple test).

## Privilege and security effects

None beyond existing unauthenticated asset serving. Theme preference is not a security boundary.

## Persistence, protocol, and configuration compatibility

No schema. No API. Purely embedded assets.

## Failure, cancellation, restart, and contention

- Invalid stored value → fall back to System.
- `localStorage` unavailable → System only; switcher still works for the tab session if feasible.

## Focused tests

- Ceiling tests updated to new bounds; current assets still under ceiling.
- Asset inventory forbids unexpected remote URLs in `app.css`/`app.js`/`index.html`/`enroll.*`.
- Optional DOM/contract test if the repo already fixtures shell strings for `data-theme` / storage key names.

## Linux and network-namespace integration evidence

None.

## Broad verification commands

Ordinary gates.

## Documentation updates

After land: short note in `architecture/management-http.md` or product-management UI section that theme is client-side System/Light/Dark. Do not claim server persistence.

## Acceptance criteria

1. Operator can select System, Light, or Dark; reload preserves explicit choice.
2. System tracks OS preference changes.
3. New ceilings are enforced; no third-party asset URLs introduced.

## Stop conditions

- Loading fonts/icons/charts from a CDN.
- Removing the ceiling entirely without a replacement bound.

## Closure evidence requirements

Measured asset sizes in the closure record; theme acceptance notes.
