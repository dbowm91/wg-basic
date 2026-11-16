# Operator UI polish roadmap

Status: planned 2026-11-16. Phase 12 workstream. No implementation has landed.

Date: 2026-11-16

Repository baseline: `0119227ae2849937a8921016fb42984838634e15`.

Canonical references:

- `plans/000-long-term-specification.md` §3 (wg-easy is UX reference; matching every feature is not required for the first release — this roadmap is the later polish pass)
- `plans/002-long-term-roadmap.md` §14
- `plans/003-planning-process.md`
- `plans/adr/012-authentication-expansion-totp-oidc.md` (account/login surfaces)
- `plans/adr/013-observability-metrics-and-telemetry-history.md` (sparkline data)

Related work this roadmap does not own:

- Auth API semantics (operator-auth-expansion).
- Prometheus/JSON scrape and history **storage** (observability-metrics); this roadmap owns in-app rendering of history once the read API exists.
- i18n, Gravatar, AmneziaWG, hooks (remain deferred).

## 1. Purpose

Raise the embedded operator shell’s finish quality toward wg-easy: **system/light/dark theme with a switcher**, denser clearer layout, and **Tx/Rx sparklines**, while remaining a **self-contained** embedded UI (no third-party CDN fonts, icons, or chart libraries where first-party alternatives suffice).

Maintainer decisions: larger embedded shell is acceptable; avoid third-party assets where able.

## 2. Ownership boundary

Owns:

- embedded asset size ceilings and inventory discipline;
- theme tokens, `prefers-color-scheme`, and System/Light/Dark switcher persistence;
- visual/layout polish of existing product pages (setup, clients, telemetry, audit, enrollment);
- sparkline widgets consuming the authenticated history API;
- ensuring enrollment pages follow the same theme tokens.

Does not own:

- introducing a SPA framework or npm build pipeline (stays buildless `include_str!` assets unless a later ADR says otherwise);
- metrics enablement, Bearer secrets, or sample retention;
- bulk multi-select client ops (optional later polish; not required for this roadmap’s closure).

## 3. Invariants

1. Assets remain embedded in the binary and served from the closed inventory table.
2. No script/style loaded from a third-party origin in production assets.
3. Theme default is **System**; explicit Light/Dark overrides persist client-side (`localStorage` is enough).
4. Sparklines are decorative operational UX; missing history never blocks mutations.
5. Auth and product CSRF/Host rules are unchanged by CSS/JS polish.

## 4. Current repository evidence

- `src/http/assets/{index.html,app.css,app.js,enroll.html,enroll.js}` embedded via `assets.rs`.
- Ceilings: `MAX_EMBEDDED_ASSET_BYTES = 48 KiB` total, `28 KiB` per file. Measured ~43.5 KiB total; `app.js` ~26.8 KiB.
- CSS already sets `color-scheme: light dark` and a `@media (prefers-color-scheme: dark)` palette. **No switcher**, no `localStorage` theme key.
- Telemetry cards refresh live bytes/handshake; no chart.

## 5. Dependency graph

```text
Maintainer ceiling decision (this roadmap)
        |
        v
M001  raise ceilings + theme switcher (+ enroll parity)   [ready]
        |
        v
M002  visual polish pass (layout, density, empty states) [ready after M001]
        |
        +---- observability M003 history API (hard for charts)
        |
        v
M003  Tx/Rx sparklines from history API                  [ready after M002 + obs M003]
```

Auth M001–M004 may land in parallel and will share the raised ceilings; coordinate conflicts in `app.js` size rather than blocking this roadmap on auth.

## 6. Milestones

| Milestone | Class | Status | Plan |
|---|---|---|---|
| M001 theme switcher + asset ceilings | polish / infrastructure | **ready** | `plans/implementation/operator-ui-polish/001-theme-switcher-and-asset-ceilings.md` |
| M002 visual polish | polish | planned (hard: M001) | `plans/implementation/operator-ui-polish/002-visual-polish.md` |
| M003 sparklines | polish / capability | planned (hard: M002 + observability M003) | `plans/implementation/operator-ui-polish/003-telemetry-sparklines.md` |

## 7. Cross-cutting concerns

- **Size.** New ceilings (suggested floor for planning): total **128 KiB**, per-file **64 KiB**. Milestones may raise further with justification in the closure record; they must keep an explicit ceiling and inventory tests.
- **Accessibility.** Theme switcher is a real control with a name; contrast holds in all three modes.
- **Enrollment.** Public enroll page follows theme tokens without requiring login storage when possible (system default + optional local override).

## 8. Deferred

| Item | Disposition |
|---|---|
| i18n / multilanguage | Deferred |
| Gravatar | Deferred (would be third-party) |
| Bulk multi-select | Optional later |
| SPA framework | Requires a new ADR |

## 9. Risks

- Auth and UI milestones editing `app.js` concurrently — integrate on one branch or sequence merges carefully.
- Sparkline JS blowing ceilings — M003 stop if first-party chart code cannot fit; split an `charts.js` asset rather than adding a CDN.
