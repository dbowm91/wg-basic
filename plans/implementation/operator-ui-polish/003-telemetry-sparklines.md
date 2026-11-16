# Operator UI polish M003 — Telemetry sparklines

Status: planned (hard dependencies: UI M002 closed **and** observability-metrics M003 closed)

Repository baseline: set when both hard dependencies are closed.

Source roadmap: `plans/subsystems/operator-ui-polish-roadmap.md` M003

Canonical requirements and ADRs: ADR-013 §2.5–2.6; observability roadmap M003 API contract.

Primary work class: polish / capability

Hard dependencies: operator-ui-polish M002; observability-metrics M003.

## Objective

Render short-window **Tx/Rx sparklines** (and optionally handshake freshness) on the client/telemetry UI from the authenticated history API, using **first-party** canvas or SVG — comparable in spirit to wg-easy’s per-client traffic charts, not a Grafana replacement.

## Explicit non-goals

- No Chart.js, D3 CDN, or other third-party chart libraries.
- No durable history beyond what observability M003 stores.
- No Prometheus scrape from the browser.

## Current repository evidence

- Live telemetry cards/table from `/api/v1/clients/telemetry`.
- After observability M003: bounded history read API exists.
- After UI M002: polished layout and ceilings.

## Invariants

- Missing or empty history shows a calm empty/placeholder state; never blocks enable/disable/export.
- Points are rendered from server samples; the browser does not invent counter history.
- Theme colors use CSS variables so charts work in Light/Dark/System.
- Asset ceilings remain enforced; split `charts.js` (or similar) into the inventory if needed rather than exceeding a single-file cap.

## Expected production changes

1. Fetch history for visible clients on telemetry refresh (bounded concurrency).
2. Sparkline components for rx/tx (absolute counters plotted as series; document whether the UI shows absolute or delta — prefer **delta between samples** for readability, computed client-side from absolute samples).
3. Wire into client rows or telemetry cards.
4. `prefers-reduced-motion`: static last-point or non-animated draw.

## Ordered work packages

1. API client helper for history read.
2. First-party sparkline renderer.
3. Integrate into UI; ceiling check; tests for delta math and empty history.

## Privilege and security effects

Session-authenticated reads only. No new secrets.

## Persistence, protocol, and configuration compatibility

Consumes additive history API only.

## Failure, cancellation, restart, and contention

- History 503/empty: show placeholder.
- Truncation flag from API: still draw available points.

## Focused tests

- Delta computation unit tests.
- Renderer handles empty and single-point series.
- No third-party URLs; ceilings hold.

## Linux and network-namespace integration evidence

None required for UI. Optional manual check with sampler running.

## Broad verification commands

Ordinary gates.

## Documentation updates

Product UI section: sparklines reflect ~1 hour (or whatever N×interval observability closed with); long-range graphs use Prometheus/Grafana.

## Acceptance criteria

1. When history samples exist, Tx/Rx sparklines render per client without third-party scripts.
2. When history is empty, UI remains usable.
3. Themes apply to chart strokes/fills.

## Stop conditions

- Adding a CDN chart library.
- Writing telemetry from the browser into SQLite.

## Closure evidence requirements

Screenshots optional; size numbers required; API paths used listed.
