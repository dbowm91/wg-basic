# ADR-013 — Observability metrics and bounded telemetry history

Status: accepted

Date: 2026-11-16

Canonical references:

- `plans/000-long-term-specification.md` §19 (Prometheus/OpenMetrics MAY; avoid unbounded cardinality)
- `plans/002-long-term-roadmap.md` §14 Phase 12
- `plans/adr/003-management-http-auth-and-worker-boundary.md` (unauthenticated surfaces, admission)
- `plans/adr/004-product-management-enrollment-and-api-semantics.md` (live telemetry is non-durable **desired state**)
- `plans/003-planning-process.md`

Maintainer decisions recorded 2026-11-16:

1. Expose Prometheus metrics with **both stable client id and human `name` labels** for Grafana.
2. Also provide **wg-easy-shaped JSON metrics** and **UI sparkline history** (not Prometheus-only).

## 1. Context

Phase 8 ships authenticated `GET /api/v1/clients/telemetry`: a fresh `ObserveWireGuardDevice` join, never written to SQLite. Operator-parity deferred charts/Prometheus because “live telemetry stays non-durable” as a **desired-state** invariant — not because operators must never see history.

wg-easy exposes:

- `GET /metrics/prometheus` and `GET /metrics/json`, optional shared Bearer password (Argon2 digest), enable flags in admin settings;
- Per-peer bytes, handshake age, aggregate configured/enabled/connected gauges;
- UI Tx/Rx charts from live stats (connected ≈ handshake younger than **10 minutes**).

wg-basic needs scrape parity plus a **bounded** history store that does not become desired state or drive reconciliation.

## 2. Decision

### 2.1 Metrics are an explicit unauthenticated product surface

- Paths (wg-easy-aligned): `GET /metrics/prometheus` and `GET /metrics/json`.
- Default: both **disabled**. Enabling requires durable settings.
- Optional shared **Bearer** secret: store Argon2id PHC of the presented password (same family as admin passwords). When a secret is configured, requests without a valid `Authorization: Bearer …` receive `401`. When metrics are enabled and **no** secret is configured, only **loopback** peers may scrape; non-loopback requests receive `401`/`403` (fail closed). This is stricter than wg-easy’s “empty password means open” default and is intentional for an appliance.
- Metrics handlers MUST NOT use the administrator session cookie as auth.
- A **dedicated admission limiter** (separate from `/healthz` and login) bounds scrape floods before the management worker queue.

### 2.2 Observation path

- Scrapes and history samples obtain peer counters through the existing worker observation path (`ObserveWireGuardDevice` / product telemetry join). They do **not** open SQLite from HTTP tasks and do **not** call `netd` outside existing typed observe operations.
- Metrics NEVER write desired generations, peer intent, or convergence evidence.
- Connected peer definition for gauges matches wg-easy: last handshake younger than **10 minutes** (document the constant).

### 2.3 Prometheus cardinality and labels

Per-peer series include at least:

| Label | Purpose |
|---|---|
| `client_id` | Stable UUID; preferred for alerts |
| `name` | Operator label for Grafana readability |
| `interface` | Managed interface name |
| `enabled` | `"true"` / `"false"` |

Optional address labels (`ipv4_address`, `ipv6_address`) MAY be included when assigned.

**MUST NOT** use the peer’s current endpoint `IP:port` as a time-series label (high churn). Endpoint MAY appear in JSON metrics as a value field and MUST NOT create a new Prometheus series identity per endpoint change.

Metric names aim for operator familiarity with wg-easy where truthful:

- `wireguard_configured_peers`, `wireguard_enabled_peers`, `wireguard_connected_peers`
- `wireguard_sent_bytes`, `wireguard_received_bytes` (counters)
- `wireguard_latest_handshake_seconds` (gauge; `0` when unknown)

Help/TYPE lines are required. Label values are Prometheus-escaped.

### 2.4 JSON metrics

`GET /metrics/json` returns the aggregate counts plus a bounded per-client list (name, enabled, addresses, public key, endpoint, latest handshake, transfer rx/tx) under the same enablement and Bearer rules. Cap list size consistently with product telemetry (existing 1,024 ceiling / truncated flag pattern).

### 2.5 Bounded sparkline / history store

- History is a **derivative operational cache**, not desired state. Schema tables for samples do not advance DesiredGeneration.
- While `serve` runs and a server is configured, the management worker (or a worker-owned sampler) records periodic samples of per-client rx/tx absolute counters and handshake age. Default interval: **30 seconds**. No sample loop when no server is configured.
- Retention is bounded, for example: keep the newest **N** samples per client (suggested **N = 120** → ~1 hour at 30s) and/or drop samples older than a fixed wall window. Exact N is a milestone constant; changing it is not a generation event.
- On client delete, samples for that client are deleted in the same transaction family as other client cleanup, or by FK cascade — milestone picks one and tests it.
- Authenticated product API exposes a history read for the embedded UI (session + Host policy; safe GET). Response is bounded points suitable for sparklines.
- History MUST NOT be required for reconcile, enrollment, or disable correctness. Loss of history after restore/crash is acceptable; document it.

### 2.6 UI charts

- Sparklines render from the history API inside the embedded shell using **first-party** canvas/SVG/CSS — no Chart.js, no CDN, no third-party font/icon hosts.
- Prometheus remains the system for long-range Grafana dashboards; in-app history is short-window operational UX.

## 3. Alternatives considered

| Alternative | Why rejected |
|---|---|
| Prometheus only; no JSON/UI history | Rejected by maintainer decision. |
| Durable desired-state telemetry | Would violate Phase 8/ADR-004 authority model. |
| Endpoint-as-Prometheus-label (wg-easy) | Violates this product’s cardinality MUST in §19 of the long-term spec. |
| Unauthenticated open scrape when password empty on all binds | Too weak for a non-loopback appliance; loopback-only exception is enough for local Prometheus. |
| Third-party chart CDN in the shell | Rejected; UI must stay self-contained where able. |

## 4. Consequences

Positive:

- Grafana/Prometheus operators get familiar metric names with useful `name` labels.
- Short UI history without making telemetry authoritative.
- Separate admission protects login/mutation capacity (extends S001 lesson).

Costs:

- New unauthenticated routes and settings surface.
- SQLite growth from sample rows — must stay capped and tested.
- `name` label renames create new series; operators should key alerts on `client_id`.

## 5. Compatibility and migration

- Additive schema for metrics settings and sample tables.
- No change to WireGuard peer projection or firewall policy.
- Older binaries refuse newer schema heads.

## 6. Ownership

Subsystem roadmap: `plans/subsystems/observability-metrics-roadmap.md`.
UI consumption of history is coordinated with `plans/subsystems/operator-ui-polish-roadmap.md`.
