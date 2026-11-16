# Observability metrics M001 — Prometheus scrape

Status: **ready**

Repository baseline: `0119227ae2849937a8921016fb42984838634e15`

Source roadmap: `plans/subsystems/observability-metrics-roadmap.md` M001

Canonical requirements and ADRs:

- `plans/adr/013-observability-metrics-and-telemetry-history.md`
- `plans/000-long-term-specification.md` §19
- S001 lesson: separate admission for unauthenticated reads (`plans/closure/security-audit/001-status.md`)

Primary work class: capability

Hard dependencies: ADR-013 accepted (done).

## Objective

Expose `GET /metrics/prometheus` with enable flag, optional Bearer (Argon2id), loopback-only when enabled without secret, dedicated scrape limiter, and label set including `client_id` and `name`.

## Explicit non-goals

- No JSON metrics (M002).
- No sample history (M003).
- No UI charts.
- No endpoint-as-label series.
- No OpenMetrics protobuf.

## Current repository evidence

- `GET /api/v1/clients/telemetry` performs the observe join.
- `/healthz` has its own limiter; login limiter is separate.
- No metrics settings or routes.

## Invariants

- Default disabled.
- Enabled + no Bearer secret ⇒ loopback peers only.
- Enabled + Bearer secret ⇒ valid Bearer required for all peers.
- Session cookies are ignored for authorization on this route.
- Series use labels from ADR-013; escape label values.
- Connected gauge uses handshake age < 10 minutes.
- Scrape admission is a dedicated limiter consulted before worker observe.
- Observe path does not write desired state.

## Expected production changes

1. Durable settings: `prometheus_enabled`, optional metrics password PHC (shared with JSON later).
2. Authenticated admin API (and/or CLI) to enable/disable and set/clear Bearer password.
3. `GET /metrics/prometheus` text exposition.
4. Dedicated `LoginLimiter`-style scrape limiter (capacity chosen in implementation; document in closure).
5. Architecture/management-http docs after land.

## Ordered work packages

1. Settings schema + worker commands.
2. Exposition builder from telemetry snapshot (shared helper with future JSON).
3. Route + authz + limiter wiring.
4. Tests; docs.

## Privilege and security effects

New unauthenticated (Bearer/loopback) surface on `serve`. Must not leak private keys or PSK. Public keys in labels are acceptable if JSON/wg-easy also expose them — prefer **not** putting public keys in Prometheus labels (use `client_id`/`name` only) to limit cardinality and PII-adjacent churn.

## Persistence, protocol, and configuration compatibility

Additive migration for settings. DesiredGeneration unchanged.

## Failure, cancellation, restart, and contention

- `netd` down: scrape returns empty peer series or HTTP 503 — pick fail-closed **503** when observe cannot run and document it.
- Limiter exhausted: 503 (same family as health admission).
- Settings race: enable flag read at request time.

## Focused tests

- Disabled → 404 or 400 (pick one; wg-easy uses 400 “not enabled”; either is fine if documented).
- Enabled without secret: loopback 200; non-loopback refused.
- Enabled with secret: wrong/missing Bearer 401; correct 200.
- Body contains HELP/TYPE and `client_id` + `name` labels when clients exist.
- Endpoint IP:port does not appear as a label key/value identity.
- Limiter isolates from login slots (flood scrape; login still admits).

## Linux and network-namespace integration evidence

Not required for exposition correctness. Optional: one rootful observe smoke if an existing suite already covers telemetry; do not invent a new topology solely for metrics.

## Broad verification commands

Ordinary gates. Rootful only if an existing telemetry-related suite is the cheapest regression proof.

## Documentation updates

After land: `architecture/management-http.md`, operations runbook scrape example (Prometheus YAML), note loopback-vs-Bearer policy difference from wg-easy.

## Acceptance criteria

1. Operators can enable Prometheus and scrape with Bearer or loopback policy.
2. Labels include stable `client_id` and human `name`.
3. Scrape floods do not consume login admission tokens.

## Stop conditions

- Session-cookie auth as the only scrape auth.
- Open scrape on non-loopback with empty secret.
- Writing telemetry into desired state.

## Closure evidence requirements

Example scrape body (redacted), limiter test evidence, settings API paths.
