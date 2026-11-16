# Observability metrics M003 — Bounded telemetry history

Status: planned (hard dependency: M002 closed)

Repository baseline: set at observability M002 closure head when this plan becomes ready.

Source roadmap: `plans/subsystems/observability-metrics-roadmap.md` M003

Canonical requirements and ADRs: ADR-013 §2.5; ADR-004 (history is not desired state).

Primary work class: capability / infrastructure

Hard dependencies: observability-metrics M002 closed.

Interface dependency for UI: operator-ui-polish M003 consumes this API (soft/interface from this side).

## Objective

While `serve` is up and a server is configured, record periodic per-client rx/tx/handshake samples into a **capped** SQLite cache and expose an authenticated history read for sparklines — without advancing DesiredGeneration or coupling reconcile to history.

## Explicit non-goals

- No long-term TSDB.
- No Prometheus remote-write.
- No drawing sparklines (UI polish M003).
- No sample loop inside `netd`.

## Current repository evidence

- After M002: scrape paths reuse an observe snapshot builder.
- Product telemetry join already maps peers to client ids/names.

## Invariants

- Default sample interval **30s**; retention newest **N = 120** samples per client (~1h) unless closure records a justified constant change.
- Sampler runs only when a managed server exists; idle otherwise.
- Insert/prune happens in worker-owned store transactions; HTTP never opens SQLite.
- DesiredGeneration unchanged by sampling.
- Client delete removes that client’s samples.
- Authenticated GET history API: session + Host policy; CSRF not required (safe method); bounded response.
- Crash/restore may lose or truncate history; product remains correct.

## Expected production changes

1. Schema: `telemetry_samples` (client_id, observed_at_unix, rx_bytes, tx_bytes, handshake_age_seconds nullable) + indexes for (client_id, observed_at).
2. Worker sampler wake integrated with runtime (similar discipline to expiry sleep — no busy poll).
3. `GET /api/v1/clients/<uuid>/telemetry-history` (or a batch history endpoint for the UI — prefer one batch GET with explicit client id list ceiling to avoid N+1).
4. Prune on write and on startup.

## Ordered work packages

1. Migration + store prune/insert/list.
2. Sampler in management runtime.
3. Authenticated read API (single + batch as needed).
4. Tests for retention cap, delete cascade, generation unchanged.
5. Docs.

## Privilege and security effects

History reveals traffic volumes to session holders (already implied by live telemetry). No unauthenticated history route.

## Persistence, protocol, and configuration compatibility

Additive schema. Backup includes samples unless explicitly excluded — prefer **include** but document size; optional purge command is out of scope unless cheap.

## Failure, cancellation, restart, and contention

- Observe failure: skip sample; do not poison settings.
- Restart: resume sampling; do not backfill gaps.
- Contention with mutations: sampler uses observe+insert; MUST NOT starve reconcile — schedule after ordinary work or use the same single worker queue with low priority command.

## Focused tests

- Insert 121st sample drops oldest for that client.
- Delete client → no leftover samples.
- History GET requires session; returns chronological points.
- DesiredGeneration identical before/after sampling in a controlled test.
- No sample rows when server unset.

## Linux and network-namespace integration evidence

Optional: rootful observe producing non-zero counters then assert samples increase — only if cheap against existing fixtures. Not mandatory if host-free observe stubs already prove the store path.

## Broad verification commands

Ordinary gates; rootful only if used above.

## Documentation updates

`architecture/product-management.md` / management-http: history is operational cache; Prometheus for long range; interval and N constants.

## Acceptance criteria

1. Samples accumulate under the cap while serve runs with clients.
2. Authenticated history API returns points UI polish M003 can chart.
3. Reconcile/generation behavior unchanged.

## Stop conditions

- Advancing DesiredGeneration from sampling.
- Unbounded sample growth.
- Sampling from HTTP threads with direct rusqlite.

## Closure evidence requirements

Measured row counts under load test; API examples; confirmation UI polish M003 can start.
