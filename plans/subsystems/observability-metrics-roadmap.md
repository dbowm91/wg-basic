# Observability metrics roadmap

Status: planned 2026-11-16. Phase 12 workstream. No implementation has landed.

Date: 2026-11-16

Repository baseline: `0119227ae2849937a8921016fb42984838634e15`.

Canonical references:

- `plans/000-long-term-specification.md` §19
- `plans/002-long-term-roadmap.md` §14
- `plans/003-planning-process.md`
- `plans/adr/003-management-http-auth-and-worker-boundary.md`
- `plans/adr/004-product-management-enrollment-and-api-semantics.md`
- `plans/adr/013-observability-metrics-and-telemetry-history.md`

Related work this roadmap does not own:

- In-app sparkline **rendering** (operator-ui-polish M003).
- Auth expansion.
- Durable traffic history beyond the bounded sample cache in ADR-013.

## 1. Purpose

Ship wg-easy-comparable **Prometheus** and **JSON** scrape endpoints with Bearer/loopback policy, plus a **bounded per-client sample history** API that the polished UI can chart — without making telemetry desired state.

## 2. Ownership boundary

Owns:

- metrics enable flags and Bearer secret settings (CLI and/or authenticated admin API);
- `GET /metrics/prometheus` and `GET /metrics/json`;
- dedicated scrape admission limiter;
- worker-owned periodic sampler and retention;
- authenticated history read API for UI/sparklines;
- cardinality/label contract from ADR-013.

Does not own:

- Grafana dashboards as product artifacts;
- changing WireGuard observe opcodes;
- UI theme or chart drawing code.

## 3. Invariants

1. Metrics and history never advance DesiredGeneration or alter peer intent.
2. HTTP tasks never open SQLite; settings and samples go through the worker.
3. Scrapes are not session-cookie authenticated.
4. Enabled metrics without a Bearer secret accept **loopback only**.
5. Prometheus labels include `client_id` and `name`; endpoint is not a label.
6. Sample retention is capped; delete client deletes or cascades samples.
7. Connected = handshake age < 10 minutes (wg-easy parity constant).

## 4. Current repository evidence

- Authenticated `GET /api/v1/clients/telemetry` joins observe results to product clients.
- S001 added a separate `/healthz` limiter; login and mutation admission remain distinct.
- No `/metrics` routes; no sample tables; schema head 10.

## 5. Dependency graph

```text
ADR-013 accepted
        |
        v
M001  Prometheus scrape + enable + Bearer/loopback     [ready]
        |
        v
M002  JSON metrics                                     [ready after M001]
        |
        v
M003  bounded sample history + authenticated read API  [ready after M002]
```

UI polish M003 hard-depends on this M003.

## 6. Milestones

| Milestone | Class | Status | Plan |
|---|---|---|---|
| M001 Prometheus | capability | **ready** | `plans/implementation/observability-metrics/001-prometheus-scrape.md` |
| M002 JSON metrics | capability | planned (hard: M001) | `plans/implementation/observability-metrics/002-json-metrics.md` |
| M003 telemetry history | capability / infrastructure | planned (hard: M002) | `plans/implementation/observability-metrics/003-telemetry-history.md` |

## 7. Cross-cutting concerns

- **Security.** Metrics settings mutations are session+CSRF. Bearer compares against Argon2id. Scrape limiter separate from health/login.
- **Cardinality.** Document that renaming a client creates new `name` series; alerts should prefer `client_id`.
- **Performance.** Sampler interval 30s default; scrape triggers a fresh observe and MUST NOT unbounded-block the worker (reuse existing observe path bounds).

## 8. Deferred

| Item | Disposition |
|---|---|
| OpenMetrics protobuf | Out of scope |
| Pushgateway | Out of scope |
| Long-term TSDB inside wg-basic | Out of scope; use Prometheus |
| Endpoint-info Prometheus series | Explicitly rejected in ADR-013 |

## 9. Risks

- Scrape storms filling the worker — dedicated limiter + observe reuse.
- History table growth — hard N retention tests.
- Label `name` with odd characters — Prometheus escaping tests.
