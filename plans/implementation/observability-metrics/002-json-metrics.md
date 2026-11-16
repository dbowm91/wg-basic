# Observability metrics M002 — JSON metrics

Status: planned (hard dependency: M001 closed)

Repository baseline: set at observability M001 closure head when this plan becomes ready.

Source roadmap: `plans/subsystems/observability-metrics-roadmap.md` M002

Canonical requirements and ADRs: ADR-013 §2.4; wg-easy `/metrics/json` shape as reference.

Primary work class: capability

Hard dependencies: observability-metrics M001 closed.

## Objective

Expose `GET /metrics/json` under the same enablement and Bearer/loopback policy as Prometheus, returning aggregate counts and a bounded per-client statistics list (wg-easy parity fields where truthful).

## Explicit non-goals

- No history samples (M003).
- No separate password from Prometheus (shared metrics secret).
- No UI charts.

## Current repository evidence

- After M001: Prometheus route, settings, limiter, exposition helper exist.

## Invariants

- Same enable flag **or** a dedicated `json_enabled` flag alongside `prometheus_enabled` (wg-easy has both). Prefer **independent enable flags** sharing one Bearer secret — match wg-easy.
- Same authz and limiter family as Prometheus (shared scrape limiter is OK).
- Endpoint may appear as a **JSON field**, not a Prometheus label.
- List ceiling aligns with product telemetry (1,024 + truncated).

## Expected production changes

1. Settings: `json_metrics_enabled` (if not reused).
2. `GET /metrics/json` application/json response.
3. Admin UI/API toggles for JSON enablement (may wait for a small settings section; CLI acceptable for M002 if UI settings land with auth roadmap — document).
4. Reuse observe snapshot builder.

## Ordered work packages

1. Flag + route.
2. JSON serializer tests vs fixture snapshot.
3. Docs scrape/curl examples.

## Privilege and security effects

Same surface class as M001. Public keys in JSON match wg-easy — acceptable; still no private keys/PSK.

## Persistence, protocol, and configuration compatibility

Additive settings field if needed.

## Failure, cancellation, restart, and contention

Same as M001 (503 when observe unavailable; 401/loopback policy).

## Focused tests

- Independent enable: Prometheus on / JSON off and the reverse.
- Authz matrix shared with M001.
- Truncation flag when over ceiling.

## Linux and network-namespace integration evidence

None beyond M001 practice.

## Broad verification commands

Ordinary gates.

## Documentation updates

Operations runbook JSON example; management-http route table.

## Acceptance criteria

1. JSON metrics scrape works under the shared secret/loopback policy.
2. Counts and per-client fields are sufficient for simple automation without Prometheus parsers.

## Stop conditions

- Diverging authz from Prometheus in an undocumented way.
- Including private keys.

## Closure evidence requirements

Example JSON (redacted); flag matrix test results.
