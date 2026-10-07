# Management Service M001 — EggServe Runtime and Bounded Management Worker

Status: closed. See `plans/closure/management-service/001-status.md`.

Repository baseline: `c49c2eb3ec85b671849be4f8aa9ab2d622d9764e`

Source roadmap: `plans/subsystems/management-service-security-roadmap.md` M001.

Canonical architecture: `plans/adr/003-management-http-auth-and-worker-boundary.md`.

## Objective

Turn `wg-basic serve` into a real unprivileged loopback EggServe HTTP service while keeping `ManagementRuntime` and SQLite behind one bounded blocking worker. Do not expose auth-sensitive or desired-state mutation routes yet.

## Required implementation

- Depend directly on `eggserve-server` 0.4.x and `eggserve-primitives` 0.2.x; verify Rust 1.89. Do not add Axum, Tower, `eggserve-core`, `eggserve-static`, or direct Hyper.
- Add a dedicated `http/` application boundary. HTTP code may use EggServe primitives, worker client, and safe config values; it must not import rusqlite, state SQL/schema internals, rtnetlink/nl-wireguard, firewall backends, or privileged dispatch internals.
- Create one OS thread that owns `ManagementRuntime`, fed by a bounded Tokio MPSC queue with typed commands and one-shot replies. M001 commands are limited to `Health` and `Shutdown`.
- Worker startup opens the runtime and attempts current-generation reconciliation. Database/path/migration failures are fatal; netd outage/conflict/refusal is degraded but must not prevent the management listener from starting.
- Queue saturation or reply deadline returns generic 503. Do not bypass the bound with unbounded `spawn_blocking`.
- Expose only `GET /healthz`, returning minimal `ok`/`degraded`-class liveness with no installation ID, generation, path, desired-state fact, or backend detail. Unknown routes/methods return bounded generic 404/405. Reject body-bearing routes before application work.
- Set explicit EggServe connection, in-flight, target/header/body, header-timeout, handler-timeout, connection-lifetime, and graceful-shutdown ceilings. Default bind is loopback only.
- `serve` owns worker + EggServe lifecycle: initialize, attempt reconcile, bind, report URL, serve, signal shutdown, stop accepts, bounded drain, stop worker, close store, deterministic exit.

## Required evidence

Test loopback ephemeral bind, health behavior, rejected body, route/method negatives, worker-only health access, queue saturation, worker timeout, degraded startup without netd, fatal corrupt/unsafe DB startup, and graceful HTTP+worker shutdown. Add architecture guards preventing HTTP→SQL/network-backend imports.

Run fmt/check/clippy/tests, Rust 1.89, and every existing rootful suite.

## Acceptance

M001 closes only when direct EggServe leaf crates suffice, one bounded worker owns `ManagementRuntime`, async handlers never access SQLite directly, resource/time limits are explicit, only minimal unauthenticated liveness exists, degraded-vs-fatal startup semantics are proven, shutdown is bounded, and all CI is green.

## Stop conditions

Stop/research if direct EggServe `Service` cannot express the bounded routes, worker ownership would require sharing raw `StateStore` connections, auth decisions become necessary for M001 safety, or a general framework is proposed solely for routing convenience.

## Closure record

Record exact EggServe versions/features, dependency diff, configured limits/queue/deadlines, startup matrix, route matrix, saturation/shutdown evidence, MSRV/CI, and M002 readiness.
