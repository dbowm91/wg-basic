# Management Service M001 Closure — EggServe Runtime and Bounded Management Worker

Status: closed.

Planning baseline: `c49c2eb` (Phase 7 management-service roadmap registration).
Repository baseline at implementation start: `cffee10` (the plan record was one
registration commit behind the working tree; the real starting head is recorded
here rather than the stale value in the plan header).
Final implementation head: `5b57d49`.
Disposition: **closed**.

## Outcome

M001 is strictly closed. `wg-basic serve` is a real unprivileged loopback HTTP
service that owns a dedicated blocking worker holding `ManagementRuntime` and the
durable state store, and publishes exactly one route: `GET /healthz`.

Every acceptance criterion in the plan is met. Two things the plan asked for
were not delivered in the form it anticipated, and both are recorded below rather
than glossed over: EggServe rejects a zero capacity for file streaming and
tunnelling, so the surface pins the transport floor rather than zero; and the
`serve` lifecycle that M004 §3 also describes is implemented here, because M001's
own implementation list requires it, leaving M004 the shell, readiness
differentiation, and end-to-end qualification.

## Dependency evidence

Direct EggServe leaf crates only, as ADR-003 requires:

| Crate                 | Version | Notes |
|---|---|---|
| `eggserve-server`     | 0.4.0   | Direct dependency. No `eggserve-core`, no `eggserve-static`, no Tower/Axum adapter. |
| `eggserve-primitives` | 0.2.2   | Direct dependency, for request/response/status/header values. |

Transitive and newly enabled: `hyper` 1.12, `hyper-util` 0.1.21, `http`,
`http-body`, `http-body-util`, `httparse`, `httpdate`, `bytes`, `futures-util`,
`tokio-macros`, `atomic-waker`.

`tokio` features were widened from `["net", "rt", "time"]` to
`["macros", "net", "rt", "rt-multi-thread", "sync", "time"]`. `sync` is required
by the bounded queue and the one-shot replies. `rt-multi-thread` is required
because the loopback integration tests use a hand-written blocking HTTP client;
a single-threaded runtime cannot make progress while that client blocks. `macros`
backs `#[tokio::test]`.

No dependency was added for routing, templating, or an HTTP client.

`the_management_http_surface_ships_no_router_or_client_crate` pins this: it fails
on `eggserve-core`, `eggserve-static`, `axum`, `actix-web`, `actix-rt`, `warp`,
`tower-http`, `reqwest`, `ureq`, `hyper-tls`, or `rustls`.

## Requirement-to-evidence matrix

| Plan requirement | Evidence |
|---|---|
| Depend directly on `eggserve-server` 0.4.x / `eggserve-primitives` 0.2.x; verify Rust 1.89 | Table above. `cargo +1.89.0 check --all-targets --locked` passes. |
| No Axum, Tower, `eggserve-core`, `eggserve-static`, or direct Hyper | `the_management_http_surface_ships_no_router_or_client_crate`. `hyper` is present only transitively through `eggserve-server`. |
| Dedicated `http/` boundary; HTTP code must not import rusqlite, state SQL/schema internals, rtnetlink/nl-wireguard, firewall backends, or privileged dispatch internals | `src/http/{mod,config,response,service,serve}.rs`. `the_http_boundary_never_reaches_the_durable_store_or_the_kernel` forbids `rusqlite`, `crate::protocol`, `crate::aggregate`, `crate::reconcile`, `crate::wireguard`, `crate::state`, `crate::firewall`, `netlink`, and `rtnetlink`. |
| One OS thread owning `ManagementRuntime`, fed by a bounded tokio mpsc queue with typed commands and one-shot replies | `src/management/worker.rs`. `mpsc::channel(capacity)`, `oneshot` replies, `blocking_recv` on the worker thread, `DEFAULT_QUEUE_CAPACITY = 32`, `DEFAULT_REPLY_DEADLINE = 5s`. `the_management_worker_queue_is_bounded` pins `mpsc::channel(capacity)`, forbids `mpsc::unbounded` and `spawn_blocking`, and requires a non-blocking `try_send`. |
| M001 commands limited to `Health` and `Shutdown` | `WorkerCommand` has exactly those two variants; both reply types are closed enums. |
| Worker startup opens the runtime and attempts current-generation reconciliation; DB/path/migration failure is fatal; netd outage/conflict/refusal is degraded but must not prevent the listener from starting | `spawn` performs a startup handshake over a blocking channel and returns `Err` for `ManagementError::State`/`Projection`/`WorkerStartFailed`. `ManagementError::is_fatal_without_authority` and `evidence_category` are the single rule. `an_unusable_state_path_is_fatal` and `a_fatal_state_failure_never_binds_a_listener`. `a_degraded_startup_still_serves_health` commits a real desired state, points at an absent socket, asserts `StartupReconcile::Degraded { BackendUnavailable }`, and proves health is still answerable with `netd_reachable == false`. |
| Queue saturation or reply deadline returns generic 503; no unbounded `spawn_blocking` bypass | `WorkerError::{Saturated, TimedOut, Stopped}` all render as the single literal `unavailable` with 503 (`response_for_worker_error`). `a_full_queue_is_refused_rather_than_queued` fills a hand-built capacity-1 channel and proves the next admission is refused. `a_missed_reply_deadline_is_overload_not_success` uses a zero deadline. `a_stopped_worker_answers_503_without_detail` and the on-the-wire `a_worker_that_is_stopped_becomes_a_bounded_503` prove the stopped case. |
| Expose only `GET /healthz` with minimal `ok`/`degraded` liveness and no installation ID, generation, path, desired-state fact, or backend detail | `routing_is_an_exact_match` (11 near misses, all unknown routes), `only_get_is_answered_on_the_health_route` (7 methods refused, `HEAD` included), `a_query_string_does_not_change_the_matched_route`, `the_query_is_never_part_of_the_path_match`, `a_known_route_answers_a_bounded_liveness_class`, `a_health_snapshot_is_reduced_to_two_states`. `Liveness::from_health` consults only `is_healthy()`. |
| Unknown routes/methods return bounded generic 404/405 | `a_unknown_route_is_a_bounded_404`, `a_known_route_with_an_unknown_method_is_a_bounded_405`, `a_unknown_route_reported_by_another_method_stays_a_404` (a prober cannot enumerate the surface by varying the method). |
| Reject body-bearing routes before application work | `ManagementService::request_body_policy` returns `RequestBodyPolicy::Reject`, so the transport refuses before routing. `the_service_declines_every_request_body` and the on-the-wire `a_body_bearing_request_never_reaches_application_work`. |
| Explicit EggServe connection, in-flight, target/header/body, header-timeout, handler-timeout, connection-lifetime, and graceful-shutdown ceilings; loopback default bind | The full table is published in `architecture/management-http.md` and asserted by `the_default_limits_reach_the_runtime_config` against the assembled `RuntimeConfig`, so a limit cannot silently drift from the code that applies it. `the_default_bind_is_loopback_only`. |
| `serve` owns worker + EggServe lifecycle with deterministic exit | `src/http/serve.rs` implements validate → worker → bind → report → serve → stop accepts → bounded drain → stop worker → release store. `an_invalid_bind_address_is_refused_before_anything_is_opened` proves nothing authority-bearing is opened on a bad limit. `the_lifecycle_serves_then_drains_and_releases_the_store` (unit) and `the_lifecycle_releases_the_state_store_before_it_returns` (integration, real second `StateStore` open) prove the store is released before `run` returns. |
| Loopback ephemeral bind, health behaviour, rejected body, route/method negatives, worker-only health access, saturation, worker timeout, degraded startup, fatal startup, graceful shutdown | `tests/management_http.rs` (9 tests, real TCP sockets, hand-written HTTP/1.1 client) plus 33 unit tests across `http::config`, `http::response`, `http::service`, `http::serve`, and `management::worker`. Worker-only health access: `ManagementService` holds a `WorkerClient` and nothing else; there is no other route to `ManagementRuntime`, which the HTTP-boundary guard pins. |
| Architecture guards preventing HTTP→SQL/network-backend imports | Three guards, listed above. |
| Run fmt/check/clippy/tests, Rust 1.89, and every existing rootful suite | See "Verification". |

## Architecture guard change, and why it is not a weakening

`the_management_role_never_becomes_an_http_surface` previously forbade the bare
token `tokio::` in `src/management/`. Phase 7 legitimately needs one async
primitive there — the bounded command queue in `worker.rs` that *is* the ADR-003
boundary between synchronous authority and the async surface.

The guard is now narrower and stricter at the same time:

- No web stack anywhere in `src/management/`: `egg::`, `EggServe`, `eggserve`,
  `hyper`, `axum`, `actix`, `warp::`, `reqwest`, `TcpListener`, `crate::http`.
- `tokio::` is allowed **only** in `src/management/worker.rs`.

That is strictly more informative than "no async at all": it is the property that
actually matters, and it cannot be satisfied by a management module quietly
growing its own listener.

Guards now inspect code with comments stripped (`code_only`), because this
codebase deliberately names forbidden dependencies in prose to explain what it is
not doing. Without stripping, documentation that says "no `spawn_blocking` here"
would fail its own guard and train readers to ignore guards.
`the_comment_stripper_actually_strips_and_preserves` qualifies the stripper
itself, so the token guards cannot silently degrade into no-ops.

## Verification actually run

All commands were run from the repository root on the final implementation head.

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo check --all-targets --locked` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass, no warnings |
| `cargo test --locked` | pass — 153 lib + 17 architecture guards + 9 management HTTP + 30 state store + 20 + 9 + 5 + 3 + 2, no failures |
| `cargo +1.89.0 check --all-targets --locked` | pass |
| `cargo test --locked --test privileged_protocol` | pass — 2 tests |
| `sudo cargo test --locked --features linux-integration --test wireguard_kernel` | pass — 2 tests, real kernel handshake/telemetry/peer preservation in disposable namespaces |
| `sudo cargo test --locked --features linux-integration --test durable_owner` | pass — 10 tests |
| `sudo cargo test --locked --features linux-integration --test durable_restart` | pass — 9 tests, real `netd` + `reconcile` child processes |
| `sudo cargo test --locked --features linux-integration --test durable_backup` | pass — 2 tests, real restored-database WireGuard/forwarding/NAT |

M001 mutates no kernel, firewall, or durable-state behaviour, so no new rootful
fixture was required; the four existing rootful suites were re-run green as the
plan requires.

## Startup matrix

| Startup condition | Result | Evidence |
|---|---|---|
| Fresh store, no managed interface | Ready, `NothingToApply` | `a_started_worker_answers_health_and_shuts_down` |
| Store holds a desired state, `netd` absent | Ready, `Degraded { BackendUnavailable }`, listener up | `a_degraded_startup_still_serves_health` |
| State path is not an openable database | Fatal, no listener | `an_unusable_state_path_is_fatal`, `a_fatal_state_failure_never_binds_a_listener` |

## Route matrix

| Method | Path | Status | Body |
|---|---|---|---|
| `GET` | `/healthz` | 200 | `ok` or `degraded` |
| `POST`/`PUT`/`DELETE`/`HEAD` | `/healthz` | 405 | `method not allowed` |
| any | anything else | 404 | `not found` |
| any | any, worker saturated/timeout/stopped | 503 | `unavailable` |

## Security and ownership evidence

- The management process gains no capability and spawns nothing. `serve` never
  spawns or elevates netd; it reaches the kernel only through the authorized
  socket, from the worker thread, on behalf of a request.
- Every response body on the surface is a fixed literal. There is no formatting
  hook into a response anywhere in `src/http/`, so an error path cannot disclose a
  path, a socket address, a generation, or an internal type by accident.
  `every_body_is_a_bounded_literal` and `MAX_MANAGEMENT_BODY_BYTES` enforce the
  ceiling.
- No `Server` header is emitted; `the_surface_advertises_no_stack_and_no_tunnels`
  proves it survives runtime-config assembly.
- Every response is `cache-control: no-store`, so an intermediary cannot serve a
  stale `ok` after an outage.
- Both liveness classes are `200` by design. Serving `degraded` as `503` would
  make a liveness probe restart a healthy listener, and would conflate "the
  appliance is unhealthy" with "this endpoint is unavailable".
- No forwarded header is trusted and PROXY protocol is disabled, so a client
  cannot forge its observed address.
- A non-loopback bind is warned about loudly and not refused; the warning names
  the missing TLS and authentication.

## Documentation evidence

- `architecture/management-http.md` (new): current implemented behaviour of the
  HTTP boundary, the worker, startup fatality, disclosure rules, the full limits
  table, lifecycle, and off-host bind guidance.
- `architecture/overview.md`: `serve` is now the management service role, and the
  HTTP boundary is listed as implemented with a link.
- `README.md`: current capabilities state `serve` serves the loopback surface, and
  state plainly that authentication, sessions, mutation routes, and the UI are
  absent.
- `docs/development.md`: how to run `serve`, its flags, and the TLS caveat.

## Corrective finding made during M001

`ManagementHealth::netd_reachable` was derived from the convergence state, so a
recorded `backend_unavailable` disposition — which *is* the record of netd not
answering — projected as `netd_reachable == true`. The derivation was untested.

It was corrected here rather than deferred, because M001 consumes that field and
M003 will render it on an authenticated endpoint: a health projection that
contradicts the evidence it is derived from is not a safe input for a surface.

`health::netd_reachability` now derives reachability from the recorded
disposition directly: `BackendUnavailable` and `FailedBeforeMutation` disprove
reachability, every other category is a disposition the backend answered to
produce, and no recorded outcome establishes nothing either way.
`a_backend_outage_never_projects_as_a_reachable_netd` and
`an_untried_installation_has_no_reachability_evidence` are the regression tests.

This changes no previously closed plan's verified surface: `is_healthy()` was
already `false` in the `Retryable` case, so no existing test or operator output
changes. Historical closure records were not edited.

## Known limitations

- Phase 7 has no TLS. Any non-loopback bind must sit behind a TLS-terminating
  reverse proxy.
- There is no authentication, session, or desired-state mutation route. M001's
  surface is deliberately one unauthenticated liveness route.
- The file-stream and tunnel capacities are pinned to EggServe's minimum of 1,
  not 0: the runtime rejects zero for both. No M001 route can consume either
  capability, and the pin is asserted. Zero is not expressible, so this is
  recorded as a limit of the claim rather than a gap.
- `a_missed_reply_deadline_is_overload_not_success` uses a zero deadline, which
  races the worker's reply. It asserts that every outcome is truthful and that a
  dropped channel is never a silent success; it does not deterministically prove
  the timeout path. Saturation is proven deterministically on a hand-built
  channel instead.

## Unresolved findings

None. No high, medium, or low finding is open against M001.

## M002 readiness

M002 is **unblocked**. Its hard dependency, M001, is strictly closed, and every
interface M002 needs is now real rather than assumed:

- One bounded worker owns `ManagementRuntime`; `WorkerCommand`/`WorkerClient` are
  closed enums that M002 extends with credential and session commands.
- `ManagementError::is_fatal_without_authority` and `evidence_category` give M002
  one rule for fatal-versus-degraded at startup and at login.
- The schema v1 → v2 migration has a real owner: `src/state/schema/migrations.rs`
  still has only migration 1, and the `test_only_migrations` harness added during
  Phase 6 will need to yield to a genuine version 2, as the Phase 6 closure
  record anticipated.
- The HTTP boundary is proven not to reach the store, so M002's credential and
  session code belongs behind the worker, not in `src/http/`.

One correction to carry into M002's plan: `cargo test --locked` shows
`src/state/schema/mod.rs` currently exercises the migration runner through a
`#[cfg(test)]`-only step at version 2. The moment a real migration 2 exists, that
harness collides, so M002 must replace it with fixtures built from the production
v1 schema rather than extending it.