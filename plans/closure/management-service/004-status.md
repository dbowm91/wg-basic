# Management Service M004 Closure — Service Lifecycle and Phase 7 Qualification

Status: closed. **Phase 7 is closed.**

Planning baseline: `plans/implementation/management-service/004-service-lifecycle-and-phase7-qualification.md`.
Repository baseline at implementation start: `9cfcf1b`.
Final implementation head: `d5d5ca9`.
Disposition: **closed**.

## Outcome

M004 is strictly closed, and with it **Phase 7**. The service/security substrate
is complete and qualified: a self-contained embedded shell, a deterministic
lifecycle that a supervisor can actually stop, sessions whose behaviour across a
restart is proven over real cookies, four-way readiness differentiation, and
end-to-end plus abuse/resource qualification against real processes and a real
network backend.

All ten acceptance criteria in plan §11 are met. §12's stop conditions were not
reached: Phase 7 never needed peer/client CRUD to prove the substrate, the HTTP
service never required `CAP_NET_ADMIN`, session persistence did not conflict with
backup/restore semantics, graceful shutdown does bound worker and HTTP tasks, and
the security headers and origin policy never required trusting a forwarded
header.

### Four findings worth reading

1. **`serve` could not be stopped by a process supervisor.** The `ctrlc`
   dependency handles `SIGINT` by default; `SIGTERM` and `SIGHUP` are behind its
   `termination` feature, which was not enabled. A supervisor sends `SIGTERM`.
   So the long-running role died *from the signal* with status `-1`, skipping
   stop-accepts, drain, stop-worker, and close-DB entirely — the entire ordering
   the plan's §3 exists to establish. This was found by asserting the exit status
   on the real binary, not by reading the code: the code looked correct. It is the
   single most consequential defect M004 found, and it was invisible until the
   lifecycle was driven from outside a test process.
2. **`netd_reachable` could not answer the question an operator asks.**
   `ManagementHealth::netd_reachable` is derived from *recorded* convergence
   evidence — deliberately, since M001 corrected it to stop reporting a reachable
   backend during an outage. But a fresh installation that manages an interface
   has recorded nothing, so it reports `netd_reachable: false` with
   `convergence: pending` whether netd is up or down. §4 requires that a listener
   may be up while netd is unavailable, and requires the operator to be able to
   tell the cases apart. They could not be told apart. A live, read-only `Ping`
   was added, on the authenticated route only — an unauthenticated caller must
   not be able to make this process dial the privileged backend.
3. **The worker queue cannot be saturated through the HTTP surface, by
   design.** The login limiter's global budget (20) is smaller than the worker
   queue (32), and every non-login route issues at most one fast command, so the
   limiter is always the binding constraint. The queue bound is therefore
   qualified directly at the `WorkerClient`, where `Authenticate` is the only
   command slow enough to fill it. The first attempt at that test drove
   concurrency from OS threads and never filled the queue — `Handle::block_on`
   serialises them — so it measured thread scheduling rather than the bound. The
   working version polls every future from one task, which is deterministic by
   construction.
4. **`Shutdown` is an ordinary queue entry.** After a saturated burst its
   *confirmation* can miss the five-second reply deadline. The thread is joined
   unconditionally either way, so the database is always released; only the
   confirmation is late. This is bounded by the queue draining, not by the
   deadline. Recorded as a known limitation rather than "fixed", because the fix
   would be a priority lane for `Shutdown` that no other command has.

## Dependency evidence

| Dependency | Version | Change in M004 | Why |
|---|---|---|---|
| `ctrlc` | 3.5.2 | **`termination` feature enabled** | Without it `SIGTERM` kills the long-running roles without a graceful shutdown. This is the corrective in finding 1. |

No new crates. `src/http/readiness.rs` adds `serde`-derived types only, and the
embedded assets add no dependency at all — they are `include_str!`d.

## Requirement-to-evidence matrix

| Plan § | Requirement | Evidence |
|---|---|---|
| §2 | Minimal self-contained shell | `src/http/assets.rs` + `src/http/assets/{index.html,app.css,app.js}`, 12,723 bytes, `include_str!` at compile time |
| §2 | No filesystem document root | No path lookup in the request path; `assets::response_body` resolves from a static table. Guard `the_shell_is_embedded_at_compile_time_and_never_read_from_disk` |
| §2 | No external scripts/fonts/styles/CDN | Guard `no_embedded_asset_names_an_external_origin`; verified on the wire — no `http`/`https` literal in any of the three documents |
| §2 | No inline-script CSP concession | Guard `the_asset_shell_needs_no_csp_concession_and_no_build_step`; the shell is served with the unmodified `default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'` |
| §2 | Deterministic content type/length | `assets::content_type`, `assets::body`; observed `text/html; charset=utf-8` 3669 B, `text/css; charset=utf-8` 3432 B, `text/javascript; charset=utf-8` 5596 B |
| §2 | Bounded inventory | `INVENTORY` is three entries; `MAX_EMBEDDED_ASSET_BYTES = 32 KiB` total and `16 KiB` each, asserted in unit tests |
| §2 | MUST NOT implement peer/client management | Guard `the_shell_offers_no_phase_8_management`; `tests/service_e2e.rs` serves `/` and asserts its `fetch` calls are only to the three Phase 7 routes |
| §3.1–3.2 | Validate config, then start worker/open state | `serve::run` step 1 precedes `spawn`; `an_invalid_bind_address_is_refused_before_anything_is_opened` |
| §3.3 | Unconditional startup reconcile | `run` calls `worker.reconcile()` unconditionally; `nothing to apply` / `converged` observed in `tests/service_e2e.rs` |
| §3.4–3.5 | Bind, report readiness | `run_publishing` binds, logs the effective exposure mode and the classified readiness, then publishes the snapshot |
| §3.6 | Serve | — |
| §3.7–3.8 | Signal → stop accepts → drain bounded | `control.shutdown()` precedes `completion.wait()`, pinned by guard `only_the_serve_module_orders_the_service_lifecycle` |
| §3.9–3.10 | Stop worker, close DB | `worker.stop()` after the drain, same guard; store reopen asserted in `shutdown_with_a_request_in_flight_drains_and_exits` |
| §3.11 | Exit cleanly | Exit status `0` on `SIGTERM` asserted in `tests/service_e2e.rs` and `tests/service_rootful_e2e.rs`; verified manually against the real binary |
| §3 | Management never spawns/elevates netd | `serve_does_not_spawn_or_elevate_netd` reads `/proc` and asserts `serve` has no child processes, then starts netd afterwards and observes `backend.answered` become `true` with no restart |
| §4 | Process liveness | `Readiness::Ready`; `/healthz` → `ok` |
| §4 | DB fatal startup state | `Readiness::Fatal { Database }`, logged and the process exits before binding; `a_fatal_state_failure_never_binds_a_listener`, `a_fatal_state_failure_is_not_a_degraded_one` |
| §4 | Backend degraded state | `Readiness::Degraded { unhealthy }`; asserted with the backend running, absent, and mid-restart |
| §4 | Authenticated detailed health | `/api/v1/health` renders `{ health, backend }`, session-gated |
| §4 | Listener may be up while netd unavailable/conflicted | `the_management_surface_reflects_real_network_state_in_both_directions` |
| §4 | `/healthz` must not reveal why | Guard `the_anonymous_health_answer_comes_only_from_the_readiness_projection`; unit test `the_public_projection_is_exactly_two_tokens`; on-the-wire assertions that no dependency name appears in the body or any header |
| §5 | Non-expired session survives restart | `a_non_expired_session_survives_a_serve_restart` |
| §5 | Logout still invalidates | `logout_across_a_restart_invalidates_the_old_cookie` |
| §5 | Password reset invalidates every prior session | `a_password_reset_invalidates_every_prior_session_across_a_restart` — two sessions, both minted before the restart, both dead after |
| §5 | Expiry survives restart | `an_expired_session_stays_expired_across_a_restart` |
| §5 | Test the actual HTTP cookie | Every case parses `Set-Cookie` and replays `Cookie`; no assertion reads the session table |
| §6 | Real SQLite, real netd child, real serve child, real TCP | `tests/service_e2e.rs` |
| §6 | Required flow, steps 1–9 | `the_required_service_flow_survives_a_real_serve_restart` |
| §6 | Verify startup reconciliation state | Log line asserted, and `wg-basic health` (a second entry point) compared against the HTTP projection |
| §6 | Rootful fixture with real netd/network state | `tests/service_rootful_e2e.rs` — real netd in a namespace, a real WireGuard device, real convergence evidence |
| §7.1 | Connection/in-flight saturation | `more_connections_than_the_limit_are_answered_or_closed_never_queued`, `the_in_flight_ceiling_holds_under_a_slow_client_flood` |
| §7.2 | Worker queue saturation | `the_worker_queue_is_bounded_and_refuses_rather_than_queueing`, `worker_overload_is_never_reported_as_a_credential_refusal` |
| §7.3 | Oversized login body | `an_oversized_login_body_is_refused_with_a_bounded_answer` |
| §7.4 | Repeated throttled login | `repeated_logins_are_throttled_with_a_usable_retry_after`, `a_login_flood_costs_far_less_cpu_than_one_verification_per_attempt` |
| §7.5 | Slow/stalled handler bounded by timeout | `a_stalled_request_head_is_dropped_at_the_header_timeout`, `a_stalled_request_body_is_dropped_at_the_body_timeout`, `a_slow_handler_still_answers_within_the_handler_timeout` |
| §7.6 | Shutdown with in-flight request | `shutdown_with_a_request_in_flight_drains_and_exits` |
| §7.7 | Worker unavailable during request | `the_worker_queue_is_bounded_and_refuses_rather_than_queueing` (every answer is one of four decisive variants); `a_worker_that_is_stopped_becomes_a_bounded_503` in `tests/management_http.rs` |
| §7.8 | Expired session cleanup | `expired_sessions_are_reclaimed_and_the_table_does_not_grow` |
| §7 | No unbounded sleeps | Every wait is a deadline. No `sleep` is used to hope for ordering; the shutdown case waits on a channel the client signals after writing its request |
| §8 | Seven static guards | 43 guards total, up from 39. Four new for M004: `the_anonymous_health_answer_comes_only_from_the_readiness_projection`, `the_live_backend_probe_is_reachable_only_from_the_authenticated_route`, `only_the_serve_module_orders_the_service_lifecycle`, `the_long_running_roles_catch_a_supervisors_termination_signal` |
| §9 | Footprint and latency evidence | `tests/service_footprint.rs` on the release binary; figures below |
| §10 | Documentation | `architecture/management-http.md`, `architecture/authentication.md`, `architecture/overview.md`, `README.md`, `docs/development.md` |
| §11.1 | Assets binary-contained | `the_shell_is_embedded_at_compile_time_and_never_read_from_disk`, `no_build_toolchain_is_required_to_produce_the_shell` |
| §11.2 | Deterministic lifecycle/shutdown | Exit-status-0 assertions, plus the ordering guard |
| §11.3 | Sessions survive restart, honour revocation/expiry | Four §5 cases |
| §11.4 | HTTP + worker + SQLite + netd integration | `tests/service_e2e.rs`, `tests/service_rootful_e2e.rs` |
| §11.5 | Host/Origin/CSRF/rate-limit load-bearing in E2E | `the_security_perimeter_holds_over_the_real_wire` — every check against a real child process |
| §11.6 | Saturation is bounded | 15 §7 cases |
| §11.7 | Rootful suites remain green | Six suites, all passing (below) |
| §11.8 | No privileged capability in serve | `serve_does_not_spawn_or_elevate_netd`; `the_management_role_survives_its_backend_disappearing_and_picks_it_up_again` |
| §11.9 | No unresolved high/medium security finding | None. All findings are Low or accepted; see below |
| §11.10 | Docs state Phase 8 is pending | `README.md`, `architecture/overview.md`, and a new "What Phase 8 still owns" section in `architecture/management-http.md` |

## Verification

All commands run on the final implementation head `d5d5ca9`.

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo check --all-targets --locked` | pass, no warnings |
| `cargo clippy --all-targets --locked -- -D warnings` | pass, no warnings |
| `cargo test --locked` | **438 passed, 0 failed** |
| `cargo +1.89.0 check --all-targets --locked` | pass (MSRV) |
| `cargo test --release --locked --test service_footprint` | pass |

Per-suite counts, `cargo test --locked`:

| Suite | Tests |
|---|---|
| `src/lib.rs` unit tests | 262 |
| `src/main.rs` unit tests | 3 |
| `architecture_guards` | 43 |
| `auth_sessions` | 15 |
| `authenticated_api` | 13 |
| `management_http` | 18 |
| `network_reconcile` | 0 (rootful-gated) |
| `state_backup_restore` | 20 |
| `state_durability` | 5 |
| `state_store` | 30 |
| `service_e2e` | 4 |
| `service_footprint` | 2 |
| `service_resource_limits` | 15 |
| `service_session_restart` | 6 |

Rootful suites, `sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test <name> -- --test-threads=1`:

| Suite | Result |
|---|---|
| `privileged_protocol` | 2 passed |
| `wireguard_kernel` | 2 passed |
| `durable_owner` | 10 passed |
| `durable_restart` | 9 passed |
| `durable_backup` | 2 passed |
| `service_rootful_e2e` | 3 passed |

The pre-existing rootful suites are unchanged by M004 and remain green, which is
§11.7.

## Network-namespace and real-kernel evidence

`tests/service_rootful_e2e.rs` is the first fixture where the management HTTP
surface is driven against a **real converged network**. Three cases:

1. **`the_management_surface_reflects_real_network_state_in_both_directions`.**
   Seeds a store that really manages an interface, starts a real `netd` inside a
   disposable network namespace, and asserts `ip link show wgm4vpn` succeeds
   inside it — the device exists because `netd` applied it. `/healthz` is `ok`;
   `/api/v1/health` reports `backend.answered: true` **and**
   `health.convergence: "converged"`. Then the backend is stopped and `serve` is
   restarted: the startup reconcile fails, the readiness line reads
   `degraded: network convergence`, `/healthz` becomes `degraded`, and the
   authenticated route reports `backend.answered: false` with the record no longer
   claiming convergence.

   A note on how the degraded state was produced, because the obvious approach
   does not work: deleting the managed link does **not** produce a failed
   reconcile. `netd` owns the link, so the startup reconcile simply re-creates it
   and reports `converged` — correctly, and not a bug. A reconcile that genuinely
   fails needs a backend that cannot act.

2. **`the_management_role_survives_its_backend_disappearing_and_picks_it_up_again`.**
   Stops `netd` under a running `serve`. `serve` stays alive, `/healthz` reports
   the record (`ok` — see known limitation L1), the live probe reports
   `backend.answered: false`, the existing session keeps working, and a restarted
   `netd` is picked up with no restart of `serve`. A role that owned its backend
   could not survive either half.

3. **`no_key_material_reaches_the_management_surface`.** With a real device
   applied, renders the session body, the authenticated health body, all three
   shell documents, `/healthz`, and the child's own log, then asserts the
   interface private key appears in none of them in base64 or hex, and that no
   marker word (`private_key`, `PrivateKey`, `preshared`) appears at all.

### A deliberate design note on process topology

`netd` runs inside the namespace; `serve` and the HTTP client run on the host. A
namespace has its own loopback, so a listener bound to `127.0.0.1` inside one is
a different socket from `127.0.0.1` outside it — the first version of this
fixture could not connect to its own service at all, which is why it is recorded
here. `ip netns exec` does not remount `/tmp`, so the netd socket is the same file
on both sides and `serve` reaches the in-namespace backend over exactly the
authorized Unix socket path the unprivileged deployment uses. The integration is
the real one, not a shortcut.

## Security and ownership evidence

| Property | Where it is proven |
|---|---|
| Shell responses carry the same security headers as every other response | Goes through the single `headers::seal`; guard `the_shell_goes_through_the_same_single_seal_point`; `every_response_kind_carries_the_security_headers` |
| The shell needed no CSP relaxation | Guard `the_asset_shell_needs_no_csp_concession_and_no_build_step`; the header is byte-identical to the M003 value |
| A foreign `Host` is refused before routing, on every route including the shell | `the_security_perimeter_holds_over_the_real_wire`, four paths, real child process |
| An unsafe method without the exact `Origin` never reaches a handler | Same, against the real binary |
| A logout without the CSRF token changes nothing | Same — the session is still live afterwards |
| A CLI password reset revokes every live session with no restart | Same |
| `serve` spawns no backend | `serve_does_not_spawn_or_elevate_netd` — `/proc` process tree has no children |
| `serve` does not own the backend's lifetime | `the_management_role_survives_its_backend_disappearing_and_picks_it_up_again` |
| The live backend probe is reachable only from the authenticated route | Guard `the_live_backend_probe_is_reachable_only_from_the_authenticated_route` — exactly one caller, and it is `src/http/api.rs` |
| The probe is read-only | Same guard: its body contains `RequestOperation::Ping`, no `Apply`/`Remove`/`Set`/`Replace`/`Delete`/`Commit`, and no `?;` — a health check must report non-answer, not raise it |
| No key material reaches any rendered response | `no_key_material_reaches_the_management_surface`, rootful, with a real device applied |
| The limiter gained no persistence | Guard `the_login_limiter_stays_in_memory_across_a_restart`, re-verified in M004 |
| Only `src/http/serve.rs` orders the lifecycle | Guard `only_the_serve_module_orders_the_service_lifecycle` |
| Both long-running roles stop on `SIGTERM` | Guard `the_long_running_roles_catch_a_supervisors_termination_signal` plus exit-status-0 assertions on the real binary |

## Documentation evidence

* `architecture/management-http.md` — eight-route table, `src/http/assets.rs`
  and `readiness.rs` in the boundary diagram, a new **What Phase 8 still owns**
  section, the `{ health, backend }` payload with the reason both halves are
  necessary, the four readiness states, the three-way distinction between
  startup readiness / runtime readiness / the record-versus-observation split,
  and the `SIGTERM` section including the queue-drain caveat.
* `architecture/authentication.md` — a **Sessions survive a restart, and honour
  revocation** table covering all six events, and the statement that all are
  asserted over the real cookie across a real restart.
* `architecture/overview.md` — Phase 7 recorded as closed; installation and the
  product lifecycle recorded as not implemented.
* `README.md` — the Phase 7 paragraph, an explicit **no peer/client/interface
  CRUD, no enrollment, no direct TLS** paragraph, and the new test instructions
  including the rootful service fixture.
* `docs/development.md` — a **Phase 7 service suites** section with the per-suite
  table, how to run the footprint measurement, how to run the rootful fixture and
  why the process topology is what it is, and the two findings a future editor
  should know before editing the limiter or the shutdown path.

## Footprint and latency evidence

`cargo test --release --locked --test service_footprint -- --nocapture`, on
16 logical CPUs, median of 5 samples. These are the **release** binary: Argon2 in
a debug build costs ~300 ms per verification, so a debug measurement would report
the optimiser's absence rather than the product.

| Figure | Measured |
|---|---|
| Cold readiness (spawn to first accepted connection) | 36 ms |
| `/healthz` latency | 1.1 ms |
| Login latency, including Argon2id | 39 ms |
| `/api/v1/health` latency | 20 ms |
| `serve` RSS | 8.67 MiB |
| `netd` RSS | 4.67 MiB |
| **Combined RSS** | **13.34 MiB** (engineering signal: < 30 MiB) |
| Idle CPU over 2 s | `serve` 0 ticks, `netd` 0 ticks |
| Embedded shell, all three documents | 12,723 bytes |
| Worker queue capacity | 32 commands, 5 s reply deadline |

The test asserts **order-of-magnitude bounds, not wall-clock numbers**, because a
CI runner's scheduler should not be able to fail this suite. It asserts a
*floor* on login latency — a login faster than a millisecond would mean the
Argon2id parameters had been weakened, which plan §11 of M002 forbids outright.

Nothing was weakened to meet the 30 MiB signal. The measurement is reported
beside it, and the assertion is a loose bound that would catch an
order-of-magnitude regression.

## Abuse and resource qualification

`tests/service_resource_limits.rs`, 15 cases. The property under test is not
"it survived" but that **the answer to abuse is always one of a small set of
bounded responses and the process is still serving afterwards**. Every case ends
by asserting the surface still answers `/healthz`.

Two results are worth stating explicitly because they are load-bearing:

* **The limiter is ahead of the hash.** Twelve logins with a peer bucket of 3
  cost measurably less than half of one verification per attempt, where the
  comparison baseline is a single verification *measured on the same machine* in
  the same test. If the limiter ran after the hash, the same flood would cost
  twelve.
* **The queue bound refuses rather than queues.** A burst of 64 against a queue of
  32 produces exactly four answer kinds — `Rejected`, `Saturated`, `TimedOut`, and
  never `authenticated` — and the whole burst finishes inside the reply deadline
  plus a margin, because refused commands do not wait at all.

## Known limitations

**L1 — `/healthz` reports the record and can be stale.** It does not probe. A
backend that dies *after* the last successful reconcile is invisible to
`/healthz` and visible immediately to `/api/v1/health`. This is deliberate: the
probe costs a round trip to a privileged socket, and an unauthenticated caller
must not be able to make this process dial it. The consequence is asserted rather
than hidden, in
`the_management_role_survives_its_backend_disappearing_and_picks_it_up_again`.

**L2 — `Shutdown` confirmation can be late.** After a saturated burst it queues
behind the backlog and its confirmation may miss the 5 s reply deadline. The
thread is joined unconditionally, so the store is always released. Bounded by
the queue draining, not by the deadline.

**L3 — The login limiter resets on restart.** In-memory by design; a restart
returns the full budget. Guarded against persistence deliberately. A rate limit
that survived restart could be used to lock an operator out of their own
appliance.

**L4 — The HTTP suite drives the client synchronously.**
`tests/management_http.rs` uses a blocking hand-written client, which is why the
concurrency-sensitive M004 suites use scoped OS threads and poll futures from a
single task rather than async tasks.

**L5 — Footprint figures are from one machine.** 16 logical CPUs, one kernel,
release profile. They are recorded as an engineering signal, not a specification.

## Unresolved findings by severity

No high or medium findings. All of the following are Low or accepted.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| F1 | **Low** | `SIGTERM` killed `serve` without draining | **Corrected** in `d5d5ca9` via the `ctrlc` `termination` feature, with exit-status assertions on the real binary and an architecture guard |
| F2 | **Low** | `netd_reachable` could not distinguish "backend down" from "nothing applied yet" | **Corrected** in `d5d5ca9` with the authenticated live probe; the recorded field is unchanged and still evidence-based |
| F3 | **Low** | `/healthz` can be stale about a backend that died since the last reconcile | Accepted, as L1. The alternative is an unauthenticated dial to a privileged socket |
| F4 | **Low** | `Shutdown` confirmation can miss its deadline after a saturated burst | Accepted, as L2 |
| F5 | **Informational** | The worker queue cannot be saturated through HTTP | Accepted. The limiter is always the binding constraint; the queue is qualified directly |
| F6 | **Informational** | A 12-hour session lifetime is long for a single-administrator appliance | Not addressed in Phase 7. The lifetime is a named constant and is session-scoped, not a token property, so changing it is a migration question for Phase 8 |
| F7 | **Informational** | `wg-basic serve` still has no systemd unit, no install path, and no log rotation | Expected. Installation is Phase 8 |

## Phase 7 disposition and Phase 8 readiness

**Phase 7 is closed.** All four milestones are closed with strict evidence:

| Milestone | Status | Closure record |
|---|---|---|
| M001 EggServe runtime + bounded management worker | closed | `plans/closure/management-service/001-status.md` |
| M002 local admin + session persistence | closed | `plans/closure/management-service/002-status.md` |
| M003 authenticated HTTP security perimeter | closed | `plans/closure/management-service/003-status.md` |
| M004 service lifecycle and Phase 7 qualification | closed | this record |

**Phase 8 is unblocked** by this closure, on the evidence in this record and the
three before it. The substrate Phase 8 needs exists and is qualified:

* a bounded, rate-limited, CSRF-protected, `Host`-checked authenticated surface
  with a single header-seal point;
* server-side sessions with revocation, expiry, and reset semantics;
* a durable store with backup, restore, and ordered migrations;
* a reconcile loop with an authorized privileged backend, proven against real
  namespaces;
* 43 architecture guards that fail the build when the invariants move.

Phase 8 inherits the same constraints M004 qualified, and they are properties of
the design rather than of the milestone:

* a configuration-mutating route will be the first thing that can be abused
  through the perimeter — every M003 guard applies to it, and the CSRF and
  `Origin` checks were built for exactly that;
* `MAX_MANAGEMENT_BODY_BYTES` is 16 KiB and the login route's own bound is 4 KiB;
  a peer/client CRUD route needs a bound decided deliberately, not inherited;
* the login limiter's global budget of 20 was sized against the *slow*
  verification cost, so it remains the binding constraint once CRUD routes exist
  and will need re-sizing against whatever those routes cost;
* Phase 7 terminates no TLS. Phase 8 must not imply otherwise.

No historical closure record was edited. M001's, M002's, and M003's records are
unchanged; the two M002 defects found in M003 and the three findings above are
recorded in the records of the milestones that found them.