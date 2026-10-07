# Durable State M003 Closure

Status: closed

Planning baseline: `3011062` (M002 closure)
Final implementation head: `6a9cbc7`
Qualification run: see the registry entry for the CI run that qualified this head

## Outcome

M003 is strictly closed. The unprivileged management role owns the durable state store, projects the committed desired generation into one aggregate network intent, applies it through authorized `netd`, and records convergence evidence. After a process crash or a host restart, the management role re-derives kernel state from the database without operator resubmission.

Backup, restore, and multi-version migration qualification are **not** implemented; that is M004.

## Requirement-to-evidence matrix

| Plan requirement | Evidence |
|---|---|
| §2 management runtime ownership | `management::ManagementRuntime` owns the `StateStore` lifetime, the current desired generation, projection into `InstallationNetworkIntent`, aggregate `netd` requests, and convergence evidence. It hosts no HTTP. `ManagementHealth` carries no receipt, error string, or key material, so a future Phase 7 surface can be added without reshaping it. |
| §3 canonical startup sequence | `ManagementRuntime::open` validates the path and runs migrations, then `reconcile_current` loads the snapshot and generation, projects it, connects to authorized `netd`, submits one aggregate apply, and conditionally records evidence. The `reconcile` CLI role is the process-level entry point, exercised by every rootful restart fixture as a real child process. |
| §3 startup reconciles unconditionally | Startup applies the current generation even when `last_converged_generation == desired_generation`. `a_committed_generation_converges_after_a_management_process_restart` re-runs management against an already-converged generation and requires a successful idempotent replay, proving the evidence is a hint rather than a reason to skip work. |
| §4 conditional convergence API | `record_attempt_start`, `record_attempt_result`, and `record_converged_if_current`. The last re-checks the generation inside the same write transaction that updates the evidence. `attempt_outcomes_are_recorded_as_categories` proves an outcome is stored as a category and never as a message. |
| §4 stale completion cannot advance convergence | `record_converged_if_current` returns `false` and records `superseded` when the store has moved on. `a_stale_completion_cannot_mark_a_newer_generation_converged` (rootful) and `a_stale_receipt_cannot_mark_a_newer_generation_converged` both prove an older receipt leaves `last_converged_generation` at the older value and never claims the newer generation. |
| §5 mutation-to-reconcile coordinator | `ReconcileCoordinator` is a bounded single-slot machine shared by startup and in-process mutation. `the_coordinator_coalesces_writes_before_an_apply_starts`, `a_newer_generation_waits_while_an_apply_is_running`, and `an_idle_coordinator_does_no_work` prove coalescing, waiting, and idle behavior. There is no unbounded per-write task and no background scheduler. |
| §6 bounded retry, no spin on conflicts | Retryable classes are `BackendUnavailable` and `PartialFailure`, bounded by `MAX_TRANSIENT_RETRIES` with a fixed backoff. `transient_transport_errors_are_treated_as_backend_unavailable` and `refusals_are_not_mistaken_for_an_unavailable_backend` prove a conflict, an authorization refusal, or a hard refusal is never retried as a transient outage. `an_absent_network_service_is_a_bounded_unavailable_state` proves a missing `netd` ends in a bounded, clearly-named unavailable state well under a 30-second ceiling. |
| §6 non-retryable without operator/state change | Ownership and state conflicts map to `ManagementError::Conflict`, authorization to `Unauthorized`, and hard refusals to `Rejected`. `non_retryable_categories_never_project_as_retryable` proves `state_conflict`, `unauthorized`, and `rejected` never project as `Retryable`. |
| §7 crash point A (commit before apply) | `a_committed_generation_converges_after_a_management_process_restart`: generation 2 is committed with no `netd` call, a real `reconcile` child process is started, and it converges the kernel and records the evidence. |
| §7 crash point B (partial apply) | `a_partially_applied_generation_recovers_after_a_restart`: the owned link is deleted and a foreign-marked `inet wg_basic` table is planted, so the interface layer mutates and the firewall layer refuses. The test proves the link was recreated with its durable tag (a genuine partial apply), the foreign table survived untouched, the desired generation was preserved, and the next `reconcile` process converged once the operator cleared the conflict. |
| §7 crash point C (converged before evidence) | `a_committed_generation_converges_after_a_management_process_restart` covers the replay half: a second management process start against an already-converged generation succeeds idempotently and reports `converged`. |
| §7 crash point D (newer generation during older apply) | `a_stale_completion_cannot_mark_a_newer_generation_converged` plus the coordinator unit tests cover receipt ordering; the coordinator then applies the latest state. |
| §8 owned link deleted while stopped | `startup_restores_deleted_owned_link_and_owned_table` asserts the deleted link is recreated and re-tagged with its durable owner tag. |
| §8 owned nftables table deleted while stopped | The same fixture asserts the deleted owned table is recreated. This fixture now seeds a network policy; before that it was seeded without one, so the firewall layer was a no-op and the table assertions were vacuous. Correcting the seed is what makes this row real evidence. |
| §8 ownership loss fails closed | `a_changed_owner_tag_fails_closed_instead_of_re_adopting` replaces the link alias with a foreign installation tag and requires that startup refuses, that the foreign tag survives untouched, and that the durable desired generation is preserved. The firewall equivalent is proven by the partial-apply fixture, where the foreign table marker is refused and never adopted. |
| §9 secret handling | `startup_never_exposes_secret_material` requires that CLI stdout/stderr contain no key material, that the snapshot `Debug` output contains `[REDACTED]` while not containing the secret, and that the database file remains `0600`. Outcomes are stored as categories, so no reconcile message can reach the database. |
| §10 netd availability | `an_absent_network_service_is_a_bounded_unavailable_state` proves the bounded retry and the named unavailable error. Management never falls back to privileged local mutation and never spawns `netd`; the privilege-boundary doc and the existing architecture guards cover the no-escalation rule. |
| §11 state mutation test API | Reconcile-on-write is exposed through the internal `commit_and_reconcile` API and the `reconcile`/`health` command roles. No public administration CLI and no HTTP API were built, so Phase 7 API semantics stay unfrozen. |
| §12 reconcile-on-write returns two statuses | `commit_and_reconcile` returns the committed generation and the reconcile outcome separately, because a durable commit is not kernel convergence. `a_commit_does_not_imply_kernel_convergence` pins that distinction at the store level. |
| §13 service health state | `ManagementHealth` reports database health, netd reachability, current desired generation, last converged generation, `Converged`/`Pending`/`Retryable`/`Failed`, and a category-only last failure. `health_reports_pending_when_convergence_lags_the_desired_generation` proves the projection, and a companion test proves the rendered health contains no receipt internals or key material. |
| §14 rootful restart harness | `tests/durable_restart.rs` runs the **real** `wg-basic netd` binary and the **real** `wg-basic reconcile` role as separate child processes against a temporary on-disk SQLite file, disposable namespaces, real RTNETLINK, real WireGuard, and real nftables, with explicit child lifecycle and bounded timeouts. It is process restart, not in-process reconstruction. |
| §15 verification | `cargo fmt --all --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`, `cargo +1.89.0 check --all-targets --locked` (with and without `linux-integration`) all pass. Every historical rootful suite (`privileged_protocol`, `durable_owner`, `network_reconcile`, `wireguard_kernel`, `network_control_e2e`) was re-run green. A dedicated `durable-restart` CI job runs the new suite under root. |
| §16 documentation | `architecture/startup-recovery.md` (new), `architecture/state-store.md`, `architecture/overview.md`, `architecture/privilege-boundary.md`, `README.md`, and `docs/development.md` are current and factual. Backup/restore and migration qualification are documented as M004. |

## Two defects found by the fixtures

Both were found by qualifying the restart path, and both are recorded here because they changed production behavior.

### 1. Every refusal was classified as an outage

`classify_io` collapsed every transport failure into `BackendUnavailable`. A foreign owner tag was therefore retried three times with backoff and recorded as a transient `backend_unavailable` — exactly the wrong diagnosis, and the wrong advice for an operator.

The protocol client was erasing the wire error into a bare `io::ErrorKind`. It now stores the `ProtocolError` as the payload of the returned `io::Error` and keeps the historical `ErrorKind` mapping unchanged, so management classifies on what `netd` actually said. `refusals_are_not_mistaken_for_an_unavailable_backend` and `a_preserved_protocol_error_outranks_the_transport_kind` pin the new behavior; the existing tests that assert `io::ErrorKind::AlreadyExists` for a conflict still pass unchanged.

### 2. A partial apply was reported as a hard refusal

`netd` deliberately answers a partial apply with `ProtocolError::BackendFailure`, because an earlier layer changed state and a later one failed — a fresh attempt is expected to converge. That collapsed into the same "hard refusal" bucket as an unsupported backend.

It is now a distinct retryable `ManagementError::PartialFailure` recorded as the `partial_failure` category. The rootful fixture shows the whole sequence honestly: the first attempt is a partial failure, the retry finds the interface already converged so only the foreign table remains, and the recorded outcome settles at `state_conflict` — a clean ownership conflict requiring an operator.

## A vacuous test, corrected

`startup_restores_deleted_owned_link_and_owned_table` claimed to qualify owned-nftables-table recreation, but it seeded a desired state with `network_policy: None`. The firewall layer is a no-op without a policy, so no `inet wg_basic` table was ever created and both table assertions passed trivially.

The fixture now seeds a NAT policy, and the same scenario exercises the owned table for the first time. Worth recording because a passing test that proves nothing is worse than a missing test.

## Scope boundaries observed

- No HTTP, EggServe, or web surface. `ManagementHealth` is shaped for one, but none was added.
- No systemd unit, packaging, or install command. "Restart the process" remains an operator or service-manager action.
- No permanent high-frequency reconciliation loop. Recovery is driven by process start.
- Management never escalates privilege, never opens a privileged socket, never mutates the kernel directly, and never spawns `netd`.
- No ownership marker was ever weakened. Every fail-closed path from M002 still fails closed.

## Test totals

Unprivileged: 103 library, 1 binary, 10 architecture guards, 29 state store, 2 privileged protocol — 145 total, all passing.

Rootful: `durable_restart` 8, `durable_owner` 10, `network_control_e2e` 2, `wireguard_kernel` 2, `network_reconcile` 2, `privileged_protocol` 2 — 26 total, all passing.

## Recommendation on M004 readiness

M004 is unblocked. The durable store is in place and exercised by a real process-restart fixture, so backup, restore, and migration qualification have a concrete artifact to operate on, and `architecture/startup-recovery.md` documents exactly what M004 does not yet cover.

One item is carried forward from the M002 closure: the plan §16 fault-injection cases 12 and 13 now have real rootful coverage through `a_partially_applied_generation_recovers_after_a_restart`, which injects a firewall-layer failure after interface mutation during enable and exercises the restart recovery. The disable-path equivalent is still covered only by ordering unit tests plus the existing end-to-end disable fixture.