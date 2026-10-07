# Durable State Post-Phase-6 C001 — Status

Status: **closed**

Disposition: **closed**

Repository baseline: `53d24756c55a090d2ee4d2e8845498f6cd822447` (Phase 6 closure head)

Implementation commits (this corrective):

| Commit | Subject |
|---|---|
| `7df1bb5` | docs: reconcile current-state docs with the Phase 6 code |
| `7df155f` | test: qualify the disable path when the firewall layer refuses |
| `635a130` | refactor: give management and state one owner per subject |

Final implementation head: `635a1303ddce086bb1f61a23bd1efedeb75ddf3b`

Plan: `plans/implementation/durable-state/c001-post-phase6-reconciliation-and-pre-phase7-hardening.md`

Source addendum: `plans/subsystems/durable-state-post-phase6-reconciliation-addendum.md`

Phase 6 remains closed throughout this corrective. ADR-002, desired-generation semantics, durable ownership, aggregate reconciliation ordering, and the backup/restore contracts were not changed.

## 1. Requirement-to-evidence matrix

| # | Requirement | Evidence | Result |
|---|---|---|---|
| 1 | All current-state docs agree Phase 6 is closed | `architecture/state-store.md`, `architecture/ownership.md`, `architecture/privilege-boundary.md`, `architecture/firewall.md`, `architecture/wireguard-control.md`, `docs/development.md`, `plans/002-long-term-roadmap.md` Phase 6 row now `closed` | pass |
| 2 | Historical closure records unchanged and honest | `git diff 53d2475 -- plans/closure/` is empty; `plans/closure/durable-state/001-status.md` still cites `src/state/schema.rs::open_connection` as accurate **at that head** | pass |
| 3 | Disable-path firewall failure qualified with a real netd process and a real kernel-managed interface | `a_failing_firewall_blocks_the_disable_and_recovers_on_equal_generation_retry` runs the real `wg-basic netd` binary in a disposable namespace against a real kernel WireGuard link | pass |
| 4 | Firewall teardown failure leaves the interface and managed resources intact | Same test asserts the owned table is still present with its installation marker, and `wg-restart` still exists **and still carries the expected owner tag** | pass |
| 5 | Convergence does not falsely advance after the failed disable | Same test asserts `last_outcome == rejected` and `last_converged_generation == 2` while `current_generation == 3` | pass |
| 6 | Equal-generation retry after clearing the failure removes firewall state, then tears down the interface, and converges | Same test, second `run_management` against the **same live netd**: owned table absent, `table_comment()` is `None`, no `wg_basic` object in the namespace listing, link gone, `last_converged_generation == 3`, `last_outcome == converged` | pass |
| 7 | No production fault-injection API/hook added | `git diff 53d2475 -- src/` outside the module move introduces no `cfg(feature = "test")`, no `inject`, no `fail_next`, no fault knob. Injection lives entirely in `tests/durable_restart.rs` and is scoped to one child process's `PATH` | pass |
| 8 | Module cleanup contract-preserving and demonstrably better, or a rejected split documented | See §4. Public surface proven unchanged by a compile-time probe of every previously-public `management` and `state` path | pass |
| 9 | No schema/wire/protocol semantic change | `src/state/migrations/001_initial.sql` byte-identical to baseline; `PROTOCOL_VERSION` still `1`; no new `Migration` entry; `Cargo.toml` and `Cargo.lock` unchanged | pass |
| 10 | All unprivileged and rootful CI passes on the final head | §2, §3 | pass |
| 11 | No unresolved high/medium finding | §7 | pass |

## 2. Documentation and status drift corrected

The drift was not confined to the lines the addendum listed. A sweep of `architecture/`, `docs/`, and the roadmap status tables for milestone-era future tense found and corrected the following. Every correction states current implemented behavior, per `plans/003-planning-process.md` §15; none of it claims planned behavior.

| Document | Drift | Correction |
|---|---|---|
| `architecture/state-store.md` | "created by Phase 6 milestone M001… does **not** yet reconcile the kernel on startup — durable owner tags and generation-aware protocol fields belong to M002, and startup reconciliation/recovery belongs to M003" | Describes the store as it stands; adds a module-layout table for the new file tree |
| `architecture/state-store.md` | `convergence_state` described as "reconciliation evidence, not yet driven by M001" | Lists the four columns it actually carries |
| `architecture/state-store.md` | Migration location omitted the runner | Names `src/state/schema/migrations.rs` as the runner over embedded SQL in `src/state/migrations/` |
| `architecture/ownership.md` | "Automatic application of the durable desired state at startup is not implemented yet — that is Phase 6 M003" | Describes unconditional startup apply and the converged-only-if-current guard as implemented |
| `architecture/privilege-boundary.md` | "Persistence and HTTP are not implemented" | "Persistence is implemented and confined to the unprivileged management role; an HTTP surface is not" |
| `architecture/firewall.md` | "M004 link/address/route removal remains an explicit separate typed desired-state request" | States the aggregate disable ordering, that teardown runs only after firewall removal succeeds, and that the new fixture verifies the blocked teardown and its recovery |
| `architecture/wireguard-control.md` (two places) | "both map to `not_found` until M004 adds authoritative link-kind observation"; "Firewall, forwarding, and NAT remain M005 work" | Both corrected: link-kind resolution is attributed to the reconciliation engine reading RTNETLINK, and firewall/forwarding/NAT are described as the aggregate coordinator's second layer |
| `docs/development.md` | "Two rootful suites qualify the durable-state milestones" above three listed commands | "Three rootful suites"; all three still need root and serialize |
| `plans/002-long-term-roadmap.md` | Phase 6 row read "planned / M001 blocked", blocker "network-control C001" | Phase 6 `closed`, blocker `—` |
| `plans/subsystems/durable-state-restart-reconciliation-roadmap.md` §3.4 | "The current nftables table marker is product-specific only and will become installation-specific in M002" | States the actual `wg-basic:v1:<installation id>` marker and the refusal of a foreign one |
| `plans/subsystems/durable-state-restart-reconciliation-roadmap.md` §5 | Present-tense "C001 … so M001 is unblocked"; "Research/planning is not blocked by C001" | Past tense plus a pointer to this closure record |

Historical records were left alone deliberately: `plans/closure/durable-state/001-status.md` still names `src/state/schema.rs::open_connection`, which was accurate at head `88f10f9`, and the addendum still lists the three monolithic files, which was accurate at the baseline. `plans/003-planning-process.md` §13 requires historical closure records to stay period-accurate.

## 3. Disable-path fault injection

### Topology

Everything below is real. One disposable network namespace; inside it:

- the real `wg-basic netd` binary serving the typed local protocol on a `0700` Unix socket in a `0700` runtime directory;
- a real kernel WireGuard interface `wg-restart`, owned via `IFLA_IFALIAS`;
- the real `inet wg_basic` table, carrying `comment "wg-basic:v1:<installation id>"`;
- a real SQLite store on disk, opened by the real `wg-basic reconcile` management role as a child process.

No mocked backend participates.

### Injection mechanism

`NftFailureShim` in `tests/durable_restart.rs` writes a small `/bin/sh` script named `nft` into a fixture-private `0o700` directory and prepends that directory to the `PATH` of the **netd child process only** (`Netd::start_with_path`). `ip netns exec` preserves the `PATH` it is given, which was verified before relying on it.

The script forwards every read-only probe (`--version`, `-j list tables`, `-j list table inet wg_basic`) to the real `nft` found on the inherited `PATH`, and refuses only the mutating verbs (`delete`, `add`, `flush`, `insert`, `replace`, `rename`, `-f`). That is what makes the case qualify the **shipped** firewall-first ordering rather than a test-only branch: the firewall layer still observes the owned table, still plans `RemoveOwnedNftablesTable`, and still genuinely reaches the mutation, which then fails.

The shim installs transparent and is armed with `NftFailureShim::arm` for exactly the step under test. Because arming is a file the live process re-reads on every invocation, `disarm()` restores real behavior **without restarting netd**. That is deliberate: it makes the recovery run an equal-generation retry inside one live netd process, against the generation-acceptance state that the failed attempt already advanced. Restarting netd would have thrown that state away and tested something weaker.

`git diff 53d2475 -- src/firewall src/aggregate.rs src/protocol` is empty apart from the negative controls, which were reverted. No production code path reads an environment variable to decide whether to fail.

### Failed-disable observations

After committing generation 3 (interface `Absent`, addresses `Absent`, policy dropped) and running management with the shim armed:

| Observation | Value | Why it matters |
|---|---|---|
| `run_management` exit status | non-zero | A disable whose firewall removal failed must not report success |
| `owned_table_present()` | `true` | Not half-removed |
| `table_comment()` | `wg-basic:v1:<installation id>` | Still owned, not orphaned or foreign |
| `link_exists("wg-restart")` | `true` | **The teardown did not run** |
| `link_alias("wg-restart")` | expected owner tag | Blocked teardown leaves the link owned, not unowned |
| `convergence().last_outcome` | `rejected` | A firewall backend failure is refused, not retried forever |
| `convergence().last_converged_generation` | `2` | Convergence did **not** advance |
| `current_generation()` | `3` | The committed disable survives the failure for the retry |

`rejected` is the honest disposition here: `ApplyRejection::FirewallLayerIncomplete` is reported by netd as `InternalFailure`, which `classify_protocol` maps to `ManagementError::Rejected` and `FailureClass::Refused`, so management fails fast rather than burning its bounded retry budget on a backend that is deterministically refusing.

### Equal-generation recovery

After `shim.disarm()`, the second `run_management` targets the same committed generation 3 against the same live netd:

| Observation | Value |
|---|---|
| exit status | success |
| `owned_table_present()` | `false` |
| `table_comment()` | `None` |
| `nft list tables` contains `wg_basic` | `false` |
| `link_exists("wg-restart")` | `false` |
| `convergence().last_converged_generation` | `3` |
| `convergence().last_outcome` | `converged` |

### The case is load-bearing

Two negative controls were run against the shipped code and then reverted, so the closure does not rest on a test that would pass regardless.

| Control | Mutation | Outcome |
|---|---|---|
| 1 | Removed the firewall-incomplete guard so the failed disable continued to teardown | Test **failed** at `a disable whose firewall removal failed must not report success` |
| 2 | Moved the interface teardown ahead of the firewall removal | Test **failed** at `the interface teardown must not run after the firewall layer failed` |

Control 2 is the one that matters: it fails on exactly the ordering claim requirement 4 and §12 of the plan name, and it fails without the production guard being removed.

## 4. Module inventory

Split by subject, not by size. No split was forced where it would have created a cycle or widened SQL helpers.

### Before (baseline `53d2475`)

| File | Bytes |
|---|---|
| `src/management.rs` | 34,238 |
| `src/state/schema.rs` | 40,063 |
| `src/state/store.rs` | 35,904 |

### After (`635a130`)

| File | Bytes | Owns |
|---|---|---|
| `src/management/mod.rs` | 2,688 | Module docs, re-exports, boundary statement |
| `src/management/health.rs` | 6,683 | `ConvergenceState`, `ManagementHealth`, convergence derivation |
| `src/management/error.rs` | 8,515 | `ManagementError`, `FailureClass`, `ProjectionFailure`, the one classification rule |
| `src/management/coordinator.rs` | 3,747 | `ReconcileCoordinator`, `CoordinatorAction` |
| `src/management/runtime.rs` | 16,208 | Startup sequence, apply/retry loop, intent building, store opening |
| `src/state/store/mod.rs` | 5,105 | The `StateStore` façade and its ownership lifecycle |
| `src/state/store/desired.rs` | 22,428 | Snapshot read/write, the atomic generation advance |
| `src/state/store/convergence.rs` | 5,390 | Attempt start, attempt result, the converged-only-if-current guard |
| `src/state/store/sql.rs` | 7,210 | Row decoding shared by the two subject modules |
| `src/state/schema/mod.rs` | 25,901 | The canonical connection initializer and singleton invariants |
| `src/state/schema/validation.rs` | 7,009 | Ownership/permission checks, hardened pragmas, read-back |
| `src/state/schema/migrations.rs` | 9,780 | Ordered migration runner, pre-migration recovery snapshot |

### Boundary argument

The store layering is one-directional: `sql` → `desired` / `convergence` → `mod`. Row decoding is the only place a SQLite column becomes a domain type, so a stored-representation change has one owner, and neither subject module can depend on the other. That is asserted statically rather than left to convention.

For the schema, the recovery snapshot moved **into** `migrations.rs` rather than staying in the opener. It exists for exactly one reason — to protect a schema-changing migration — so its ownership follows its reason, and the opener calls it without knowing what it does.

Two judgment calls worth recording:

- The plan offered `store/{mod.rs, desired.rs, convergence.rs, sql.rs}`. `sql.rs` was taken to mean **row and column conversion helpers**, not "all SQL text moved here". Lifting every inline query into string constants would have been a large, non-mechanical rewrite that would obscure the queries next to the logic they serve, for no ownership gain. Queries stay next to their subject; only decoding is centralized. The file count matches the plan; the contents are the defensible reading of it.
- The schema contract test suite stayed whole in `schema/mod.rs` rather than being distributed into the three modules it now spans. Its fixtures (`TempDir`, `open_inspection`, `populated_state`) are shared across all three subjects, and splitting the suite would have required either duplicating fixtures or adding a test-only helper module. The suite tests the schema **contract**, which is what `mod.rs` now owns.

### Public export compatibility

Every previously-public path was proven reachable after the split by a throwaway compile-time probe over `wg_basic::management::{ManagementRuntime, ManagementHealth, ConvergenceState, ManagementError, FailureClass, ReconcileOutcome, ReconcileCoordinator, CoordinatorAction, ProjectionFailure}` and `wg_basic::state::{StateStore, AttemptDisposition, ConvergenceRecord, InstallationMetadata, PersistedDesiredState, ProjectionError, ResolvedNetworkIntent}`. It compiled, and the probe was deleted rather than committed.

All nine `management` items are re-exported from `management/mod.rs`, so callers see one flat module exactly as before. `StateStore`'s public methods are inherent methods, so the method set is unchanged by construction.

## 5. Dependency diff

`Cargo.toml` and `Cargo.lock` are byte-identical to the baseline. No dependency was added, removed, or upgraded. In particular the fault-injection fixture needs none: it uses a shell script and `PATH`, both already available to a rootful test.

## 6. Verification actually run

### Routine gates

```
cargo fmt --all -- --check                                  # clean
cargo check --all-targets --locked                          # clean
cargo clippy --all-targets --locked -- -D warnings          # clean
cargo test --locked                                         # 187 passed, 0 failed
cargo +1.89.0 check --all-targets --locked                  # clean
```

`cargo test --locked` per target:

| Target | Passed |
|---|---|
| `src/lib.rs` unit tests | 114 |
| `src/main.rs` unit tests | 3 |
| `tests/architecture_guards.rs` | 13 |
| `tests/privileged_protocol.rs` | 2 |
| `tests/state_backup_restore.rs` | 20 |
| `tests/state_durability.rs` | 5 |
| `tests/state_store.rs` | 30 |
| `tests/durable_backup.rs`, `durable_owner.rs`, `durable_restart.rs`, `network_control_e2e.rs`, `network_reconcile.rs`, `wireguard_kernel.rs` | 0 (feature-gated off) |
| doc tests | 0 |

`architecture_guards.rs` went from 10 to 13 cases. Three were added:

- `the_management_role_never_becomes_an_http_surface` — management must not acquire an HTTP or async server dependency, since that would put a request-driven path in the process that owns the durable store and the retry policy.
- `the_state_backup_and_restore_path_stays_local_to_the_database` — backup/restore may not reach the privileged socket, netlink, or a spawned process.
- `the_state_store_submodules_stay_a_one_directed_layering` — pins the layering above, and that row-decoding helpers stay private.

The existing privileged-boundary guards were extended rather than replaced: `src/state/backup.rs` and `src/state/inuse.rs` were previously unregistered and are now covered, and every split module replaced its monolith in the registered-source table.

### Real-kernel rootful suites

Run as root on the local host with kernel WireGuard, `iproute2`, and `nftables` present (`nft --version` → nftables v1.0.9):

```
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test <suite> -- --test-threads=1
```

| Suite | Result |
|---|---|
| `wireguard_kernel` | 2 passed |
| `network_reconcile` | 2 passed |
| `network_control_e2e` | 2 passed |
| `durable_owner` | 10 passed |
| `durable_restart` | 9 passed (8 pre-existing + the new case) |
| `durable_backup` | 2 passed |
| `privileged_protocol` | 2 passed |

### Hosted CI

Run `37638334930` on head `635a130`: seven jobs, all green — `rust`, `wireguard-kernel`, `network-reconcile-kernel`, `network-control-e2e`, `durable-owner`, `durable-restart`, `durable-backup`.

`durable-restart` on the hosted runner therefore executes the new disable-path case as real process and kernel evidence under `linux-integration`, as the plan requires.

## 7. Known limitations and unresolved findings

No high or medium correctness, security, or evidence finding remains. Recorded for honesty:

- **low** — `architecture/wireguard-control.md` keeps milestone names (`M003 contract`, `M002 protocol`) in its library-selection rationale and heading. Those sections are historical decision records; rewriting them would edit history rather than correct drift, so the stale *behavioral* claim in that document was fixed and the selection rationale was left alone.
- **low** — `plans/subsystems/durable-state-post-phase6-reconciliation-addendum.md` still describes `src/management.rs`, `src/state/schema.rs`, and `src/state/store.rs` as monoliths. That was true at the baseline and is the record of why this corrective existed. Correcting it would erase the justification.
- **informational** — The shell script in the fixture means `tests/durable_restart.rs` contains the string `#!/bin/sh`. The no-shell guard (`no_module_shells_out_through_a_shell`) scans `src/` only, by design: production code must never shell out, while a rootful test may legitimately wrap a system binary. The guard's scope was not widened.
- **informational** — The fixture requires `/bin/sh` on the rootful host. It is present on every distribution these suites already target, and the suites already require `iproute2`, `nftables`, and kernel WireGuard.
- **informational** — `NftFailureShim` keys the real `nft` off the first executable `nft` on the inherited `PATH`; a host with several `nft` binaries could in principle arm a shim that forwards to a different one than netd would have used. This does not affect the assertion, which is that a failing mutation blocks teardown, not which binary failed.

## 8. Downstream recommendation

**Phase 7 planning and implementation may proceed.**

Phase 7 was already unblocked for research and planning; this corrective was the thing standing between it and implementation, and it is now closed. The management and state APIs Phase 7 will consume have one owner per subject and a documented layering, the only outstanding rootful evidence debt from M002/M003 is retired, and the current-state docs no longer describe shipped behavior as pending.

Suggested first Phase 7 step: write the management service/auth/UI subsystem roadmap against `ManagementHealth` as the single non-secret projection, now that its derivation rule lives alone in `management/health.rs`.

When Phase 7 implementation begins, `architecture/state-store.md` and `architecture/firewall.md` should be extended for the surface and the blocking-worker adapter the store's module docs already anticipate.