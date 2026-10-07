# Durable State C001 — Post-Phase-6 Reconciliation and Pre-Phase-7 Hardening

Status: ready

Repository baseline: `53d24756c55a090d2ee4d2e8845498f6cd822447`

Source roadmap:

- `plans/subsystems/durable-state-post-phase6-reconciliation-addendum.md`

Historical closure baseline:

- network-control C001: `0e74a40`;
- durable-state M001: `88f10f9`;
- durable-state M002: `65339b8`;
- durable-state M003: `6a9cbc7`;
- durable-state M004 implementation/qualification: `772203d`;
- Phase 6 closure head: `53d24756`;
- current-head CI: run `37630866396`, seven jobs green.

Primary class: corrective / evidence / maintainability

## 1. Objective

Perform one bounded post-Phase-6 corrective before Phase 7 planning/implementation becomes the active development line.

The pass must:

1. reconcile current-state docs and canonical roadmap status;
2. add the missing real-kernel/process-level disable-path firewall-failure fixture carried from M002/M003;
3. improve management/state internal module boundaries where that can be done mechanically without changing product contracts.

This plan does not reopen Phase 6 architecture.

## 2. Current evidence

At the baseline:

- Phase 6 is declared strictly closed in the registry and subsystem roadmap;
- current-head CI is green across:
  - Rust/MSRV;
  - kernel WireGuard;
  - RTNETLINK reconciliation;
  - network-control E2E;
  - durable owner/generation reconcile;
  - durable restart;
  - durable backup/restore;
- M003 closure explicitly states the enable-path injected firewall failure has rootful coverage;
- M003 closure explicitly states the disable-path equivalent still has only ordering/unit + successful-disable evidence;
- current `AggregateCoordinator::apply_disabling` correctly runs firewall removal before interface teardown and returns early on firewall failure;
- current `architecture/ownership.md` and long-term roadmap contain stale pre-M003/pre-C001 wording.

## 3. Non-goals

Do not:

- change ADR-002;
- reopen Phase 6 M001–M004;
- change database schema;
- change SQLite pragmas;
- change desired-generation allocation or CAS behavior;
- change netd protocol version or serialized fields;
- change firewall rule semantics;
- change aggregate enable/disable ordering;
- add new operator product features;
- introduce HTTP/auth/UI;
- alter backup/restore behavior except for mechanical module moves if required.

## 4. Work package A — Canonical/current-state reconciliation

Review and correct current-state/future-tense drift in at least:

- `plans/002-long-term-roadmap.md`;
- `plans/registry.md`;
- `plans/subsystems/durable-state-restart-reconciliation-roadmap.md`;
- `architecture/ownership.md`;
- `architecture/state-store.md`;
- `architecture/startup-recovery.md`;
- `architecture/overview.md`;
- README and development docs where applicable.

Required canonical result:

- Phase 6: closed;
- C001: active/ready until this corrective closes;
- Phase 7: ready to plan but not implemented;
- Phase 8: blocked on Phase 7;
- startup reconciliation: implemented;
- backup/restore: implemented;
- no systemd/install/update claim;
- no HTTP/auth/UI claim.

Do not rewrite historical closure records to remove the fact that the disable-path evidence was missing at M002/M003 closure.

## 5. Work package B — Rootful disable-path fault injection

Close the one explicitly carried evidence gap.

### 5.1 Initial real state

Build a disposable Linux namespace fixture using the production stack:

1. initialize durable state;
2. run real `netd`;
3. reconcile a present interface + owned firewall/NAT policy at generation N;
4. prove the WireGuard link has the expected owner tag;
5. prove `inet wg_basic` has the expected installation marker.

### 5.2 Transition to disabled desired state

Commit generation N+1 requesting the managed interface absent and no network policy, preserving the exact managed resources required by the existing deletion contract.

### 5.3 Deterministic firewall failure

Qualify the production process boundary without adding a production protocol escape hatch.

Preferred fixture strategy:

- seed/verify initial state using the real system `nft`;
- restart or launch the real `wg-basic netd` process with a fixture-private directory prepended to `PATH`;
- that directory contains an executable named `nft` that satisfies only the minimum version/probe behavior required to reach apply and then deterministically fails the firewall mutation;
- no production code path or wire operation is added for fault injection.

If the current nft backend probes/version-checks in a way that makes this shape awkward, use an equally process-local mechanism that fails the nft subprocess while leaving the real kernel/interface untouched. Do not change production semantics merely to make the test easy.

### 5.4 Required assertions after failure

The failed N+1 apply must prove:

- management reports a firewall/partial or hard state failure according to the actual existing contract;
- the WireGuard interface still exists;
- its owner tag is unchanged;
- its managed addresses/routes remain;
- no RTNETLINK teardown happened;
- desired generation N+1 remains committed;
- convergence does not advance to N+1;
- unrelated host state remains untouched.

The test must distinguish “interface happened to exist” from “the disable path never invoked teardown” through observation of exact managed resources/owner tag.

### 5.5 Equal-generation recovery

Remove the failing nft shim and use the real nft binary again.

Re-run the same committed generation N+1.

Prove:

- equal-generation retry is accepted;
- owned firewall state is removed;
- interface teardown then occurs;
- post-observation verifies absence;
- convergence records N+1;
- no stale/duplicate firewall objects remain.

### 5.6 CI

Add the case to the existing `durable-restart` or `durable-owner` rootful job if that keeps evidence obvious, or add one narrowly named job if isolation is cleaner.

Do not hide this requirement inside an unrelated test file without a clearly named test.

## 6. Work package C — Pre-Phase-7 management/state boundary cleanup

Before moving code, inventory responsibilities and current public consumers.

The cleanup is required only where it materially improves Phase 7's dependency surface. Prefer mechanical extraction/re-export over redesign.

### 6.1 Management module

`src/management.rs` currently owns several separable concerns:

- health model;
- error classification;
- reconcile coordinator/coalescing;
- runtime/store ownership;
- retry policy;
- netd submission/projection integration.

Preferred target:

```text
management/
  mod.rs
  health.rs
  error.rs
  coordinator.rs
  runtime.rs
```

Exact names may differ.

Requirements:

- preserve current public types through stable re-exports where practical;
- keep `ManagementRuntime` as the primary Phase 7-facing façade;
- do not expose raw `StateStore::connection` or protocol internals;
- do not make the module async yet;
- do not add the Phase 7 blocking-worker adapter yet.

### 6.2 State store/schema

Inspect `src/state/store.rs` and `src/state/schema.rs`.

If extraction can be largely mechanical, separate:

```text
state/store/
  mod.rs
  open.rs          secure path/open/pragma lifecycle
  load.rs          typed snapshot reads
  mutation.rs      generation-CAS desired mutations
  convergence.rs   attempt/convergence evidence

state/schema/
  mod.rs
  migrations.rs
  validation.rs
```

Do not force a split if it would create circular modules or expose SQL helpers publicly.

The acceptance criterion is clearer ownership and a small `StateStore` façade, not a specific file count.

### 6.3 Aggregate module

`src/aggregate.rs` may remain one file if its responsibilities are still cohesive.

Only split it if C001's dependency review demonstrates that Phase 7 would otherwise import implementation-only coordinator details instead of the typed intent/receipt boundary.

Do not perform size-driven churn.

## 7. Public/API compatibility

Record before/after public exports.

C001 SHOULD preserve:

- `wg_basic::management::ManagementRuntime`;
- `ManagementHealth`;
- state-store public methods/types;
- aggregate intent/receipt types;
- protocol operation names/version.

If an internal module move requires a compatibility re-export, keep it.

Any intentional public removal requires a separate compatibility decision and is out of scope.

## 8. Static architecture guards

Retain existing guards and add narrowly useful assertions:

- management does not import HTTP/EggServe;
- state SQL remains confined to the state storage layer;
- state backup/restore remains free of network/protocol/process execution;
- netd remains free of rusqlite/database access;
- only the firewall nft backend executes `nft`;
- no shell execution is introduced;
- privileged protocol still contains no generic exec/file/raw-netlink/raw-nft operation.

Do not build a custom lint framework.

## 9. Verification

Required routine gates:

```text
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
```

Required current rootful suites:

```text
wireguard_kernel
network_reconcile
network_control_e2e
durable_owner
durable_restart
durable_backup
privileged_protocol
```

The new disable-path injected-failure case must run as real process/kernel evidence under the `linux-integration` feature.

Current-head hosted CI must remain fully green.

## 10. Documentation

Update current-state docs as part of the same implementation commit(s), but do not change historical closure evidence.

At closure:

- `plans/002-long-term-roadmap.md` Phase 6 must say closed;
- `plans/registry.md` must record C001 closure and Phase 7 readiness;
- `architecture/ownership.md` must describe startup reconciliation as implemented;
- any module-architecture document must reflect final paths.

## 11. Acceptance criteria

C001 closes only when:

1. all current-state docs agree that Phase 6 is closed;
2. historical closure records remain unchanged and honest about their original evidence;
3. the disable-path firewall failure is qualified with a real netd process and real kernel-managed interface;
4. firewall teardown failure leaves the interface and managed resources intact;
5. convergence does not falsely advance after the failed disable;
6. an equal-generation retry after clearing the failure removes firewall state then tears down the interface and converges;
7. no production fault-injection API/hook was added;
8. management/state module cleanup is contract-preserving and demonstrably improves ownership boundaries, or the closure record explicitly documents why a proposed split was rejected;
9. no schema/wire/protocol semantic change occurred;
10. all unprivileged and rootful CI passes on the final head;
11. no unresolved high/medium correctness/security/evidence finding remains.

## 12. Stop conditions

Stop and create a separate corrective/ADR if:

- the disable-path fixture reveals interface teardown can occur after firewall failure;
- generation/convergence evidence can advance incorrectly on failed disable;
- reliable fault injection requires changing the production privileged protocol;
- module decomposition requires changing persistence or reconciliation semantics;
- Phase 7 API/auth design becomes necessary to complete the cleanup;
- a public/wire compatibility break becomes unavoidable.

## 13. Closure evidence

Create:

- `plans/closure/durable-state-post-phase6-reconciliation/c001-status.md`.

Record:

- documentation/status drift corrected;
- rootful disable-failure topology and injection mechanism;
- exact failed-disable observations;
- equal-generation recovery result;
- before/after management/state module inventory and approximate sizes;
- public export compatibility;
- dependency diff;
- static guard results;
- routine/MSRV results;
- all rootful job results and CI run;
- unresolved findings;
- recommendation that Phase 7 planning/implementation may proceed.
