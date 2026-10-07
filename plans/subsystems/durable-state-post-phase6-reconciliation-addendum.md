# Durable State Post-Phase-6 Reconciliation Addendum

Status: closed; C001 strictly closed at `635a130`

Canonical references:

- `plans/000-long-term-specification.md`
- `plans/001-terminology-and-domain-model.md`
- `plans/002-long-term-roadmap.md`
- `plans/003-planning-process.md`
- `plans/adr/001-linux-native-control-plane.md`
- `plans/adr/002-durable-state-generations-and-ownership.md`
- `plans/subsystems/durable-state-restart-reconciliation-roadmap.md`

Historical closure references:

- `plans/closure/durable-state/001-status.md`
- `plans/closure/durable-state/002-status.md`
- `plans/closure/durable-state/003-status.md`
- `plans/closure/durable-state/004-status.md`

## 1. Purpose

Phase 6 is closed and remains closed.

This addendum records one bounded post-closure corrective pass before Phase 7 adds HTTP/auth/UI consumers. It exists to:

1. reconcile stale current-state documentation and roadmap status;
2. close the one real-kernel evidence gap explicitly carried forward from durable-state M002/M003;
3. reduce avoidable management/state module concentration before the Phase 7 service layer depends on those internals.

It does not reopen ADR-002, the desired-generation model, ownership semantics, SQLite authority, or M001–M004 closure.

## 2. Findings

### 2.1 Current-state documentation drift

Current repository evidence and the registry say Phase 6 is closed, but some canonical/current-behavior surfaces are stale.

Known examples:

- `plans/002-long-term-roadmap.md` still says Phase 6 is planned and blocked on C001;
- `architecture/ownership.md` still says automatic startup application is not implemented and belongs to M003, even though M003 is strictly closed;
- `plans/registry.md` still labels its last planning reconciliation as C001 closure rather than Phase 6 closure.

The corrective must search for equivalent stale milestone-era wording rather than patch only these literals.

### 2.2 Disable-path rootful evidence gap

Durable-state M002 required two injected firewall-failure cases.

M003 later provided real process/kernel coverage for the enable-path case: the interface layer mutates, the firewall layer fails, and restart/equal-generation retry converges.

The disable-path equivalent remains below the intended evidence standard:

- code ordering is correct;
- unit coverage proves `apply_disabling` stops before interface teardown when the firewall layer does not complete;
- normal successful disable is covered end to end;
- but no rootful process-level failure fixture proves that a real interface survives a firewall teardown failure.

This is evidence debt, not evidence of a known implementation defect.

### 2.3 Pre-Phase-7 module concentration

C001 successfully decomposed network-control modules.

Phase 6 added new concentrated management/state files:

- `src/management.rs` ~34 KiB;
- `src/state/schema.rs` ~40 KiB;
- `src/state/store.rs` ~36 KiB;
- `src/state/backup.rs` ~25 KiB;
- `src/aggregate.rs` ~28 KiB.

Size alone is not a defect. However, Phase 7 will add async HTTP routing, authentication/session handling, a blocking-worker adapter around SQLite, and request concurrency. The management/state public boundary should be clear before those consumers arrive.

## 3. Invariants

C001 MUST preserve:

1. Rust 1.89 MSRV.
2. `unsafe_code = "deny"`.
3. SQLite as authoritative desired state.
4. netd as database-free privileged authority.
5. monotonic `DesiredGeneration` and expected-generation CAS.
6. installation/interface `OwnerTag` semantics.
7. installation-specific nftables ownership.
8. aggregate generation-aware reconciliation ordering.
9. one outer netd mutation serialization boundary.
10. startup unconditional observation/reconciliation.
11. bounded transient retry and fail-closed ownership conflicts.
12. online backup/offline validated restore semantics.
13. all M001–M005/C001/Phase 6 rootful and unprivileged evidence.
14. existing public/wire compatibility unless a purely internal re-export move is required.

## 4. Non-goals

C001 MUST NOT:

- add HTTP or EggServe;
- add authentication/session state;
- add CSRF;
- add UI/static assets;
- add systemd/install/update behavior;
- add IPv6;
- add periodic drift monitoring;
- change SQLite schema solely for cleanup;
- create a fake production migration;
- change desired-generation semantics;
- weaken owner-tag/table-marker conflicts;
- replace the nft backend;
- add a generic test hook to the production privileged protocol.

## 5. Corrective milestone

### C001 — Post-Phase-6 reconciliation, missing fault evidence, and pre-Phase-7 boundary cleanup

Status: closed.

Implementation plan:

- `plans/implementation/durable-state/c001-post-phase6-reconciliation-and-pre-phase7-hardening.md`

Closure record:

- `plans/closure/durable-state-post-phase6-reconciliation/c001-status.md` (head `635a130`, CI run `37638334930`)

Primary class:

- corrective / evidence / maintainability.

## 6. Exit conditions

C001 closes only when:

- all current-state planning/architecture docs describe Phase 6 as implemented and closed;
- the disable-path firewall-failure invariant has real process/kernel evidence;
- the failure fixture proves the managed interface remains intact when firewall teardown fails;
- clearing the injected firewall failure and retrying the same generation converges;
- any module decomposition is behavior-preserving and keeps the Phase 7-facing management/state API smaller and clearer;
- no schema/wire/protocol compatibility change is introduced;
- all seven current CI jobs remain green;
- the corrective adds its own closure record.

## 7. Closure record

Create:

- `plans/closure/durable-state-post-phase6-reconciliation/c001-status.md`

Historical M001–M004 closure records remain unchanged and period-accurate.
