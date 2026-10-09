# Distribution M004 C001a — Eggup Failed-unit Recovery Adoption and C001 Closure Evidence

Status: active — Eggup prerequisites and typed failed-unit adoption are complete; the signed-fixture updater and isolated rootful CI lane are implemented, with hosted recovery evidence pending.
Repository baseline: `dbowm91/wg-basic` branch `plans/m004-update-correctives` at `297af6c` (2026-10-09), with `plans/closure/distribution/004-c001-status.md` disposition `corrective required`.
Source milestone: `plans/implementation/distribution/004-transactional-self-update-and-rollback.md`.
Corrective predecessor: `plans/implementation/distribution/004-c001-update-retry-recovery-invariants.md`; unresolved evidence in `plans/closure/distribution/004-c001-status.md`.
Next handoff: `plans/implementation/distribution/004-c002-rootful-update-qualification-and-doc-reconciliation.md`.
Primary work class: corrective / invariant / integration qualification.

## 1. Objective

Integrate Eggup's **proven** owned failed-service quiescence contract into the wg-basic transactional updater, then qualify the remaining C001 acceptance cases on the actual updater rather than relying on journal-only kill tests or the Phase 9 raw database rehearsal. Close C001 only when a failed candidate can be safely quiesced, its old-compatible database restored before the old binary starts, services return healthy, and rollback/retry/recovery are repeatable under bounded faults.

## 2. Upstream dependency and discriminating choice

Eggup owner: `eggstack/eggup`.
- Service M010: closed at source `eggstack/eggup@0bde3fefbda07019529ad7566c02e6e4ec141fd6`; hosted run `37875012280` passed all five jobs, including the real-systemd failed-state matrix.
- Service M011: required and closed. `eggup-service = "=0.1.3"` is published; registry SHA-256 is `9f7f7ea854577158e66aa202709ab1c97a3aedcf00b06c1ab914d25b132124dc`, package source `feb6ae5aea4c9b61c4051957f3662ca49d845f9e`, post-publication hosted run `37883703334` passed all five jobs. Closure records: Eggup `plans/closure/service-lifecycle/010-status.md` and `011-status.md`.
- C001 closure record notes Eggup 0.1.2 `ActiveState=failed -> LifecycleState::Unknown`, a failed-state `is-active` stop-confirmation ambiguity, and a downstream `stop_owned_services()` preflight accepting only `Running | Stopped`. These are **distinct** checks. Do not change both to permissive Unknown acceptance.

This is a bounded corrective that does not replace M004 C002's wider x86_64/aarch64 release qualification, full systemd/traffic CI or final CLI/doc reconciliation.

## 3. Required invariants

1. First prove exact owned registration for both `wg-basic.service` and `wg-basic-netd.service` via `ServiceSpec`, executable/argv/unit definition, secure installation receipt, and Eggup's owner check. An unknown *lifecycle* classification must never be treated as known stopped or as ownership proof.
2. Update/recover may stop only service identities proven owned. A failed unit must be stopped/proven quiescent by Eggup's qualified typed path; foreign, modified, missing, transitioning or manager-inaccessible units fail closed.
3. Maintain stop ordering `serve -> netd`; start ordering `netd -> serve`. Confirm serve lease released and netd socket is not active before SQLite/database rollback. Do not start old binary on migrated candidate schema.
4. The root-owned install/update lock, signed candidate/manifest parsing, fixed target, no Cargo/unsigned downgrade fallback and product health remain unchanged.
5. Journal/backup/digest/typed InstallationId/schema/generation and runtime binary compatibility are reverified after failure and after repeated recovery. Report RecoveryRequired rather than false success; retain artifacts.
6. Do not add root-owned arbitrary `systemctl` invocations, new privileged IPC commands, process killing by PID, `reset-failed` as a substitute for stop, or unsafe selector flags.
7. `Cargo.toml` pins exact published Eggup package versions. Use a local path/git dependency only for temporary non-release evaluation outside committed production manifests, never for final closure or build.

## 4. Ordered work packages

### WP1 — Rebaseline on Eggup closure — complete

M010 proved published 0.1.2 insufficient and introduced the private typed systemd failed-state stop proof without changing public lifecycle variants. M011 published 0.1.3. `Cargo.toml` and `Cargo.lock` pin/resolve the exact registry release and checksum above; no path/Git dependency is used. Record `cargo tree -i eggup-service --locked` with closure evidence.

### WP2 — Repair the local pre-stop gate without widening authority — implementation complete; focused integration evidence pending

Audit `src/update.rs` `stop_owned_services`, `stop_owned_service`, `start_owned_service`, `recover`, `apply`, `fail_before_services`, `mark_recovery_required`, and Eggup binary callback failure path. Replace the unconditional `Running|Stopped` rejection with a narrow, typed **known owned failed** transition that consumes Eggup M010's successful stop/quiescence proof. Leave truly Unknown/Transitioning and failed ownership blocked. Recheck exact service identity after mutation, and validate actual stopped lease/socket. Factor service-stop handling into one shared safe path to prevent different terminal/nonterminal recovery semantics.

The public enum still has no `Failed` variant. wg-basic allows `Unknown` only through exact-owned `SystemdManager::stop`; it requires `TransitionResult::completed()`, rechecks ownership, accepts a still-Unknown post-state only for that completed path, and checks serve lease release/netd socket inactivity. Ambiguous and transitioning states fail closed.

### WP3 — Real signed-fixture rollback/retry

Use the existing C001 implementation's typed state identity and unique restore staging; extend focused tests rather than recreating transaction machinery. Build an isolated signed release fixture (old compatible binary, strictly newer candidate, exact manifest/Minisign key and hashes) with a **test-only injection seam** for release acquisition/verification; do not provision a fixture key in production.

In a clean disposable actual systemd host: install the old owned binary, prepare state, force a candidate failure after binary commit and actual v4->v5 database migration, confirm candidate failed and correctly quiesced; prove old-compatible DB restored and verified before restoring/starting old binary. Assert source InstallationId, original schema, desired generation, peer/identity metadata, install receipt, security permissions, and services match the original. The same signed-fixture update can run again to Committed from a RolledBack terminal journal. Tamper the journal/old binary/backup/unit to demonstrate fail-closed blocking.

This is the focused C001 evidence even if a subset overlaps C002: C002 will extend it to full real VPN traffic and release qualification. Do not make the focused tests automatically authorize a public release.

### WP4 — Real updater SIGKILL and repeat recovery

Use external SIGKILL of the **actual updater process**, not only journal writer subprocess, at meaningful durable phases: ServicesStopped, BinaryCommitted, CandidateStarted and CandidateHealthy; include restoration after candidate migration and interruption inside SQLite restore. Call `update recover` twice and prove: no service overlap, compatible binary+DB after replay, verified terminal journal/receipts, no residual live service lease, and deterministic cleanup/retention policy. If incomplete evidence requires RecoveryRequired, verify that neither service runs incompatible state.

Add tests for failed/unknown/foreign unit states, altered ExecStart, stuck restart job, timeout, corrupt old-binary recovery copy, stale restore staging and disabled-network healthy profile. A source assertion or artificial journal test cannot substitute for a destructive rootful fixture.

### WP5 — Close C001 honestly, then unblock C002

Retain the historical `plans/closure/distribution/004-c001-status.md` original implementation disposition as period-accurate; add a dated append-only follow-up with exact M010/M011 evidence, new implementation commit, experiment results, commands and run links, and strict closure decision, or write a linked additive C001a closure note if the governance convention calls for one. Reconcile `plans/registry.md` and subsystem roadmap *only after* closure evidence is real. If any required updater signed-fixture/repeat recovery evidence remains unavailable, classify C001 `corrective required`, keep C002 blocked and write a precise remaining blocker instead.

## 5. Security and compatibility impacts

Preserve installed binary+SQLite compatibility pair, signed root chain and Minisign signature-before-manifest projection, target mapping, root-owned root-only update journal, management-owned SQLite, and netd's no-DB rule. No HTTP, privileged IPC, WireGuard wire format or public release signing change. Do not log secrets or state backup contents. Cross-platform service-API changes belong exclusively in Eggup.

## 6. Tests and verification commands

```text
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
cargo audit
cargo tree -i eggup-service --locked
git diff --check
```

Additional required current-head evidence: C001-focused rootful owned failed-service integration, updater rollback -> RolledBack -> re-update to Committed, actual updater SIGKILL/recover twice with v4/v5 database, negative corrupted/foreign fixtures, Phase 9 `upgrade_rehearsal` and `upgrade_rehearsal_rootful`, old M002 system installation tests on disposable host when available. Capture kernel/systemd version and GitHub run IDs. Existing 559-test baseline is historical, not automatically current-head green.

## 7. Documentation, acceptance and stop conditions

Update service-rollback contract and operations-runbook only when behavior actually changes, including exact `wg-basic update recover` CLI and failure diagnosis. C001a closes when its upstream pin is proven, failed-unit quiescence never damages foreign resources, all replay/rollback identity tests pass on real installed services and the surviving artifact journal is durable, with no medium/high unknown risk.

Stop if Eggup M010 remains unqualified; registry publication is required but missing; exact service unit ownership cannot be proven; quiescence requires resetting failure state to conceal facts; candidate and old schema cannot be reconciled; reproducer is inconclusive; fixture signing bleeds into production; or rootful tests would run on an irreplaceable development machine.

## 8. Handoff evidence

Record upstream source/published version/checksum, lock graph, C001 implementation SHA, rootful VM/systemd/architecture, all forced failure and crash cutpoints, old/new state identity proofs, journaling/retained artifacts, negatives, routine+MSRV+audit status, and C002 unblock recommendation. M004 itself stays active until C002 and canonical milestone closure satisfy all gates. M005 remains blocked.

## 9. Implementation progress — qualification harness added (2026-10-09)

The opt-in `update-test-fixtures` feature supplies an in-process signed-release
fixture transport, a candidate startup failure marker, migration-v4 simulation,
and bounded durable-phase / SQLite-restore gates. The fixture seam is absent
from default builds and release workflow files are pinned by an architecture
guard. The signed fixture key is generated ephemerally by the rootful test;
only its public key is written to the private fixture directory.

`tests/update_transaction_rootful.rs` provisions a clean native systemd
installation, installs the current binary against a v4 database, and drives a
strictly newer signed candidate through updater recovery. It externally
SIGKILLs the actual updater at BackupVerified, ServicesStopped, BinaryCommitted,
CandidateStarted, and CandidateHealthy, calling recovery twice after each
cutpoint. It then forces a post-migration candidate startup failure, kills the
updater during staged SQLite rollback, recovers twice, and retries the same
signed update to Committed. Database schema, installation ID, generation, and
client count are checked across rollback and retry. A dedicated Ubuntu 24.04
systemd CI lane builds the newer candidate in an isolated source copy and runs
this ignored rootful test on its ephemeral hosted VM. The first hosted
attempt exposed that the base runner omits `/etc/sysusers.d`; the fixture now
creates that standard directory before provisioning the managed account.

Local verification on this implementation tree: formatting, ordinary check
and clippy, feature clippy, Rust 1.89 check, the complete ordinary suite (561
passed, 3 ignored), cargo audit (211 locked dependencies), the pinned Eggup
service dependency graph, and `git diff --check` passed. The updater rootful
test compiles but has not been run on this shared host. The hosted qualification
has not yet passed, so this plan remains active and C001 remains
corrective-required. Do not unblock C002 or M005 until hosted destructive
qualification passes and remaining C001 acceptance cases are reconciled.

Hosted run `37887926091` passed every existing CI job but exposed a C001a
recovery failure at the first updater kill point. Diagnostic run `37888759782`
identified the cause: terminal health called `doctor` while `serve` was active;
doctor intentionally refuses immutable inspection when the live SQLite WAL
sidecars exist and reports State, NetworkOwnership, and Forwarding as Unknown.
`validate_candidate_health` and `validate_running_product_health` now rely on
the already-run systemd `ExecStartPre` doctor check plus owned-service state,
live management health, typed identity, and the product health endpoint while
services are active. Hosted verification of this correction is pending.

Hosted run `37889231874` then passed the BackupVerified and ServicesStopped
recovery cutpoints and reached BinaryCommitted. SIGKILL there left Eggup's
transaction lock record, as expected when the updater dies inside Eggup's
post-commit callback. Recovery now authorizes Eggup's own stale-lock claim only
while holding wg-basic's exclusive install lock and after validating the update
journal, candidate/old binaries, backup, root-private lock record, exact
wg-basic product/release identity, and absence of the recorded PID. Unknown,
malformed, mismatched, or live records remain blocked. The rootful matrix now
asserts Eggup removes the claimed record after each recovery. This correction
has not yet been hosted-verified; C001/C001a remain corrective-required and
C002/M005 remain blocked.
