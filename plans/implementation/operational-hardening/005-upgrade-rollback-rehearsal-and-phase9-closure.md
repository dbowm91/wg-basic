# Operational Hardening M005 — Upgrade/Rollback Rehearsal and Phase 9 Closure

Status: blocked on Operational Hardening M004 closure

Source roadmap:

- `plans/subsystems/operational-hardening-roadmap.md#9-m005--upgraderollback-rehearsal-and-phase-9-closure`

Canonical architecture:

- `plans/adr/005-operational-hardening-maintenance-and-recovery.md`

Primary class: operations / release-readiness / qualification

Hard dependency: Operational Hardening M004 strict closure.

## 1. Objective

Prove the binary+database upgrade and rollback transaction that Phase 10 must automate.

Phase 9 must not close on “the new binary migrates successfully” alone. It must prove recovery when the new binary has already migrated state and then fails release health validation.

## 2. Old-version baseline

Use the immutable Phase 8 closure commit:

```text
e8fd6b1212491576f3c6bdd7468591a97d5aaf3c
```

as the initial old binary.

It supports schema v4.

Build it from the same repository history in a dedicated CI job with full-history checkout.

Do not move/tag/reinterpret that commit.

## 3. New-version baseline

The Phase 9 candidate contains the real schema-v5 network-operational-state migration from M002 plus every M001–M004 hardening change.

The rehearsal therefore uses a genuine old/new schema boundary, not a fake test migration.

## 4. CI/job structure

Add a dedicated `upgrade-rehearsal` job.

Requirements:

- checkout with history sufficient to build old commit;
- build old binary with its own Cargo.lock;
- build current candidate separately;
- never overwrite one binary with the other;
- label paths explicitly `old` and `candidate`;
- use disposable state/runtime/namespace paths;
- root privileges only for the network fixture portions.

A Rust integration harness may orchestrate both binaries via environment variables if clearer than shell.

## 5. Establish old product state

Using the old binary only:

1. initialize admin;
2. start old netd/serve;
3. authenticated server setup;
4. create at least two clients with distinct product settings;
5. establish one real client handshake/traffic;
6. create session state;
7. create/consume/revoke representative enrollment state where supported;
8. record safe semantic snapshot:
   - InstallationId;
   - DesiredGeneration;
   - server public identity;
   - client IDs/public keys/addresses/labels/enabled state;
   - audit count/order;
   - session validity;
   - exported config hash without logging config.

Confirm schema version 4.

## 6. Pre-update backup

While old version is still authoritative:

- create an explicit secret-bearing backup using old binary;
- verify it read-only;
- record schema v4, installation ID, generation;
- preserve it outside the live state path.

This is the rollback state artifact.

Do not rely only on the automatic pre-migration snapshot, because Phase 10 updater needs an explicit transaction artifact it owns/records.

## 7. Upgrade to candidate

Stop old serve/netd cleanly.

Start candidate against the old v4 database.

Prove:

- service lease acquisition;
- automatic pre-migration-v4 recovery snapshot;
- migration to v5;
- operational_enabled backfilled true;
- InstallationId unchanged;
- DesiredGeneration unchanged merely by migration;
- server/client identities unchanged;
- auth/session/product state preserved;
- startup reconcile converges;
- real client config still handshakes/passes traffic;
- doctor passes required checks.

## 8. Candidate health validation

Define the minimum Phase 10 release-health gate Phase 9 proves:

- candidate process stays running;
- doctor has no required failure;
- `/healthz` = ok for an enabled healthy installation;
- authenticated health reports DB/backend/convergence healthy;
- product read succeeds;
- real network smoke/handshake succeeds in the rootful rehearsal.

Phase 10 may choose a subset appropriate to update latency, but cannot call a candidate committed while it is merely started and unvalidated.

## 9. Failure-after-migration scenario

After a successful v4→v5 migration, deliberately make candidate release health fail without corrupting the DB, for example by withholding/stopping required netd before the release-health decision.

Prove:

- live DB remains schema v5;
- old binary refuses to open/use schema v5 as designed;
- simply replacing the executable with old binary is therefore **not** a rollback.

This negative case is load-bearing.

## 10. Rollback transaction

Correct rollback ordering:

1. stop candidate serve/netd;
2. restore the explicit pre-update v4 backup to live state using a compatible offline restore path;
3. restore/select old binary;
4. start old netd/serve;
5. validate old doctor/health/product;
6. prove client handshake/traffic;
7. prove original identities/config/session semantics expected from the snapshot.

Do not start old serve before the v4 state is restored.

## 11. Re-upgrade

After successful rollback:

1. stop old version;
2. start candidate again;
3. re-run v4→v5 migration;
4. validate health/product/traffic again.

This proves the recovery artifact can support another update attempt and the migration is deterministic/idempotent over the restored old state.

## 12. Automatic recovery artifact relationship

Compare:

- updater-owned explicit pre-update backup;
- state-layer automatic `.pre-migration-v4`.

Both are secret-bearing.

The explicit updater backup is the Phase 10 rollback authority because its lifecycle is part of the update transaction.

The automatic snapshot remains defense in depth for migration failure/manual recovery.

Document retention/cleanup expectations without deleting either before update commit.

## 13. Crash-window matrix

Exercise or reason/test with deterministic seams for:

- crash before backup complete;
- crash after backup, before binary replacement;
- crash after new binary replacement, before start;
- crash during migration;
- crash after migration, before health;
- crash after health but before update commit marker;
- rollback interrupted after old DB restored but before old service start.

For each, record which binary/state pair is authoritative and the safe next action.

Phase 10 will encode these states into Eggup/update orchestration.

## 14. Phase 10 handoff document

Create:

- `architecture/update-rollback-contract.md`.

It must state:

- binary+state are one compatibility transaction;
- required pre-update backup;
- service stop/start ordering;
- migration ownership;
- health gate;
- commit point;
- rollback order;
- recovery-required states;
- secret handling for snapshots;
- ownership revalidation.

Map these requirements to Eggup capabilities:

- stage;
- verify integrity;
- validate candidate;
- lock/revalidate destination;
- replace;
- rollback/recovery evidence;
- service lifecycle.

Do not claim Eggup supplies release authenticity; ADR/spec retain that as project/release-policy owned.

## 15. Recovery drill

In addition to upgrade rollback, run a documented operator disaster-recovery drill:

1. take and verify backup;
2. disable/stop services;
3. restore onto clean disposable host/namespace state;
4. doctor;
5. start services;
6. startup reconcile;
7. login/product smoke;
8. real client traffic.

This may reuse Phase 6/8 fixtures but must execute the Phase 9 operator commands and doctor semantics.

## 16. Full regression

Before closure run:

- ordinary Rust/MSRV;
- cargo-audit/security gate;
- doctor suites;
- network disable/purge/recovery suites;
- crash/resource suites;
- HTTP/protocol abuse;
- all existing network/durable/management/product rootful suites;
- upgrade-rehearsal job.

No historical closure record is rewritten.

## 17. Documentation reconciliation

Update:

- README;
- long-term roadmap;
- registry;
- state backup/restore docs;
- new operations runbook;
- service-hardening architecture;
- update/rollback contract.

Mark Phase 9 closed only after final green CI.

Mark Phase 10 unblocked for research/planning, not implemented.

## 18. Acceptance criteria

M005 closes only when:

1. real old binary creates schema-v4 product state;
2. candidate performs real v4→v5 migration and preserves semantics;
3. old binary demonstrably refuses migrated v5 state;
4. explicit pre-update backup restores old compatibility;
5. old binary works/serves/handshakes after rollback;
6. candidate can upgrade the restored state again;
7. failure/crash windows have deterministic recovery instructions;
8. Phase 10 update contract is explicit and Eggup responsibilities are correctly bounded;
9. disaster-recovery drill passes;
10. no unresolved high/medium operational/security finding remains;
11. all CI/MSRV/rootful/security jobs are green.

## 19. Stop conditions

Stop/ADR if rollback cannot restore a database compatible with the old binary, if state migration changes network identity unexpectedly, if the candidate can partially migrate without a recoverable snapshot, or if Phase 10 would need to infer update state from process/PID heuristics.

## 20. Closure evidence

Record old/candidate binary identities, schema versions, pre-update backup identity, migration semantic diff, old-binary refusal, rollback/re-upgrade traces, crash-window matrix, doctor/health/traffic results, update-contract/Eggup mapping, full CI matrix, Phase 9 disposition, and Phase 10 readiness.
