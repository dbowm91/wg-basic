# Durable State M004 — Backup, Restore, Migration, and Phase 6 Qualification

Status: blocked on Durable State M003 closure

Source roadmap:

- `plans/subsystems/durable-state-restart-reconciliation-roadmap.md#9-milestone-m004--backup-restore-migration-and-phase-6-qualification`

Canonical requirements:

- `plans/adr/002-durable-state-generations-and-ownership.md`
- `plans/000-long-term-specification.md#12-durable-storage`
- `plans/000-long-term-specification.md#16-installation-and-operations`

Primary class: capability / operational invariant

Hard dependency:

- Durable State M003 strictly closed.

## 1. Objective

Close Phase 6 by proving that durable wg-basic state can be backed up, upgraded, restored, validated, and then used to reconstruct network state without weakening ownership or secret-handling guarantees.

M004 owns database recovery mechanics, not general package rollback.

## 2. rusqlite backup support

Enable rusqlite's `backup` feature if not already enabled.

Use SQLite's online backup API for a consistent source snapshot.

Do not implement backup as a blind `cp state.db` while WAL mode is active.

The backup API may run while the management store is open; wg-basic may additionally serialize its own state mutations during backup to simplify “backup corresponds to generation N” evidence.

## 3. Backup result contract

A backup operation returns:

- source installation ID;
- source desired generation;
- destination path;
- schema version;
- completion disposition.

It MUST NOT print secret contents.

The destination SQLite file itself is secret-bearing.

## 4. Backup path safety

Requirements:

- destination parent must be a real directory;
- existing destination is rejected by default;
- symlink destination rejected;
- temporary output created with restrictive permissions;
- final file mode restrictive;
- no shell;
- no world-readable intermediate file;
- failed backup cleans only its owned temporary artifact.

If an explicit overwrite feature is desired, defer it unless atomic safe replacement is implemented and clearly justified.

## 5. Backup consistency

Required test:

1. desired generation N exists;
2. backup starts;
3. concurrent mutation attempt is either serialized or produces a documented snapshot generation;
4. completed backup opens and reports one complete valid generation, never mixed rows.

Simplest acceptable Phase 6 policy: hold the StateStore mutation lock for the short backup on this small database.

Record backup generation in the returned receipt.

## 6. Restore boundary

Restore is offline/exclusive.

Do not restore into the database currently owned by a live StateStore connection.

Provide a library/CLI path that:

1. proves active target state store is not in use according to current process contract;
2. validates candidate path/no-follow;
3. opens candidate read-only;
4. configures hardened read connection;
5. runs `quick_check` or stronger integrity check;
6. rejects schema newer than binary;
7. copies candidate into an owned private temp database;
8. applies pending migrations to the temp copy;
9. loads and validates the entire typed desired state;
10. verifies installation/generation invariants;
11. closes/fsyncs as required;
12. atomically replaces the inactive target;
13. preserves/reports the old target for recovery or removes it only after explicit successful replacement policy.

Because Phase 10 owns install/update lifecycle, M004 may require the management service to be stopped manually for the CLI restore command.

## 7. Restore and kernel semantics

Restore never directly mutates networking.

After restore, ordinary M003 management startup:

- loads restored InstallationId/generation;
- projects intent;
- reconciles through netd;
- applies durable owner rules.

Cases:

### Clean host

No owner-tagged resources exist. Desired present interface is created with restored owner tag.

### Host already has matching restored owner tag

Reconcile it.

### Host has foreign/same-name resources

Fail closed.

A restored DB does not authorize takeover of unrelated host state.

## 8. Migration fixture strategy

Retain schema fixtures under tests/fixtures or construct them deterministically from historical migration boundaries.

For every retained schema version:

- open fixture;
- run migration to latest;
- validate user_version;
- validate foreign keys;
- load full typed state;
- compare expected semantic state;
- verify generation/install identity preservation.

Never rewrite historical migration SQL to make a new test pass. Add a new migration.

## 9. Pre-migration recovery

Before applying a migration to a non-empty user database, create a recovery snapshot using the same safe backup mechanism unless implementation evidence shows an equally strong replacement.

Rules:

- no snapshot required for brand-new migration-0 initialization;
- snapshot must correspond to the pre-migration schema;
- migration failure leaves original DB untouched or restores it atomically;
- recovery snapshot naming/location is deterministic and documented;
- bounded retention policy may keep only the immediately previous migration snapshot initially.

Do not accumulate unbounded automatic backups.

## 10. Corruption/tamper handling

Required cases:

- malformed SQLite file -> fail closed;
- `quick_check` failure -> fail closed;
- user_version newer than binary -> fail closed;
- missing required singleton installation row -> fail closed;
- foreign-key violation -> fail closed;
- invalid key/address/domain row -> fail closed;
- duplicate IDs/relations -> fail closed;
- unsafe database owner/mode/path -> fail closed.

No privileged reconcile call occurs from an unvalidated candidate database.

## 11. CLI/operator surface

Add a small state-focused CLI surface if it fits the existing command layout.

Candidate commands:

```text
wg-basic state status
wg-basic state backup <path>
wg-basic state restore <path>
```

Exact naming is implementation-defined.

Requirements:

- concise human output;
- no secret dump;
- machine-readable output may be deferred;
- restore clearly warns/requires inactive management state;
- backup output states that the file contains VPN credentials.

Do not add general SQL/database shell access.

## 12. State status

A safe status projection may show:

- installation ID;
- schema version;
- desired generation;
- last attempted generation;
- last converged generation;
- convergence status;
- DB path;
- DB integrity state.

It MUST NOT show private/preshared keys.

## 13. End-to-end backup/restore qualification

Rootful scenario:

1. initialize SQLite state for a real namespace topology;
2. startup reconciles and traffic succeeds;
3. create backup at generation N;
4. stop management/netd;
5. remove state DB and managed kernel resources or create a fresh namespace/server environment;
6. restore backup;
7. start netd/management;
8. startup reconciles restored generation;
9. WireGuard handshake and forwarding/NAT succeed;
10. peer/client IDs and desired configuration equal backup source semantically.

Add a variant where a foreign same-name resource exists; restore succeeds as a database operation but startup reconciliation fails closed and preserves foreign host state.

## 14. Upgrade qualification

Create at least one synthetic migration 1 -> 2 by the time M004 executes, even if it is a harmless additive metadata field, only if a genuine schema evolution has occurred during Phase 6.

Do not manufacture production schema churn solely to exercise migrations.

If Phase 6 still has one schema version, build a test-only historical fixture using migration-runner mechanics without shipping a meaningless migration.

The closure record must distinguish real migration history from test-only migration harness evidence.

## 15. Power-loss/durability evidence

Do not claim full hardware power-cut testing unless actually performed.

Required evidence:

- WAL + synchronous FULL readback;
- process-kill/crash tests around commit boundaries where practical;
- SQLite integrity after abrupt process termination in test fixture;
- documented limitation that filesystem/hardware lying about fsync is outside application control.

Correctness claims should be precise.

## 16. Verification

Routine Rust/MSRV.

All previous rootful network + restart suites remain green.

Add backup/restore/migration tests and one real-kernel restored-state scenario.

## 17. Documentation

Add/update:

- `docs/state-backup-restore.md`;
- `architecture/state-store.md`;
- `architecture/startup-recovery.md`;
- README current capability statement;
- registry and long-term roadmap Phase 6 state.

Explicitly document:

- backups contain VPN secrets;
- restore is not host-state takeover;
- stop/offline requirement;
- schema-newer-than-binary behavior;
- recovery snapshot behavior.

## 18. Acceptance criteria

M004 closes only when:

1. online backup creates a consistent secret-safe-permission snapshot;
2. backup never blindly copies active WAL state;
3. restore validates before replacement;
4. failed restore preserves original DB;
5. newer/corrupt/invalid DB fails closed;
6. migration runner upgrades all retained fixtures;
7. pre-migration recovery behavior is tested;
8. restored DB drives normal startup reconciliation;
9. real restored-state WireGuard + forwarding/NAT qualification passes;
10. foreign host resources remain preserved/conflicting;
11. all prior Phase 6/network tests remain green;
12. docs/registry describe Phase 6 as implemented only after closure.

## 19. Stop conditions

Stop/research if:

- online backup cannot be used without unsafe file-path behavior;
- atomic restore requires Phase 10 service/install machinery not yet available;
- migration recovery cannot preserve the original DB;
- backup/restore introduces a second secret format or separate authority;
- tests would need to weaken owner-tag conflict behavior.

## 20. Closure evidence

Record:

- backup API/version;
- path/mode/no-overwrite evidence;
- snapshot generation consistency;
- restore validation matrix;
- migration fixture matrix;
- corruption/newer-version behavior;
- process-kill durability evidence;
- rootful restore-to-network result;
- all hosted CI;
- remaining limitations;
- Phase 6 closed/conditional disposition and Phase 7/8 readiness.