# Update and rollback contract

This contract is Phase 9 output for Phase 10. It describes the required
transaction around a candidate binary and the authoritative SQLite database;
wg-basic does not yet implement an automatic updater.

## Transaction rule

The executable and state database form one compatibility pair. A candidate is
not committed merely because it starts or migrates successfully. Before the
update begins, the updater must own an explicit, verified, owner-only backup
that remains outside the live database path until the commit point.

The safe sequence is:

1. Validate the staged candidate integrity and release metadata.
2. Lock/revalidate the installation paths and current binary/state identities.
3. Ask the current compatible binary to create and verify an explicit
   pre-update backup; record its path, schema, installation ID and generation.
4. Stop `serve` and `netd`; confirm both have exited and released their
   service/socket ownership.
5. Replace the binary, retaining the old binary as the rollback selection.
6. Start the candidate against the existing database. The candidate owns the
   transactional migration and its automatic `.pre-migration-v4` snapshot.
7. Run the release-health gate: candidate remains alive, doctor has no required
   failure, `/healthz` is `ok` for an enabled/healthy installation, authenticated
   health reports reachable backend and convergence, product reads succeed, and
   the rootful release rehearsal confirms client traffic.
8. Persist the update commit marker only after every required health result has
   passed. This is the transaction commit point.
9. Retain both the explicit updater backup and automatic migration snapshot
   through the commit point. Cleanup afterward follows the documented backup
   retention policy.

`serve` and `netd` must never overlap old and candidate versions against the
same state/runtime paths. The old binary must not start against migrated v5
state: its refusal is expected and does not constitute rollback.

## Rollback order

If any migration or health step fails before the commit marker:

1. Stop candidate `serve` and `netd`, then confirm the service lease is free.
2. Restore the explicit pre-update database backup using a binary that can
   validate its schema (the old binary in the Phase 9 v4 rehearsal).
3. Verify restored schema, installation identity, generation, integrity and
   ownership metadata.
4. Select the retained old binary.
5. Start old `netd` and `serve`; only then run old doctor, authenticated product
   checks and the real traffic smoke test.
6. Keep the candidate and both recovery artifacts until the rollback is
   recorded as complete.

If rollback is interrupted after the v4 database is restored but before the
old service starts, the compatible pair is old binary + v4 database. The next
safe action is to start that old pair and validate it. If the migration failed
inside SQLite, first preserve the live file and inspect the automatic
pre-migration snapshot; do not start an old binary against an uncertain schema.

## Crash-window matrix

| Crash point | Authoritative pair/artifact | Safe next action |
|---|---|---|
| Before explicit backup completes | Old binary + live v4 database | Discard only the incomplete staged backup; keep serving old version. |
| After backup, before binary replacement | Old binary + live v4; explicit v4 backup | Restart old service; retain backup for retry. |
| After candidate binary replacement, before candidate start | Candidate binary + live v4; explicit v4 backup | Start candidate, which owns v4→v5 migration; if health fails, restore explicit v4 before selecting old binary. |
| During migration | Candidate + SQLite transaction state; automatic pre-migration v4 snapshot | Let SQLite recover, inspect integrity/schema offline, then start candidate or restore explicit v4. |
| After migration, before health | Candidate + live v5; explicit and automatic v4 snapshots | Do not start old binary. Stop candidate and restore explicit v4 before old selection. |
| After health, before update commit marker | Candidate + live v5; both v4 snapshots | Treat as uncommitted until the marker is durable; rollback by restoring v4 first. |
| Rollback after v4 restore, before old service start | Old binary + restored v4 database | Start old netd/serve and validate; never relaunch candidate implicitly. |
| After durable update commit marker | Candidate + live v5; retained recovery artifacts | Candidate is authoritative; recovery follows the committed release transaction and operator policy. |

The marker is the sole commit discriminator. PID files, process names, or
“service appears to be running” observations cannot infer transaction state.

## Secret and ownership handling

The explicit backup and automatic snapshot contain server/client private keys,
preshared keys, password verifiers, session state, enrollment digests and audit
history. Keep them owner-only under a protected state directory; never include
their bytes in logs, argv, environment, health reports, or release artifacts.
Only retain paths and safe metadata in the updater journal. Do not delete a
recovery artifact before the update commit marker.

Restoring data does not grant ownership of unrelated host state. On every
start, netd revalidates interface tags and nftables installation markers and
fails closed on foreign or ambiguous objects. The rollback health gate must
confirm those ownership rules and actual traffic, rather than assume a database
restore recreated a trustworthy kernel state.

## Phase 10 responsibility mapping

| Required capability | Update orchestration responsibility |
|---|---|
| Stage | Stage old/candidate binaries and the explicit backup at separate protected paths. |
| Verify integrity | Verify the candidate artifact and backup before any live replacement. Release authenticity remains wg-basic/release-policy owned. |
| Validate candidate | Start the candidate only after the old service stops; run doctor, liveness, authenticated product and traffic health gates. |
| Lock/revalidate destination | Hold an update transaction lock and revalidate current binary, state path, owner, schema, installation ID, generation and service lease before replacement/restore. |
| Replace | Keep old and candidate binaries distinct; never overwrite the only rollback binary. |
| Rollback/recovery evidence | Journal safe metadata and commit marker; restore compatible state before selecting the old binary; preserve snapshots through commit. |
| Service lifecycle | Stop old roles, start candidate, stop failed candidate, restore state, then start old roles in that order. |

Eggup is the preferred Phase 10 local replacement substrate. This contract
does not claim that Eggup supplies release authenticity, product health policy,
SQLite migration ownership, binary/database transaction semantics, or the
rollback commit marker. Phase 10 must validate the concrete Eggup API and keep
those responsibilities in wg-basic orchestration.
