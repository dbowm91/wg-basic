# Durable State M004 Closure — Phase 6 Closure

Status: closed. Phase 6 is closed.

Planning baseline: `5309cf6` (M003 closure)
Final implementation head: `772203d`
Qualification run: see the registry entry for the CI run that qualified this head

## Outcome

M004 is strictly closed, and with it **Phase 6**. Durable wg-basic state can be backed up while the service is running, validated, restored, and used to reconstruct real network state without weakening any ownership or secret-handling guarantee.

Every acceptance criterion in the plan is met. Two things the plan asked for were not delivered in the form it anticipated, and both are recorded below rather than glossed over: there is no second schema version to migrate (so the migration evidence is a test-only harness), and there is no hardware power-cut evidence (because none is claimed).

## Requirement-to-evidence matrix

| Plan requirement | Evidence |
|---|---|
| §2 rusqlite backup support | `rusqlite`'s `backup` feature is enabled. `StateStore::backup` uses `rusqlite::backup::Backup`, which snapshots a live database through SQLite's online backup API. It is never a `cp`. |
| §2 no blind copy of active WAL state | `a_backup_is_not_a_blind_copy_of_the_live_database` backs up, advances the live store, and proves the snapshot did *not* follow it. The fixture comment and `docs/state-backup-restore.md` state the WAL hazard explicitly. |
| §3 backup result contract | `BackupReceipt` carries installation identity, desired generation, destination path, schema version, and a `BackupDisposition`. `a_backup_receipt_carries_no_secret_contents` proves neither the receipt nor the operator output contains key material. |
| §4 backup path safety | `prepare_destination` requires a real, correctly-owned, non-group/world-writable parent and refuses an existing destination or a symlink. The staging artifact is created `0600` at creation rather than narrowed afterwards. `a_backup_refuses_a_destination_inside_an_unsafe_directory`, `a_backup_refuses_to_overwrite_an_existing_destination`, `backup_artifacts_are_owner_only_and_leave_no_temporary_files`, and `a_failed_backup_removes_only_its_own_temporary_artifact` cover each rule, including that a failed backup deletes only what it created. |
| §4 no shell | The state module never executes a program. `backup_and_restore_stay_a_local_file_operation` pins this in source, forbidding `Command::new`, `std::process::Command`, `libc`, sockets, and `setuid` in the module. |
| §5 backup consistency | The store's mutation lock is held for the whole operation, so the receipt's generation is exactly the file's generation. `a_backup_is_a_consistent_snapshot_of_exactly_one_generation` proves the independent copy reports the same generation, the same installation identity, and byte-equal typed state. |
| §6 restore boundary | Restore is a free function over paths, refuses a target or candidate this process still holds open (`a_restore_refuses_while_the_target_is_open_in_this_process`, `a_restore_refuses_a_candidate_opened_by_this_process`), validates the candidate read-only, migrates a private staging copy, loads and validates the full typed state, verifies the identity and generation agree, fsyncs file and directory, then renames into place. `a_restore_round_trips_identity_generation_and_typed_state` covers the happy path. |
| §6 previous target preserved | `replace_target` moves the old database to `<state>.pre-restore` rather than deleting it. `a_restore_retains_the_previous_database_for_recovery` proves the retained file is still a usable store with its original installation identity. |
| §6 failed restore preserves the original | `a_failed_restore_preserves_the_original_database` restores a structurally valid database whose rows cannot be typed, then proves the original identity and snapshot are intact, no `.pre-restore` was created, and the staging artifact was cleaned up. |
| §7 restore and kernel semantics | Restore never touches the kernel. The rootful `a_restored_database_drives_real_wireguard_forwarding_and_nat` proves the clean-host case end to end: a fresh environment is built, the backup is restored, ordinary startup reconciles it, and real traffic flows. |
| §7 foreign/same-name host resources | The rootful `a_restore_does_not_authorize_taking_over_a_foreign_same_name_link` plants an unrelated same-name WireGuard link with a foreign owner tag. Restore succeeds as a database operation; startup then fails closed, the foreign link survives with its tag intact, and the desired generation is preserved. |
| §8 migration fixture strategy | See "Migration evidence" below. Historical migration SQL was not rewritten; the pre-existing migration is untouched. |
| §9 pre-migration recovery | `recovery_snapshot` writes `<state>.pre-migration-v<N>` before a schema-changing migration, using the same online backup API and `0600`. `a_pre_migration_snapshot_is_taken_before_a_schema_change` proves the snapshot exists, is owner-only, and carries the *pre-migration* version. `no_snapshot_is_taken_when_there_is_nothing_to_migrate` proves no snapshot for a fresh initialization or an already-current database, and `a_snapshot_name_is_deterministic_and_documented` pins the name. Retention is bounded by the version in the name. |
| §10 corruption and tamper handling | `a_file_that_is_not_sqlite_is_refused`, `a_truncated_database_is_refused_by_the_integrity_check`, `a_schema_newer_than_the_binary_is_refused_before_anything_is_replaced`, `a_missing_singleton_installation_row_is_refused`, `a_duplicate_identifier_is_refused_at_every_layer`, `a_world_readable_candidate_is_refused`, and `a_symlinked_candidate_is_refused` cover malformed files, `quick_check` failure, a future schema, a missing singleton, duplicate identities and relations at all three layers, and unsafe mode/path. |
| §10 no privileged reconcile from an unvalidated candidate | Restore has no path to the protocol or to netd. The module-level guards in `tests/state_store.rs` keep `backup.rs` free of `crate::protocol`, `crate::reconcile`, `crate::firewall`, and every netlink type. |
| §11 CLI/operator surface | `wg-basic state status|backup|restore`. Status prints identifiers, generations, categories, and the integrity verdict, and states that it never includes keys. Backup output states the file contains VPN credentials. Restore states that it did not touch the kernel and that a restored database is not authority over host state. `the_state_cli_offers_no_sql_or_shell_access` pins that no SQL or shell vocabulary is advertised. |
| §12 state status | `ManagementHealth` and `state status` are the two projections. Neither has a field for a receipt, an error string, or key material. |
| §13 end-to-end qualification | `tests/durable_backup.rs` manages the server side of a real three-namespace topology entirely through the store: real `wg-basic reconcile` child processes, the real `netd` binary, real RTNETLINK and nftables, and real WireGuard traffic through the tunnel and out via masquerade. The backup and the restore both go through the operator CLI. The restored installation identity, generation, interface identity, peer, and client assignment are all compared against the backup source. |
| §14 upgrade qualification | See "Migration evidence". No production schema churn was manufactured. |
| §15 durability evidence | `tests/state_durability.rs`. A child process commits real generations and then dies via `abort()`, so SQLite gets no chance to close cleanly or checkpoint. The parent proves the database reopens, that what survives is one whole generation rather than a partial write, that the snapshot still passes typed validation, that WAL sidecars did not become world-readable, and that a backup of the recovered database is itself consistent. |
| §15 no over-claiming | `docs/state-backup-restore.md` states plainly that hardware power-cut safety is **not** claimed: a filesystem or disk that acknowledges `fsync` without durably storing data has already violated the contract SQLite relies on, and no application-level test can detect it. |
| §16 verification | `cargo fmt --all --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`, and `cargo +1.89.0 check --all-targets --locked` (with and without `linux-integration`) all pass. Every prior rootful suite was re-run green. Two new rootful jobs, `durable-restart` and `durable-backup`, run in CI. |
| §17 documentation | `docs/state-backup-restore.md` (new), `architecture/state-store.md`, `architecture/startup-recovery.md`, `architecture/overview.md`, `README.md`, and `docs/development.md`. |

## Migration evidence: real history versus test-only harness

**Phase 6 shipped exactly one real migration.** There is no genuine version 1 → 2 upgrade to replay, and the plan explicitly forbids manufacturing production schema churn to create one.

The migration fixtures therefore drive the **real migration runner** over a `#[cfg(test)]`-only second step (`schema::test_only_migrations`), which adds an unused metadata table. This qualifies the runner's ordering, version stamping, foreign-key check, transactionality, and state preservation, and it qualifies the pre-migration snapshot path against a simulated upgrade.

This is a **test-only harness, not migration history**. No closure claim should read it as evidence that wg-basic has migrated a user's database across a schema boundary in production.

What the fixtures do establish:

- `the_runner_upgrades_a_historical_fixture_to_the_latest_version` — a database built at the real version-1 boundary is upgraded, the new version's schema exists, the installation identity is preserved, and the result is genuinely newer than what the binary ships, so the production opener correctly refuses it.
- `an_upgrade_preserves_installation_identity_and_typed_state` — the installation identity, desired generation, and the entire typed desired state survive an upgrade unchanged.
- `a_schema_newer_than_the_binary_is_refused_rather_than_downgraded` — a database stamped beyond the supported version is refused, never downgraded.
- `foreign_keys_are_checked_after_every_migration_step` — a dangling relation fails the migration step.

The one real migration (`001_initial.sql`) was not modified.

## A fail-closed gap found and fixed

`enforce_singleton` only rejected **more** than one singleton row. A database whose `installation` row had been deleted — through tampering, or a partial write — therefore opened successfully and was merely unusable afterwards. A store that opens and then silently cannot identify its installation is exactly the failure mode the plan's corruption section is meant to prevent.

It now requires **exactly one** row, and the check runs after seeding, so a brand-new initialization still satisfies it while a reopened database missing its rows fails closed. `a_missing_singleton_installation_row_is_refused` and `the_store_refuses_a_database_whose_singleton_row_is_missing` cover both intents.

## A vacuous architecture guard, corrected

`the_desired_state_module_does_not_depend_on_the_network_backends` asserted that no state file mentions `rusqlite::backup`. That was written in M001 precisely *because* the `backup` feature was deliberately not yet enabled, and M004 enables it. The guard was inverted relative to the new intent.

It is now `the_state_module_does_not_depend_on_the_network_backends`, which keeps the real boundary — no state module reaches reconcile, firewall, protocol, `rtnetlink`, or `nl_wireguard` — across all five state files, and explicitly exempts `projection.rs` from the reconcile check because projecting a snapshot into kernel intent is that module's entire purpose. `backup_and_restore_stay_a_local_file_operation` was added alongside it, pinning the positive rule that backup and restore stay a local file operation.

## Fixture findings worth recording

Three defects in the new rootful fixture were found while bringing it up, and are recorded because each would have produced a passing test that proved nothing:

- The topology generated a server keypair while the desired state hardcoded a *different* private key, so the client could never complete a handshake.
- `configure_client` generated a *second* client keypair instead of using the topology's, so the server's configured peer did not exist on the client.
- The first post-restore traffic assertion was checking a file the test had not written to.

The kernel's `ip` output does not print WireGuard peers, so these were only visible by asking `netd` to observe the device. The fixture now does that on failure.

The post-restore phase deliberately builds a **fresh** set of namespaces instead of tearing the old ones down. That is the stronger claim — the restored database must rebuild an environment that has never seen it — and it avoids carrying namespace-scoped kernel state, conntrack entries above all, across the two phases. Reusing the namespaces failed for exactly that reason and would have tested fixture hygiene rather than recovery.

## Test totals

Unprivileged: 114 library, 3 binary, 10 architecture guards, 30 state store, 20 backup/restore, 5 durability, 2 privileged protocol — 184 total, all passing.

Rootful: `durable_backup` 2, `durable_restart` 8, `durable_owner` 10, `network_control_e2e` 2, `wireguard_kernel` 2, `network_reconcile` 2, `privileged_protocol` 2 — 28 total, all passing.

## Phase 6 disposition and downstream readiness

**Phase 6 is closed.** The durable state store, ownership, startup recovery, and backup/restore chain is complete and qualified end to end against a real kernel.

Phase 7 (management service, auth, HTTP/API/UI) is **unblocked for planning and implementation**. The inputs it depends on are now stable: a typed, versioned `netd` protocol; a health projection shaped so a surface can be added without exposing internals; a reconcile-on-write path that reports committed state and kernel convergence separately; and an operator CLI that already refuses to become a SQL shell.

Phase 8 (distribution, install, update) remains **blocked**, because Phase 7 has not closed and because restore currently requires an operator to stop the management service by hand. A systemd unit and an upgrade path with automatic pre-migration snapshots are Phase 10 work; the pre-migration snapshot mechanism that such an upgrade would rely on is implemented and tested now.

## Remaining limitations

- No hardware power-cut evidence, and none is claimed.
- No second schema version exists, so no production upgrade has ever been performed.
- Restore requires the management service to be stopped manually; there is no systemd unit or in-place upgrade flow.
- The state surface is a CLI, not an API. Phase 7 will decide the API shape; this milestone deliberately did not freeze it.
- Encrypted-at-rest key management remains deferred until an independent key-protection domain exists. A backup is plaintext secrets in a `0600` file.