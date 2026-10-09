# Diagnostics and maintenance

This is the deep dive for the read-only diagnostics and guarded maintenance
surface: `src/doctor.rs`, `src/operational.rs`, `src/state/diagnostic.rs`,
`src/state/service_lease.rs`, `src/state/backup.rs`, `src/state/inuse.rs`, and
the `doctor` / `state` / `network` paths in `src/main.rs`.

Start with [the overview](overview.md). For storage internals see
[state-store](state-store.md); for startup reconciliation see
[startup-recovery](startup-recovery.md); for the binary+database transaction
rule and rollback ordering see
[update-rollback-contract](update-rollback-contract.md). Operator procedures
live in [the runbook](../docs/operations-runbook.md) and
[state backup and restore](../docs/state-backup-restore.md).

## Doctor check catalog

`doctor` assembles a `DoctorReport` (`version` = binary version, `overall`,
`checks`) and exits with the report's code. Each check carries a bounded
(`240`-char) `summary`, `evidence`, and `remediation`. Backend errors are
classified at their boundary and never copied into the model.

### Dispositions and exit codes (`src/doctor.rs`)

| Disposition | Meaning | Exit |
|---|---|---|
| `pass` | check satisfied | `0` (only if every check passes) |
| `warn` | attention, still usable | `1` |
| `unknown` | could not be determined | `1` |
| `fail` | required failure | `2` |

Overall is the maximum over checks with rank
pass(0) < warn(1) < unknown(2) < fail(3). `--json` prints the report to
**stdout**; a bounded `doctor.completed` event goes to **stderr**; the process
exits with `report.exit_code()`.

### Check catalog (`src/main.rs` doctor assembly)

| `DoctorCheckId` | Pass | Warn | Fail | Unknown |
|---|---|---|---|---|
| `Sqlite` | bundled SQLite ≥ 3.51.3 (WAL safety floor) | — | below floor | — |
| `State` (×2 when decodable) | immutable ownership/integrity/schema checks passed; second check names schema, installation, desired generation | uninitialized (path missing) | ownership, schema, integrity, or typed-validation failure | live `-wal`/`-shm` sidecars (`Busy`: immutable mode refuses to ignore WAL) |
| `Product` | desired + product snapshots decoded (counts interfaces/clients) | — | — | — (absent without snapshot) |
| `Convergence` | no managed interface is configured, or `last_converged == desired` generation | configured interfaces lack convergence evidence | — | — |
| `RecoveryArtifacts` | no unsafe pre-migration snapshot | — | an artifact is present with unsafe path/owner/mode (never auto-deleted) | — |
| `Netd` | `InspectCapabilities` answered and runtime dir safe + `CAP_NET_ADMIN` present | — | answered but runtime/capability checks failed | no safe capability response |
| `NetworkOwnership` | aggregate plan has zero actions (converged), or no managed interface exists | owned drift repairable by normal reconciliation | ownership conflict / invalid intent / projection failure | plan unavailable, unexpected response, or no state snapshot |
| `Rtnetlink` | bounded observation completed via the aggregate plan (also Pass when nothing is managed) | — | — | plan did not complete |
| `Nftables` | read-only nftables plan completed (also Pass when nothing is managed) | — | — | plan did not complete |
| `WireGuard` | Generic Netlink observation succeeded (also Pass when nothing is managed) | — | — | interface absent / probe incomplete |
| `ListenPort` | observed port matches configured port | managed port differs from desired | — | ambiguous (no managed interface observed, or no configured value) |
| `Forwarding` | forwarding not required, or required and `/proc/.../ip_forward == 1` | — | required but `0` (remediation: enable via host config; doctor did not write it) | procfs unreadable, or no snapshot |
| `Ipv6Forwarding` | not required, or required and fixed global IPv6 forwarding is `1` | — | required but `0` (the global value remains enabled after policy disable) | procfs unreadable/malformed, or no snapshot |
| `ServiceLease` | lease free | a serve process holds the lease | — | lease could not be inspected safely |
| `HttpPolicy` | only emitted when `--http-bind` is given and the same `ServeConfig` policy `serve` uses accepts the bind/origin | — | policy rejected | — |

## Read-only and immutable-inspection guarantees

`src/state/diagnostic.rs::inspect_readonly` is the only lens doctor, `network
status`, and purge use. It deliberately avoids `StateStore::open`, whose
contract applies pending migrations:

- Path is absolutized; the parent must be an owned, non-group/world-writable
  directory; the file must be a regular non-symlink owned by the caller with
  mode masked by `0o077`.
- `-wal` / `-shm` sidecars are refused **before and after** inspection
  (`StateError::Busy`): immutable mode ignores WAL data, so a result raced by
  a concurrent writer is discarded rather than reported.
- The database is opened `mode=ro&immutable=1` (`READ_ONLY | NOFOLLOW | URI`):
  no migrations, no pragma updates, no WAL creation, no sidecar writes.
- `PRAGMA quick_check` must be `ok`; `pragma_foreign_key_check` must be empty;
  `user_version` must be positive and not newer than the binary
  (`SchemaTooNew` is returned without migrating).
- Singleton structure, typed desired/product/convergence rows, and
  `validate_desired_state` must all succeed; recovery artifacts
  (`<state>.pre-migration-v<N>`) are reported as present/safe booleans only.
- `StateDiagnostic` implements neither `Debug` nor serialization: the desired
  snapshot contains secrets and must not be loggable.

Doctor's kernel contact is limited to read-only netd operations
(`PlanInstallationNetworkIntent`, `ObserveWireGuardDevice`, capability
inspection) plus procfs/sysfs reads. Remediation strings say so explicitly
("doctor did not mutate/bind/write"). `tests/doctor_readonly.rs` qualifies
this: database bytes, directory entries, routes, link state, and `ip_forward`
are identical before/after, and the exit status always equals
`report.exit_code()`.

## Operational events

`src/operational.rs` emits small, project-owned events on **stderr only**;
command results and machine-readable output stay on **stdout**. The supervisor
owns retention. `--log-format json|human` selects rendering.

Closed schema: `timestamp_unix_ms`, `event_code`, `severity`
(info/warn/error), `role`, `operation`, `outcome`, plus optional
`resource_kind`, `resource_id`, `desired_generation`, `stage`. JSON is one
object per line with no ANSI escapes; human form is
`SEVERITY role event_code operation=… outcome=… …`. `command_failure` prints
`wg-basic: <message>` (human) or a `command.failed` event (JSON); every CLI
failure exits `2`. `netd.request_rejected` and `security.rate_limited` are
rate-limited to one event per second.

| Event code | Emitted by |
|---|---|
| `serve.started/stopping/degraded/reconcile` | `serve` lifecycle and worker reconcile |
| `netd.started/stopping`, `netd.request_rejected` | `netd` listener |
| `reconcile.started/completed/degraded` | management reconcile coordinator |
| `doctor.completed` | `doctor` (generation + `checks` stage) |
| `state.backup_completed` / `state.restore_completed` | `state backup` / `state restore` (generation + promotion/replacement stage) |
| `network.enabled` / `network.disabled` | `network enable` / `disable` (`enforced`→info, otherwise warn) |
| `security.rate_limited`, `command.failed` | HTTP limiter / CLI failure path |

Secrecy rules: events are bounded values, never formatted backend errors
(`rusqlite::Error` is collapsed; SQL text and bound values never reach a
log). Tests assert the doctor JSON contains no `private_key`/`session`/
`enrollment` fields and the serve event stream contains no passwords, tokens,
keys, or `[Interface]` blocks.

## Leases

`src/state/service_lease.rs` provides two crash-safe advisory locks, both
held by an open file descriptor (released on process death, including
SIGKILL), with file contents informational only (never proof of ownership).
Both refuse unsafe paths: non-directory, foreign-uid, or group/world-writable
parents; `O_NOFOLLOW | O_CLOEXEC` opens; `0600` files re-verified by uid/mode
before and after locking. Contention surfaces as `Busy`; unsafe paths as
`Unsafe`.

| Lease | Path | Mode | Held by |
|---|---|---|---|
| `ServiceLease` | `<state>.serve.lock` | exclusive, non-blocking | `serve`, `network disable/enable`, `state purge`, `state restore` (each acquires it, so any of them refuses while another holder is alive) |
| `MaintenanceLease` | `<state>.maintenance.lock` | **shared** for `state backup`; **exclusive** for `state restore` / `state purge` | coordinates purge/restore against online backups without stopping serve |

`ServiceLease::is_held` attempts an exclusive non-blocking lock: missing and
stale lock files are free (contents not consulted); `EWOULDBLOCK` means held.
`MaintenanceLease` allows shared–shared coexistence while any exclusive
holder excludes everything. Restore additionally checks the per-process open
registry (`src/state/inuse.rs`: every `StateStore` registers its normalized
path): if this process holds the target or candidate open, restore refuses
with `TargetInUse`/`CandidateInUse` as defense in depth — the cross-process
flock is the authority across processes.

## Backup, restore, verify

All artifacts are created `0600` at creation time (no world-readable window),
synced (`fsync` file + directory on promotion/replacement), and receipts
carry identifiers only (installation, generation, schema, path) — never row
contents. No shell or subprocess is used anywhere.

### `state backup <destination>`

Uses SQLite's **online backup API** (never `cp` of a live WAL database),
stepping 64 pages at a time (bounded at 1M steps, 50 ms backoff on
busy/locked). The store mutation lock is held throughout, so the receipt's
generation is exactly the generation the file contains; a shared maintenance
lease keeps purge/restore from racing the snapshot while `serve` keeps
running. Flow: refuse an existing destination (overwrite is refused; choose a
new path) → stage to `.<name>.backup.<pid>` beside the destination (same
filesystem, atomic rename) → copy → verify integrity, foreign keys, schema,
installation, and generation against the receipt → promote. Failure removes
only the staging artifact. Refuses: existing destination, symlink destination,
missing/foreign-uid/writable parent.

### `state restore <candidate>`

Offline and exclusive: stop the management service first. The CLI runs
`validate_candidate` first for a clear error, then `restore()` re-validates
internally before replacing anything (validate-then-replace):

1. acquire the service lease (refuses an active serve) and the exclusive
   maintenance lease (refuses a concurrent backup);
2. refuse a target/candidate this process holds open;
3. candidate path checks: regular non-symlink file, caller-owned, not
   group/world-accessible, no `-wal`/`-shm` sidecars;
4. immutable read-only open; `quick_check` + foreign-key check;
5. reject `user_version` newer than the binary (never downgraded);
6. copy the candidate into a private staging database beside the target (the
   operator's candidate is never migrated in place);
7. apply pending migrations to the staging copy; load and validate the full
   typed desired state; check installation-identity and generation
   consistency;
8. `0600`, `fsync`, move the previous target aside to the deterministic
   `<state>.pre-restore`, rename staging into place, `fsync` the directory.

Any failure leaves the original database exactly as it was, creates no
`.pre-restore`, and removes only the staging artifact. Restore never touches
the kernel: startup reconciliation applies the restored generation under the
ordinary owner-tag rules, failing closed on foreign or same-name resources
(see [startup-recovery](startup-recovery.md) and the host-state table in
[state backup and restore](../docs/state-backup-restore.md)).

### `state verify <candidate>`

Read-only report — installation, generation, schema vs. supported schema,
integrity, foreign-key status, `would_migrate`, `too_new` — without migrating
or modifying the candidate. Output warns the file contains VPN credentials.

## Disable / enable / purge

`state status`, `network status`, and `state verify` are read-only projections
(identifiers, generations, outcome categories, integrity verdicts — never
keys or row contents). The mutating workflows are guarded as follows.

### `network disable` / `network enable` (schema v5 switch)

Removes (`disable`) managed networking and owned firewall state while
preserving the configured server, clients, keys, addresses, and endpoint, or
reapplies that same identity (`enable`). Each acquires the service lease
(refuses while another serve process holds the state path), requires a
configured server, and is a no-op (no generation committed) when already in
the requested state. Otherwise it commits exactly one audited generation via
`ProductService::set_network_enabled` and reconciles through the configured
netd socket, reporting `enforced`, `committed-but-not-enforced (degraded)`,
or `unknown` (reconcile unconfirmable — rerun `wg-basic reconcile`).

### `state purge` (uninstall/reset)

The only state command that asks netd for a read-only plan before deleting.
Requires `--confirm-installation-id` matching the database and
`--dry-run` for a preview (preview still prints unmet preconditions and
refuses to delete). Actual purge:

1. acquire the service lease + exclusive maintenance lease;
2. immutable snapshot; installation-ID confirmation must match;
3. preconditions: network operationally disabled, current desired generation
   recorded as converged, a configured server present;
4. project the disabled diagnostic intent and request a **fresh** netd plan —
   any interface or firewall action (or any plan failure) refuses the purge;
5. delete exactly the verified wg-basic artifacts: the database, its `-wal` /
   `-shm` sidecars, `<state>.pre-restore`, pre-migration snapshots below the
   current schema version, and known `.<name>.backup|restore.<pid>`
   temporaries — each re-checked (regular, owned, `0600`-masked) immediately
   before removal.

| Refusal | Reason |
|---|---|
| ID mismatch | confirmation does not match this state |
| `network must be disabled` | operational flag still enabled |
| `the current desired generation must be recorded as converged` | unreconciled state |
| `netd did not prove owned network resources are absent` | plan unavailable |
| `netd plan still contains owned network changes` | owned networking still present; reconcile and retry |
| `unsafe purge artifact` | a removal path failed the ownership/mode check — abort, do not delete |

Preserved: both lease files (avoid locking a different inode after unlink),
operator backups/configuration, and every other file in the state directory.

## Test qualification (high level)

| Suite | What it qualifies |
|---|---|
| `tests/doctor_readonly.rs` | `doctor --json` mutates neither the database (bytes + directory entries) nor host network state (routes, link attributes, `ip_forward`); exit status equals `report.exit_code()`; `State` + `NetworkOwnership` pass on a fresh store with netd. The `linux-integration` variant further shows plan-only diagnosis: warn on unapplied drift, pass after apply, fail on a foreign same-name link — all without mutating the namespace or database. |
| `tests/service_lease.rs` | `serve` is a singleton (second instance fails with "already held"); `state restore` refuses while serve is active ("state service is active"); SIGKILL releases the advisory lease; restore succeeds after; 20 serve crash cycles leak no file descriptors or threads. |
| `tests/operational_events.rs` | long-running `serve` events are stderr-only with one JSON object per line (`serve.started` present); a fixed secret corpus (passwords, tokens, keys, `[Interface]`) never appears; human format emits `INFO serve serve.started`. |
