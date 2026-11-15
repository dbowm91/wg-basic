# State backup, restore, and purge

The state database is authoritative for desired configuration and contains the
server private key, client private keys, preshared keys, password verifiers,
sessions, and enrollment digests. A backup contains the same secrets as the
live database. Protect both with owner-only permissions and never commit them
to version control.

The default Linux state path is `/var/lib/wg-basic/state.db`.

## Commands

```sh
wg-basic state status [--state <path>]
wg-basic state backup <destination> [--state <path>]
wg-basic state verify <candidate>
wg-basic state restore <candidate> [--state <path>]

wg-basic state purge --dry-run \
  --confirm-installation-id <uuid> [--state <path>] [--socket <path>]
```

`state status` prints identifiers, schema version, desired and convergence
generations, the last outcome category, and integrity. It never prints key
material or database rows. `verify` reads a candidate without migrating or
modifying it. Purge is the only listed command that asks `netd` for a read-only
network plan before removing files.

## Back up

Backup uses SQLite's online backup API. Do not copy `state.db` with ordinary
filesystem tools while it is live. Committed transactions may still be in the
WAL sidecar, so a direct copy can look valid while missing recent changes.

The store's mutation lock is held during the snapshot. Before it is promoted,
the result is checked for SQLite integrity, foreign keys, schema, installation
identity, and desired generation. The receipt identifies the exact generation
in the backup. Online backup can run while `serve` is active.

The destination must be new. Its parent must be an existing real directory
owned by the calling user and must not be group- or world-writable. The
destination cannot be a symlink. Staging and final files use mode `0600`. On
failure, the command removes only its own staging file. Replace the example
`/secure/wg-basic` path with a directory that meets these requirements.

```sh
wg-basic state backup /secure/wg-basic/before-maintenance.db \
  --state /var/lib/wg-basic/state.db
wg-basic state verify /secure/wg-basic/before-maintenance.db
```

Keep backups outside the live state directory. Choose a new filename for each
copy because existing destinations are never overwritten.

## Restore

Restore is offline. Stop `serve` and any other process that can write the
state database. The command acquires the state lease and refuses an active
management service. `netd` does not open the database.

```sh
wg-basic state restore /secure/wg-basic/before-maintenance.db \
  --state /var/lib/wg-basic/state.db
```

Restore validates the candidate before replacing anything. It checks that the
candidate is a regular file owned by the caller, checks SQLite integrity and
foreign keys, rejects a schema newer than the binary supports, copies the
candidate to a private staging database, applies migrations to that copy, and
validates the full typed desired state. It then syncs the staged file and
retains the previous database as `<state>.pre-restore` before promotion.

If validation or promotion fails, the current database remains in place and
the candidate is not modified. Do not start an older binary against a database
with a newer schema. Use a compatible binary or a backup from before the
schema change.

## Restoring onto another host

The installation identity is stored in the backup. Startup reconciliation
still follows the normal ownership rules. It can recreate resources it can
prove belong to the restored installation, but the backup does not authorize
taking over a foreign interface, route, or firewall table with the same name.

After restoring, start the normal management process, let it reconcile, and
check `state status`, `doctor`, and real client connectivity. Do not declare
recovery complete from a successful database restore alone.

## Migrations

Migrations run in order and each migration is transactional. Historical
migration SQL is not rewritten. Before migrating an existing database, the
program writes a recovery snapshot named `<state>.pre-migration-v<N>`, where
`N` is the schema version being migrated from. New databases and databases
with no pending migration do not get a snapshot. Existing snapshots are kept,
not overwritten, so wg-basic does not accumulate repeated automatic backups.

Migration snapshots contain the same secrets as the live database. Protect
them in the same way.

## Purge

Purge removes only verified wg-basic state and recovery artifacts. It does not
remove arbitrary operator backups or configuration. A dry run prints the
paths it would remove and preserve:

```sh
wg-basic state purge --dry-run \
  --confirm-installation-id '<installation-id>' \
  --state /var/lib/wg-basic/state.db --socket /run/wg-basic/netd.sock
```

Actual purge requires networking to be disabled, the current generation to be
recorded as converged, and a fresh no-op `netd` plan proving that owned
networking is gone. Stop `serve` before purge and keep `netd` available for the
plan. To perform the purge, repeat the command without `--dry-run`.

Service and maintenance lock files may remain after purge. Keeping them avoids
locking a different inode if the state path is later recreated.

## Durability limits

The database uses WAL mode with `synchronous = FULL`. Qualification covers
process crashes, consistent generations, private WAL sidecars, and backups of
recovered databases. Hardware power-loss safety is not claimed. It depends on
the filesystem and storage device honoring `fsync`.

## See also

- [Operations runbook](operations-runbook.md)
- [State store architecture](../architecture/state-store.md)
- [Startup recovery architecture](../architecture/startup-recovery.md)
- [Ownership model](../architecture/ownership.md)
