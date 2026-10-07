# State backup, restore, and migration

The wg-basic state database is authoritative for desired configuration and is **secret-bearing**: it holds the server private key and every client private and preshared key. A backup is a second copy of those secrets, never a sanitized export.

The default location is `/var/lib/wg-basic/state.db`.

> **Backups contain VPN credentials.** Treat a backup file exactly as you treat the live database: owner-only permissions, off-host storage you control, never in version control.

## Commands

All three operate on the database directly. None of them contacts the kernel.

```sh
# Safe status projection: identifiers, generations, integrity.
wg-basic state status [--state <path>]

# Consistent snapshot to a new file.
wg-basic state backup <destination> [--state <path>]

# Validate a candidate and install it as the live database.
wg-basic state restore <candidate> [--state <path>]
```

`state status` prints the database path, schema version, installation identity, current desired generation, last attempted and last converged generations, the last outcome **category**, and the integrity verdict. It never prints private keys, preshared keys, or any row contents.

There is deliberately **no** SQL, query, or shell access. The state surface can snapshot, validate, and install a database; it cannot be used to read or write arbitrary tables.

## Backup

Backup uses SQLite's **online backup API**, not a file copy.

This matters. The database runs in WAL mode, so committed transactions may still live in a `-wal` sidecar. Copying `state.db` while that is true produces a file that is missing recent commits — and the result looks like an intact database, which is worse than an obviously stale one.

The store's mutation lock is held for the duration. The database is small, so serializing is cheap, and it makes the receipt meaningful: **the generation in the receipt is exactly the generation the file contains.**

A backup prints the destination, the generation, the schema version, and the installation identity, then warns that the file contains VPN credentials.

### Path and permission rules

| Rule | Behavior |
|---|---|
| Destination parent must be a real directory owned by the calling user | otherwise refused |
| Destination parent must not be group- or world-writable | otherwise refused |
| Destination must not already exist | refused; choose a new path |
| Destination must not be a symbolic link | refused |
| Staging artifact is created `0600` | never briefly world-readable |
| Final file mode | `0600` |
| Shell or subprocess execution | never used |
| Failure | removes only the staging artifact it created |

Overwriting an existing backup is refused rather than done unsafely. If you need a new copy, use a new filename.

## Restore

Restore is **offline and exclusive**. Stop the management service first.

```sh
systemctl stop wg-basic          # or however you run the management role
wg-basic state restore /secure/backup.db
systemctl start wg-basic
```

Restore refuses to run if the target or the candidate is still open **in this process**. That covers the common mistake of restoring from inside a running management process; it does not cover a second, independent process, which is why stopping the service is still the operator's job.

The order is **validate, then replace**:

1. refuse a target or candidate this process holds open;
2. validate the candidate path — not a symlink, a regular file, owned by the calling user, not group- or world-accessible;
3. open the candidate **read-only** and run `PRAGMA quick_check` plus a foreign-key check;
4. reject a `user_version` **newer than this binary understands**;
5. copy the candidate into a private staging database beside the target;
6. apply pending migrations to the staging copy;
7. load the entire typed desired state and validate it;
8. verify the installation identity and desired generation are consistent;
9. `fsync` the file and its directory;
10. move the previous target aside to `<state>.pre-restore` and rename the staged database into place.

A failure at any step leaves the original database exactly as it was, and the staging artifact is removed.

### What a failed restore preserves

If validation fails, nothing is displaced: the original database stays in place, no `.pre-restore` file is created, and the operator's candidate file is untouched — restore never migrates the candidate in place.

### Schema newer than this binary

A database written by a **newer** wg-basic is rejected, by `state restore` and by ordinary startup alike. It is never downgraded or partially interpreted. Start the newer binary, or restore from a backup taken before the upgrade.

### Restore is not host-state takeover

Restore replaces a database. It does **not** grant authority over unrelated host state.

After restore, ordinary startup reconciliation applies the restored desired generation under the ordinary owner-tag rules:

| Host state after restore | Startup behavior |
|---|---|
| no owned resources exist | created, tagged with the restored installation identity |
| owned resources matching the restored owner tag | reconciled |
| foreign or same-name resources | **fails closed**, preserved untouched |

The installation identity travels with the backup, so restoring onto a different host recreates resources carrying the same durable owner identity — which means a restore can only ever reclaim resources this installation can prove it owns.

## Migrations and the pre-migration recovery snapshot

Schema changes are applied in order, each inside one transaction, with a foreign-key check after every step. Historical migration SQL is never rewritten; a schema change is a new migration.

When a migration is about to run against an existing user database, wg-basic first writes a recovery snapshot beside it:

```
<state>.pre-migration-v<N>
```

where `N` is the schema version being migrated *from*. No snapshot is taken for a brand-new initialization (nothing to lose) or when no migration is pending. The snapshot uses the same online backup API and the same `0600` mode, so it holds the same secrets.

Retention is bounded and deterministic: the name carries the version, and an existing snapshot for that same version is kept rather than replaced. wg-basic does not accumulate automatic backups.

## Durability, precisely stated

What is verified:

- WAL journal mode with `synchronous = FULL`, both read back at open;
- an abruptly killed process leaves a database that reopens cleanly;
- what survives is one whole generation, not a partial write, and still passes typed validation;
- WAL sidecars do not become world-readable after an unclean death;
- a backup of a recovered database is itself internally consistent.

What is **not** claimed:

- **Hardware power-cut safety.** If a filesystem or disk acknowledges `fsync` without durably storing the data, the operating system and hardware have already violated the contract SQLite relies on. No application-level test can detect that, and none is attempted.

## Restoring onto a new host

1. Install the same `wg-basic` version that wrote the backup.
2. Place the backup where the management user can read it, with `0600` permissions.
3. Stop the management service.
4. `wg-basic state restore /path/to/backup.db`
5. Start the management service. Startup reconciles the restored desired generation and creates the owned resources.
6. Confirm with `wg-basic state status` and `wg-basic health`.

Step 4 retains the previous database as `<state>.pre-restore`. If the restore turns out to be wrong, that file is still there.

## See also

- [architecture/state-store.md](../architecture/state-store.md) — storage, schema, and the generation contract
- [architecture/startup-recovery.md](../architecture/startup-recovery.md) — startup reconciliation and drift repair
- [architecture/ownership.md](../architecture/ownership.md) — how ownership is proven