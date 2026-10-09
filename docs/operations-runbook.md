# Operations and recovery runbook

This runbook describes current state and recovery operations. Native systemd
installation is implemented, but production update/check remain fail-closed
because the production release trust root is unprovisioned and M004 qualification
is open. The installed CLI currently spells the commands `update check`,
`update run`, and `update recover`.

## Protect a pre-update backup

The state database and all backups contain VPN keys, password verifiers,
sessions and enrollment digests. Keep the backup owner-only in a protected
directory outside the live database path.

```sh
wg-basic state backup /var/lib/wg-basic/backups/pre-update.db \
  --state /var/lib/wg-basic/state.db
wg-basic state verify /var/lib/wg-basic/backups/pre-update.db
```

Record the backup schema version, installation ID and generation. Do not copy a
live SQLite database with ordinary filesystem tools.

## Recovery after a failed update

Stop both roles and confirm that neither holds the state lease or netd socket.
Use the binary compatible with the backup schema to restore it before starting
that binary:

```sh
wg-basic state restore /var/lib/wg-basic/backups/pre-update.db \
  --state /var/lib/wg-basic/state.db
wg-basic state status --state /var/lib/wg-basic/state.db
wg-basic doctor --state /var/lib/wg-basic/state.db \
  --socket /run/wg-basic/netd.sock --json
```

The restore is offline and does not touch kernel state. Start netd by itself,
run doctor against its typed read-only backend, then start serve and let startup
reconcile the restored desired state. Confirm doctor required checks,
authenticated product health, and a real client handshake/traffic before
declaring recovery complete. If an old binary refuses a newer schema,
that is expected: restore a compatible database first; never start the old
binary against a migrated database and call the refusal rollback.

For an interrupted M004 transaction, run recovery as root and repeat it if the
first attempt reports an interruption:

```sh
sudo wg-basic update recover
```

Recovery returns success only after checking the journaled binary and install
receipt, typed state identity, retained transaction artifacts, owned running
services, and product health. A refusal leaves the journal and recovery set in
place. Do not remove or rename journaled files to make another update proceed.
Restore staging files are named
`.wg-basic-restore-<transaction-id>-<unique-id>.db` in the state directory and
contain VPN secrets; protect them like the database. If recovery cannot prove
that both services are stopped and owned, leave the system untouched and use
the failure classification from the command before attempting manual service
operations.

After restoring an old state, the next startup still validates netd ownership
tags. A backup does not authorize taking over a foreign same-name interface,
route or nftables table.

## Safe service disable and purge

For a planned maintenance window, use the durable network-disable operation
while netd and serve are available. Wait for convergence before stopping the
roles. Purge is an uninstall/reset operation and requires a verified disabled,
converged, no-op network plan; prefer `--dry-run` first.

```sh
wg-basic network disable --state /var/lib/wg-basic/state.db \
  --socket /run/wg-basic/netd.sock
wg-basic network status --state /var/lib/wg-basic/state.db \
  --socket /run/wg-basic/netd.sock
wg-basic state purge --dry-run \
  --confirm-installation-id '<installation-id>' \
  --state /var/lib/wg-basic/state.db --socket /run/wg-basic/netd.sock
```

The detailed current behavior and exact CLI options are in
[state backup and restore](state-backup-restore.md) and
[development](development.md). Release health and binary/database rollback
ordering are specified in the
[update and rollback contract](../architecture/update-rollback-contract.md).
