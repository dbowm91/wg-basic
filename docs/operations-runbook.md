# Operations and recovery runbook

This runbook describes current state and recovery operations. Native systemd
installation and the M004 transactional update/recovery contract are qualified
on disposable systemd hosts. Phase 10 lifecycle qualification is closed for
fresh installation and state-preserving uninstall/reinstall on x86_64 and
aarch64. Production update discovery and mutation remain fail-closed because
the production release trust root is unprovisioned. The canonical CLI commands are
`wg-basic update check`, `wg-basic update run`, and `wg-basic update recover`.

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

IPv6 forwarding is an explicit server policy. Enabling it writes the fixed
host-global `/proc/sys/net/ipv6/conf/all/forwarding` control to `1`, which
changes Linux Host/Router and Router Advertisement behavior across interfaces.
The setting remains enabled after wg-basic disables the network policy or tears
down the WireGuard interface. Arrange an upstream route to the configured
tunnel prefix; wg-basic does not add that route and does not perform NAT66.
Doctor reports the desired/observed forwarding state without writing it.

Client IPv4 and IPv6 routes are selected independently in setup and the client
editor: no route, the family's full-tunnel default (`0.0.0.0/0` or `::/0`), or
split prefixes. IPv6 routes require both a managed server IPv6 tunnel range and
an IPv6 address assigned to the client. Address assignment alone does not
enable IPv6 routes. For IPv6, arrange routed egress and an upstream return route
for the tunnel prefix; wg-basic does not perform NAT66. A route selection is
client configuration intent. Verify the client receives the exported config
and that the selected egress and return paths are available before relying on
it for connectivity.

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
first attempt reports an interruption. The disposable-host qualification
verified repeated recovery at durable journal cutpoints, including interruption
between retaining the old database and installing the restored database:

```sh
sudo wg-basic update recover
```

`update run` and `update recover` require effective root; wg-basic does not
invoke sudo. `update check` is read-only and does not stop services or acquire
the mutating transaction lock. With the current unprovisioned production key,
`update check` and `update run` fail closed before network access. Do not run an
update until the maintainer-provisioned key and production-signed release are
available. M004 technical qualification does not authorize a public release.
When a transaction owns the root lock, competing mutating commands return a
contention error and leave the journal for the current owner.

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

The updater uses the pinned Eggup service adapter for an exact-owned systemd
unit left in `failed` or `activating (auto-restart)`. Eggup keeps a failed
lifecycle observation as `Unknown`; its bounded typed stop must report
completion, and wg-basic rechecks exact ownership. A `Transitioning` unit is
accepted as quiescent only after a completed stop and a fresh `Stopped`
observation. wg-basic also checks that the serve lease is released and netd's
socket is inactive before it restores SQLite. A failed/unknown result, foreign
unit, changed unit definition, or incomplete transition leaves recovery
unresolved; do not use `reset-failed` or process killing to force the update
forward.

After restoring an old state, the next startup still validates netd ownership
tags. A backup does not authorize taking over a foreign same-name interface,
route or nftables table.

## Uninstall and reinstall

Default system uninstall preserves the database and service identities:

```sh
sudo wg-basic system uninstall
```

It refuses modified or foreign service/program material. After uninstall, the
state database remains at `/var/lib/wg-basic/state.db` and remains owned by the
same management UID. Reinstall a trusted, compatible candidate with
`sudo ./wg-basic system install --candidate ./wg-basic`, then check
`sudo ./wg-basic system status`, authenticated product health, and client
traffic. See the [installation guide](installation.md) for the authenticity
boundary of local candidates and the bootstrap trust model.

Uninstall does not disable WireGuard networking or purge secrets. To remove
the database, first use the disable/convergence/purge sequence below while the
services are still installed; then run `sudo wg-basic system uninstall` to
remove the remaining owned system files. This sequence preserves operator
backups outside the canonical live-state path.

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
