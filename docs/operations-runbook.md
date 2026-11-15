# Operations and recovery runbook

This guide covers the currently available state and network commands. Examples
use the Linux default state and socket paths; replace them with the paths used
by your processes. A supported product installer and transactional self-update
are not implemented. No macOS release is supported.

## Protect the state database

The database and its backups contain VPN keys, password verifiers, sessions,
and enrollment digests. Keep them owner-only in a protected directory. Use the
online backup command rather than copying a live SQLite file:

```sh
wg-basic state backup /var/lib/wg-basic/backups/before-maintenance.db \
  --state /var/lib/wg-basic/state.db
wg-basic state verify /var/lib/wg-basic/backups/before-maintenance.db
```

The destination must not already exist. See
[state backup and restore](state-backup-restore.md) for path requirements and
recovery behavior.

## Check current state

```sh
wg-basic state status --state /var/lib/wg-basic/state.db
wg-basic network status --state /var/lib/wg-basic/state.db
wg-basic doctor --state /var/lib/wg-basic/state.db \
  --socket /run/wg-basic/netd.sock --json
```

`network status` reports whether networking is enabled and the last converged
generation. `doctor` checks state and the typed `netd` backend. Run it as an
account that `netd` authorizes.

## Disable networking

`serve` and the standalone network command cannot hold the state lease at the
same time. Stop `serve` cleanly, keep `netd` available, then disable the network:

```sh
wg-basic network disable --state /var/lib/wg-basic/state.db \
  --socket /run/wg-basic/netd.sock
wg-basic network status --state /var/lib/wg-basic/state.db
```

The command commits the disabled state and attempts to apply it. If the result
says it is not enforced or cannot be confirmed, do not assume traffic has
stopped. Check `netd`, retry reconciliation, and confirm the converged
generation before relying on the disable or purging state:

```sh
wg-basic reconcile --state /var/lib/wg-basic/state.db \
  --socket /run/wg-basic/netd.sock
wg-basic network status --state /var/lib/wg-basic/state.db
```

## Purge state

Purge is destructive. Back up and verify the database first. Stop `serve`, keep
`netd` available, and confirm that networking is disabled and converged. Get
the installation ID from `state status`, then preview the exact paths:

```sh
wg-basic state purge --dry-run \
  --confirm-installation-id '<installation-id>' \
  --state /var/lib/wg-basic/state.db --socket /run/wg-basic/netd.sock
```

If the preview is correct, repeat the command without `--dry-run`. Purge also
requires a fresh read-only `netd` plan proving that owned networking is gone.
It removes only verified wg-basic state and recovery artifacts. It preserves
separate operator backups and configuration. Lock files may remain so a later
process cannot accidentally lock a different inode.

## Restore a backup

Restore is offline. Stop every process that can write the database, then follow
the [restore procedure](state-backup-restore.md). A failed restore leaves the
current database in place. After a successful restore, start the normal
management process and confirm the state and network have converged before
relying on service.

## IPv6 considerations

Linux IPv6 forwarding is host-global. Enabling a policy that requires it sets
the host forwarding control to `1`, and disabling the wg-basic network does not
turn it off. Plan the upstream route and return path for the tunnel prefix.
wg-basic does not perform NAT66. Client route settings describe what goes into
the exported client configuration; they do not configure upstream routers.
See [client configuration and enrollment](client-enrollment.md) before
changing client routes.
