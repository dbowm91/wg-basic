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
the mutating transaction lock. By maintainer decision there is no production
key and none is planned, so `update check` and `update run` fail closed
before network access permanently; every release requires a fresh install.
M004 technical qualification does not authorize a public release.
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

## Routed LAN on macOS

A routed LAN lets clients reach administrator-approved downstream LAN prefixes
through the managed tunnel, and the traffic comes back through the same
tunnel. It is selected in the server setup — `mode` is `routed_lan` and
`destination_prefixes` names the approved prefixes, in the management UI's
"Network policy mode" and "Routed LAN destinations" fields, or in the
`POST /api/v1/setup` body — and it is implemented on macOS only. A routed-LAN
policy never masquerades. The internet-exit gateway mode is refused on macOS.

The product does not configure the host for a routed LAN. It observes the host,
reports what it observed, and refuses to converge while a prerequisite is
missing. Three things belong to the operator.

Enable host forwarding. The host's global IPv4 and IPv6 forwarding must be on
for every family the policy needs. Those switches are shared with everything
else that routes packets on the machine, so wg-basic reads them
(`net.inet.ip.forwarding`, `net.inet6.ip6.forwarding`) and never writes them.
Enable them in the host's own configuration — `/etc/sysctl.conf` for a setting
that must survive a reboot, or `sysctl -w` for the current boot:

```sh
sudo sysctl -w net.inet.ip.forwarding=1
sudo sysctl -w net.inet6.ip6.forwarding=1
```

Install the routes for the approved prefixes. Each approved downstream prefix
must be reached by a specific route through the declared egress interface. A
routed LAN never depends on the default route, and wg-basic never takes the
default route over:

```sh
sudo route -n add -net 192.168.9.0/24 -interface en0
```

The return path is the upstream router's job: it must route the tunnel pool
back to this host's address on the LAN. wg-basic does not configure the
upstream router. The pool's own route on this host must be scoped to the
managed `utun` device.

Route the pool back through **this host's LAN address**, not as a link-level
route on the router's own interface:

```sh
# on the upstream router, where 192.168.9.3 is this host's LAN address
sudo route -n add -net 10.77.0.0/24 192.168.9.3
```

A link-level route on the router's own interface makes it look for the pool
address on that interface, where it does not exist — the pool lives on this
host's tunnel device — so the router caches a rejection and the return path
never leaves the router. The IPv6 equivalent has the same shape and must name
this host's link-local address on that interface.

The failure is silent, so check the shape rather than discovering it as a
missing return path:

```sh
# on the upstream router: the pool route must name this host's LAN address
netstat -rn -f inet | grep 10.77
```

A line that ends in an interface (`link#3`, `en0`) is the wrong shape. The
route must name an address, and that address must be this host's address on
the LAN. wg-basic cannot check this for you: it can only observe the routes on
the host it runs on, never the routing table of the router upstream.

Install the filter and attach the anchor. The filter that bounds a routed LAN
is operator-managed: the rules go into the installation's own anchor, and the
anchor is attached from your own pf configuration. wg-basic writes neither the
rules nor `/etc/pf.conf`, and it never enables or disables PF. The doctor
reports the exact rules to install:

```sh
wg-basic doctor --state /var/db/wg-basic/state.db \
  --socket /var/run/wg-basic/netd.sock --json
```

The doctor reaches netd over the authorized socket, so run it as an account
netd admits; on Darwin that is the management service account, and root is not
a universal bypass there. The `routed_lan` check appears only when that plan
succeeded.

The rules travel as structured data, not as prose. The doctor's evidence is
bounded, and a routed LAN's rule set outgrows that bound, so the exact rules
are carried in the check's `required_filter_rules` array and the bounded
evidence only reports how many rules there are. Read them out with:

```sh
wg-basic doctor --state /var/db/wg-basic/state.db \
  --socket /var/run/wg-basic/netd.sock --json \
  | jq -r '.checks[] | select(.id == "routed_lan") | .required_filter_rules[]'
```

Diagnosing offline. The doctor inspects the state database without writing to
it, and it refuses a database that still has live write-ahead sidecars. The
management service is what holds them, so a diagnosis that has to run with the
service down is done in this order: stop the management service, close the
database cleanly, run the doctor, then start the service again.

On macOS the management service is a bootstrapped system service, and
`launchctl stop` is not accepted for one. Unload the job, close the database
cleanly, run the doctor, and register the job again:

```sh
sudo launchctl bootout system/com.wg-basic.serve
sudo -u _wg-basic-serve wg-basic state status --state /var/db/wg-basic/state.db
sudo -u _wg-basic-serve wg-basic doctor --state /var/db/wg-basic/state.db \
  --socket /var/run/wg-basic/netd.sock --json
sudo launchctl bootstrap system /Library/LaunchDaemons/com.wg-basic.serve.plist
```

The `state status` command in the middle is what closes the database cleanly,
so the sidecars are gone before the doctor opens it. Unloading the job is what
keeps launchd from bringing the service back: the job carries `KeepAlive`, so
a process that exits is started again, and a restart that was already
scheduled still runs after the job is disabled. Do **not** disable the job
instead — a disabled job is registered but never starts, which is the wrong
shape for a service that has to come back afterwards.

Unloading also stops the service: the service acts on `SIGTERM`, drains its
listener, and stops its worker within its own bounded budget. The job carries
an exit timeout as well, so a service that wedges is killed rather than
waiting. If the process is still there after the unload, kill it outright:

```sh
sudo launchctl kill SIGKILL system/com.wg-basic.serve
```

A management service that does not act on `SIGTERM` is not expected any more.
The service holds the state lease and the write-ahead log until it exits, so
the doctor's lease check reports it as held while it is still draining.

The anchor is named after the installation, and `wg-basic state status` prints
that installation id:

```sh
wg-basic state status --state /var/db/wg-basic/state.db
```

Put the reported rules into an anchor file and load them into that anchor,
whose name is `wg-basic-v1-<installation-id>`:

```sh
sudo pfctl -a wg-basic-v1-<installation-id> -f /etc/pf.anchors/wg-basic-routed
```

The anchor file has to end with a newline. PF rejects a file whose last rule
is not terminated, and it reports that as a syntax error in the `load anchor`
line that pulled the file in, not in the file itself.

Attach that anchor from your own `/etc/pf.conf`, then load the configuration
and enable the filter:

```text
anchor "wg-basic-v1-<installation-id>"
```

```sh
sudo pfctl -f /etc/pf.conf
sudo pfctl -e
```

Reading the verdict. The `routed_lan` check reports one verdict, and each
verdict names a different missing prerequisite:

| Verdict | What doctor reports | What to do |
|---|---|---|
| `ready` | the routed-LAN prerequisites are in place | none |
| `forwarding_disabled` | host forwarding is not enabled for a family this policy requires | enable it through host configuration |
| `filter_missing` | the operator-managed filter is absent or is not attached | install the reported rules and attach the anchor |
| `filter_drift` | the operator-managed filter does not match the rendered policy | reinstall the reported rules; wg-basic never repairs a drifted filter |
| `missing_return_route` | no observed route carries traffic back to the tunnel pool | restore the pool route, and make sure the upstream router routes the pool back to this host |
| `route_conflict` | a foreign or ambiguous route covers an approved destination | remove the competing route, or narrow the approved destinations |
| `unsupported_topology` | the approved destinations are not reachable through the declared egress interface | install a specific route for each approved destination through the egress interface |
| `tunnel_unavailable` | the managed tunnel is not up, so its filter cannot be proven | start the managed network, then rerun doctor |

The rendered rules name the tunnel device and the egress interface explicitly,
so they have to be reinstalled when the helper is renumbered and its `utun`
device changes.

## When the helper dies

The managed tunnel is carried by a helper process that the privileged daemon
spawns and supervises. If that helper exits on its own, the kernel releases
its device and the tunnel goes down with it.

The privileged daemon replaces the helper it lost. The replacement re-applies
the configuration, addresses, and routes that belonged to the tunnel, and the
kernel may assign a different `utun` number to the new device. The recovery
is reported in the privileged daemon's log:

```sh
sudo tail -f /var/log/wg-basic/netd.log
```

`netd.helper_recovery_started` marks the replacement, and
`netd.helper_recovery_completed` or `netd.helper_recovery_failed` ends it.

A renumbered device means the rendered filter rules no longer match: the
rules name the device, so reinstall the rules the doctor reports after the
recovery, exactly as you would after any device change.

If the recovery fails, the doctor reports `tunnel_unavailable` and the
remediation is to start the managed network again. The privileged daemon
refuses to adopt a device it cannot prove, so nothing is left half-owned.
