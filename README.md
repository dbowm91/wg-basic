# wg-basic

Linux-first WireGuard management appliance. The unprivileged `serve` process
owns the SQLite desired state and management UI. The privileged `netd` process
applies network changes through typed local IPC and never opens the database.

## Try the local demo

This quickstart runs the management UI on loopback. It does not start `netd`,
create a VPN, or configure host networking. It requires Rust 1.89.0, selected
by `rust-toolchain.toml`.

```bash
set -eu
RUNTIME="$(mktemp -d)"
chmod 700 "$RUNTIME"
printf 'Demo state: %s\n' "$RUNTIME"
read -r -s -p "Administrator password: " ADMIN_PASSWORD
printf '\n'
printf '%s\n' "$ADMIN_PASSWORD" | cargo run --locked -- \
  admin set-password --password-stdin --state "$RUNTIME/state.db"
unset ADMIN_PASSWORD
cargo run --locked -- serve \
  --state "$RUNTIME/state.db" \
  --socket "$RUNTIME/netd.sock"
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) and sign in as `admin`
with the password you entered. The service stays in the foreground. Stop it
with Ctrl-C. Health will report degraded because this demo does not run `netd`.
The demo state is in the printed directory. Remove it after stopping the
service if you no longer need it.

## Current status

Linux network control, durable state, management, client enrollment, and
operational diagnostics are implemented and qualified. Update commands fail
closed. Releases are checksums-only, with no production signing key or trust
root. Apple silicon macOS headless server publication is maintainer-authorized
under ADR-014; a published “macOS supported” claim still waits on C015
teardown evidence and C005 packaging closure. Intel Macs are refused. Darwin
self-update is not available.

## Documentation

| Document | Purpose |
|---|---|
| [Deployment status](docs/installation.md) | What is and is not available for installation |
| [Operations runbook](docs/operations-runbook.md) | Check state, disable networking, and prepare a purge |
| [State backup and restore](docs/state-backup-restore.md) | Protect, verify, restore, and purge the database |
| [Client configuration and enrollment](docs/client-enrollment.md) | Export profiles, configure routes, and share one-time links |
| [Development](docs/development.md) | Local services, build gates, and test fixtures |
| [Architecture overview](architecture/overview.md) | System design and component index |
