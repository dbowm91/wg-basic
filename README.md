# wg-basic

Linux-native WireGuard appliance in one small Rust binary. Unprivileged
`serve` owns the SQLite desired state and the management HTTP surface;
privileged `netd` applies it to the kernel through typed local-IPC
operations. The database is authoritative, kernel state is reconciled
from it, and `netd` never opens the database.

## Quickstart

Needs Rust 1.89.0 (pinned by `rust-toolchain.toml`) and loopback only —
no root, no namespaces:

```sh
cargo build --locked
install -d -m 700 /tmp/wg-basic-runtime
printf '%s\n' 'a strong administrator password' | \
  cargo run --locked -- admin set-password --password-stdin \
    --state /tmp/wg-basic-runtime/state.db
cargo run --locked -- serve \
  --state /tmp/wg-basic-runtime/state.db \
  --socket /tmp/wg-basic-runtime/netd.sock
```

In another terminal, check liveness, log in, and read back the session:

```sh
curl -s http://127.0.0.1:8000/healthz
curl -s -c cookies.txt http://127.0.0.1:8000/api/v1/login \
  -H 'Host: 127.0.0.1:8000' \
  -H 'Origin: http://127.0.0.1:8000' \
  -H 'Content-Type: application/json' \
  --data '{"username":"admin","password":"a strong administrator password"}'
curl -s http://127.0.0.1:8000/api/v1/session -b cookies.txt \
  -H 'Host: 127.0.0.1:8000' \
  -H 'Origin: http://127.0.0.1:8000'
```

Then open `http://127.0.0.1:8000/` for the operator UI, and stop `serve`
with Ctrl-C (it drains, closes the database, and exits `0`).

`healthz` reports `degraded` here because no privileged `netd` is
running — expected for the loopback demo. Real networking needs `netd`
as root plus server setup; see
[local netd](docs/development.md#local-netd) and
[client enrollment](docs/client-enrollment.md).

## Status

Network control, durable state/restart reconciliation, management/auth,
product/enrollment/UI, and operational hardening are implemented and
qualified in Linux namespaces. Transactional self-update is **not implemented**;
native installation is under implementation and not yet release-qualified (see
[plans/registry.md](plans/registry.md)).

## Docs

| Document | Covers |
|---|---|
| [docs/development.md](docs/development.md) | Gates, local `netd`/`serve`, credentials, test fixtures |
| [docs/operations-runbook.md](docs/operations-runbook.md) | Backup, recovery, disable/purge |
| [docs/state-backup-restore.md](docs/state-backup-restore.md) | Backup/restore/verify mechanics |
| [docs/client-enrollment.md](docs/client-enrollment.md) | Config/QR export, one-time enrollment links |
| [architecture/overview.md](architecture/overview.md) | System design and component index |
