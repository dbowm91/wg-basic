# Testing and qualification

This document describes **current implemented behaviour**: the integration-test
targets under `tests/`, which need privilege and which do not, the static
architecture guards, the rootful fixture prerequisites, the Phase 9
old/new upgrade rehearsal, and the CI job mapping. It is the deep dive behind
the [architecture overview](overview.md); copy-pasteable commands live in
[development](../docs/development.md).

The ordinary suite needs no privilege:

```sh
cargo test --locked
```

## Suite catalog

Targets with `linux-integration` only compile/run under
`--features linux-integration` on Linux. Rootful targets additionally need
`sudo` and serialize with `--test-threads=1` where namespaces have fixed names.

| Target | Privilege | What it proves |
|---|---|---|
| `architecture_guards` | none | Static source-text invariants over shipped code (see categories below) |
| `auth_sessions` | none | Real v1→v2 migration, Argon2id cost, credential/session persistence; no HTTP |
| `authenticated_api` | none | Request policy directly: `Host`/`Origin`/`Sec-Fetch-*`, CSRF, cookie, limiter ordering |
| `management_http` | none | Same perimeter over real HTTP/1.1 on a real TCP socket: routing, headers, `Origin`, CSRF, bounded 503 |
| `service_session_restart` | none | Sessions across a real `serve` restart over real cookies; expiry/logout/reset still hold |
| `service_resource_limits` | none | Admission/deadline boundaries: connections, in-flight, worker queue, body, timeouts, shutdown |
| `service_e2e` | none (spawns binaries) | Real `admin` + `netd` + `serve` children: process topology, CLI→HTTP credential seam, startup reconcile, restart preserves cookie |
| `service_footprint` | none, Linux, release binary | Footprint/latency figures on the release binary; asserts only design bounds (incl. login-latency *floor*) |
| `service_lease` | none | Real `serve` lock: second process and restore refused while held; restore proceeds after kill |
| `operational_events` | none (spawns binaries) | Stderr-only, line-delimited event format and secrecy |
| `runtime_stability` | none (spawns binaries) | Bounded HTTP and state-row growth over repeated valid/rejected requests |
| `product_management` | none | Product layer with no HTTP: setup, allocation, enable/disable, delete, audit atomicity, committed-vs-enforced receipts |
| `state_store` | none | Init, hardened open, migrations, generation CAS, rollback, secrets, projection |
| `state_backup_restore` | none | Backup/restore/verify on temp SQLite files; corruption fails closed |
| `state_durability` | none | Interrupted process leaves a cleanly reopening DB holding one whole generation (not power-cut safety) |
| `privileged_protocol` | Linux, unprivileged | UDS capability/auth IPC: peer-credential authorization, socket lifecycle, fail-closed collisions |
| `upgrade_rehearsal` | none, `#[ignore]`d, needs `WGB_OLD_BINARY` | v4 preservation, config hashes, old-binary refusal, explicit restore, repeated migration |
| `wireguard_kernel` | root | Real-kernel handshake, telemetry, peer update/preservation in temp namespaces; netd workers run inside the namespaces |
| `network_reconcile` | root | Link/address/route lifecycle and reconciliation in a namespace |
| `network_control_e2e` | root | Forwarding, NAT, firewall ownership across namespaces |
| `durable_owner` | root | Owner tags and generation-aware aggregate reconcile against the real kernel |
| `durable_restart` | root, needs built `wg-basic` binary | Startup reconciliation and crash/restart recovery via real `netd` + `reconcile` child processes |
| `durable_backup` | root | Restored database drives real traffic (3 namespaces, handshake, forwarding, NAT); foreign same-name link fails closed |
| `product_management_rootful` | root | Real-device client lifecycle via HTTP: setup, create, export, enrollment consume/replay, handshake traffic, telemetry/audit, disable/re-enable/delete |
| `maintenance_rootful` | root | CLI disable/re-enable through a real handshake; disabled state survives restart; purge needs disabled+converged+no-op plan |
| `doctor_readonly` | mixed: first case unprivileged, rest root | Empty-install checks unprivileged; configured-but-unapplied install in a disposable namespace plans repair without applying; snapshots unchanged |
| `service_rootful_e2e` | root | HTTP surface reflects real network state (`ok` vs `degraded`), survives backend loss without restart, leaks no key material; `serve` on host, `netd` in namespace |
| `upgrade_rehearsal_rootful` | root, `#[ignore]`d, needs `WGB_OLD_BINARY` + `WGB_CANDIDATE_BINARY` | Real v4 product traffic, backup verification, candidate migration/failed health, v4 restore, doctor, old-service recovery, re-upgrade |

## Architecture-guard categories

`tests/architecture_guards.rs` currently contains 47 `#[test]` functions
(including the comment-stripper self-test and runtime checks such as
secret redaction and the bundled-SQLite version). They are cheap
source-text assertions that run in the ordinary suite. By category:

| Category | What is pinned |
|---|---|
| No shell-out / no escape hatch | No `wg`/`wg-quick`/`ip` invocation; process execution isolated to `src/firewall/nft.rs`; no `sh`/`bash`; the nft backend spawns exactly `nft` |
| Closed privileged protocol | No generic `Exec`/`Shell`/`RawNetlink`/`WriteFile`/`Sysctl`/etc. operation in `src/protocol/wire.rs`; operation vocabulary and `PROTOCOL_VERSION = 1` pinned |
| Privilege separation and layering | Aggregate coordinator database-free; `src/state/` never reaches the privileged boundary; privileged path never opens the DB; management never becomes an HTTP surface; HTTP reaches management only through the bounded worker (`mpsc::channel(capacity)` + `try_send`); backup/restore stay local; store submodules stay one-directional |
| Authentication secrecy | Closed secret-safe event schema; secret wrappers redact `Debug`/`Display`; raw `SessionToken` has no path into `store::auth` (digests only, one `expose_once`); auth only via the worker thread; no plaintext password parameter reaches a query; migration list is exactly real v1+v2; admin password arrives on stdin only |
| Doctor read-only | Doctor dispatch uses `Plan…` ops and `inspect_readonly` only; no `StateStore::open`, no apply ops, no process spawn |
| HTTP perimeter (M003) | No CORS headers at all; no JWT/OAuth/session-crate dependencies; session-cookie attributes pinned (`HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`, `Secure` from origin profile); no forwarded-header trust; one `headers::seal` call site; limiter consulted before worker authentication; bounded limiter peer map; routable bind refused without acknowledgement; response bodies only from `response.rs`/`api.rs`; failed logins always spend one Argon2 verification |
| Embedded UI shell (M005) | Assets name no external origin; no inline script/style or event handlers (no CSP concession); no build toolchain or manifest build step; assets are `include_str!` constants with no filesystem reads; shell served through the single seal point; shell uses product/telemetry/audit routes only |
| Service lifecycle (M004) | Limiter stays in-memory; anonymous `/healthz` answers only from the readiness projection (`ok`/`degraded`); backend probe is a read-only `Ping` reachable only from the authenticated route; only `src/http/serve.rs` orders shutdown (stop accepts → drain → stop worker); exactly `netd` and `serve` install `ctrlc` handlers with the `termination` feature; hardening contract matches netd runtime requirements |
| Toolchain / runtime pins | Bundled SQLite newer than the WAL-reset advisory range (recorded `3.53.2`); `ctrlc` `termination` feature enabled |

## Rootful fixture prerequisites and invocation pattern

Prerequisites (from `docs/development.md`): root, `CAP_NET_ADMIN`,
`iproute2`, plus `iputils-ping` for kernel-handshake suites and `nftables`
for durable/doctor/maintenance suites, plus kernel WireGuard support. When
`CI` is set, unavailable namespace/kernel prerequisites fail instead of
skipping. Suites that create fixed-name namespaces serialize with
`--test-threads=1`.

`sudo` resets `HOME`, so rootful invocations preserve `PATH` and give Cargo a
writable home:

```sh
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test durable_owner -- --test-threads=1
```

Per-target commands (all from `docs/development.md`):

```sh
cargo test --locked --test privileged_protocol -- --nocapture
sudo -E cargo test --locked --features linux-integration --test wireguard_kernel -- --nocapture
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test durable_restart -- --test-threads=1
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test product_management_rootful -- --test-threads=1
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test durable_backup -- --test-threads=1
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test doctor_readonly -- --test-threads=1
cargo test --locked --test service_lease -- --test-threads=1
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test maintenance_rootful -- --test-threads=1
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test service_rootful_e2e -- --test-threads=1
```

Phase 7 service suites run with the ordinary suite; the footprint suite runs
on the release binary:

```sh
cargo test --locked
cargo test --release --locked --test service_footprint -- --nocapture
```

`service_rootful_e2e` starts a real `netd` inside a disposable namespace and
runs `serve` on the host against it over the shared socket path (`ip netns
exec` does not remount `/tmp`, so the socket file is visible on both sides;
a namespace has its own loopback, so `serve` cannot run usefully inside it).

## Upgrade-rehearsal shape (old/new binary pair)

CI builds the immutable Phase 8 baseline (`e8fd6b1`) with its own lockfile
into one target directory and the candidate into another, then passes both
absolute paths as environment. The rootful rehearsal uses disposable
namespaces and a temporary state directory:

```sh
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  CARGO_TARGET_DIR=/tmp/wg-basic-upgrade-rootful-target \
  WGB_OLD_BINARY=/path/to/phase8/wg-basic \
  WGB_CANDIDATE_BINARY=/path/to/candidate/wg-basic \
  cargo test --locked --features linux-integration \
    --test upgrade_rehearsal_rootful -- --ignored --nocapture --test-threads=1
```

Both rehearsal targets are `#[ignore]`d and require `--ignored`. The
unprivileged companion (`--test upgrade_rehearsal`) owns no host networking
and covers v4 product/session/enrollment/audit preservation, config hashes,
old-binary refusal, explicit restore, and repeated migration. The rootful
target covers real v4 product creation and WireGuard traffic, explicit backup
verification, candidate migration/failed health, v4 restore, doctor,
old-service recovery, and candidate re-upgrade.

## CI job mapping (`.github/workflows/ci.yml`)

| CI job | Test command |
|---|---|
| `rust` | `cargo fmt --all -- --check`, `cargo check --all-targets --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked` (covers all unprivileged suites incl. `privileged_protocol` on Linux) |
| `dependency-audit` | `cargo audit` on the committed lockfile |
| `upgrade-rehearsal` | `cargo test --locked --test upgrade_rehearsal -- --ignored --nocapture` with `WGB_OLD_BINARY` / `WGB_CANDIDATE_BINARY` |
| `upgrade-rehearsal-rootful` | Rootful rehearsal above with old/candidate binaries, `iproute2` + `iputils-ping` installed |
| `wireguard-kernel` | `--test wireguard_kernel` (installs `iproute2` + `iputils-ping`) |
| `network-reconcile-kernel` | `--test network_reconcile` (installs `iproute2`) |
| `network-control-e2e` | `--test network_control_e2e` (installs `iproute2` + `iputils-ping` + `nftables`) |
| `durable-owner` | `--test durable_owner -- --test-threads=1` |
| `durable-restart` | `--test durable_restart -- --test-threads=1 --nocapture` |
| `durable-backup` | `--test durable_backup -- --test-threads=1 --nocapture` |
| `product-management-rootful` | `--test product_management_rootful -- --test-threads=1 --nocapture` |
| `doctor-readonly` | `--test doctor_readonly -- --test-threads=1` |
| `maintenance-rootful` | `--test maintenance_rootful -- --test-threads=1 --nocapture` |

No dedicated CI job is evident for `service_rootful_e2e`; it is
feature-gated, so the ordinary `cargo test --locked` in the `rust` job does
not run it.
