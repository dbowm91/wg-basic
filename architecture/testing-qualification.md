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
| `helper_provenance` | none | The declared helper build input is pinned, and there is exactly one declaration, one builder, and no second copy of the upstream source in the workflow |
| `auth_sessions` | none | Real v1→v2 migration, Argon2id cost, credential/session persistence; no HTTP |
| `authenticated_api` | none | Request policy directly: `Host`/`Origin`/`Sec-Fetch-*`, CSRF, cookie, limiter ordering |
| `management_http` | none | Same perimeter over real HTTP/1.1 on a real TCP socket: routing, headers, `Origin`, CSRF, bounded 503, rejected IPv6 routes preserve generation |
| `service_session_restart` | none | Sessions across a real `serve` restart over real cookies; expiry/logout/reset still hold |
| `service_resource_limits` | none | Admission/deadline boundaries: connections, in-flight, worker queue, body, timeouts, shutdown |
| `service_e2e` | none (spawns binaries) | Real `admin` + `netd` + `serve` children: process topology, CLI→HTTP credential seam, startup reconcile, restart preserves cookie |
| `service_footprint` | none, Linux, release binary | Footprint/latency figures on the release binary; asserts only design bounds (incl. login-latency *floor*) |
| `service_lease` | none | Real `serve` lock: second process and restore refused while held; restore proceeds after kill |
| `operational_events` | none (spawns binaries) | Stderr-only, line-delimited event format and secrecy |
| `runtime_stability` | none (spawns binaries) | Bounded HTTP and state-row growth over repeated valid/rejected requests |
| `product_management` | none | Product layer with no HTTP: setup, allocation, IPv6 route prerequisites and generation safety, enable/disable, delete, audit atomicity, committed-vs-enforced receipts |
| `state_store` | none | Init, hardened open, migrations, generation CAS, rollback, secrets, projection |
| `state_backup_restore` | none | Backup/restore/verify on temp SQLite files; corruption fails closed |
| `state_durability` | none | Interrupted process leaves a cleanly reopening DB holding one whole generation (not power-cut safety) |
| `privileged_protocol` | Linux, unprivileged | UDS capability/auth IPC: peer-credential authorization, socket lifecycle, fail-closed collisions |
| `upgrade_rehearsal` | none, `#[ignore]`d, needs `WGB_OLD_BINARY` | v4 preservation, config hashes, old-binary refusal, explicit restore, repeated migration |
| `update_transaction_rootful` | root, isolated systemd VM, `#[ignore]`d | Signed-fixture installed update with disabled and enabled health profiles, real client traffic, startup timeout, post-migration rollback, crash recovery, retained session, and retry to Committed |
| `wireguard_kernel` | root | Real-kernel handshake, telemetry, peer update/preservation in temp namespaces; netd workers run inside the namespaces |
| `network_reconcile` | root | Link/address/route lifecycle and reconciliation in a namespace |
| `durable_owner` | root | Owner tags and generation-aware aggregate reconcile against the real kernel |
| `durable_restart` | root, needs built `wg-basic` binary | Startup reconciliation and crash/restart recovery via real `netd` + `reconcile` child processes |
| `durable_backup` | root | Restored database drives real traffic (3 namespaces, handshake, forwarding, NAT); foreign same-name link fails closed |
| `product_management_rootful` | root | Authenticated API exports an explicit dual-family full-tunnel config; real client handshake/IPv4+IPv6 tunnel traffic; client disable stops IPv6 traffic and re-enable restores it; enrollment consume/replay, telemetry/audit, whole-network restart/reapply |
| `maintenance_rootful` | root | CLI disable/re-enable through a real handshake; disabled state survives restart; purge needs disabled+converged+no-op plan |
| `doctor_readonly` | mixed: first case unprivileged, rest root | Empty-install checks unprivileged; configured-but-unapplied install in a disposable namespace plans repair without applying; snapshots unchanged |
| `network_control_e2e` | root | Three namespaces qualify IPv4 NAT and IPv4/IPv6 full and split client routes, positive/negative split traffic, routed IPv6 without NAT66, global forwarding persistence, foreign-state preservation, independent firewall drops, restart, and retry after injected nft failure |
| `service_rootful_e2e` | root | HTTP surface reflects real network state (`ok` vs `degraded`), survives backend loss without restart, leaks no key material; `serve` on host, `netd` in namespace |
| `upgrade_rehearsal_rootful` | root, `#[ignore]`d, needs `WGB_OLD_BINARY` + `WGB_CANDIDATE_BINARY` | Real v4 product traffic, backup verification, candidate migration/failed health, v4 restore, doctor, old-service recovery, re-upgrade |
| `darwin_ipc` | none, macOS only | Native `getpeereid` IPC auth, framing, socket lifecycle, SIGTERM/restart against the real `netd` binary |
| `wireguard_darwin_live` | root, macOS only, `#[ignore]`d, needs `WGB_DARWIN_LIVE=1` + `WGB_WIREGUARD_GO` (+ `WGB_BINARY` for launchd) | Ephemeral-hosted-runner fixtures only: loopback handshake/traffic/counters (v4+v6), route inventory preservation, PF anchor lifecycle (with the attachment controls — the real positive, collision, and negative cases against live `pfctl` output), forwarding/PF cycle, launchd bootstrap/reinstall, production backend ownership, unprivileged management daemon, backend convergence; `--test-threads=1` |
| `wireguard_darwin_controlled` | root, macOS only, `#[ignore]`d, needs `WGB_DARWIN_LIVE=1` + `WGB_WIREGUARD_GO` + `WGB_BINARY` (+ `WGB_PEER_COMMAND` for the off-host peer, `WGB_C002_REBOOT_PHASE` for the reboot leg) | Disposable controlled-host fixtures only, in a separate target so the hosted runner never picks them up: product path against an off-host Linux-kernel peer, and the three-phase cold-reboot leg; `--test-threads=1` |
| `wireguard_darwin_routed` | root, macOS only, `#[ignore]`d, needs `WGB_DARWIN_LIVE=1` + `WGB_WIREGUARD_GO` + `WGB_BINARY` (+ `WGB_PEER_COMMAND` for the peer driver) | Disposable controlled-host fixture only, in a separate target: the routed-LAN leg against an approved downstream prefix, and the host's filter state before the leg and after its teardown; `--test-threads=1` |

### What the hosted live fixture proves about the managed device

The hosted live fixture runs on a host whose `utun` namespace is not under the
fixture's control: the host creates and destroys `utun` devices on its own and
**recycles the indices**. A device that existed when the fixture started may
be gone before the product's own observation, and the kernel may hand that
same index to the helper the product spawns. Two rules follow, and the
fixture holds to both.

**The device is proved new from the product's own observation.** The fixture
does not compare the device the product chose against an inventory snapshot it
took at some earlier moment; it uses the inventory the product read
immediately before it spawned the helper, which the spawn returns as its own
evidence (`devices_before_spawn`). A snapshot taken at a different instant
proves nothing on a host that recycles indices, and asserting against one
fires on correct product behaviour.

**A contention refusal is a legitimate outcome.** When the product's diff finds
more than one new device, it refuses to identify its own — it will not adopt a
device by number. That refusal is `managed_device_ambiguous`, and it is a
correct answer, not a failure to start. The fixture waits for a **quiescent**
`utun` namespace, retries a contention refusal a bounded number of times,
records **every attempt and every inventory** it observed, and still fails if
the refusal persists. A refusal that is about *identity* or *executability* is
never retried: retrying it would only repeat a correct answer.

The fixture identifies **its own** helper by the control socket the helper
published, and it identifies that socket by its **device and inode** rather
than by its path: macOS derives the socket path from the `utun` index, so a
respawned helper replaces the previous socket at exactly the same path with a
new inode, and the path alone cannot tell the two apart. This is the
fixture's own business; the product's own device-identification method is a
separate question and is not changed by the fixture's method.

The fixture claims only what it created: it asserts that **its** helper, **its**
socket, and **its** receipt are gone, rather than that a set difference
against a possibly stale inventory is empty. A failing live test keeps its
evidence — the evidence file is written when the test ends, including when it
ends in a panic, and the baseline the assertions compared against is logged —
so a failure can be diagnosed from its own artifact.

## Architecture-guard categories

`tests/architecture_guards.rs` currently contains 67 `#[test]` functions
(including the comment-stripper self-test and runtime checks such as
secret redaction and the bundled-SQLite version). They are cheap
source-text assertions that run in the ordinary suite. By category:

| Category | What is pinned |
|---|---|
| No shell-out / no escape hatch | No `wg`/`wg-quick`/`ip` invocation; process execution isolated to `src/firewall/nft.rs`; no `sh`/`bash`; the nft backend spawns exactly `nft` |
| Closed privileged protocol | No generic `Exec`/`Shell`/`RawNetlink`/`WriteFile`/`Sysctl`/etc. operation in `src/protocol/wire.rs`; operation vocabulary and `PROTOCOL_VERSION = 1` pinned |
| Privilege separation and layering | Aggregate coordinator database-free; `src/state/` never reaches the privileged boundary; privileged path never opens the DB; management never becomes an HTTP surface; HTTP reaches management only through the bounded worker (`mpsc::channel(capacity)` + `try_send`); backup/restore stay local; store submodules stay one-directional |
| Authentication secrecy | Closed secret-safe event schema; secret wrappers redact `Debug`/`Display`; raw `SessionToken` has no path into `store::auth` (digests only, one `expose_once`); auth only via the worker thread; no plaintext password parameter reaches a query; migrations are ordered immutable v1-v7 steps; admin password arrives on stdin only |
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

## macOS qualification mapping (`.github/workflows/macos-qualification.yml`)

Apple silicon is the only supported Darwin target (ADR-009), so the
qualification workflow has one architecture.

| CI job | Test command |
|---|---|
| `gates-arm64` (`macos-15`) | `cargo fmt --all -- --check`, `cargo check --all-targets --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`, the `aarch64-apple-darwin` target check, MSRV check |
| `live-arm64` | Pinned-helper build (tag + commit + license verified) then the ignored `wireguard_darwin_live` target as root with `WGB_DARWIN_LIVE=1`: all eight fixtures, evidence artifacts uploaded |

The routed-LAN leg (`wireguard_darwin_routed`) is **not** in the workflow: it
needs a disposable macOS host, a second WireGuard implementation for the peer
host, and a real PF, and a hosted runner cannot produce that.

## The routed-LAN leg restores the filter it loaded (C014)

The routed-LAN leg is a disposable controlled-host fixture
(`tests/wireguard_darwin_routed.rs`). Its traffic assertions are unchanged —
the forwarded traffic, the spoofed-source rejection, the unapproved-destination
rejection, and the helper-recovery leg all stay as they are. What changed is
what the leg leaves behind.

### The defect it corrected

The C003 leg **left the host's packet filter loaded**. Its teardown removed
the anchor's `load anchor` line from `/etc/pf.conf` and deleted the anchor
file, which restores the *ruleset* but not the anchor's **loaded rules**:
macOS keeps them across `pfctl -f` and `pfctl -F all`. The leg also ran
`pfctl -e` and never put PF back, and it left the `.drift` file it wrote for
the drift control in `/etc/pf.anchors/`.

Measured on the disposable guest immediately after the leg was re-run against
`d26c886` — recorded in
`plans/closure/macos-native-server-corrective/c003-status.md` §12.1: PF was
still **Enabled**, the managed anchor still held **eight** loaded rules, and
`/etc/pf.anchors/` still held the `.drift` sibling.

Two of the eight leftover rules matched on `utun0`. macOS recycles `utun`
indices, so a later tunnel that is handed that index inherits the previous
leg's rules, on a device the previous leg never saw. The `.drift` file is
the drift control's own artifact — the leg writes a drifting rule to it and
loads that file into the anchor — and it is the same file the residue check
now looks for.

### What the leg measures now

The leg **measures** the host's filter state before it installs anything and
again after it tears down:

- PF's enable state;
- the main filter and NAT rulesets;
- the managed anchor's own two rulesets;
- the anchors-directory listing.

The teardown empties the managed anchor's **filter class and NAT class**
separately, removes the anchor's lines from `/etc/pf.conf` and reloads the
main ruleset, removes the anchor file and its `.drift` sibling, restores PF's
enable state, and then asserts that the residue is empty. The restoration runs
even when the leg fails part-way — or is cancelled part-way: the filter
context is recorded before the filter is installed, so a leg that fails
between the install and the end is restored too.

The `-F rules` / `-F nat` split is not a detail. **`-F rules` alone leaves the
NAT rules loaded**, so a restoration that flushes only the filter class leaves
a translation rule evaluated on the host. macOS keeps a loaded anchor's
**rules** across `pfctl -f` and `pfctl -F all`, and `pfctl -F all` without
`-a` flushes the **main** ruleset, not every anchor — so the leg's own
`pfctl -a <anchor> -F all` did not stop the anchor's rules from being loaded
again afterwards, and the eight rules survived the final
`pfctl -f /etc/pf.conf`.

The scoped flush also works on an anchor that is **detached** from the main
ruleset — measured on the disposable guest: `pfctl -a <anchor> -F rules` exits
0 with `rules cleared`, and `-F nat` likewise.

### How it is qualified

The leg is qualified by being run **twice on the same guest**. The second
run's baseline is the proof that the first run left nothing: that baseline is
the host's own filter state before the second run, and it has to show no
loaded rules in the leg's anchor, no file of the leg's in the anchors
directory, the original PF enable state, and the original main rulesets.

The restoration planner and the residue check are pure functions, so their
regressions run in the ordinary gate order on a Darwin host — they need no PF
and no root.
