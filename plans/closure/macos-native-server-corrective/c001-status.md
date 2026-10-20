# macOS Native Server C001 — Production Backend Wiring and Host-Only Convergence

Disposition: **blocked** (narrowed again 2026-10-20: the production Darwin wiring
and the **arm64 controlled-host** product path are now closed with observed
evidence — a real installer, a real `netd` and unprivileged `serve`, the real
authenticated HTTP surface, an off-host independent Linux-kernel WireGuard peer,
a real handshake, dual-stack IPv4/IPv6 traffic, and API telemetry; what remains
is the **native Intel** arch of the same product path, which needs the off-host
peer to be reachable from a hosted macOS runner).

Date: 2026-10-20.

## Implementation revision

- Repository baseline: `0887964` (the C001–C005 corrective handoff).
- Implementation head: `b53ce2d` ("macos(c001,c002): make the Darwin route messages and the tunnel pool real"),
  on top of `1806d3e` ("macos(c002): release the privileged socket when the daemon is stopped"),
  on top of `c9f8fc9` ("macos(c002): read the effective identity the way BSD ps
  reports it"), on top of `e4f47d5` ("macos(c002): own the receipt and the privileged
  socket explicitly"), `1d8ca63` ("macos(c001,c002): fix the Darwin interface
  inventory and the hosted live failures") and `e94306c` ("macos(c001,c002): wire the
  production Darwin host-only backend and installer").
- Source plan: `plans/implementation/macos-native-server/c001-production-wiring-host-only.md`.
- Source roadmap: `plans/subsystems/macos-native-server-corrective-roadmap.md` (C001).
- Historical M002–M004 and M007 closures are untouched and remain as recorded.

## Requirement-to-evidence matrix

| Requirement (plan) | Evidence | Result |
|---|---|---|
| §1 Service-backed helper: replace the Darwin `UnsupportedBackend` facade; `observe_device`/`apply_patch` against a durable per-netd managed runtime registry keyed by InstallationId/logical InterfaceId; authorize helper path and hash before launch; fixed argv, restricted environment, bounded output/time, redacted secrets; separate logical identity from ephemeral `utunN` and UAPI path | `src/wireguard/darwin.rs` (supervisor, UAPI render/parse, device delta, `verify_helper_sha256`) and `src/wireguard/darwin_backend.rs` (`RuntimeRegistry`, `ManagedRuntime`, `DarwinWireGuardBackend`). The registry is a process-local map plus owner-only receipts under `/var/run/wg-basic/managed`; it is evidence, not a desired-state store. The helper path is absolute, hash-pinned from the verified install receipt, spawned with a fixed argv and a cleared environment. The logical `InterfaceName` and the ephemeral `utunN`/UAPI path are separate types | Passed (code + unit + native live) |
| §2 Ownership: prove process executable identity, protected receipt, kernel utun, UAPI socket owner and live observations jointly; re-observe before stop/delete/replace; never terminate a PID from a receipt alone; never kill another VPN's utun; idempotent generations; abort rather than guess on mixed state | `prove_ownership` re-observes `proc_pidpath(pid)` (a reused pid is a different executable), the helper executable's digest, the UAPI socket's owner and type, and the kernel device; only a joint proof authorizes mutation. A receipt that fails re-proof is observed as **absent**, so the planner recreates rather than adopts or destroys. `delete_managed_tunnel` stops the helper, waits for the kernel device to disappear, and only then drops the receipt; a device that lingers fails the delete | Passed (code + unit + native live) |
| §3 Darwin reconciliation: real service behind `src/reconcile/service_darwin.rs` using the typed planner, direct constrained Darwin APIs (routing socket/`getifaddrs`, bound address control) and fresh observation; test-only `ifconfig`/`route` probes are not a backend; preserve foreign routes/host defaults; typed conflict/degraded errors, never false success | `src/reconcile/backend_darwin.rs` observes through `getifaddrs` and the `sysctl(CTL_NET, PF_ROUTE, …, NET_RT_DUMP)` table dump and mutates through `SIOCSIFFLAGS`/`SIOCGIFMTU`, `SIOCAIFADDR`/`SIOCDIFADDR` (IPv4) and `SIOCAIFADDR_IN6`/`SIOCDIFADDR_IN6` (IPv6), and `AF_ROUTE` `RTM_ADD`/`RTM_DELETE` messages — no `ifconfig`/`route` parsing and no subprocess. `src/reconcile/apply.rs` holds the one portable observe/plan/apply/verify sequence that Linux and Darwin share. Foreign routes are classified out of the managed set and counted as unsupported rather than touched | Passed (code + unit) |
| §4 Host-only firewall semantics: `NoChange` only for an explicitly host-only intent with no forwarding/NAT obligation; refuse with `Unsupported` for every routed, masquerade, unsupported or ambiguous policy; a blanket no-op for all Darwin policies is forbidden | `src/firewall/service_darwin.rs` validates the policy and refuses `Ipv4Forwarding::Required`, `Ipv6Forwarding::Required`, and `NatMode::Masquerade` with `FirewallError::Unsupported`; a host-only policy yields an empty action list and an honest `NoChange` receipt with `table_changed=false` and `forwarding_changed=false`. The host's global forwarding state is read through the audited boundary and never written | Passed (code + unit) |
| §5 Aggregate control and visibility: real `protocol::dispatch`/`aggregate` through WireGuard + interface + verified host-only firewall ordering; the applied generation is committed only when the exact generation's observed state is reached; honest health/doctor/counters in the existing authenticated surface; the narrow privileged request vocabulary is retained | The dispatch is unchanged: `ObserveWireGuardDevice`, `ApplyWireGuardDevice`, `PlanManagedInterface`, `ApplyManagedInterface`, `PlanNetworkPolicy`, `ApplyNetworkPolicy` and the aggregate intents reach the Darwin services through the same typed paths, so **no wire shape changed** and no migration was needed. `NetworkCapabilitySnapshot` now reports the real Darwin control surface (the pinned helper, only when the installed helper still matches the receipt digest) and still reports no Linux capability, namespace, or nftables value | Passed (code + unit) |
| §6 Operational contract: deterministic replay, cleanup, retention or degraded results for enable/disable/peer mutations/SIGTERM/helper crash/netd crash/repeat/concurrent/replace; document the helper recovery and no-foreign-adoption contract | The Darwin service serializes observe/plan/apply/verify with one installation-wide lock; the receipt registry survives a reader restart and re-proves itself; the ownership and no-foreign-adoption contract is written into `architecture/wireguard-control.md` and `architecture/ownership.md`. Repeated apply is idempotent through the portable planner's keep/set/clear semantics. The full SIGTERM/helper-crash/netd-crash/concurrent/replace matrix on a real product deployment is part of the blocked off-host qualification below | Partially passed (code + contract); live matrix blocked |
| Security/compatibility: `serve` unprivileged; `netd` the only host-network authority; SQLite keeps keys/generation/authorship with the existing secret handling and redaction; UDS `getpeereid` authorization and bounded framing; explicit typed operations only; a protected receipt alone NEVER authorizes deletion; macOS helper source MIT license/revision, no PATH discovery, no unsafe shell | `serve` runs as the dedicated `_wg-basic-serve` principal and `netd` as root (C002). The privileged socket is `0660`, bound to the management group, and the privileged daemon admits the management UID that the *verified receipt* records. The reported device private key is converted to the device public key and dropped; the per-peer preshared key is never read at all. The helper is hash-pinned, absolute, and spawned with a cleared environment and a fixed argv. The receipt never authorizes anything on its own | Passed (code + unit + native live) |
| Focused tests: Linux netlink behavior unchanged; Darwin UAPI hex/errno parsing; helper restart/utun renumber; ambiguous ownership; malicious UDS frames; wrong helper digest; stale socket; missing/foreign address; global route conflicts; peer update/delete; exact-generation CAS; a replaced stub must fail the end-to-end test | Unit coverage in `crates/darwin-sys` (9), `src/wireguard/darwin_backend.rs` (UAPI mapping, hex decoding, partial peer updates, refusal), `src/reconcile/backend_darwin.rs` (route classification, absence), and `src/firewall/service_darwin.rs` (host-only refusal). New architecture guards pin the isolated `unsafe` boundary, the joint ownership proof, the host-only firewall refusal, the closed launchctl verb set, the non-root management daemon, the privileged socket's ownership, and the receipt's owner. Linux netlink behavior is unchanged: the Linux reconciliation service now shares the same portable apply module with byte-identical plan and failure mapping, and the Linux build and clippy are clean | Passed |
| Root-run disposable ARM64 and native Intel: real `netd` + unprivileged `serve`, SQLite/admin init, server configuration and peer enrollment over HTTP, handshake, IPv4 **and** IPv6 packets with local Mac-owned addresses, telemetry at the API, disable/delete with interface/route/pid/socket cleanup, netd/helper restart, idempotent replay, foreign-owner refusal, before/after route and VPN inventory | The new native live test `live_c001_production_backend_owns_and_configures_a_managed_tunnel` drives the **production** path (registry receipt → joint ownership proof → production backend observe → reader restart → teardown with no leaked device, socket, or receipt) on the hosted arm64 and Intel runners, run `39427791794`. The existing M003/M004/M005 live suites still pass on the same run. The **arm64 controlled-host** product path is now also proven end to end by `live_c001_product_path_carries_traffic_to_an_off_host_linux_peer`, run as root on a disposable arm64 Mac against an independent Ubuntu 24.04 Linux-kernel WireGuard peer on another host: the product's own installer, the real privileged and unprivileged daemons, the real authenticated HTTP surface, a real handshake, dual-stack traffic, and API telemetry — observed output is reproduced under *Verification* below. The **native Intel** arch of the same product path is not yet run: the hosted Intel runner cannot reach the off-host peer, which sits on a private LAN | Partially passed (native hosted backend evidence; **arm64** controlled-host product path); **blocked** on the native Intel product-path leg |

## Verification

Native Darwin arm64 (macOS 26.6.2, rustc 1.89.0), run from the repository root:

- `cargo fmt --all -- --check` — passed.
- `cargo clippy --locked --all-targets -- -D warnings` — passed.
- `cargo test --locked` — passed: 641 tests, 0 failures. The suite was run four times in a row after the scratch-path fix; every run was green.
- `cargo test --locked -p wg-basic-darwin-sys` — passed: 9 tests.
- `cargo check --locked --target aarch64-apple-darwin` — passed.
- `cargo check --locked --target x86_64-apple-darwin` — passed.
- `cargo zigbuild --locked --target x86_64-unknown-linux-gnu --all-targets` — passed (the Linux **test** targets compile too; several modules and fixtures exist only on Linux and a macOS build never sees them).
- `cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets -- -D warnings` — passed, with and without the `linux-integration` feature.
- Linux native CI, run `39427800154`: every job passes — `rust`, `doctor-readonly`, `system-install-systemd`, `wireguard-kernel`, `network-control-e2e`, `network-reconcile-kernel`, `product-management-rootful`, `durable-owner`, `durable-backup`, `durable-restart`, `maintenance-rootful`, `upgrade-rehearsal`, `upgrade-rehearsal-rootful`, and `update-transaction-rootful` — except `dependency-audit`, which fails on **pre-existing** upstream advisories in `zip 6.0.0` (RUSTSEC-2026-0368/0369 and one more), which arrives through `eggup-archive v0.1.3` and cannot be resolved in this repository because `eggup-archive` is pinned with `=0.1.3` and `zip` cannot take a semver-major upgrade. It is unrelated to C001/C002 and is recorded as an unresolved finding below.
- The branch's Linux `cargo clippy --all-targets --locked -- -D warnings` gate was **red before this change** (a dead `getsockopt`/`PeerCredentials` import left behind in `src/protocol/socket.rs` when M002 moved peer identity into `src/protocol/auth.rs`). This change removes the dead import, and the gate is green again.

Native hosted macOS qualification, run `39427791794` on `plans/macos-native-support`:
**all four jobs passed** — `gates-arm64`, `gates-intel`, `live-arm64`, and
`live-intel-tunnel`. The new C001 live qualification passed on the hosted
arm64 runner and wrote its evidence to the run's
`macos-live-evidence-arm64` artifact:

```
helper created utun4
ownership proven jointly from receipt, process, socket, and device
the production backend observed the managed device
the durable receipt survives a reader restart
teardown complete: no device, socket, or receipt left behind
```

Three earlier hosted runs of this line failed, and every failure was a real
defect in this change rather than an environment gap: run `39420943827` (the
managed helper could not start, and the M006 launchd cycle asserted a
synchronous socket removal), run `39423536138` (the M006 cycle failed as
collateral of the C002 qualification leaving a job registered), and run
`39425260093` (the privileged socket kept an inherited group, the receipt was
unreadable by the management daemon, and the daemon did not release its socket
when it was stopped during startup). The root causes are recorded under
*Unresolved findings by severity* below.

### Arm64 controlled-host product path

The arm64 leg of the product path was run as root on a disposable arm64 Mac
(macOS 26.6.2, rustc 1.89.0) against an **independent Linux-kernel** WireGuard
peer on a different host (Ubuntu 24.04, kernel 6.8, `wireguard.ko`, the
in-kernel `wireguard-tools` implementation). The peer is driven through
`tests/fixtures/darwin-peer/wg-basic-peer.sh`, whose contract keeps the Rust
fixture free of SSH and topology knowledge. The fixture is
`live_c001_product_path_carries_traffic_to_an_off_host_linux_peer` in
`tests/wireguard_darwin_controlled.rs` — the controlled-host target, kept
apart from the hosted-runner suite so a hosted runner never executes a
fixture that needs a host it cannot be.

Commands, run from the repository root:

```
cargo fmt --all
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --bin wg-basic
cargo test --locked --no-run --test wireguard_darwin_controlled
WGB_DARWIN_LIVE=1 WGB_WIREGUARD_GO=/tmp/wgb-qual/wireguard-go \
WGB_HELPER_SHA256=a490f82f540130730f0fde5d10a3e6dab6a4dfa066b94c6968873c8104c69d21 \
WGB_BINARY=$PWD/target/debug/wg-basic WGB_EVIDENCE_DIR=/tmp/wgb-qual/evidence \
WGB_PEER_COMMAND=$PWD/tests/fixtures/darwin-peer/wg-basic-peer.sh \
WGB_PEER_SSH_HOST=192.168.182.143 WGB_PEER_SSH_USER=sugarwookie \
WGB_PEER_SSH_KEY=/Users/davidbowman/.ssh/id_ed25519 \
  target/debug/deps/wireguard_darwin_controlled-* \
  live_c001_product_path_carries_traffic_to_an_off_host_linux_peer \
  --ignored --exact --test-threads=1 --nocapture
```

(The fixture was run from the `wireguard_darwin_live` target at the time of
the observation. It now lives in the separate `wireguard_darwin_controlled`
target, because the hosted runner executes every `#[ignore]`d test in the
hosted target and must never pick up a controlled-host fixture.)

Observed output (the evidence file the run wrote,
`c001-product-path-off-host-peer.txt`):

```
the transactional installer completed the deployment
the administrator was provisioned as the management identity
the management session is authenticated
the product converged a server from the HTTP setup
the product enrolled client 9c8aa140-b06d-4375-82ed-52b83c399024 with public key Qz7lwtkvNxIoI3X4w7WnZ3UaCT1RCWoMf+RSlWCKDgU=
the off-host peer installed the exported configuration
the managed device carries the enrolled peer: {"client_id":"9c8aa140-...","drift":false,"enabled":true,"endpoint":"192.168.182.143:38144","latest_handshake_age_seconds":0,"latest_handshake_unix_seconds":1792513929,"observation":"present","peer_id":"06c20504-...","rx_bytes":180,"tx_bytes":92}
the off-host peer completed a handshake at 1792513930
IPv4 traffic reached 10.77.0.1 from the off-host peer
--- 10.77.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
IPv6 traffic reached 2001:db8:77::1 from the off-host peer
--- 2001:db8:77::1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms
telemetry: handshake age 51s rx=1028 tx=908
disabling the client removed the peer from the managed device
```

The two implementations agree independently: the macOS product's API reports
the handshake timestamp `1792513929` and the peer's own
`wg show … latest-handshakes` reports `1792513930` for the same session, and
the peer carries the server's public key while the server's telemetry carries
the peer's endpoint `192.168.182.143:38144`.

The same run also proved the Darwin backend's convergence on a product-shaped
desired state (`live_c001_darwin_backend_converges_a_product_shaped_desired_state`):

```
the Darwin backend converged: status=Applied planned=[CreateWireGuardLink, ConfigureWireGuard, AddAddress 10.78.0.1/32, AddAddress 2001:db8:78::1/128, SetLinkUp, AddRoute 2001:db8:78::/64] completed=6 failed=None
the managed device is observed with 3 address(es) and 2 route(s)
```

Four real defects were found by this leg and fixed; each is recorded under
*Unresolved findings by severity* below.

## Security and ownership evidence

- The Darwin kernel boundary is the only `unsafe` in the workspace, and it lives in one small workspace member (`crates/darwin-sys`) whose only unsafe module is the OS boundary. The product crate keeps `#![forbid(unsafe_code)]`. New guard `the_darwin_unsafe_lives_in_one_isolated_os_boundary` pins both facts.
- The boundary exposes typed values only: no raw pointer, descriptor, or `errno` escapes to a caller, and nothing in it parses a human-readable tool's output or executes a subprocess.
- The request numbers, struct layouts, and message shapes were taken from the macOS SDK headers (`sys/sockio.h`, `net/if.h`, `netinet6/in6_var.h`, `net/route.h`, `ifaddrs.h`) and from Apple's own `route(8)` and `ifconfig(8)` implementations, so the wire shapes are the platform's supported interface.
- Ownership is proven jointly, never from a receipt alone. A foreign `utunN`, a reused pid, a replaced helper, or a replaced socket fails closed.
- The Darwin helper is hash-pinned from the verified install receipt and spawned with a cleared environment and a fixed argv; no `PATH` discovery and no shell.

## Docs and operations evidence

- `architecture/wireguard-control.md` — the Darwin userspace backend and the ownership receipt.
- `architecture/ownership.md` — the Darwin interface-ownership contract.
- `architecture/reconciliation.md` — the Darwin reconciliation service and route classification.
- `architecture/firewall.md` — the Darwin host-only contract.
- `architecture/privilege-boundary.md` — the Darwin service identity and the isolated OS boundary.
- `architecture/overview.md` — the module index now names `crates/darwin-sys` and the Darwin backend modules.
- `docs/development.md` — the Darwin gate list now includes the boundary crate's suite.

## Known limitations

1. **The native Intel leg of the product path is unqualified.** The arm64
   controlled-host leg is now proven end to end (see *Verification*), but the
   same leg on a hosted Intel runner needs the off-host Linux-kernel peer to
   be reachable from that runner. The peer used here sits on a private LAN
   with no inbound path from the internet, so the Intel runner cannot reach
   it. This is the same off-host interop residual M003 already records, now
   narrowed to one architecture rather than both.
2. **The product `serve`/`netd` deployment is now exercised live as a pair**
   on the arm64 controlled host: the same run drives the installer, the
   privileged daemon, the unprivileged management daemon, the authenticated
   HTTP surface, and the off-host peer. The Intel arch of that pairing is the
   remaining gap above.
3. **IPv6 link-local and scoped behaviour is preserved, not re-created.** The backend observes and refuses to touch the kernel's own address-derived routes, but it does not manage link-local scope.
4. **The peer endpoint is reported by the helper, but the helper's UAPI dump is the only source.** A peer endpoint that the helper does not report is reported as absent rather than invented.
5. **No release claim exists.** ADR-008/M007 still withhold every macOS release, and this record changes nothing about that.

## Unresolved findings by severity

- **Medium (pre-existing, out of scope):** the `dependency-audit` CI job fails on three upstream `zip 6.0.0` advisories reached through `eggup-archive = "=0.1.3"`. Not resolvable in this repository without an upstream release; it does not affect the C001 code.
- **Low (pre-existing, fixed here):** the dead `getsockopt`/`PeerCredentials` import in `src/protocol/socket.rs` had the branch's Linux `-D warnings` gate red before this change; it is removed here and the gate is green.
- **Medium (introduced by this change, fixed here):** the audited interface inventory in `crates/darwin-sys` listed only interfaces that carried an address. `getifaddrs` reports one entry per interface/address pair, and a freshly created tunnel has no address yet, so the managed `utunN` was invisible: the helper spawn timed out (`StartupFailed`), the reconciliation reported a live tunnel as absent, and the delete path's "wait for the device to disappear" check was vacuous. The inventory now lists every interface, and the grouping rule is unit-tested in `crates/darwin-sys`.
- **Medium (introduced by this change, fixed here):** the Darwin route message carried no gateway at all. The kernel refuses an `RTM_ADD` that has no `RTA_GATEWAY` (`bsd/net/rtsock.c`, `route_output`), so **every** route addition failed with `EINVAL` and the managed interface could never carry its tunnel prefix. The message now carries the interface's own link-level `sockaddr_dl` in `RTA_GATEWAY`, which is the shape Apple's `route(8)` sends for `route add -interface` and the shape the kernel matches against the interface's link-level address.
- **Medium (introduced by this change, fixed here):** the route dump parser read the interface index out of `RTA_IFA` as a four-byte integer. `RTA_IFA` carries the interface's own socket address, and the interface index is in the header's `rtm_index`; the parser also stopped the walk at the first address shorter than a `sockaddr`, while the kernel writes a zero-length address as one four-byte word. Every managed route was therefore attributed to no interface, so the reconciliation saw a converged tunnel as having no routes. The parser now reads the index from the header and walks the addresses in `RTAX_*` order with the rounding Apple's `route print` applies.
- **Medium (pre-existing, fixed here):** the desired state carried the tunnel-pool route for the IPv6 prefix only. WireGuard AllowedIPs selects the peer but adds no host route, and on macOS the helper adds none either, so the IPv4 half of the tunnel had no route at all: the peer's IPv4 echo request was answered through the default route instead of the tunnel. The desired state now carries the pool route for **every** tunnel prefix; on Linux the IPv4 route is redundant with the kernel's AllowedIPs route and the more specific per-peer route still wins.
- **Low (pre-existing, configuration, not a defect):** the exported client configuration carries no persistent keepalive by default. A peer behind NAT that holds no traffic of its own never initiates a session, so the two ends never met. The management API already exposes `client_keepalive_seconds`, the exported configuration carries it when it is set, and the qualification enrolls the off-host peer with it. The default stays unset because an interactive WireGuard client initiates on connect.
- **Low (introduced by this change, fixed here):** the managed helper publishes its UAPI control socket a moment after the kernel hands it the device, so a spawn that returned on the device alone could hand back a tunnel nobody could configure yet. `spawn_managed_tunnel` now waits for the control socket before it returns.
- **Low (pre-existing, fixed here):** the test scratch paths were suffixed with `SystemTime::now()` nanoseconds. The macOS wall clock is coarse enough that concurrent tests routinely receive the same value, so two tests collided on one directory (`AlreadyExists`) and the gate failed intermittently. Reproduced at the pre-C001 baseline `0887964`. The scratch paths now use a per-process counter.

## Disposition

**Blocked (narrowed to the native Intel arch).** The implementation is complete
and the **arm64 controlled-host** product path is now closed with observed
evidence: the product's own installer deploys the privileged daemon and the
unprivileged management daemon, the real authenticated HTTP surface converges a
server and enrolls a client, an **independent Linux-kernel** WireGuard peer on
another host completes a real handshake with it, IPv4 and IPv6 traffic crosses
the tunnel in both directions, the API reports that traffic as telemetry, and
disabling the client removes the peer from the device. Four real defects were
found by that leg and are fixed and recorded above.

What is still open is the plan's requirement to run the same product path on
the **native Intel** arch. The hosted Intel runner has no second kernel and no
path to the off-host peer, so the Intel leg of the product path is
**environmental**, not an implementation gap. Per the planning process,
closure is not claimed from expected evidence, so C001 remains **blocked** —
now narrowed from "both arches" to "the Intel arch". C003's hard dependency on
C001 therefore stays **blocked** as well.
