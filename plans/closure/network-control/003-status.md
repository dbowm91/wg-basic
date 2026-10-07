# M003 Closure — WireGuard Kernel Control and Live Telemetry

Disposition: **closed**

Implementation plan: `plans/implementation/network-control/003-wireguard-kernel-control-and-telemetry.md`

Repository baseline: `594e2f1` (M002 strict closure)

Implementation commits: `f7f75c3`, `a134b39`

Final implementation head: `a134b39`

Hosted CI run: [37584435943](https://github.com/dbowm91/wg-basic/actions/runs/37584435943)

## Requirement-to-evidence matrix

| Requirement | Evidence | Result |
|---|---|---|
| Current backend research and selection | `architecture/wireguard-control.md` | Pass. Compared DefGuard, `wireguard-control`, `nl-wireguard`, lower-level Generic Netlink, and `nlink`, including license/MSRV/API/scope tradeoffs. Selected MIT `nl-wireguard` 0.3.0; locked Rust 1.89 checks pass. |
| Existing kernel device observation/configuration without runtime tools | `src/wireguard/backend.rs`; source guard below | Pass. `nl-wireguard` handles typed Generic Netlink. Production source has no `wg`, `wg-quick`, or `ip` command execution. Link creation remains M004. |
| Key semantics and secret handling | `src/wireguard/keys.rs`, `src/domain/secret.rs`; unit tests | Pass. X25519 key generation and known derivation fixture; private/preshared keys redact Debug/Display, observed secret strings are zeroized, kernel error context is not returned. Dependency/compiler temporary copies are explicitly outside the zeroization guarantee. |
| Device key/listen configuration round-trip | `tests/wireguard_kernel.rs` | Pass. Rootful test sets each server key/listen port and asserts the observed public key and listen port match. |
| Explicit bounded peer mutation | `src/wireguard.rs`, `src/wireguard/backend.rs`, kernel fixture | Pass. Typed add/update/remove operations; at most one peer mutation per request; missing removal is idempotent. The fixture adds both peers, updates keepalive and AllowedIPs, then removes one peer. |
| Safe AllowedIPs replacement and unrelated-state preservation | `build_patch`, `ReplaceAllowedIps` flags, `tests/wireguard_kernel.rs` | Pass. Update explicitly replaces AllowedIPs for one peer, never uses `ReplacePeers`, and the unrelated peer remains observed before and after the update/removal. Cross-peer overlaps and duplicate prefixes are rejected. |
| Typed M002 protocol and secret-safe diagnostics | `src/protocol/wire.rs`, `src/protocol/server.rs`; protocol tests | Pass. Added typed observe/apply operations while retaining bounded v1 framing and `SO_PEERCRED`; permissions, unsupported backend operations, and kernel rejection have separate response categories. |
| Real Linux handshake and live telemetry | Rootful hosted run 37584435943, `wireguard-kernel` job | Pass. The isolated two-namespace fixture observed no initial handshake/traffic, sent tunnel pings, then required a handshake, endpoint, and nonzero RX/TX counters. Both integration tests passed; no prerequisite skip occurred. |
| Routine/MSRV verification | Local Rust 1.89 checks and hosted `rust` job in run 37584435943 | Pass. Formatting, all-target locked check, Clippy with warnings denied, and default tests passed. |
| Documentation and current scope | README, `architecture/overview.md`, `architecture/privilege-boundary.md`, `architecture/wireguard-control.md`, `docs/development.md` | Pass. Documents typed WireGuard control, the rootful test command, and the remaining M004/M005 boundary. |

## Verification actually run

Local Rust 1.89 commands exited successfully:

```text
cargo +1.89.0 fmt --all -- --check
cargo +1.89.0 check --all-targets --locked
cargo +1.89.0 clippy --all-targets --locked -- -D warnings
cargo +1.89.0 test --locked
cargo +1.89.0 test --locked --features linux-integration --test wireguard_kernel -- --nocapture
```

The local kernel integration command explicitly skipped the real namespace test because this development environment is unprivileged. It is not counted as kernel evidence.

Hosted CI run [37584435943](https://github.com/dbowm91/wg-basic/actions/runs/37584435943) completed successfully. Its rootful `wireguard-kernel` job ran the real fixture: `2 passed; 0 failed; 0 ignored` in 2.44 seconds. The ordinary Rust CI job also passed formatting, locked check, Clippy, and the default test suite.

Source guard:

```text
rg -n 'Command::new|std::process::Command|wg-quick|Command::new\("wg"\)|Command::new\("ip"\)' src
```

Result: no matches. The integration fixture invokes `ip` only through direct argv for temporary namespace, veth, address, and WireGuard-link setup. Production device and peer configuration goes through the typed backend.

## Protocol and backend details

- Backend: `nl-wireguard` 0.3.0, MIT, Generic Netlink; `x25519-dalek` 2.0.1, BSD-3-Clause; MSRV remains Rust 1.89.
- Protocol v1 adds `observe_wireguard_device` and `apply_wireguard_device`.
- Device and peer patch fields distinguish `keep`, `clear`, and `set`; each request contains no more than one peer mutation.
- AllowedIPs are limited to 256 per peer operation; duplicates and cross-peer overlapping prefixes are rejected.
- Single-peer update sends `ReplaceAllowedIps` only for that peer. Device-wide `ReplacePeers` is never sent.
- Observation returns public device identity, listen port, peers, AllowedIPs, endpoint, keepalive, latest handshake, and current RX/TX counters. It omits private and preshared keys.
- The fixture creates two disposable namespaces joined by a veth underlay, creates one WireGuard device in each, starts a namespace-local netd worker, configures peers through IPC, and pings across the tunnel.

## Limitations and unresolved findings

- M003 configures existing WireGuard links; M004 owns production link lifecycle, addresses, and routes. M005 owns firewall, forwarding, and NAT.
- `nl-wireguard` does not classify an absent link separately from a non-WireGuard link; both safely map to `not_found`. M004's RTNETLINK observation can provide link-kind detail.
- Netd serializes its own requests, but another process can race the backend's observe/patch sequence. Deployment must provide one writer per managed device; durable ownership/locking remains future work.
- Kernel-reported counters are point-in-time values and may reset after device recreation. No durable connected state or monotonic counter is synthesized.
- The crate consumes set configurations; wg-basic does not claim zeroization of every dependency/compiler temporary copy.
- No unresolved high- or medium-severity security/correctness finding remains in M003 scope.

## Readiness recommendation

M003 is strictly closed. Promote M004 to **ready** against implementation head `a134b39`. M004 must add typed RTNETLINK ownership while preserving this existing WireGuard backend and its no-device-wide-replacement semantics. M005 remains blocked until strict M004 closure.
