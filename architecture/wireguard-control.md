# WireGuard kernel control

## Backend selection

M003 selects [`nl-wireguard`](https://crates.io/crates/nl-wireguard) 0.3.0, an MIT-licensed Generic Netlink WireGuard client from the rust-netlink project. It reads a named device, sets one typed device/peer patch, removes a peer without replacing other peers, and exposes endpoint, latest handshake, RX/TX, keepalive, and AllowedIPs. Its API has explicit `ReplaceAllowedIps` and `ReplacePeers` flags; wg-basic uses only the former for an individual peer and never sends `ReplacePeers`.

| Candidate | Current evidence | Decision |
|---|---|---|
| DefGuard `defguard_wireguard_rs` | High-level API and active project; current 0.12.2 requires Rust 1.91, above wg-basic's Rust 1.89 MSRV. Earlier 0.10.0 meets MSRV but its API also includes interface creation, address, route, and DNS helpers that M003 must keep outside this backend. | Rejected: current version raises MSRV; older version broadens the control surface and adds cross-platform/userspace dependencies. |
| `wireguard-control` | Latest 2.0.0 identifies as high-level control but is LGPL-2.1-or-later and declares no Rust version. | Rejected for the initial dependency set because its license and MSRV fit are less straightforward than the MIT native Generic Netlink option. |
| `nl-wireguard` | 0.3.0; MIT; Rust-netlink Generic Netlink implementation. It provides device get/set, per-peer remove, explicit peer AllowedIPs replacement, and live peer telemetry. Manifest does not declare an MSRV; actual Rust 1.89 locked check passes. | Selected: narrow Linux kernel-control API that preserves unrelated peers by default and leaves link/address/route lifecycle to M004. |
| `netlink-packet-wireguard` plus generic-netlink transport | MIT packet types, but requires wg-basic to own transaction, dump, multipart, and error handling that `nl-wireguard` already provides. | Not selected; lower-level composition adds code without a demonstrated correctness benefit. |
| `nlink` | Modern consolidated Linux netlink API, but current 0.29.0 requires Rust 1.98. | Rejected: exceeds the established MSRV. |

References: [nl-wireguard API](https://docs.rs/nl-wireguard/latest/nl_wireguard/), [DefGuard crate metadata](https://crates.io/crates/defguard_wireguard_rs), [`wireguard-control` crate metadata](https://crates.io/crates/wireguard-control), [netlink-packet-wireguard](https://docs.rs/netlink-packet-wireguard/latest/netlink_packet_wireguard/), and [nlink crate metadata](https://crates.io/crates/nlink).

## M003 contract

`WireGuardBackend` operates on an existing named WireGuard device. It does not create/delete links, set link addresses, install routes, configure firewall policy, or call `wg`, `wg-quick`, or `ip`. A missing device and a non-WireGuard device currently map to the same safe `not_found` protocol category because the selected WireGuard-only API does not provide the RTNETLINK link-kind observation M004 will own.

The M002 protocol adds typed `observe_wireguard_device` and `apply_wireguard_device` operations. A request can update device private key/listen port and carry at most one peer mutation. `FieldUpdate` distinguishes `keep`, `clear`, and `set`. Peer operations are explicit `add`, `update`, and `remove`; add/update pre-observe the device and enforce existence expectations. An absent peer removal is an idempotent no-op.

Peer AllowedIPs are checked for duplicates, bounded to 256 per operation, and checked against other peers for prefix overlap. This initial policy rejects overlaps across peers. Update sends `ReplaceAllowedIps` for the selected peer only. It never sends device-wide `ReplacePeers`, so a one-peer change preserves other peers. Each request contains one bounded netlink operation; whole-device multi-message replacement is not used.

Netd serializes requests within one process. A separate external WireGuard controller can still race the pre-observe/patch sequence; production ownership must ensure one writer for wg-basic-managed devices. Durable installation ownership and cross-process reconciliation locking remain later work.

## Key and error handling

`x25519-dalek` 2.0.1 generates 32-byte WireGuard keypairs using its static-secret API. Private/preshared keys keep redacted `Debug` and `Display` forms and are validated when deserialized. The backend zeroizes private/preshared strings returned by kernel observation after converting the public observation result. The selected `nl-wireguard` crate also redacts key attributes in its kernel-error messages. Its set API consumes a configuration value; wg-basic cannot guarantee that every dependency or compiler temporary copy is zeroized, so no such guarantee is claimed.

The protocol returns stable categories only; it does not return raw netlink error payloads or request strings. Kernel permission failures, unsupported operations, and other kernel rejections map to distinct protocol categories. Invalid fields/keys map to `invalid_input`, missing interface/peer to `not_found`, and duplicate peer/AllowedIP ownership to `conflict`. The selected WireGuard-only API cannot distinguish a missing interface from an existing non-WireGuard link; both map to `not_found` until M004 adds authoritative link-kind observation.

Handshake time is the kernel-reported time since Unix epoch, represented as an optional duration. RX/TX are current kernel counters and may reset when a device is recreated; wg-basic does not synthesize monotonic totals. Preshared keys are never returned by observation.

## Remaining network boundaries

The kernel backend has no rootless network-namespace evidence. M003 closure requires the rootful `wireguard_kernel` integration target to configure two real kernel WireGuard devices, complete a handshake, observe endpoint/handshake/counter changes, and prove an unrelated peer survives a single-peer update. M004 owns link, address, and route mutation; M005 owns firewall, forwarding, and NAT.
