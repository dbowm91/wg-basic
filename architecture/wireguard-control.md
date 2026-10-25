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

`WireGuardBackend` operates on an existing named WireGuard device. It does not create/delete links, set link addresses, install routes, configure firewall policy, or call `wg`, `wg-quick`, or `ip`. Because the selected WireGuard-only API cannot report link kind, a missing device and a non-WireGuard device map to the same safe `not_found` category *at this layer*; the reconciliation engine above it resolves the distinction authoritatively from RTNETLINK and reports a same-name untagged link as a conflict.

The M002 protocol adds typed `observe_wireguard_device` and `apply_wireguard_device` operations. A request can update device private key/listen port and carry at most one peer mutation. `FieldUpdate` distinguishes `keep`, `clear`, and `set`. Peer operations are explicit `add`, `update`, and `remove`; add/update pre-observe the device and enforce existence expectations. An absent peer removal is an idempotent no-op.

Peer AllowedIPs are checked for duplicates, bounded to 256 per operation, and checked against other peers for prefix overlap. This initial policy rejects overlaps across peers. Update sends `ReplaceAllowedIps` for the selected peer only. It never sends device-wide `ReplacePeers`, so a one-peer change preserves other peers. Each request contains one bounded netlink operation; whole-device multi-message replacement is not used.

Netd serializes requests within one process. A separate external WireGuard controller can still race the pre-observe/patch sequence; production ownership must ensure one writer for wg-basic-managed devices. Durable installation ownership and cross-process reconciliation locking remain later work.

## Key and error handling

`x25519-dalek` 2.0.1 generates 32-byte WireGuard keypairs using its static-secret API. Private/preshared keys keep redacted `Debug` and `Display` forms and are validated when deserialized. The backend zeroizes private/preshared strings returned by kernel observation after converting the public observation result. The selected `nl-wireguard` crate also redacts key attributes in its kernel-error messages. Its set API consumes a configuration value; wg-basic cannot guarantee that every dependency or compiler temporary copy is zeroized, so no such guarantee is claimed.

The protocol returns stable categories only; it does not return raw netlink error payloads or request strings. Kernel permission failures, unsupported operations, and other kernel rejections map to distinct protocol categories. Invalid fields/keys map to `invalid_input`, missing interface/peer to `not_found`, and duplicate peer/AllowedIP ownership to `conflict`. The selected WireGuard-only API cannot by itself distinguish a missing interface from an existing non-WireGuard link. Authoritative link-kind and owner-tag observation is resolved one layer up, by the reconciliation engine reading RTNETLINK directly, so a same-name untagged link is reported as a conflict rather than as `not_found`.

Handshake time is the kernel-reported time since Unix epoch, represented as an optional duration. RX/TX are current kernel counters and may reset when a device is recreated; wg-basic does not synthesize monotonic totals. Preshared keys are never returned by observation.

## Ownership layering

The WireGuard backend owns device and peer configuration/telemetry. The reconciliation engine composes those typed patches with RTNETLINK link, address, and route operations; it does not absorb WireGuard state into an opaque network configuration call. See [reconciliation and ownership](reconciliation.md) for lifecycle ownership, route limits, ordering, and retry behavior. The aggregate coordinator above the reconciliation engine owns firewall, forwarding, and NAT as a second layer, and removes the owned firewall table before tearing an interface down so a blocked disable can never orphan a policy.

## Darwin userspace backend (C001)

macOS has no kernel WireGuard interface. A managed tunnel on Darwin is a
supervised `wireguard-go` helper that owns one kernel-assigned `utunN` device
and serves the WireGuard UAPI protocol on a Unix socket. The production
backend lives in `src/wireguard/darwin_backend.rs`; the reusable primitives
(supervisor, UAPI rendering and parsing, device delta, ownership verification)
live in `src/wireguard/darwin.rs`.

The helper identity is hash-pinned. `verify_helper_sha256` runs before every
spawn, the executable path is absolute and never a `PATH` lookup, the argv is
fixed to `[helper, "utun"]`, and the environment is cleared to a single
foreground marker. The helper digest comes from the verified install receipt,
so a replaced helper is refused rather than executed.

### The declared helper build input (C008)

The install receipt anchors the helper at **runtime**: it records the digest
of the bytes that were installed, and the product refuses a helper whose
bytes have changed. The chain from the upstream source to those bytes is
anchored at **build time**, by a declared input.

`helper/wireguard-go.provenance.json` is the single declaration of that
input: the upstream repository, the release tag, the immutable commit, the
SPDX license identifier and the license text marker to look for, the Go
toolchain version, the supported target triple, and the build flags.
Nothing else in the repository names the upstream source.

`scripts/build-wireguard-go-helper.py` is the only builder. It refuses to
produce a helper unless the clone resolves to the declared commit, the
checkout is clean, the license file carries the declared marker, and the Go
toolchain is the declared version. It writes the helper and a **provenance
receipt** recording the source URL, tag and commit, the license identifier
and license file digest, the Go version, the target triple, the build flags,
the binary's SHA-256, and the binary's own embedded build settings —
including the `vcs.revision` stamp, which carries the same commit.

With `-trimpath`, a fixed toolchain, and a clean checkout at a fixed
commit, the build is byte-reproducible: the same source and toolchain
produce the same digest for the same target. The macOS qualification
workflow builds the helper through that builder for the one supported
target and uploads the receipt as a run artifact, so a qualification run
can be tied to one specific helper build.

The device name is ephemeral, so netd records which `utunN` it owns and
re-proves it. Nothing is ever selected by numeric guess, and a foreign
`utunN` is never adopted.

### Darwin ownership receipt

Darwin has no kernel interface alias that can carry the durable owner tag, so
the durable claim is a **protected receipt**: an owner-only file in the
managed-runtime directory that binds the installation, the logical interface,
the kernel device, the helper pid, the helper executable and its digest, and
the UAPI socket path.

The receipt is a claim, never permission. `prove_ownership` re-observes the
helper process (`proc_pidpath`, so a reused pid is a different executable, not
the same one), the helper executable's digest, the UAPI socket's owner and
type, and the kernel device, and only a joint proof authorizes a mutation. A
receipt that cannot be re-proven is treated as absent, not as a foreign
device to destroy.

The executable the proof compares against the receipt is compared **as the
file it names**, not as the string it was spelled. The kernel reports the
canonical path of a running executable, while the receipt records the path the
helper was installed at, and on macOS `/tmp` is `/private/tmp` on every host:
`lsof` reports a helper started as `/tmp/wireguard-go` running as
`/private/tmp/wireguard-go`. Comparing the two spellings reported a live,
correct helper as a mismatch, so the claim read as stale, the receipt was
dropped, and the tunnel was recreated into the same verdict — an installation
whose helper lived under a symlinked directory could never hold a managed
tunnel. Both sides are now resolved to the files they name and compared as
those files; a path that cannot be resolved names nothing and therefore
matches nothing, so the proof still fails closed. The receipt's stored path is
unchanged, so a receipt written before this correction is proved correctly too.

A receipt that cannot be re-proven is also not a reason to refuse a create.
The tunnel is recreated over it and the stale receipt is dropped; a receipt
that *does* re-prove is a live tunnel, and a second tunnel over it is refused.
See [ownership](ownership.md) and
[startup recovery](startup-recovery.md).

### The device observation is fallible, and says so

Reading the host's `utun` inventory can fail, and a failed read is not an empty
host. `observe_utun_interfaces` returns the inventory or an error;
`utun_interface_names` is the best-effort wrapper for the callers that only
need a name list, and no caller that reasons about ownership uses it.

An unreadable inventory is carried as its own value, never as an absence:

- `DeviceObservation::Unreadable` is what `classify_device_observation`
  returns when the inventory could not be read.
- `OwnershipOutcome::InterfaceUnreadable` is what the ownership proof returns
  in that case. It is neither a proof nor a refutation, and it is never a
  licence to mutate.
- `OwnerClaim::Unreadable` is what the runtime registry returns for a receipt
  whose claim could not be read. It is **refused and retried**, and the receipt
  is **not** dropped: a claim that could not be read is neither live nor
  stale, and treating a failed read as a stale claim tore down tunnels whose
  devices were still there.

The helper's spawn is observed the same way. `spawn_managed_tunnel` returns a
`ManagedTunnel` carrying the helper, the device it chose, and
`devices_before_spawn` — the inventory it read **immediately before** the
helper started. The spawn's own evidence travels with its result, so a caller
can check the product's observation instead of taking a second one of its own
at a different moment. The device is identified by diffing the inventory
around the spawn, and a diff that finds **more than one** new device is
`HelperError::DeviceAmbiguous` (`managed_device_ambiguous`): the namespace was
contended, and the product refuses to identify its own device by number. A
failed observation is `HelperError::ObservationFailed`
(`interface_inventory_unreadable`).

### The helper is replaced when it dies

`netd` spawns the helper as a supervised foreground child, and it supervises
it: a helper that exits on its own takes the kernel device with it, so the
authority that spawned it replaces it rather than leaving the tunnel down
until an operator intervenes.

The replacement re-applies the desired interface that was applied for that
helper, which recreates the child, re-adopts exactly one new `utunN` device,
and restores the configuration, addresses, and routes that belonged to the
tunnel. The device may be renumbered by the kernel, and the receipt is
rewritten for the new one.

The replacement restores; it never decides. It uses the desired state that was
already applied, does not consult the durable store, and does not observe the
host for drift. The monitoring interval is fixed and slow, and it only does
work when a supervised child died.
