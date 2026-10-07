# Architecture overview

## Implemented foundation

The repository is a Rust 2021 package with one library and one executable. The library owns typed identifiers, Linux interface-name validation, IP prefix values, desired/observed state shells, client assignment validation, and secret wrappers. It also owns the unprivileged durable application-state store: SQLite storage with hardened opening, ordered migrations, one stable installation identity, a monotonic desired generation with compare-and-swap mutation, and deterministic projection into kernel intent. Private and preshared keys redact ordinary `Debug` and `Display` formatting and zeroize their owned strings when dropped. Key strings are validated as base64-encoded 32-byte WireGuard keys when constructed or deserialized.

The executable accepts `serve`, `netd`, and `doctor`. `netd` serves a bounded, versioned protocol over a local Unix-domain socket. It provides ping and read-only capability inspection, typed WireGuard device observation/patch operations through Generic Netlink, and high-level managed-interface planning/application. Linux link, address, and route operations use RTNETLINK. `serve` makes a protocol request as the unprivileged management role; HTTP/API/UI are not implemented. `doctor` requests a read-only capability snapshot.

Linux-specific code has a `platform::linux` boundary. The library can still be built on other targets for domain use, but production network roles and the UDS protocol are Linux-only by design.

## Implemented boundaries

The state store is authoritative for desired state; kernel state is derivative and only ever observed. It is secret-bearing and must stay owner-only. Only the unprivileged management role opens it, and `netd` remains database-free. See [durable state store](state-store.md).

M004 manages explicitly declared WireGuard links, exact tunnel addresses, and a bounded main-table unicast route shape through deterministic desired/observed reconciliation. M005 adds typed IPv4 forwarding and optional masquerade policy in a dedicated `inet wg_basic` table, with ownership checks and an end-to-end namespace fixture. Durable interface ownership and one generation-aware aggregate reconcile are also implemented: created links carry an installation/interface owner tag, the owned nftables table binds to the installation identity, and a single outer coordinator serializes aggregate applies with in-process generation monotonicity. Automatic startup application of durable desired state is not implemented yet. These are the kernel network-control foundation plus the Phase 6 ownership contract only; durable application state, service/UI, installation, and product lifecycle are later work. See [reconciliation and ownership](reconciliation.md), [firewall ownership](firewall.md), and [the network-control roadmap](../plans/subsystems/network-control-roadmap.md).
