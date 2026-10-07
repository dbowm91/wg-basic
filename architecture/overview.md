# Architecture overview

## Implemented foundation

The repository is a Rust 2021 package with one library and one executable. The library owns typed identifiers, Linux interface-name validation, IP prefix values, desired/observed state shells, client assignment validation, and secret wrappers. Private and preshared keys redact ordinary `Debug` and `Display` formatting and zeroize their owned strings when dropped. Key strings are validated as base64-encoded 32-byte WireGuard keys when constructed or deserialized.

The executable accepts `serve`, `netd`, and `doctor`. `netd` serves a bounded, versioned protocol over a local Unix-domain socket. It provides ping and read-only capability inspection, typed WireGuard device observation/patch operations through Generic Netlink, and high-level managed-interface planning/application. Linux link, address, and route operations use RTNETLINK. `serve` makes a protocol request as the unprivileged management role; HTTP/API/UI are not implemented. `doctor` requests a read-only capability snapshot.

Linux-specific code has a `platform::linux` boundary. The library can still be built on other targets for domain use, but production network roles and the UDS protocol are Linux-only by design.

## Implemented boundaries

M004 manages explicitly declared WireGuard links, exact tunnel addresses, and a bounded main-table unicast route shape through deterministic desired/observed reconciliation. It re-observes and verifies after mutation, reports partial progress, and permits a fresh retry. See [reconciliation and ownership](reconciliation.md). Firewall, NAT, and host forwarding remain M005 work and are not implemented. See [the network-control roadmap](../plans/subsystems/network-control-roadmap.md).
