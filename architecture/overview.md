# Architecture overview

## Implemented foundation

The repository is a Rust 2021 package with one library and one executable. The library owns typed identifiers, Linux interface-name validation, IP prefix values, desired/observed state shells, client assignment validation, and secret wrappers. Private and preshared keys redact ordinary `Debug` and `Display` formatting and zeroize their owned strings when dropped. Key strings are validated as base64-encoded 32-byte WireGuard keys when constructed or deserialized.

The executable accepts `serve`, `netd`, and `doctor`. `netd` serves a bounded, versioned protocol over a local Unix-domain socket. It provides ping and read-only capability inspection plus typed WireGuard device observation and patch operations through the Linux Generic Netlink backend. `serve` makes a protocol request as the unprivileged management role; HTTP/API/UI are not implemented. `doctor` requests a read-only capability snapshot.

Linux-specific code has a `platform::linux` boundary. The library can still be built on other targets for domain use, but production network roles and the UDS protocol are Linux-only by design.

## Planned boundaries

The implemented network control currently covers existing WireGuard device and peer configuration/telemetry. M004 adds link/address/route reconciliation, and M005 adds firewall/forwarding. Those capabilities are not implemented in this repository state. See [the network-control roadmap](../plans/subsystems/network-control-roadmap.md).
