# Architecture overview

## Implemented foundation

The repository is a Rust 2021 package with one library and one executable. The library owns typed identifiers, Linux interface-name validation, IP prefix values, desired/observed state shells, client assignment validation, and secret wrappers. Private and preshared keys redact ordinary `Debug` and `Display` formatting and zeroize their owned strings when dropped. Key strings are validated as base64-encoded 32-byte WireGuard keys when constructed or deserialized.

The executable accepts `serve`, `netd`, and `doctor`. The two service roles return an explicit not-implemented error; `doctor` is a read-only placeholder. No role opens sockets or changes host network state.

Linux-specific code has a `platform::linux` boundary. The library can still be built on other targets for domain use, but production network roles are Linux-only by design and have no implementation yet.

## Planned boundaries

The planned process topology separates an unprivileged management role from the privileged network role. Later plans define a typed local protocol, WireGuard control, link/address/route reconciliation, then firewall/forwarding. Those capabilities are not implemented in this repository state. See [the network-control roadmap](../plans/subsystems/network-control-roadmap.md).
