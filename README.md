# wg-basic

wg-basic is a Linux-native WireGuard appliance in active development, focused on straightforward client management without requiring a container runtime. The repository contains the Rust domain/runtime foundation and a local read-only `netd` protocol; it does not configure WireGuard or change host networking.

The executable has separate `serve` and `netd` roles. `serve` currently verifies local protocol connectivity, `netd` reports read-only host capabilities, and `doctor` displays that snapshot. HTTP management, persistence, WireGuard control, routes, firewalling, and forwarding are not implemented.

See [architecture/overview.md](architecture/overview.md) for implemented boundaries and [plans/registry.md](plans/registry.md) for implementation status.
