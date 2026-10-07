# wg-basic

wg-basic is a planned Linux-native WireGuard appliance focused on straightforward client management without requiring a container runtime. The repository currently contains the Rust domain/runtime foundation only; it does not create WireGuard interfaces or change host networking.

The executable exposes truthful placeholders for the future `serve` and `netd` roles. `doctor` currently reports that read-only checks are not implemented.

See [architecture/overview.md](architecture/overview.md) for implemented boundaries and [plans/registry.md](plans/registry.md) for implementation status.
