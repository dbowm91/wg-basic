# wg-basic

wg-basic is a Linux-native WireGuard appliance in active development, focused on straightforward client management without requiring a container runtime. The repository contains a typed local `netd` protocol and a Rust Generic Netlink backend for configuring and observing existing kernel WireGuard devices.

The executable has separate `serve` and `netd` roles. `serve` currently verifies local protocol connectivity, `netd` exposes authorized typed operations, and `doctor` displays a read-only capability snapshot. WireGuard device and peer configuration is implemented; link lifecycle, address/route reconciliation, firewalling, forwarding, persistence, and HTTP management are not implemented. This is not yet a one-command VPN appliance.

The real-kernel WireGuard integration test needs root, `CAP_NET_ADMIN`, the `ip` command, and kernel WireGuard support. Run it with `sudo -E cargo test --locked --features linux-integration --test wireguard_kernel -- --nocapture`; CI runs the same fixture on a rootful Linux runner.

See [architecture/overview.md](architecture/overview.md) for implemented boundaries and [plans/registry.md](plans/registry.md) for implementation status.
