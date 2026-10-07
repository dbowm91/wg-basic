# wg-basic

wg-basic is a Linux-native WireGuard appliance in active development, focused on straightforward client management without requiring a container runtime. The repository contains a typed local `netd` protocol and Linux backends for kernel WireGuard, link/address/route reconciliation, and bounded IPv4 firewall/forwarding/NAT policy.

The executable has separate `serve` and `netd` roles. `serve` currently verifies local protocol connectivity, `netd` exposes authorized typed operations, and `doctor` displays a read-only capability snapshot. The kernel network-control foundation is implemented and qualified in Linux namespaces; durable application state, installation, persistence, and HTTP management are not implemented. This is not yet a one-command VPN appliance.

The real-kernel integration tests need root, `CAP_NET_ADMIN`, kernel WireGuard support, `iproute2`, and `iputils-ping`; the network-control test also needs nftables. Run the end-to-end fixture with `sudo -E cargo test --locked --features linux-integration --test network_control_e2e -- --nocapture`. CI runs the namespace fixtures on rootful Linux runners.

See [architecture/overview.md](architecture/overview.md) for implemented boundaries and [plans/registry.md](plans/registry.md) for implementation status.
