# wg-basic

wg-basic is a Linux-native WireGuard appliance in active development, focused on straightforward client management without requiring a container runtime. The repository contains a typed local `netd` protocol and Linux backends for kernel WireGuard, link/address/route reconciliation, and bounded IPv4 firewall/forwarding/NAT policy.

The executable has separate `serve` and `netd` roles. `serve` currently verifies local protocol connectivity, `netd` exposes authorized typed operations, `reconcile` applies the durable desired generation through authorized `netd`, `health` reports convergence without contacting it, and `doctor` displays a read-only capability snapshot. The kernel network-control foundation is implemented and qualified in Linux namespaces, and a hardened SQLite store persists authoritative desired state with a monotonic desired generation. Startup reconciliation is implemented and qualified at the process level: a restart re-derives kernel state from the database, repairs drift in owned resources, and fails closed when an ownership marker is lost or changed. Installation and HTTP management are not implemented. This is not yet a one-command VPN appliance.

The state database contains WireGuard private and preshared keys. It is secret-bearing and is created owner-only. See [architecture/state-store.md](architecture/state-store.md) and [architecture/startup-recovery.md](architecture/startup-recovery.md).

The real-kernel integration tests need root, `CAP_NET_ADMIN`, kernel WireGuard support, `iproute2`, and `iputils-ping`; the network-control, durable-ownership, and durable-restart tests also need nftables. Run the end-to-end fixture with `sudo -E cargo test --locked --features linux-integration --test network_control_e2e -- --nocapture`, and the restart-recovery fixture with `sudo -E cargo test --locked --features linux-integration --test durable_restart -- --test-threads=1`. CI runs the namespace fixtures on rootful Linux runners.

See [architecture/overview.md](architecture/overview.md) for implemented boundaries and [plans/registry.md](plans/registry.md) for implementation status.
