# Privilege boundary

## Current protocol behavior

`wg-basic netd` binds only a Unix-domain stream socket. It serves one connection at a time, with at most 16 queued connections, one bounded request per connection, and a two-second read/write timeout. It authenticates the kernel-reported peer UID with `SO_PEERCRED`, and supports `ping`, `inspect_capabilities`, `observe_wireguard_device`, and `apply_wireguard_device`. The protocol uses JSON in a four-byte big-endian length frame capped at 64 KiB. Major protocol version and request ID are checked; malformed input is closed without reflecting request bytes.

The socket parent must already exist, be a real directory owned by the effective netd UID, and not be group/world writable. The socket is created with mode `0660`. Existing regular files, symlinks, active sockets, and sockets owned by another UID are preserved and treated as conflicts. A stale socket owned by netd may be removed after a failed connect and inode/owner recheck. Shutdown removes the socket only if its device/inode/owner still match the socket netd created.

By default netd authorizes its own effective UID and root. `--allow-uid UID` adds an explicit management-service UID. The protocol carries no UID/PID authorization fields. The `serve` command is currently a one-shot local protocol client; it does not host HTTP. `doctor` asks netd for the capability snapshot. A dedicated systemd management user should be supplied to netd with `--allow-uid` and granted access to the socket's group as needed.

The snapshot reports Linux, architecture, effective UID/GID, whether `CAP_NET_ADMIN` appears in `/proc/self/status`, kernel release, and runtime-directory safety. Namespace, WireGuard, and nftables capability fields remain `unknown` until their owning backends provide authoritative probes. Capability inspection does not create links/namespaces, load modules, change sysctls, or install firewall objects. WireGuard and link/address/route operations use typed Rust netlink backends. Firewall policy uses a typed protocol operation and a bounded direct `nft` subprocess; it does not invoke a shell or accept raw nft source. Forwarding writes are fixed to `/proc/sys/net/ipv4/ip_forward`.

## Intended service privilege contract

When installed, use separate service identities where practical:

- management role: no `CAP_NET_ADMIN`; access only to its state/config and the netd socket;
- network role: the only role granted `CAP_NET_ADMIN`, plus access to the runtime socket and narrowly required configuration;
- no shell is needed for either role.

No service unit is shipped yet; package installation and service lifecycle belong to later distribution work. The protocol exposes typed network operations alongside the original peer-authorized, bounded-framed read-only operations. Two further operations carry one installation's network intent at one desired generation: `PlanInstallationNetworkIntent` and `ApplyInstallationNetworkIntent`. They revalidate owner identity and generation before any privileged work and cannot carry raw nft source, sysctl paths, or key material beyond the typed configuration the interface intent already contains. Arbitrary command, path-based sysctl, nftables-source, file-write, and raw-netlink operations are not part of the protocol.

The Linux network service supports typed WireGuard configuration, managed interface/address/route reconciliation, and IPv4 firewall/forwarding policy. The firewall service owns only `inet wg_basic`; it never flushes unrelated tables. Disabling that policy removes the owned table but deliberately leaves `net.ipv4.ip_forward` enabled. The supported policy and external-firewall interaction are documented in [firewall ownership](firewall.md). Persistence and HTTP are not implemented.
