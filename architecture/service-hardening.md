# Service hardening contract

This is the Phase 10 service-manager contract established by Phase 9. The
product-owned systemd definitions encode these controls at the canonical paths.
Native systemd qualification validated runtime ownership, capabilities,
service properties, and state access on x86_64 and aarch64 Ubuntu 24.04 hosts.

| Directive | `serve` | `netd` | Reason / qualification |
|---|---|---|---|
| `User=` | Dedicated unprivileged service account | Dedicated network-control account | Separate ownership domains; netd receives only the intended network capability. |
| `CapabilityBoundingSet=` | Empty | `CAP_NET_ADMIN` | Serve has no privileged operation. Netd needs network administration for typed link, route, WireGuard and firewall operations. |
| `AmbientCapabilities=` | Empty | `CAP_NET_ADMIN` | No ambient privilege for serve; netd receives only its required capability. |
| `NoNewPrivileges=` | `yes` | `yes` | Neither service needs privilege gain through exec. |
| `ProtectSystem=` | `strict` | `strict` | Root filesystem read-only except explicit state/runtime paths. |
| `ProtectHome=` | `yes` | `yes` | Neither role uses operator home directories. |
| `PrivateTmp=` | `yes` | `yes` | Private temporary namespace. |
| `RestrictAddressFamilies=` | `AF_UNIX AF_INET AF_INET6` | `AF_UNIX AF_NETLINK` | Serve needs its HTTP listener and privileged UDS; netd uses UDS and rtnetlink. Add a family only with runtime evidence. |
| `ReadWritePaths=` | Explicit state directory and runtime/socket directory | Explicit runtime/socket directory and `/proc/sys/net/ipv4/ip_forward` | No broad writable filesystem paths. The state database belongs only to serve. |
| `LimitCORE=` | `0` | `0` | State, keys, and process memory must not enter core dumps. |
| `TasksMax=` | `64` | `32` | Conservative task ceilings above the measured single-worker service shape. |
| `MemoryMax=` | `256M` | `128M` | Headroom above idle RSS and the 19 MiB Argon2 working set used by serve. Re-measure under release load before tightening. |
| `Restart=` | `on-failure` | `on-failure` | Recover from process failure while respecting bounded rate below. |
| `RestartSec=` | `2s` | `2s` | Avoid a hot restart loop. |
| `StartLimitIntervalSec=` / `StartLimitBurst=` | `60s` / `5` | `60s` / `5` | Bound repeated startup failures for operator diagnosis. |

The shipped profile fragments are:

```ini
# serve
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/lib/wg-basic /run/wg-basic
LimitCORE=0
TasksMax=64
MemoryMax=256M
Restart=on-failure
RestartSec=2s
StartLimitIntervalSec=60s
StartLimitBurst=5
```

```ini
# netd
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
ReadWritePaths=/run/wg-basic /proc/sys/net/ipv4/ip_forward
LimitCORE=0
TasksMax=32
MemoryMax=128M
Restart=on-failure
RestartSec=2s
StartLimitIntervalSec=60s
StartLimitBurst=5
```

Netd directly writes `/proc/sys/net/ipv4/ip_forward` as part of the managed
forwarding policy. Therefore `ProtectKernelTunables=yes` is incompatible with
the current runtime contract and MUST NOT be claimed by the shipped netd unit.
Any later change to forwarding ownership needs an explicit implementation and
security review before changing this profile.

The ceilings are conservative limits, not measured maxima. The native M005
release-candidate lifecycle runs measured installed product bytes of 9,937,817
(x86_64) and 9,096,498 (aarch64), with idle serve/netd RSS of 9,192/6,556 KiB
and 8,068/5,560 KiB respectively. Fresh install elapsed 2,387 ms and 5,195 ms
on those runners. These are single-run engineering receipts, not performance
SLOs. Service-manager journald retention owns log storage and rotation;
the binary emits human or newline-delimited JSON events to stderr and owns no
log files.
