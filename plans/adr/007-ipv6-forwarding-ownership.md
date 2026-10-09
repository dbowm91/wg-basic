# ADR-007 — Bounded host ownership for IPv6 forwarding

Status: accepted

Date: 2026-10-09

## 1. Context

Phase 11 M002 needs IPv6 packets to traverse the host between a managed
WireGuard interface and its explicitly configured egress. M001 closes only
tunnel addressing and local tunnel traffic. wg-basic already owns the
dedicated `inet wg_basic` firewall table and enables IPv4 forwarding by
writing the fixed `/proc/sys/net/ipv4/ip_forward` control to `1`. It never
resets that global value when the network is disabled.

Linux documents `/proc/sys/net/ipv6/conf/all/forwarding` as global IPv6
forwarding. Setting it also changes the per-interface Host/Router forwarding
setting for all interfaces. In addition, forwarding changes the functional
default for Router Advertisement acceptance. These effects make a
write-and-restore scheme unsafe: another service may begin relying on
forwarding while wg-basic is enabled, and restoring the old value would disable
that service. See the Linux kernel's [IP sysctl documentation](https://kernel.org/doc/html/latest/networking/ip-sysctl.html).

## 2. Decision

When durable desired policy explicitly requires IPv6 forwarding, netd may
read and set only the fixed IPv6 global forwarding control
`/proc/sys/net/ipv6/conf/all/forwarding`, and may only set it to `1`. The
protocol exposes this as a closed IPv6-forwarding policy value; callers cannot
choose a path or value.

If the control is already `1`, no sysctl mutation occurs. If it is `0`, netd
sets it to `1` before applying the owned firewall policy. If a later firewall
operation fails, the result reports partial application; forwarding remains
enabled and is reconciled on retry. Disable, interface removal, and service
shutdown remove only wg-basic's owned nftables table. They never set forwarding
to `0` and never restore a captured prior value.

This is the same monotonic host-global ownership contract already used by the
IPv4 path. The global scope and its Host/Router and Router Advertisement
effects are explicit operator-visible behavior. Doctor reports whether the
required control is enabled and directs an operator to host configuration
when observation or mutation is unavailable.

IPv6 firewall policy is confined to the existing installation-owned
`inet wg_basic` table. M002 supports routed IPv6 prefixes and stateful return
traffic; it does not add NAT66. The operator must arrange upstream routing for
the selected tunnel prefix. The independent host firewall remains able to
drop forwarded traffic.

## 3. Alternatives

### A. Set per-interface forwarding only on the WireGuard link

The kernel's per-interface forwarding control applies to packets received on
that interface. It does not by itself enable the return direction when
responses arrive on the egress interface. Enabling forwarding on each
selected foreign egress interface adds another shared host mutation and does
not improve the ownership boundary. Rejected.

### B. Require the operator to pre-enable IPv6 forwarding and never write it

This avoids sysctl mutation, but makes a product policy appear enabled while
the configured service cannot forward traffic, and diverges from the
established IPv4 policy contract. A plan-only diagnostic remains available;
it is not the selected product behavior. Rejected.

### C. Snapshot and restore the prior global value on disable

The value is shared by every host network service and may acquire new
consumers while wg-basic runs. Restoring a stale snapshot can break those
consumers. Rejected.

### D. Set global forwarding to one and never reset it

This matches the established IPv4 contract, uses one fixed typed control,
provides symmetric forwarding without editing foreign interfaces individually,
and cannot disable a concurrent consumer during teardown. Selected.

## 4. Consequences

- Enabling IPv6 forwarding can change host-wide IPv6 router behavior and the
  functional Router Advertisement defaults. This effect must be disclosed in
  current operator documentation and surfaced by diagnostics.
- Turning off wg-basic's IPv6 policy does not turn off host IPv6 forwarding.
  The administrator owns any later decision to disable the global control.
- A failure after sysctl enable but before firewall convergence is truthful
  partial application; retry repairs the firewall, while teardown leaves the
  shared forwarding setting enabled.
- The privileged protocol remains typed and closed. It gains no arbitrary
  sysctl path/value, command, netlink message, or nftables source field.
- NAT66, prefix delegation, and upstream router changes remain out of scope.
  M002 must demonstrate routed-prefix traffic and return traffic in namespaces
  and must prove foreign nftables tables are unchanged.
- No database rollback or protocol compatibility break is accepted. Any new
  desired policy field is additive and defaults to the current IPv4-only
  behavior for existing state and clients.

## 5. Validation obligations

M002 must prove with a real kernel that enabling the fixed control changes
global IPv6 forwarding to `1`, permits the typed `inet wg_basic` policy to
carry routed tunnel traffic, and leaves unrelated nftables objects untouched.
It must also exercise firewall failure after sysctl enable, retry, disable,
restart/reapply, and the sticky forwarding value. The namespace test must
include an independent later firewall drop to show that wg-basic's accept
verdict cannot override another manager.
