# IPv6 and Route-Policy Qualification Roadmap

Status: active; M001 ready after Phase 10 technical closure

Canonical references:

- `plans/000-long-term-specification.md`
- `plans/001-terminology-and-domain-model.md`
- `plans/002-long-term-roadmap.md#13-phase-11--ipv6-and-route-policy-production-qualification`
- `plans/003-planning-process.md`
- `plans/adr/001-linux-native-control-plane.md`
- `plans/closure/distribution/005-status.md`

## 1. Ownership and goal

This roadmap extends the existing IPv4 WireGuard appliance to production
dual-stack operation. It owns IPv6 tunnel addressing, client allocation,
WireGuard peer prefixes and client route policy, Linux forwarding/firewall
behavior, API/export/UI representation, and dual-stack qualification.

It does not add generic routing policy, host firewall administration, arbitrary
sysctl configuration, endpoint discovery, DNS service operation, or a new VPN
dataplane. Kernel WireGuard and the typed `netd` boundary remain authoritative.

## 2. Invariants

1. SQLite desired state remains authoritative; kernel IPv6 state is observed
   and reconciled through typed operations.
2. IPv4 behavior and existing exported configurations remain unchanged unless
   the operator explicitly selects an IPv6 policy.
3. Server-side peer `AllowedIPs` and client-side route policy remain separate.
4. Both address families use validated typed values; no caller-controlled
   shell, raw nftables text, netlink payload, or arbitrary sysctl path is added.
5. IPv6 forwarding enablement must account for the host-global or
   interface-scoped sysctl ownership semantics and preserve unrelated host
   configuration. No blind write-and-restore is allowed.
6. Firewall ownership remains installation-scoped and confined to
   `inet wg_basic`; IPv4 rules and foreign tables/rules are preserved.
7. IPv6 claims require native kernel/WireGuard traffic and namespace evidence.

## 3. Current repository baseline

At Phase 10 technical closure, core domain prefixes, peer AllowedIPs,
RTNETLINK addresses/routes, client route prefixes, DNS values, and endpoint
hosts are represented with family-capable types. Product allocation, setup,
client assigned-address validation, network-policy validation, firewall
forwarding/NAT, and operational sysctl handling are IPv4-only. Current live
product behavior must remain documented as IPv4-only until the Phase 11
qualification plans close.

## 4. Milestones and dependencies

```text
Phase 10 stable IPv4 lifecycle (closed)
  |
  v
M001 dual-stack product/domain persistence and tunnel reconciliation
  |
  v
M002 IPv6 forwarding, firewall ownership, and policy design
  |
  v
M003 client route policy, endpoint/DNS representation, and operator surface
  |
  v
M004 dual-stack end-to-end qualification and Phase 11 closure
```

All milestone dependencies are hard. M002 must not begin IPv6 forwarding
mutation until its host sysctl ownership decision is explicit and testable. If
that decision materially changes the privilege or host-ownership contract,
write and accept an ADR before implementation.

## 5. M001 — Dual-stack product/domain persistence and tunnel reconciliation

Primary class: capability / infrastructure.

Plan: `plans/implementation/ipv6-route-policy/001-dual-stack-domain-and-kernel-reconciliation.md`.

The first slice extends setup and managed-client address allocation to support
one IPv4 and one IPv6 tunnel address per client while preserving current IPv4
defaults and identifiers. It updates durable state additively, applies both
interface addresses and peer prefixes through existing typed backends, and
proves restart/reconcile behavior in a real namespace. It does not enable
forwarded IPv6 traffic or advertise IPv6 full-tunnel routes.

M001 closes when an IPv6 client address is allocated, durably stored, applied
to the WireGuard interface/peer, and recovered after service restart, while
the IPv4-only product path remains byte/behavior compatible.

## 6. M002 — IPv6 forwarding, firewall, and ownership

Primary class: invariant / capability.

M002 adds typed IPv6 forwarding and firewall policy only after a bounded
ownership strategy for the relevant kernel forwarding controls is selected.
It must qualify allow/established/return behavior, optional NAT66 decisions,
disable/reapply, foreign-state preservation, service capabilities, and
failure/retry behavior with real kernel traffic. NAT66 is not assumed: the
supported egress model and prefix routing must be explicitly justified before
selection.

## 7. M003 — Client route policy and product surface

Primary class: capability.

M003 adds explicit IPv6 full-tunnel (`::/0`) and dual-family split-tunnel
policy, endpoint and DNS representation where needed, authenticated API
validation, generated WireGuard configuration, embedded UI controls, and
documentation. Route policy must never be inferred from the assigned tunnel
address. Existing IPv4-only clients retain the same defaults and output.

## 8. M004 — Dual-stack E2E and Phase 11 closure

Primary class: qualification / capability.

M004 proves both address families with native Linux WireGuard namespaces:
client handshake, IPv4 and IPv6 tunnel traffic, enabled/disabled lifecycle,
full tunnel for both families, split tunnel for both families, restart/reapply,
and unrelated host-state preservation. It also verifies migration/backup/
restore compatibility, IPv4-only regression behavior, systemd/runtime
requirements, footprints, and current-behavior docs. No public-release claim
is implied.

## 9. Deferred work and stop conditions

Deferred: arbitrary policy routing, IPv6 endpoint discovery/DDNS, DHCP or DNS
service operation, NAT66 unless justified, multi-uplink route selection,
per-client firewall policy, and non-Linux support.

Stop and revise planning if IPv6 forwarding cannot be enabled without an
unbounded host-global mutation, ownership cannot distinguish wg-basic state
from foreign state, a migration drops existing IPv4 data, or a working IPv4
installation regresses. Do not add generic protocol/file/sysctl escape hatches
to complete the feature.

## 10. Status

| Milestone | Status | Plan | Closure | Blocker |
|---|---|---|---|---|
| M001 dual-stack product/domain persistence and tunnel reconciliation | active | `plans/implementation/ipv6-route-policy/001-dual-stack-domain-and-kernel-reconciliation.md` | — | — |
| M002 IPv6 forwarding/firewall/ownership | blocked | to be written after M001 | — | M001 closure and explicit forwarding ownership design |
| M003 client route policy/product surface | blocked | to be written after M002 | — | M002 closure |
| M004 dual-stack E2E/Phase 11 closure | blocked | to be written after M003 | — | M003 closure |
