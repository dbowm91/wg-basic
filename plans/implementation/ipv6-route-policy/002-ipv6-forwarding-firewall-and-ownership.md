# IPv6 M002 — Forwarding, Firewall, and Host Ownership

Status: active

Repository planning baseline: `fa25918b824641e00944e3edf335f7055cb11dcc` (M001 strict closure)

Source roadmap:

- `plans/subsystems/ipv6-route-policy-roadmap.md#6-m002--ipv6-forwarding-firewall-and-ownership`
- `plans/002-long-term-roadmap.md#13-phase-11--ipv6-and-route-policy-production-qualification`

Canonical requirements and decisions:

- `plans/000-long-term-specification.md#9-host-networking-ownership`
- `plans/000-long-term-specification.md#11-reconciliation-model`
- `plans/adr/001-linux-native-control-plane.md`
- `plans/adr/002-durable-state-generations-and-ownership.md`
- `plans/adr/007-ipv6-forwarding-ownership.md`
- M001 closure: `plans/closure/ipv6-route-policy/001-status.md`

Primary class: invariant / capability

Hard dependencies:

- Phase 5 firewall/forwarding ownership contract.
- M001 strict closure.
- Accepted ADR-007.

## 1. Objective

Add typed IPv6 forwarding and stateful firewall policy for explicitly enabled
managed IPv6 tunnel prefixes. Use the fixed host-global IPv6 forwarding control
under ADR-007 and the installation-owned `inet wg_basic` table. Support routed
IPv6 prefixes with return traffic; do not add NAT66. Existing IPv4 behavior
must remain unchanged.

## 2. Explicit non-goals

- NAT66, address masquerade, prefix delegation, or upstream router mutation.
- Client `::/0` full tunnel, split-route controls, endpoint/DNS product fields,
  or UI redesign; those belong to M003.
- Arbitrary sysctl paths/values, route tables/rules, nftables source text,
  command execution, or raw netlink payloads.
- Resetting or restoring a captured prior forwarding value.
- Changing IPv4 forwarding, masquerade, firewall ownership, or defaults.

## 3. Repository evidence at the baseline

- M001 stores optional IPv6 server/client addresses, the IPv6 tunnel prefix,
  IPv6 peer host prefixes, and the managed server pool route. Native
  tunnel-local IPv6 traffic and restart/reconnect are qualified.
- `DesiredNetworkPolicy` and the persisted product policy represent IPv4
  forwarding, source prefixes, egress, and IPv4 masquerade only.
- `FirewallService` owns `inet wg_basic`, enables only `/proc/sys/net/ipv4/ip_forward`
  to `1`, and never disables it on teardown.
- The firewall planner and generated nft rules validate IPv4-only prefixes.
- The privileged boundary already has typed forwarding policy values and does
  not accept caller-authored nftables or sysctl instructions.

## 4. Invariants

1. SQLite desired state is authoritative; the IPv6 global-forwarding
   observation and owned firewall table are reconciled to that state.
2. IPv6 forwarding is explicit opt-in and independent from tunnel-address
   assignment. IPv4-only setup and policy serialization keep current behavior.
3. The only IPv6 sysctl write is the fixed
   `/proc/sys/net/ipv6/conf/all/forwarding`, with value `1`; no caller-supplied
   path or value crosses the privilege boundary.
4. Forwarding is monotonic under ADR-007: disable, teardown, and failed apply
   never write `0` or restore a stale value.
5. nft mutations stay within the installation-owned `inet wg_basic` table;
   foreign tables, chains, routes, addresses, and links are not rewritten.
   The only intentional foreign-scope kernel effect is the documented
   Host/Router behavior caused by the global forwarding control in ADR-007.
6. IPv6 routed traffic is filtered by explicit source prefix, managed tunnel
   ingress, configured egress, and established/related return traffic.
   Independent firewall managers can still deny it.
7. No NAT66 is generated. The operator must route the selected tunnel prefix
   upstream; the fixture proves both forward and return paths.
8. A sysctl success followed by firewall failure is reported as partial
   application. Retry converges the owned table; teardown removes only that
   table and leaves global forwarding enabled.

## 5. Ordered work packages

### A. Extend the durable typed policy

- Add an explicit IPv6-forwarding-required policy field with an IPv4-only
  default of false.
- Extend desired-state validation so opted-in IPv6 source prefixes must be
  valid unicast IPv6 prefixes covered by configured IPv6 tunnel state; retain
  current IPv4 validation and uniqueness rules.
- Add an ordered additive SQLite migration and update old-schema/backup/restore
  compatibility. Existing databases default to IPv6 forwarding disabled.
- Keep the protocol closed: represent this as a typed boolean/enum, with no
  path/value strings.

### B. Add the bounded IPv6 sysctl operation

- Observe `/proc/sys/net/ipv6/conf/all/forwarding` as a strict boolean.
- Write only `1` to that fixed path when desired IPv6 forwarding is required
  and observation says disabled.
- Distinguish unsupported, permission, malformed, and backend failures using
  existing firewall receipt semantics; never return raw file contents.
- Order it before the nft apply as specified by ADR-007. A later nft failure
  must truthfully report partial application. Do not add teardown writes.

### C. Extend the owned nft policy

- Render typed IPv6 source-prefix matches and stateful return rules in the
  existing `inet wg_basic` forward chain.
- Preserve existing IPv4 rules and masquerade behavior exactly.
- Do not render `ip6` NAT or masquerade rules.
- Keep ownership markers, desired hashes, inventory/drift checks, and atomic
  table replacement. Reject foreign ownership and preserve foreign tables.

### D. Expose explicit opt-in and truthful diagnostics

- Add optional setup/API policy input for IPv6 forwarding, default false.
- Persist and return desired policy state without inferring forwarding from an
  assigned IPv6 address.
- Extend plan/apply receipts and doctor diagnostics to distinguish not
  required, enabled, disabled, and unreadable forwarding state.
- Document the global Host/Router and Router Advertisement consequences,
  sticky setting on disable, upstream route requirement, and absence of NAT66.

### E. Qualify recovery and host-state ownership

- Add unit tests for policy family validation, deterministic nft projection,
  existing IPv4 equality, forwarding no-op/set/sticky disable, and partial
  sysctl-success/firewall-failure receipts.
- Add migration and backup/restore cases for existing schema plus IPv6 opt-in.
- Add an isolated rootful Linux namespace with a client, wg-basic server, and
  routed IPv6 egress peer. Prove handshake, IPv6 forward traffic, established
  return traffic, disabled policy, restart/reapply, and recovery after a
  firewall failure.
- Install a foreign nftables table and a later independent drop; prove the
  foreign table is unchanged and the independent drop still blocks traffic.
- Assert the expected global forwarding value remains `1` after policy
  disable and server teardown. Record before/after per-interface forwarding
  observations because the Linux global control changes Host/Router settings.
- Run the Rust gates and complete hosted CI; never run the rootful suite
  locally.

## 6. Failure, retry, and compatibility contract

- If forwarding observation is malformed or unavailable, do not claim
  convergence; return a bounded backend/unsupported error.
- If the fixed sysctl write is denied, no nft policy is applied and the apply
  result reports failure before firewall mutation.
- If the sysctl write succeeds but nft replacement fails, preserve the global
  `1`, report partial application, and converge the table on retry.
- If an owned-table conflict exists, refuse to mutate it; forwarding may
  already have been enabled as a separately reported monotonic effect.
- Disabling IPv6 policy removes only wg-basic's owned table. The global
  forwarding value remains at its observed value (and remains `1` if wg-basic
  enabled it).
- Migration adds no required value to old rows and preserves v1-v6 backup and
  restore semantics. IPv4 fields and serialized responses retain their
  current defaults.

## 7. Security, privilege, and host effects

The single new privileged write is the exact IPv6 global-forwarding boolean
selected by ADR-007. It has an intentional host-wide scope and is never
silently reset. nftables changes are installation-scoped; no arbitrary host
firewall or route mutation is added. Failure and doctor output must not expose
sysctl contents beyond the validated boolean or leak secrets.

## 8. Documentation

Update current behavior in `architecture/firewall.md`,
`architecture/privilege-boundary.md`, `architecture/diagnostics-maintenance.md`,
`architecture/testing-qualification.md`, `architecture/product-management.md`,
`docs/operations-runbook.md`, `docs/development.md`, and the compact README
summary if needed. State clearly that IPv6 forwarding changes a global kernel
control, remains enabled after wg-basic disables the policy, requires the
operator's upstream route, and does not use NAT66.

## 9. Acceptance criteria

1. Existing IPv4-only databases, API behavior, nft rules, and forwarding
   semantics are unchanged.
2. IPv6 forwarding is explicit, persisted, validated, and reconciled through
   the typed privilege boundary.
3. Global IPv6 forwarding is enabled only by the fixed `all/forwarding`
   control, only to `1`, and is never reset by disable or failure recovery.
4. Native routed IPv6 traffic and established return traffic pass through the
   managed policy; a later foreign drop can still block it.
5. No NAT66 is emitted and foreign nftables objects remain unchanged.
6. Migration/backup/restore, partial failure, retry, disable, restart, and
   doctor evidence pass on the final hosted head.
7. M002 has a closure record mapping each acceptance criterion to exact
   evidence; no unresolved high/medium finding remains.

## 10. Stop conditions and successor handoff

Stop and revise ADR-007 or this plan if the typed fixed-path operation cannot
be implemented without an arbitrary sysctl escape hatch; the kernel's global
side effects cannot be represented truthfully; the independent firewall
preservation test fails; IPv4 rules/defaults regress; or routed IPv6 return
traffic requires NAT66 or an ownership mutation outside the selected prefix
and egress. M003 remains blocked until M002 strictly closes. M004 remains
blocked until M003 strictly closes.
