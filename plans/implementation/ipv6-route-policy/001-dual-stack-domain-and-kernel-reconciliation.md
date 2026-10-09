# IPv6 M001 — Dual-Stack Product/Domain Persistence and Tunnel Reconciliation

Status: active

Repository planning baseline: `c7de919c0b9d8f3326c50c799779ee5dc3734dca` (Phase 10 technical closure)

Source roadmap:

- `plans/subsystems/ipv6-route-policy-roadmap.md#5-m001--dual-stack-productdomain-persistence-and-tunnel-reconciliation`
- `plans/002-long-term-roadmap.md#13-phase-11--ipv6-and-route-policy-production-qualification`

Canonical requirements:

- `plans/000-long-term-specification.md#2-primary-product-goals`
- `plans/000-long-term-specification.md#9-host-networking-ownership`
- `plans/000-long-term-specification.md#11-reconciliation-model`
- `plans/001-terminology-and-domain-model.md#9-managed-client`
- `plans/001-terminology-and-domain-model.md#10-server-side-allowedips`
- `plans/001-terminology-and-domain-model.md#11-client-route-policy`
- `plans/001-terminology-and-domain-model.md#12-tunnel-address`
- `plans/adr/001-linux-native-control-plane.md`

Primary class: capability / infrastructure

Hard dependency:

- Phase 10 technical closure at `plans/closure/distribution/005-status.md`.

## 1. Objective

Add IPv6 tunnel address assignment as a compatible extension of the existing
IPv4 product path. A managed client can own an IPv4 and IPv6 tunnel address;
the server's IPv6 address and each peer's IPv6 host prefix are stored as
desired state and applied through the current typed WireGuard/RTNETLINK
backends.

This milestone is the address/persistence/kernel foundation only. It does not
enable forwarded IPv6 traffic, NAT66, or advertise `::/0` to clients. Those
require M002/M003 contracts and evidence.

## 2. Current repository evidence

- `NetworkPrefix`, `DesiredAddress`, `ManagedRoute`, peer `allowed_ips`,
  client route prefixes, endpoint, and DNS values already use family-capable
  types.
- RTNETLINK address and route backends and WireGuard peer encoding accept
  IPv6 values.
- `src/product/allocator.rs`, product setup/client operations, and state
  validation reject IPv6 assignment today.
- Durable client state currently has one `assigned_address`; interface tunnel
  prefixes and policy-prefix tables are stored as strings.
- Current firewall policy and forwarding control are IPv4-only.

Do not describe IPv6 production support as available until this and successor
milestones close.

## 3. Non-goals

- IPv6 host forwarding, nftables forwarding, NAT66, or host sysctl changes.
- Client `::/0` full tunnel or a new split-route UI; existing client route
  behavior remains unchanged.
- DNS service operation, endpoint discovery, arbitrary routing tables/rules,
  or changes to the privilege protocol's authority class.
- Rewriting current IPv4 allocation or changing existing installation,
  server, peer, or client identities.

## 4. Invariants and compatibility

1. Existing IPv4 setup, allocation order, JSON fields, exported configuration,
   database identity, and generated peer keys remain unchanged for IPv4-only
   operators.
2. IPv6 allocation is deterministic, bounded, and rejects reserved/server/
   assigned addresses, multicast, unspecified, and invalid pool shapes.
3. Each client has at most one address per family in this milestone. A client
   address must be inside the corresponding tunnel prefix and covered by the
   same peer's server-side host `AllowedIPs`.
4. Durable state migration is additive and transactional. Existing v1-v5
   databases and backups remain readable and recoverable.
5. All kernel changes use the current typed netd protocol and reconciliation
   ownership. No arbitrary netlink or command surface is introduced.
6. IPv4-only restore/migration and rootful behavior remain unchanged.

## 5. Ordered work packages

### A. Freeze the family-specific product contract

- Decide the IPv6 address reservation policy for the supported tunnel prefix
  size and document any excluded host values.
- Define JSON serialization for a client's family-address map/list. Keep
  existing `assigned_address` output for compatibility; add the IPv6 value
  only when configured.
- Ensure M001 does not silently imply that Internet IPv6 forwarding works.

### B. Add deterministic IPv6 allocation

- Add a family-specific IPv6 allocator with a bounded gap-search strategy that
  does not enumerate a `/64`.
- Reserve the server address, every enabled/disabled client address, network
  policy reservations, and any explicitly reserved operator address.
- Provide automatic and exact-request allocation, stable conflict errors, and
  deterministic lowest-available behavior.
- Retain the current IPv4 allocator and its output order unchanged.

### C. Extend durable state additively

- Add a new ordered SQLite migration for optional client IPv6 assignment and
  any required server IPv6 tunnel address data.
- Preserve IPv4 values, client identity, generations, audit semantics, backup
  and restore validation.
- Update snapshot projection, writes, generation-safe product operations,
  schema compatibility identity, and fixture coverage.
- Test migration rollback and backup/restore across v5→v6 without a production
  compatibility bypass.

### D. Reconcile IPv6 interface and peer state

- Project configured IPv6 tunnel addresses to exact managed interface
  addresses and IPv6 host prefixes to the correct server peer.
- Verify the existing typed backend encodes/observes IPv6 correctly; change
  it only where concrete evidence shows a defect.
- Preserve exact resource ownership, post-apply observation, retry, and
  unrelated addresses/routes/peers.
- Avoid changing forwarding or firewall behavior in this milestone.

### E. Integrate setup and client lifecycle

- Allow authenticated server setup to configure an IPv6 tunnel prefix/address
  as an explicit optional field.
- Allocate/store IPv6 client addresses on create and maintain them safely on
  disable, enable, edit, and delete.
- Return family-aware details from API reads without exposing private keys or
  changing the existing IPv4 response field.
- Keep IPv4-only defaults and UI behavior identical.

### F. Namespace and compatibility evidence

- Add an ignored rootful test using real kernel WireGuard and RTNETLINK in
  isolated namespaces.
- Prove IPv6 interface address, client peer host prefix, handshake, tunnel
  traffic, restart/reconcile, and exact removal of managed IPv6 state.
- Re-run existing IPv4-only product/kernel suites on the same CI matrix.
- Demonstrate existing v5 state opens without operator intervention and
  backup/restore preserves the new optional address.

## 6. Security and failure semantics

- IPv6 values are untrusted API input and must be canonicalized/validated
  before a state transaction or privileged request.
- Allocation and state updates occur in one generation-checked transaction;
  concurrent client creation cannot receive duplicate IPv6 addresses.
- A failed kernel apply leaves durable desired state with an explicit
  pending/degraded receipt; retry converges without deleting foreign state.
- Migration failure leaves the prior database schema and bytes recoverable
  through the existing migration snapshot contract.
- The network daemon remains database-free and receives only typed addresses
  and prefixes.

## 7. Focused verification

- Unit tests for IPv6 prefix boundary cases, deterministic allocation,
  reservation, conflict, and huge-pool bounded work.
- Product tests for optional IPv6 address setup/create/disable/enable/delete
  and IPv4-only serialization compatibility.
- Migration tests for clean v5 migration, populated v5 migration, rollback,
  backup, and restore.
- Rootful namespace test with actual IPv6 WireGuard traffic; compile-only or
  mocked backend results are insufficient.
- Full gates per `docs/development.md` and `.skills/wg-basic-gates/SKILL.md`.
  Rootful suites must run only on isolated hosted systemd/kernel runners.

## 8. Documentation

Update current behavior docs only for the M001 capability actually delivered:

- `architecture/domain-model.md`
- `architecture/state-store.md`
- `architecture/reconciliation.md`
- `architecture/product-management.md`
- `architecture/testing-qualification.md`
- `docs/development.md`

Keep IPv6 forwarding, full tunnel, and split-tunnel claims in plans until their
own milestones close. Keep README as a summary.

## 9. Acceptance criteria

1. A configured IPv6 tunnel prefix allocates one deterministic server address
   and one distinct IPv6 address per managed client.
2. IPv6 client addresses and matching peer host prefixes survive restart and
   migration; the kernel has the expected state after real reconcile.
3. IPv6 client tunnel traffic succeeds in an isolated native kernel fixture.
4. Disable/delete remove only the IPv6 state owned by the test installation;
   unrelated resources remain unchanged.
5. Existing IPv4-only APIs, allocation, exported configs, migrations,
   full CI, MSRV, and rootful suites remain green.
6. No host IPv6 forwarding/sysctl or nft mutation is introduced.
7. Closure record maps every acceptance criterion to observed evidence.

## 10. Stop conditions

Stop and revise the plan before expanding scope if:

- IPv6 host forwarding is required to establish even tunnel-local traffic;
- current peer/address backends cannot represent the intended values without
  an untyped escape hatch;
- preserving IPv4 output would require a breaking public/storage change;
- allocator correctness cannot be bounded for large prefixes;
- migrations cannot preserve existing state or backup compatibility.

## 11. Closure evidence

Record implementation/final heads, migration and serialization behavior,
native namespace/kernel traffic receipts, before/after IPv4 regression matrix,
exact hosted CI links, backup/restore and restart evidence, security findings,
documentation, unresolved limitations, and M002 readiness. M002 stays blocked
until M001 is strictly closed.
