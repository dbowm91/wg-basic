# IPv6 M004 — Dual-Stack E2E and Phase 11 Closure

Status: active

Repository baseline: `7bfa28f` (M003 implementation head; M003 strict closure
and hosted evidence are recorded in `plans/closure/ipv6-route-policy/003-status.md`).

Source roadmap:

- `plans/subsystems/ipv6-route-policy-roadmap.md#8-m004--dual-stack-e2e-and-phase-11-closure`
- `plans/002-long-term-roadmap.md#13-phase-11--ipv6-and-route-policy-production-qualification`

Canonical requirements and decisions:

- `plans/000-long-term-specification.md#9-host-networking-ownership`
- `plans/000-long-term-specification.md#11-reconciliation-model`
- `plans/adr/001-linux-native-control-plane.md`
- `plans/adr/007-ipv6-forwarding-ownership.md`
- M001 closure: `plans/closure/ipv6-route-policy/001-status.md`
- M002 closure: `plans/closure/ipv6-route-policy/002-status.md`
- M003 closure: `plans/closure/ipv6-route-policy/003-status.md`

Primary class: qualification / capability

Hard dependencies: strict closure of M001 dual-stack addressing, M002 IPv6
forwarding/firewall ownership, and M003 explicit authenticated client route
policy are satisfied.

## 1. Objective

Qualify the complete dual-family client path using real Linux WireGuard
interfaces in isolated network namespaces. Prove client handshake and IPv4/IPv6
traffic for explicit full-tunnel and split-tunnel route policies, including
disable/re-enable, process restart/reapply, and preservation of unrelated host
state. Reconfirm IPv4-only compatibility, database backup/restore, service
requirements, and current-behavior documentation, then strictly close Phase 11.

## 2. Explicit non-goals

- NAT66, arbitrary routing tables/rules, policy routing, multi-uplink selection,
  endpoint discovery, or DNS service operation.
- Adding generic netd operations, raw route/firewall text, arbitrary sysctl
  paths, host process execution, or host-network mutation outside disposable
  test namespaces.
- Public-release readiness, production signing, or publication claims.
- A schema migration unless a demonstrated M004 compatibility defect requires
  one and a bounded corrective plan records it.

## 3. Repository evidence at the baseline

- M001 implements durable dual-stack server/client tunnel addresses and typed
  WireGuard peer AllowedIPs.
- M002 implements explicit global IPv6 forwarding, installation-owned
  firewall source rules, routed IPv6 without NAT66, sticky forwarding, retry,
  and foreign firewall preservation.
- M003 implements bounded explicit per-family route policy, setup/create/update
  validation, IPv6 endpoint and DNS export, and embedded family controls.
- `network_control_e2e` already proves the server forwarding path in three
  namespaces; `product_management_rootful` proves dual-stack product setup,
  API, client lifecycle, and config export. No existing test yet proves that a
  client using exported full/split dual-family routes carries both families
  through the whole service/dataplane path across the requested lifecycle.
- Backup/restore and schema compatibility suites exist; current IPv4-only
  config output and prior-schema migration fixtures must remain unchanged.

## 4. Invariants

1. IPv4 and IPv6 routes are explicit client policy and are never inferred from
   address assignment.
2. Server peer AllowedIPs remain the assigned client host prefixes;
   client-export AllowedIPs remain only the selected client route policy.
3. IPv6 traffic uses routed egress and the M002-owned firewall path. No NAT66
   is introduced. Upstream return routes are explicit test-fixture state.
4. Disable, re-enable, restart, and retry preserve foreign links, addresses,
   routes, firewall tables, and unrelated forwarding controls.
5. M002 host-global IPv6 forwarding is only enabled to `1`; disable and teardown
   never reset it.
6. Existing IPv4-only installation, API, export, migration, and route behavior
   remain compatible.
7. Rootful tests mutate only their disposable namespaces and fixture resources.

## 5. Ordered work packages

### A. Build one end-to-end dual-family namespace fixture

- Extend the existing rootful product/network-control fixture where ownership
  boundaries permit; otherwise add one focused test in
  `tests/product_management_rootful.rs` using the established namespace and
  cleanup helpers.
- Exercise the authenticated product API to configure IPv4 and IPv6 tunnel
  ranges, create clients with IPv6 assignments, and select explicit route
  policies. Export and install the resulting typed configuration into the
  test client namespace using existing test-only helpers.
- Prove handshake, IPv4 tunnel traffic, IPv6 tunnel traffic, and return traffic
  through an explicit upstream IPv6 route. Keep all real kernel work rootful
  and hosted.

### B. Qualify full-tunnel and split-tunnel route behavior

- Cover IPv4 and IPv6 full-tunnel routes (`0.0.0.0/0`, `::/0`) and dual-family
  split prefixes. Verify route policy changes affect the exported/client
  AllowedIPs as intended while server peer AllowedIPs remain assigned host
  prefixes.
- Include negative destinations outside split prefixes and verify they do not
  traverse the tunnel; keep endpoint reachability available so full-tunnel
  routing does not mask test setup defects.
- Preserve the no-route/empty-policy contract and verify invalid policy does
  not commit or advance generation.

### C. Qualify lifecycle, recovery, and unrelated-state preservation

- Disable and re-enable the client, proving traffic stops and resumes after
  the existing enforcement receipt confirms each applied generation.
- Restart/reinitialize the management/network workers, force reapply, and prove
  the same assigned addresses, route policy, handshake, and traffic recover.
- Snapshot and compare unrelated host fixture state, including a foreign
  nftables table and an unrelated route/address. Confirm server policy disable
  and interface teardown preserve globally enabled IPv6 forwarding.

### D. Reconfirm persistence, migration, and IPv4-only behavior

- Use existing state backup/restore tests with full and split IPv6 route
  policies and verify restored export is byte-stable.
- Re-run the oldest supported schema/update migration and restore rehearsal;
  no IPv4 assignment, endpoint, DNS value, or route output may change.
- Keep a representative IPv4-only API/config test that asserts exact legacy
  `Address`, `DNS`, `Endpoint`, and `AllowedIPs` rendering.

### E. Review runtime qualification and current behavior docs

- Confirm the installed `netd` systemd capability allowlist still contains
  only required fixed paths and that IPv6 doctor/forwarding behavior is
  consistent with ADR-007.
- Run the release footprint suite and compare with the recorded design bounds;
  explain any material increase caused by the product UI controls.
- Update `architecture/testing-qualification.md`, relevant networking/product
  deep dives, `docs/development.md`, `docs/operations-runbook.md`, and
  `docs/client-enrollment.md` with precise qualification scope.
- Do not claim client-routed IPv6 behavior until the rootful fixture is green.

## 6. Failure, retry, restart, and compatibility contract

- Failed route-policy validation leaves desired state, product metadata, audit,
  and generation unchanged.
- An apply failure after durable commit is reported through the existing
  pending/degraded receipt; retry converges the same committed route policy.
- Restart reads the persisted state and restores the same selected routes,
  addresses, and peer host prefixes without inferring policy.
- Foreign state is preserved on success, failure, disable, and teardown; an
  ownership conflict fails closed.
- Backup/restore retains valid IPv6 route intent. Existing IPv4-only state and
  exported bytes remain compatible.

## 7. Security and product effects

The fixture adds test-only orchestration and runs in CI's disposable rootful
environment. Production protocol, privilege boundary, and runtime dependencies
should not change. Any implementation change to netd, service capabilities,
firewall ownership, or persistence beyond what M001–M003 already established
must stop for a bounded corrective plan and architecture review.

## 8. Focused tests and qualification evidence

- `cargo test --locked` covers domain validation, authenticated API rejection,
  config rendering, backup/restore, and IPv4 compatibility.
- Hosted rootful `product_management_rootful` covers full/split IPv4 and IPv6
  routes, client handshake/traffic, lifecycle, recovery, and foreign-state
  preservation.
- Hosted `network_control_e2e`, `durable_backup`, `durable_restart`,
  `maintenance_rootful`, `doctor_readonly`, and `system-install-systemd` suites
  remain green.
- Hosted `service_footprint` release run remains within its explicit bounds.
- Full repository CI passes; no rootful suite is run locally.

## 9. Acceptance criteria

1. A real client handshakes and carries IPv4 and IPv6 traffic through a managed
   server using exported route policy.
2. IPv4 and IPv6 full tunnel and dual-family split tunnel are explicitly
   selected and their positive and negative route behavior is proven.
3. Disable/re-enable and process restart/reapply stop and restore the same
   traffic and assigned addresses without route inference.
4. Foreign host state remains unchanged; no NAT66 or unowned host mutation is
   introduced; global IPv6 forwarding remains sticky.
5. Backup/restore and supported schema migration preserve IPv6 route policy
   and prior IPv4-only behavior and output.
6. Hosted rootful, systemd, footprint, Rust, and full CI evidence passes.
7. Current behavior docs accurately describe IPv6 routing limits and make no
   production-release claim.
8. M004 strict closure maps each criterion to exact evidence and has no
   unresolved high/medium finding.

## 10. Stop conditions and Phase 11 closure

Stop and revise planning if the full path requires NAT66, a generic privileged
operation, unbounded global host mutation, or loss of unrelated host state; if
the client endpoint becomes unreachable under full tunnel; or if existing
IPv4-only config/migration behavior changes. If new durable state is required,
record its migration and rollback contract before implementation.

When all criteria pass, create
`plans/closure/ipv6-route-policy/004-status.md`, mark M004 closed in this plan,
the subsystem roadmap, registry, and Phase 11 macro status, and record Phase 11
as technically closed. Production release signing remains an independent
external gate.
