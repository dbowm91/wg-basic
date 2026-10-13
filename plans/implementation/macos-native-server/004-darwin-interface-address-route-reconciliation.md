# macOS Native Server M004 — Darwin Interface, Address, Route, and Reconciliation Ownership

Status: planned; blocked on M003 real WireGuard/utun closure
Primary class: invariant / capability
Roadmap: plans/subsystems/macos-native-server-roadmap.md M004
Baseline: main 47c72b0e81d569d48396c615120453bf0cf1d46e; reconcile with actual implementation head.
Authority: plans/000-long-term-specification.md; plans/002-long-term-roadmap.md; plans/003-planning-process.md; plans/adr/008-macos-headless-platform-backends.md; existing Linux ADRs remain in force.

## Objective

Port the deterministic observe→plan→apply→reobserve engine to Darwin IP addresses and routes around a dynamically assigned, installation-owned utun, preserving host network state across topology changes and restarts.

## Non-goals

No PF, NAT, forwarding, arbitrary policy routing, global default route takeover, or adoption of manually created utun interfaces. Do not replace Linux rtnetlink implementation.

## Current repository evidence

src/reconcile/linux.rs owns RTNETLINK link/address/route observation/mutation; src/reconcile/model.rs models ifindex and IFLA_IFALIAS; src/reconcile/planner.rs expects CreateWireGuardLink, SetLinkUp, DeleteLink, route mutation semantics. src/aggregate.rs orders interface before firewall and handles teardown.

## Mandatory invariants

- OS-assigned utun number is ephemeral, logical interface identity and installed owner remain stable.
- No deletion of routes/addresses solely because they match prefix+device; assert exact installation resource identity/route attributes or record conflict.
- Preserve all unowned routes, addresses, physical interfaces and upstream default routes.
- Failed apply never marks a newer generation converged; retries use fresh observation and serialization.
- IPv6 link-local, scoped interface and destination families handled intentionally.

## Ordered implementation work

1. Research supported Darwin routing socket/sysctl/ioctl APIs; evaluate safe bindings and OS version compatibility. Favor typed socket/native operations, with any unsafe isolated and audited rather than removing crate-wide lint protection.
2. Define platform-neutral OS interface locator and Darwin-owned address/route observation, separate from Linux alias; support family, gateway, flags, ifscope, and route identity needed for safe reconciliation.
3. Implement action mapping for bound utun; do not create or delete utun independent of the proven helper ownership; ensure required source addresses set before route installation and route deletion precedes teardown.
4. Add deterministic planner cases for duplicate prefixes, conflicting routes, interface re-numbering, and outbound adapter changes. Distinguish unsupported policy combinations.
5. Qualify native Darwin route and IPv4/IPv6 tunnel packet paths through real managed interface; verify retry/rollback after injected privilege errors and crash.

## Security, persistence, protocol, failures and compatibility

netd alone changes routes/addresses; protocol accepts typed bounded address/prefix/egress identifiers already validated. Mutating foreign routes or host default routes is prohibited. Kernel observations may lack perfect attribution, so uncertain deletion must refuse. Do not derive authority from a mutable PID file or interface name. No DB access to netd.

## Native and regression tests

Real macOS address/route add/observe/no-op/remove on owned utun with IPv4 and IPv6; compare before/after full route inventories for foreign preservation. Kill helper/netd between operations, renumber utun with unrelated VPN present, change Wi-Fi→Ethernet, sleep/wake. Confirm explicit route selection, gateway scoping, traffic and receipts. Linux rootful network_control_e2e, network_reconcile, wireguard_kernel tests unchanged.

## Verification and documentation

Native sudo fixture, cargo fmt/check/clippy/test both targets, Linux full CI and kernel namespaces. Document current behavior in architecture/reconciliation.md and native developer runbook after success; capture commands, OS build, route snapshots before/after and masked packet trace.

## Explicit acceptance criteria

Managed utun IPv4/IPv6 addresses and expected routes converge idempotently and recover after crash; no unrelated route or address changes; dynamically allocated utun identifier does not enter authoritative identity; rollback/retry statuses truthful; Linux unchanged.

## Stop conditions

If Darwin route API cannot prove enough attribution to delete safely, if supported behavior requires global default-route surgery, or stale utun names can be mistaken for owned resources: stop, revise ADR, qualify narrower supported topology.

Only after implementation write plans/closure/macos-native-server/004-status.md with exact head, commands/results, native host evidence, preservation and privilege matrix, unresolved severity-graded findings, docs, and a justified closure disposition. Do not edit historical Linux closure evidence.
