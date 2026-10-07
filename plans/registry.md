# wg-basic Planning Registry

Status: active

Last planning reconciliation: 2026-10-07

This file is the compact control surface for active wg-basic planning. Detailed requirements belong in canonical documents, subsystem roadmaps, implementation plans, future closure records, and Git history.

## 1. Canonical planning authority

| Document | Role |
|---|---|
| `plans/000-long-term-specification.md` | product scope, architecture, security/operations end state |
| `plans/001-terminology-and-domain-model.md` | canonical vocabulary and type boundaries |
| `plans/002-long-term-roadmap.md` | macro dependency/order |
| `plans/003-planning-process.md` | planning, handoff, corrective, closure rules |
| `plans/adr/001-linux-native-control-plane.md` | accepted Linux-native/privilege-separated architecture |

Authority order for implementation handoff:

1. canonical specification/terminology;
2. accepted ADRs;
3. subsystem roadmap;
4. milestone implementation plan;
5. current repository evidence.

## 2. Product direction snapshot

wg-basic is a Linux-first, low-overhead WireGuard management appliance inspired by wg-easy's ease of use but canonically distributed as a small Rust binary/service installation rather than a Docker/Node runtime.

The Linux kernel owns the WireGuard dataplane.

The architecture separates:

- unprivileged management service: future HTTP/API/UI + durable application state;
- privileged network service: typed kernel/network observation and mutation over local IPC.

The privileged service does not expose arbitrary shell, command, file-write, sysctl-path, nft-script, or raw-netlink execution.

Current production code state: **M001 Rust domain/runtime foundation implemented; no network mutation, IPC, or service behavior yet**.

## 3. Eggstack reuse disposition

Current research and planning disposition:

| Eggstack project | Disposition | Handoff note |
|---|---|---|
| EggServe | preferred downstream candidate | use for hardened HTTP/static transport if Phase 7 implementation confirms it remains simpler than introducing a conventional application framework; app routing/auth remains wg-basic |
| Eggup | planned downstream reuse | Phase 10 install/update/rollback and service lifecycle; integrity substrate only, release authenticity remains wg-basic/release-policy owned |
| Eggpack | planned downstream reuse | Phase 10 producer-side deterministic release construction/draft release flow |
| Eggfetch | no current runtime need | no ordinary outbound HTTP requirement in network control |
| Eggprobe | no current runtime need | diagnostics do not replace authoritative WireGuard/RTNETLINK/nftables control |
| Eggress | out of scope | proxy transport unrelated to initial VPN appliance |
| Eggsact | out of scope | coding-agent utility, not appliance runtime |
| Eggsearch | out of scope | no search subsystem |
| Eggwork / Eggplan | development tooling only if useful | must not become shipped runtime dependencies solely for repo-family consistency |

Runtime dependency adoption remains evidence-driven.

## 4. Active subsystem roadmaps

| Subsystem | Status | Roadmap | Current milestone |
|---|---|---|---|
| Linux network-control foundation | active planning | `plans/subsystems/network-control-roadmap.md` | M001 closed; M002 ready |
| Durable state/restart reconciliation | proposed | not yet written | begins after stable M004/M005 contracts |
| Management service/auth/UI | proposed | not yet written | begins after privilege protocol + stable network foundation |
| Distribution/install/update | proposed | not yet written | begins after service/state layout stabilizes |

Do not create the later subsystem implementation plans merely to fill the roadmap. Research/write them when their predecessor contracts are stable enough for a bounded handoff.

## 5. Dependency-ready implementation plans

| Subsystem | Milestone | Status | Implementation plan | Dependencies / handoff |
|---|---|---|---|---|
| Network control | M002 privileged protocol/capability boundary | **ready** | `plans/implementation/network-control/002-privileged-protocol-and-capability-boundary.md` | M001 strict closure recorded; baseline revalidated at `e27034e` |

M002 is the only implementation-ready plan.

## 6. Blocked implementation plans

| Subsystem | Milestone | Status | Implementation plan | Hard blocker |
|---|---|---|---|---|
| Network control | M003 WireGuard kernel control/telemetry | blocked | `plans/implementation/network-control/003-wireguard-kernel-control-and-telemetry.md` | M002 strict closure |
| Network control | M004 link/address/route reconciliation | blocked | `plans/implementation/network-control/004-link-address-route-reconciliation.md` | M003 strict closure |
| Network control | M005 nftables/forwarding/NAT/E2E | blocked | `plans/implementation/network-control/005-firewall-forwarding-end-to-end.md` | M004 strict closure |

The blocked plans are pre-researched handoffs. Before implementation, revalidate their repository baseline and current dependency/API assumptions.

## 7. Recently closed work

- M001 strict closure: `plans/closure/network-control/001-status.md`.

## 8. Immediate M002 handoff summary

The next implementation agent should implement only M002.

Core constraints:

- reuse M001 domain/error types and the single executable;
- keep M002 read-only: no WireGuard, link, route, firewall, or forwarding mutation;
- implement bounded typed UDS framing, peer authorization, capability snapshot, and lifecycle handling;
- do not add generic privileged execution or raw kernel-operation surfaces;
- preserve the Rust 1.89, locked dependency, formatting, Clippy, and test gates.

The current execution environment does not permit creating network namespaces. M002 does not require kernel mutation, but credential-separation qualification must use a suitable Linux runner if local UID switching is unavailable.

## 9. Kernel/network research handoff

M003 must recheck current Rust WireGuard options at implementation time rather than taking a stale crate choice from planning.

Candidate families include:

- DefGuard WireGuard Rust control layer;
- `wireguard-control`/innernet-family primitives;
- `netlink-packet-wireguard` + Generic Netlink;
- newer consolidated Linux netlink libraries where mature.

M004 must recheck RTNETLINK support and compatibility with M003.

M005 must recheck direct nftables/NETLINK_NETFILTER libraries. A bounded internal `nft` process backend is allowed only under ADR-001's strict constraints; no shell and no raw caller-provided nft source.

## 10. External prior-art boundary

wg-easy is the primary UX/product reference.

Other WireGuard managers, including Rust/Linux control planes such as nx9-wg and DefGuard components, are architecture/interoperability references rather than source templates.

wg-basic differentiation remains:

- wg-easy-style low-friction onboarding;
- Linux-native non-container canonical installation;
- one small Rust executable with separated runtime privilege domains;
- direct kernel control;
- conservative host ownership;
- simple binary/update distribution;
- narrow appliance scope rather than general network orchestration.

## 11. Verification posture

M001: ordinary Rust/Linux CI + MSRV.

M002: Linux UDS peer-credential/lifecycle qualification.

M003: real kernel WireGuard namespace handshake and telemetry.

M004: real RTNETLINK reconciliation/idempotence/partial-failure/preservation.

M005: three-node namespace traffic with nftables, forwarding, NAT, restart/reapply, disable, and unrelated-state preservation.

No network milestone may substitute mocked kernel behavior for its required real-kernel closure evidence.

## 12. Planning hygiene

M001 has a strict closure record. Later milestones remain blocked on their hard dependencies.

There are no active corrective plans.

Canonical documents should remain stable during ordinary M002 work.

If later implementation evidence reveals a material architecture contradiction, record it and revise the appropriate plan/ADR deliberately rather than silently altering the contract.

## 13. Next status transition

Expected transition:

```text
M002 ready
  -> implementation
  -> closing
  -> closure record
  -> closed
  -> M003 promoted to ready
```

At each closure, update:

- source implementation-plan status;
- `plans/subsystems/network-control-roadmap.md` milestone table;
- this registry;
- current architecture/operator docs.

Historical closure records remain immutable evidence if later corrective work is required.
