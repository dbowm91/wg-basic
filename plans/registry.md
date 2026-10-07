# wg-basic Planning Registry

Status: active

Last planning reconciliation: 2026-10-07 (C001 closure)

This file is the compact control surface for active wg-basic planning. Detailed requirements belong in canonical documents, subsystem roadmaps, implementation plans, future closure records, and Git history.

## 1. Canonical planning authority

| Document | Role |
|---|---|
| `plans/000-long-term-specification.md` | product scope, architecture, security/operations end state |
| `plans/001-terminology-and-domain-model.md` | canonical vocabulary and type boundaries |
| `plans/002-long-term-roadmap.md` | macro dependency/order |
| `plans/003-planning-process.md` | planning, handoff, corrective, closure rules |
| `plans/adr/001-linux-native-control-plane.md` | accepted Linux-native/privilege-separated architecture |
| `plans/adr/002-durable-state-generations-and-ownership.md` | accepted Phase 6 persistence/generation/ownership architecture |

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

Current production code state: **M001–M005 and C001 are strictly closed. The network-control modules have been decomposed along ownership boundaries with no wire-format, protocol-version, network-policy, or reconciliation-ordering change, and static architecture guards now enforce those boundaries. Phase 6 durable-state M001 and M002 are strictly closed: a hardened SQLite store persists authoritative desired state with a monotonic desired generation, interface ownership is proven by a durable installation/interface owner tag, and one desired generation is the unit of privileged reconciliation. Startup reconciliation arrives in M003.**

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
| Linux network-control foundation | closed | `plans/subsystems/network-control-roadmap.md` + `plans/subsystems/network-control-post-foundation-reconciliation-addendum.md` | M001–M005 and C001 closed |
| Durable state/restart reconciliation | active | `plans/subsystems/durable-state-restart-reconciliation-roadmap.md` | M001–M002 closed; M003 ready; M004 ordered behind M003 |
| Management service/auth/UI | ready to plan | not yet written | Phase 2 is closed; typed netd protocol and network foundation are stable |
| Distribution/install/update | proposed | not yet written | begins after service/state layout stabilizes |

Do not create the later subsystem implementation plans merely to fill the roadmap. Research/write them when their predecessor contracts are stable enough for a bounded handoff.

## 5. Ready and active implementation plans

| Subsystem | Milestone | Status | Implementation plan | Dependencies / handoff |
|---|---|---|---|---|
| Durable state/restart reconciliation | M003 startup reconciliation + crash/restart recovery | **active** | `plans/implementation/durable-state/003-startup-reconciliation-and-recovery.md` | Phase 6 M002 strict closure — satisfied at `65339b8` |

M003 is the sole implementation-ready plan. It owns automatic startup reconciliation, convergence-evidence persistence, and crash/restart recovery, and it must preserve the M004/M005 kernel ownership and retry semantics that M001 and M002 left intact.

## 6. Blocked implementation plans

| Subsystem | Milestone | Status | Implementation plan | Hard blocker |
|---|---|---|---|---|
| Durable state/restart reconciliation | M004 backup/restore + migration qualification | blocked | `plans/implementation/durable-state/004-backup-restore-and-migration-qualification.md` | Phase 6 M003 |

Phase 6 is fully planned. M001, M002, and C001 are closed; M003 is eligible now; M004 remains blocked behind M003. Revalidate exact crate APIs and repository paths at each promotion.

## 7. Recently closed work

- M001 strict closure: `plans/closure/network-control/001-status.md`.
- M002 strict closure: `plans/closure/network-control/002-status.md`.
- M003 strict closure: `plans/closure/network-control/003-status.md`.
- M004 strict closure: `plans/closure/network-control/004-status.md`.
- M005 strict closure: `plans/closure/network-control/005-status.md`.
- C001 strict closure: `plans/closure/network-control-post-foundation-reconciliation/c001-status.md` (head `0e74a40`, CI run `37617879237`).
- Durable-state M001 strict closure: `plans/closure/durable-state/001-status.md` (head `88f10f9`, CI run `37619412663`).
- Durable-state M002 strict closure: `plans/closure/durable-state/002-status.md` (head `65339b8`, CI run `37623015401`).

## 8. M005 and C001 closure and downstream handoff

C001 is strictly closed and preserves every M004/M005 contract; its evidence is recorded in `plans/closure/network-control-post-foundation-reconciliation/c001-status.md` and documents the before/after module inventory, the static guards, and the unchanged wire/protocol surface.

M004 and M005 are strictly closed using their predecessor contracts. M004's RTNETLINK choice and ownership/retry semantics are recorded in `architecture/reconciliation.md`; M005's firewall/forwarding/NAT evidence is recorded in `plans/closure/network-control/005-status.md`. Rootful hosted CI supplies real kernel and end-to-end traffic evidence.

## 9. Kernel/network research handoff

M003 selected and qualified `nl-wireguard` 0.3.0. M004 selected and qualified `rtnetlink` 0.23.0 without rewriting the working WireGuard backend solely for dependency uniformity. M005 selected and qualified the bounded `nft` process backend under ADR-001 constraints; see `architecture/firewall.md` and its closure record.

Candidate families include:

- DefGuard WireGuard Rust control layer;
- `wireguard-control`/innernet-family primitives;
- `netlink-packet-wireguard` + Generic Netlink;
- newer consolidated Linux netlink libraries where mature.

The firewall backend research and selection are closed in M005. Its process boundary remains direct invocation with typed input, internal rendering, version/output/time bounds, and atomic table transactions; no shell or raw caller-provided nft source.

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

C001: unchanged behavior proven by re-running every M003–M005 rootful suite, plus static source guards that pin the architecture boundaries (no `wg`/`wg-quick`/`ip` control path, process execution isolated to the nft backend, no shell, no generic protocol escape hatch, secret redaction).

No network milestone may substitute mocked kernel behavior for its required real-kernel closure evidence.

## 12. Planning hygiene

M001–M005 and C001 have strict closure records. M005 was verified at `c67fff8` (CI run `37593324627`); C001 was verified at `0e74a40` (CI run `37617879237`).

Durable-state M001 is closed at `88f10f9` (CI run `37619412663`): hardened SQLite state store, installation identity, monotonic desired generation with CAS mutation, deterministic projection.

Durable-state M002 is closed at `65339b8` (CI run `37623015401`, five jobs). It adds the durable owner tag, installation-scoped firewall ownership, and the generation-aware aggregate reconcile with an outer coordinator lock and truthful receipts. Two real-kernel fault-injection cases in the plan's case list are implemented and unit-tested but still lack a rootful fixture; that gap is recorded in the M002 closure record and belongs with M003's crash fixtures. Startup reconciliation is deliberately not implemented yet.

C001 removed stale milestone-era documentation and decomposed `reconcile.rs`, `firewall.rs`, and `protocol/server.rs` into `reconcile/`, `firewall/`, and `protocol/` module trees before persistence/UI added more consumers.

Phase 6 planning is complete under ADR-002 and `plans/subsystems/durable-state-restart-reconciliation-roadmap.md`. M001 is now active and unblocked.

Canonical documents should remain stable during Phase 6 M003 implementation unless a material contradiction is discovered.

If later implementation evidence reveals a material architecture contradiction, record it and revise the appropriate plan/ADR deliberately rather than silently altering the contract.

## 13. Closure handoff

M001–M005, C001, and durable-state M001–M002 are closed and their strict evidence is recorded. Phase 6 planning is complete; M003 is the sole ready implementation handoff, and M004 remains blocked behind it. Phase 7 remains unblocked for planning. Phase 8 remains blocked until Phases 6 and 7 close.

At each future closure, update:

- source implementation-plan status;
- `plans/subsystems/network-control-roadmap.md` milestone table;
- `plans/subsystems/durable-state-restart-reconciliation-roadmap.md` milestone table;
- this registry;
- current architecture/operator docs.

Historical closure records remain immutable evidence if later corrective work is required.
