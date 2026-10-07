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

Current production code state: **M001–M005 are strictly closed, including rootful three-namespace WireGuard forwarding and NAT qualification. One contract-preserving post-foundation reconciliation/refactor plan (C001) is now ready; Phase 6 durable-state planning is being developed against the closed network contracts.**

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
| Linux network-control foundation | closed foundation / corrective active | `plans/subsystems/network-control-roadmap.md` + `plans/subsystems/network-control-post-foundation-reconciliation-addendum.md` | M001–M005 closed; C001 ready |
| Durable state/restart reconciliation | research/planning | not yet written | M004/M005 ownership and policy contracts are stable; C001 is contract-preserving |
| Management service/auth/UI | ready to plan | not yet written | Phase 2 is closed; typed netd protocol and network foundation are stable |
| Distribution/install/update | proposed | not yet written | begins after service/state layout stabilizes |

Do not create the later subsystem implementation plans merely to fill the roadmap. Research/write them when their predecessor contracts are stable enough for a bounded handoff.

## 5. Ready and active implementation plans

| Subsystem | Milestone | Status | Implementation plan | Dependencies / handoff |
|---|---|---|---|---|
| Network control post-foundation reconciliation | C001 documentation reconciliation + module decomposition | **ready** | `plans/implementation/network-control/c001-post-foundation-reconciliation-and-module-decomposition.md` | M001–M005 strict closure; no semantic changes permitted |

C001 is the sole implementation-ready plan while Phase 6 research/planning proceeds in parallel.

## 6. Blocked implementation plans

| Subsystem | Milestone | Status | Implementation plan | Hard blocker |
|---|---|---|---|---|
| — | — | — | — | — |

No implementation plans are currently blocked. Revalidate dependency/API assumptions when a future plan becomes ready.

## 7. Recently closed work

- M001 strict closure: `plans/closure/network-control/001-status.md`.
- M002 strict closure: `plans/closure/network-control/002-status.md`.
- M003 strict closure: `plans/closure/network-control/003-status.md`.
- M004 strict closure: `plans/closure/network-control/004-status.md`.
- M005 strict closure: `plans/closure/network-control/005-status.md`.

## 8. M005 closure and downstream handoff

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

No network milestone may substitute mocked kernel behavior for its required real-kernel closure evidence.

## 12. Planning hygiene

M001–M005 have strict closure records. The M005 implementation was verified at `c67fff8` (CI run `37593324627`).

C001 is the active corrective/polish handoff. It preserves M001–M005 behavior and exists to remove stale documentation and decompose large modules before persistence/UI add more consumers.

Canonical documents should remain stable during C001 implementation unless a material contradiction is discovered.

If later implementation evidence reveals a material architecture contradiction, record it and revise the appropriate plan/ADR deliberately rather than silently altering the contract.

## 13. Closure handoff

M001–M005 are closed and their strict evidence is recorded. C001 is the sole ready implementation handoff. Phase 6 and Phase 7 remain unblocked for planning; Phase 8 remains blocked until both have implementation plans and close. Phase 6 planning may proceed while C001 is implemented because C001 is contract-preserving, but Phase 6 production implementation should begin only after C001 closes or its final module boundaries are otherwise reconciled.

At each future closure, update:

- source implementation-plan status;
- `plans/subsystems/network-control-roadmap.md` milestone table;
- this registry;
- current architecture/operator docs.

Historical closure records remain immutable evidence if later corrective work is required.
