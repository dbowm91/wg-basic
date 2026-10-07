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

Current production code state: **M001–M004 are strictly closed, including rootful link/address/route reconciliation; M005 firewall/forwarding/NAT is active.**

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
| Linux network-control foundation | active planning | `plans/subsystems/network-control-roadmap.md` | M001–M004 closed; M005 active |
| Durable state/restart reconciliation | ready to plan | not yet written | M004 ownership contract is stable; broad product integration waits for M005 |
| Management service/auth/UI | proposed | not yet written | begins after privilege protocol + stable network foundation |
| Distribution/install/update | proposed | not yet written | begins after service/state layout stabilizes |

Do not create the later subsystem implementation plans merely to fill the roadmap. Research/write them when their predecessor contracts are stable enough for a bounded handoff.

## 5. Ready and active implementation plans

| Subsystem | Milestone | Status | Implementation plan | Dependencies / handoff |
|---|---|---|---|---|
| Network control | M005 nftables/forwarding/NAT/E2E | **active** | `plans/implementation/network-control/005-firewall-forwarding-end-to-end.md` | M004 strictly closed; baseline revalidated at `e01f35b` |

M005 is the only active implementation plan.

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

## 8. M004 closure and M005 handoff

M004 is strictly closed using the M001–M003 contracts. Its RTNETLINK choice and ownership/retry semantics are recorded in `architecture/reconciliation.md`; the full requirement-to-evidence matrix is in `plans/closure/network-control/004-status.md`. Rootful hosted CI supplies real link/address/route evidence.

## 9. Kernel/network research handoff

M003 selected and qualified `nl-wireguard` 0.3.0. M004 selected and qualified `rtnetlink` 0.23.0 without rewriting the working WireGuard backend solely for dependency uniformity. M005 is revalidating nftables library/process choices in its active plan.

Candidate families include:

- DefGuard WireGuard Rust control layer;
- `wireguard-control`/innernet-family primitives;
- `netlink-packet-wireguard` + Generic Netlink;
- newer consolidated Linux netlink libraries where mature.

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

M001–M004 have strict closure records. M005 is active against the M004 final implementation head `e01f35b`.

There are no active corrective plans.

Canonical documents should remain stable during ordinary M004 work.

If later implementation evidence reveals a material architecture contradiction, record it and revise the appropriate plan/ADR deliberately rather than silently altering the contract.

## 13. Closure handoff

M003 and M004 are closed and their strict evidence is recorded. M005 is active against `e01f35b`.

At each future closure, update:

- source implementation-plan status;
- `plans/subsystems/network-control-roadmap.md` milestone table;
- this registry;
- current architecture/operator docs.

Historical closure records remain immutable evidence if later corrective work is required.
