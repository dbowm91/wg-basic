# wg-basic Planning Registry

Status: active

Last planning reconciliation: 2026-10-07 (Phase 7 researched/planned; M001 ready)

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
| `plans/adr/003-management-http-auth-and-worker-boundary.md` | accepted Phase 7 HTTP/auth/worker security architecture |

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

Current production code state: **M001–M005 and C001 are strictly closed. The network-control modules have been decomposed along ownership boundaries with no wire-format, protocol-version, network-policy, or reconciliation-ordering change, and static architecture guards now enforce those boundaries. Phase 6 is strictly closed through M004: a hardened SQLite store persists authoritative desired state with a monotonic desired generation, interface ownership is proven by a durable installation/interface owner tag, one desired generation is the unit of privileged reconciliation, the unprivileged management role applies that generation on startup and after a crash, and the database can be backed up online, validated, restored offline, and used to rebuild real network state. The HTTP surface, installation, and product lifecycle remain later work.** Post-Phase-6 C001 has since closed: it reconciled the current-state docs with the shipped code, retired the last M002/M003 rootful evidence debt by qualifying the disable path against a failing firewall, and split `management`, `state/store`, and `state/schema` by subject with the public surface unchanged.

## 3. Eggstack reuse disposition

Current research and planning disposition:

| Eggstack project | Disposition | Handoff note |
|---|---|---|
| EggServe | selected Phase 7 substrate | direct `eggserve-server` + `eggserve-primitives` H1 service; wg-basic owns routing/auth/CSRF/rate limits and embeds its own assets; no Tower/Axum in the baseline |
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
| Durable state/restart reconciliation | closed | `plans/subsystems/durable-state-restart-reconciliation-roadmap.md` + `plans/subsystems/durable-state-post-phase6-reconciliation-addendum.md` | Phase 6 complete; M001–M004 and post-Phase-6 C001 closed |
| Management service/auth/security substrate | planned / M001 ready | `plans/subsystems/management-service-security-roadmap.md` | M001 EggServe + bounded worker ready; M002–M004 blocked in order |
| Distribution/install/update | proposed | not yet written | begins after the Phase 7 service layout stabilizes |

Do not create the later subsystem implementation plans merely to fill the roadmap. Research/write them when their predecessor contracts are stable enough for a bounded handoff.

## 5. Ready and active implementation plans

| Subsystem | Milestone | Status | Implementation plan | Dependencies / handoff |
|---|---|---|---|---|
| Management service/security | M001 EggServe runtime + bounded management worker | **ready** | `plans/implementation/management-service/001-eggserve-runtime-and-management-worker.md` | Phase 6 + post-Phase-6 C001 strict closure |

M001 is the sole implementation-ready plan. It adds the HTTP transport/worker substrate only: no administrator/session schema, no browser login, and no Phase 8 configuration API.

## 6. Blocked implementation plans

| Subsystem | Milestone | Status | Implementation plan | Hard blocker |
|---|---|---|---|---|
| Management service/security | M002 local administrator + session persistence | blocked | `plans/implementation/management-service/002-local-admin-and-session-persistence.md` | Phase 7 M001 |
| Management service/security | M003 authenticated HTTP security perimeter | blocked | `plans/implementation/management-service/003-authenticated-http-security-perimeter.md` | Phase 7 M002 |
| Management service/security | M004 service lifecycle + Phase 7 qualification | blocked | `plans/implementation/management-service/004-service-lifecycle-and-phase7-qualification.md` | Phase 7 M003 |

Phase 8 remains blocked until Phase 7 M004 closes.

## 7. Recently closed work

- M001 strict closure: `plans/closure/network-control/001-status.md`.
- M002 strict closure: `plans/closure/network-control/002-status.md`.
- M003 strict closure: `plans/closure/network-control/003-status.md`.
- M004 strict closure: `plans/closure/network-control/004-status.md`.
- M005 strict closure: `plans/closure/network-control/005-status.md`.
- C001 strict closure: `plans/closure/network-control-post-foundation-reconciliation/c001-status.md` (head `0e74a40`, CI run `37617879237`).
- Durable-state M001 strict closure: `plans/closure/durable-state/001-status.md` (head `88f10f9`, CI run `37619412663`).
- Durable-state M002 strict closure: `plans/closure/durable-state/002-status.md` (head `65339b8`, CI run `37623015401`).
- Durable-state M003 strict closure: `plans/closure/durable-state/003-status.md` (head `6a9cbc7`).
- Durable-state M004 strict closure and **Phase 6 closure**: `plans/closure/durable-state/004-status.md` (head `772203d`).
- Durable-state post-Phase-6 C001 strict closure: `plans/closure/durable-state-post-phase6-reconciliation/c001-status.md` (head `635a130`, CI run `37638334930`).

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

Durable-state post-Phase-6 C001: the existing routine, MSRV, and seven rootful suites, re-run unchanged, plus one new real-kernel case qualifying the disable path when the firewall layer refuses. Injection is a fixture-private `nft` on netd's `PATH`, so the shipped firewall-first ordering is exercised with no production fault-injection hook; two reverted negative controls confirm the case fails when that ordering is broken.

No network milestone may substitute mocked kernel behavior for its required real-kernel closure evidence.

## 12. Planning hygiene

M001–M005 and C001 have strict closure records. M005 was verified at `c67fff8` (CI run `37593324627`); C001 was verified at `0e74a40` (CI run `37617879237`).

Durable-state M001 is closed at `88f10f9` (CI run `37619412663`): hardened SQLite state store, installation identity, monotonic desired generation with CAS mutation, deterministic projection.

Durable-state M002 is closed at `65339b8` (CI run `37623015401`, five jobs). It adds the durable owner tag, installation-scoped firewall ownership, and the generation-aware aggregate reconcile with an outer coordinator lock and truthful receipts. Two real-kernel fault-injection cases in the plan's case list were recorded in the M002 closure record as lacking a rootful fixture; M003 closed that gap for the enable path with `a_partially_applied_generation_recovers_after_a_restart`.

C001 removed stale milestone-era documentation and decomposed `reconcile.rs`, `firewall.rs`, and `protocol/server.rs` into `reconcile/`, `firewall/`, and `protocol/` module trees before persistence/UI added more consumers.

Durable-state post-Phase-6 C001 is closed at `635a130` (CI run `37638334930`, seven jobs). It reconciled current-state docs that still described shipped behavior as future work, split `management`, `state/store`, and `state/schema` by subject with the public surface unchanged and no dependency change, and retired the last M002/M003 evidence debt. Its closure record notes two judgment calls: `store/sql.rs` holds row/column conversion rather than extracted query strings, and the schema contract test suite stayed whole rather than being distributed across the three modules it spans.

Durable-state M003 is closed at `6a9cbc7`: the unprivileged management role reconciles the committed desired generation on startup and after a crash, records convergence evidence only for the generation the database still holds, and qualifies restart recovery at the process level against real `netd` and management child processes, SQLite, RTNETLINK, and nftables. Two classification defects were found and fixed while qualifying: every refusal was being reported as a transient outage, and a partial apply was being reported as a hard refusal. A previously vacuous owned-table fixture was corrected to seed a network policy.

Durable-state M004 is closed at `772203d` and **Phase 6 is closed with it**. Online backup uses SQLite's backup API under the store's mutation lock rather than copying a live WAL database; offline restore validates a candidate completely before replacing anything and retains the previous database; a restored database is qualified end to end by rebuilding a fresh three-namespace environment and carrying real WireGuard, forwarding, and NAT traffic. A fail-closed gap was fixed: `enforce_singleton` accepted a missing installation row, so a tampered database opened successfully and was merely unusable afterwards. A vacuous M001 architecture guard that forbade the now-enabled `rusqlite::backup` was corrected rather than deleted.

Phase 6 is complete under ADR-002 and `plans/subsystems/durable-state-restart-reconciliation-roadmap.md`.

Phase 7 research/planning is complete under ADR-003 and `plans/subsystems/management-service-security-roadmap.md`. The selected baseline is direct EggServe H1, a bounded dedicated management worker, local Argon2id credentials, opaque revocable sessions, explicit Host/Origin/CSRF enforcement, and loopback-first binding. M001 is ready; later milestones remain blocked in order.

If later implementation evidence reveals a material architecture contradiction, record it and revise the appropriate plan/ADR deliberately rather than silently altering the contract.

## 13. Closure handoff

M001–M005, network-control C001, durable-state M001–M004, and durable-state post-Phase-6 C001 are closed and their strict evidence is recorded. **Phase 6 remains closed.** Phase 7 is now fully researched/planned; M001 is ready and M002–M004 are blocked in order. Phase 8 remains blocked until Phase 7 closes.

At each future closure, update:

- source implementation-plan status;
- `plans/subsystems/network-control-roadmap.md` milestone table;
- `plans/subsystems/durable-state-restart-reconciliation-roadmap.md` milestone table;
- `plans/subsystems/management-service-security-roadmap.md` milestone table;
- this registry;
- current architecture/operator docs.

Historical closure records remain immutable evidence if later corrective work is required.
