# wg-basic Long-Term Roadmap

Status: canonical ordered roadmap

Authoritative companions:

- `plans/000-long-term-specification.md`
- `plans/001-terminology-and-domain-model.md`
- `plans/003-planning-process.md`
- `plans/adr/001-linux-native-control-plane.md`
- `plans/adr/002-durable-state-generations-and-ownership.md`
- `plans/adr/003-management-http-auth-and-worker-boundary.md`
- `plans/adr/004-product-management-enrollment-and-api-semantics.md`
- `plans/adr/005-operational-hardening-maintenance-and-recovery.md`

This roadmap orders wg-basic from a fresh repository to a small, production-credible Linux-native WireGuard appliance. Milestone-specific execution belongs in subsystem roadmaps and `plans/implementation/`.

## 1. Ordering principles

The roadmap follows five rules:

1. Prove direct Linux kernel control before building product UI around it.
2. Close host-network ownership and rollback/retry semantics before exposing broad mutation through HTTP.
3. Establish privilege separation before a management surface is considered production-ready.
4. Preserve standard WireGuard interoperability; do not invent a custom VPN protocol.
5. Add distribution/update convenience after the binary and service boundaries are stable enough to update safely.

## 2. Macro dependency graph

```text
Phase 1 — repository/domain foundation
              |
              v
Phase 2 — privileged protocol + host capability boundary
              |
              v
Phase 3 — direct WireGuard control + telemetry
              |
              v
Phase 4 — links, addresses, routes, reconciliation
              |
              v
Phase 5 — nftables + forwarding + namespace E2E qualification
              |
              +--------------------+
              |                    |
              v                    v
Phase 6 — durable desired state   Phase 7 — service/security substrate
              |                    |
              +----------+---------+
                         v
Phase 8 — management API + embedded UI + enrollment
                         |
                         v
Phase 9 — operational hardening, backup/restore, doctor
                         |
                         v
Phase 10 — binary distribution, install/update/rollback
                         |
                         v
Phase 11 — IPv6/full-tunnel/split-tunnel production qualification
                         |
                         v
Phase 12 — optional advanced authentication/policy/backends
```

Phases 6 and 7 may proceed partly in parallel after the kernel reconciliation contract is stable.

## 3. Phase 1 — Repository and domain foundation

Status: closed.

Owned by:

- `plans/subsystems/network-control-roadmap.md` M001.

Objective:

Create the minimal Rust workspace, toolchain/MSRV policy, typed domain model, CLI/process-role skeleton, error taxonomy, secret-safe formatting rules, and verification baseline.

Required outcomes:

- Rust 1.89+ policy aligned with current Eggstack baseline unless dependency evidence requires a later MSRV;
- `unsafe_code = "deny"` by default;
- typed interface/peer/client/desired-state identifiers and validation;
- no network mutation yet;
- no HTTP server yet;
- no persistence dependency yet;
- Linux-only compilation boundary explicit;
- deterministic unit tests for address/key/domain validation.

This phase is infrastructure/invariant work, not a claim of a functional VPN server.

## 4. Phase 2 — Privileged protocol and host capability boundary

Status: closed.

Owned by:

- `plans/subsystems/network-control-roadmap.md` M002.

Objective:

Establish the privileged process boundary before kernel mutation grows.

Required outcomes:

- `serve`/management and `netd`/network roles are representable by one executable;
- authenticated local Unix-domain IPC;
- versioned typed request/response envelope;
- effective peer-credential/socket-permission checks where supported;
- host capability snapshot;
- `doctor`/preflight primitives;
- no generic command, file-write, sysctl-path, nft-program, or raw-netlink passthrough;
- integration tests proving an unauthorized local caller cannot mutate.

## 5. Phase 3 — Direct WireGuard control and live telemetry

Status: closed.

Owned by:

- `plans/subsystems/network-control-roadmap.md` M003.

Objective:

Prove kernel WireGuard control without `wg` or `wg-quick`.

Required outcomes:

- create/delete an explicitly owned WireGuard link or configure a fixture-created one through the selected kernel APIs;
- set/get private/public key identity and listen port;
- add/update/remove peers;
- configure peer AllowedIPs and keepalive;
- observe endpoint, latest handshake, RX/TX;
- duplicate/conflicting key/route validation before mutation;
- isolated Linux namespace integration tests;
- no address/route/NAT policy folded into the WireGuard backend.

## 6. Phase 4 — Link, address, route, and reconciliation engine

Status: closed.

Owned by:

- `plans/subsystems/network-control-roadmap.md` M004.

Objective:

Create the first complete desired→observed→plan→apply→verify loop for the interface/link/address/route layers.

Required outcomes:

- RTNETLINK link/address/route observation and mutation;
- typed reconciliation plan;
- idempotent no-op when converged;
- serialized mutation per managed interface;
- ownership/conflict checks;
- partial-failure receipt and safe retry semantics;
- dry-run/plan rendering;
- preservation tests for unrelated interfaces/routes.

## 7. Phase 5 — Firewall, forwarding, NAT, and network-namespace qualification

Status: closed; hard dependency Phase 4 strictly closed.

Owned by:

- `plans/subsystems/network-control-roadmap.md` M005.

Objective:

Complete the minimum road-warrior server networking path.

Required outcomes:

- dedicated wg-basic nftables ownership namespace;
- minimal forwarding/filter policy;
- optional masquerade/NAT policy;
- explicit host forwarding semantics;
- safe disable/uninstall behavior for non-exclusive sysctl state;
- direct ownership/preservation tests against unrelated nftables rules;
- real namespace/veth/WireGuard handshake and traffic path;
- restart/retry verification against kernel state.

M005 is the first kernel-control foundation closure boundary. Later service/UI work MUST NOT weaken its ownership model.

## 8. Phase 6 — Durable desired state and restart reconciliation

Status: closed. Durable-state M001–M004 are strictly closed. The bounded post-Phase-6 corrective (durable-state C001) also closed at `635a130`, retiring the remaining disable-path rootful evidence debt and reconciling the management/state boundary before Phase 7.

Owned by:

- `plans/subsystems/durable-state-restart-reconciliation-roadmap.md`.

Architecture decision:

- `plans/adr/002-durable-state-generations-and-ownership.md`.

Objective:

Make desired state durable, generation-safe, ownership-provable, and restart-reconstructable.

Expected outcomes:

- hardened bundled SQLite state store compatible with Rust 1.89;
- project-owned ordered schema migrations;
- stable InstallationId and monotonic DesiredGeneration;
- generation-CAS desired-state mutations;
- interface/peer/client/network-policy persistence;
- deterministic projection from application state to privileged network intent;
- durable link ownership through Linux interface aliases;
- installation-specific nftables ownership;
- aggregate generation-aware netd reconciliation;
- startup crash/restart recovery;
- backup/restore and migration qualification;
- clear separation of live telemetry from durable state.

Milestones:

- M001 SQLite state store + desired generations;
- M002 durable owner tags + aggregate netd reconciliation;
- M003 startup reconciliation + crash/restart recovery;
- M004 backup/restore + migration qualification.

Phase 6 implementation is complete. Post-Phase-6 corrective work was tracked in `plans/subsystems/durable-state-post-phase6-reconciliation-addendum.md`; it closed at `635a130` and did not reopen Phase 6 architecture or closure.

## 9. Phase 7 — Service/security substrate

Status: closed. M001–M004 strictly closed at `d5d5ca9`; the separate post-Phase-7 C001 corrective also closed at `df1f9e7` and does not reopen Phase 7 architecture.

Owned by:

- `plans/subsystems/management-service-security-roadmap.md`.

Architecture decision:

- `plans/adr/003-management-http-auth-and-worker-boundary.md`.

Objective:

Build a bounded unprivileged application service without yet claiming end-user UI completeness.

Expected outcomes:

- direct EggServe H1 application-service runtime;
- bounded dedicated blocking worker owning `ManagementRuntime`;
- loopback-first management bind;
- local Argon2id administrator credentials;
- revocable opaque server-side sessions;
- explicit Host/Origin/CSRF browser security;
- login throttling before password hashing;
- embedded self-contained static shell;
- strict security headers and request/resource limits;
- process supervision and graceful shutdown;
- real HTTP → worker → SQLite/netd qualification.

Milestones:

- M001 EggServe runtime + bounded management worker;
- M002 local administrator + session persistence and real schema v2;
- M003 authenticated HTTP security perimeter;
- M004 embedded shell + lifecycle + Phase 7 qualification.

Phase 7 deliberately stops before peer/client CRUD, QR/config export, and the full management UI; those remain Phase 8.

## 10. Phase 8 — Management API, UI, and enrollment

Status: closed. Phase 8 M001–M005 are strictly closed; M005 implementation head is `8b20a7c` and Phase 8 closure is recorded at `e8fd6b1`.

Owned by:

- `plans/subsystems/product-management-enrollment-ui-roadmap.md`.

Architecture decision:

- `plans/adr/004-product-management-enrollment-and-api-semantics.md`.

Objective:

Deliver the wg-easy-like user experience on top of the closed Phase 6/7 state, privilege, HTTP, and authentication contracts.

Expected outcomes:

- authenticated first-server setup after local admin bootstrap;
- generation-safe server/client product mutations;
- deterministic IPv4 address allocation;
- client create/edit/enable/disable/delete;
- explicit committed-vs-enforced mutation receipts;
- secret-safe product audit trail;
- standard WireGuard configuration export;
- locally generated QR enrollment;
- high-entropy expiring single-use enrollment capability;
- live handshake/endpoint/RX/TX presentation from kernel observation;
- fully embedded buildless management UI;
- real exported-client/rootful product E2E qualification.

Milestones:

- M001 product model + schema v3 + generation-safe mutations;
- M002 authenticated setup/client CRUD API;
- M003 standard export + QR + one-time enrollment;
- M004 live telemetry + audit/status surface;
- M005 embedded product UI + Phase 8 qualification.

Phase 8 implementation is complete. The product boundary now includes authenticated setup/client lifecycle, config/QR export, one-time enrollment, live telemetry, audit history, and the embedded buildless UI; the rootful product fixture qualifies the exported-client handshake and lifecycle end to end.

This is the first user-facing product-capability closure boundary.

## 11. Phase 9 — Operational hardening

Status: planned; M001 ready.

Owned by:

- `plans/subsystems/operational-hardening-roadmap.md`.

Architecture decision:

- `plans/adr/005-operational-hardening-maintenance-and-recovery.md`.

Objective:

Harden the complete IPv4 appliance for unattended Linux operation before distribution/update automation.

Expected outcomes:

- authoritative read-only doctor/preflight with human + JSON output;
- actual SQLite runtime/source identity and state/network drift diagnostics;
- one management service per state DB through a crash-safe advisory lease;
- durable whole-server network disable/re-enable;
- explicit fail-closed state purge semantics;
- backup verification and restore/recovery drills;
- structured secret-safe stderr events with no in-binary log files;
- bounded session/enrollment/audit housekeeping;
- repeated crash/restart and resource-leak qualification;
- documented systemd hardening/resource contract for Phase 10;
- HTTP/UDS abuse and privileged-boundary security review;
- pinned dependency-advisory checking;
- real old-binary/new-schema migration and rollback rehearsal.

Milestones:

- M001 authoritative doctor and preflight;
- M002 maintenance lease + network disable/purge + recovery UX;
- M003 structured logging + housekeeping + crash/resource hardening;
- M004 abuse/security/dependency qualification;
- M005 upgrade/rollback rehearsal + Phase 9 closure.

Phase 9 does not install systemd units or implement self-update; it produces the tested operational contracts Phase 10 will automate.

## 12. Phase 10 — Distribution, installation, update, and rollback

Status: blocked on a stable service/state layout from Phase 9.

Owned by a future distribution/operations roadmap.

Preferred Eggstack direction:

- Eggup for staged local update/replacement, ownership revalidation, locking, rollback/recovery evidence, and service lifecycle;
- Eggpack for deterministic producer-side release contracts and draft release preparation;
- project-owned release authenticity/signing policy.

Expected release targets:

- Linux x86_64;
- Linux aarch64;
- optional ARMv7 only after qualified.

Expected operator experience:

```text
install -> preflight -> initialize -> start -> print management URL
update  -> stage -> verify -> stop/replace -> start/health -> commit or rollback
uninstall -> stop/remove program files while preserving VPN state unless purge requested
```

Docker/container distribution MAY be added as secondary packaging only.

## 13. Phase 11 — IPv6 and route-policy production qualification

Status: deferred until the IPv4 appliance path is stable.

Expected outcomes:

- IPv6 tunnel address allocation;
- `::/0` full tunnel;
- split tunnel for both families;
- nftables IPv6 forwarding/NAT decisions;
- endpoint and DNS representation;
- dual-stack namespace qualification;
- no regression of IPv4-only deployments.

The domain model and firewall abstraction MUST avoid choices that make this a rewrite.

## 14. Phase 12 — Optional advanced capabilities

Status: deferred; each requires fresh research/planning.

Candidates:

- TOTP;
- OIDC;
- multi-admin RBAC;
- per-client policy groups;
- Prometheus/OpenMetrics;
- userspace WireGuard fallback;
- AmneziaWG-compatible backend;
- constrained `wg-quick` import;
- multiple managed server interfaces;
- external endpoint discovery.

None is required for the initial product identity.

## 15. Eggstack adoption constraints

Eggstack reuse is contract-driven.

| Primitive | Current disposition | Reason |
|---|---|---|
| EggServe | preferred candidate | hardened Rust HTTP/static runtime; suitable downstream service boundary |
| Eggup | planned for Phase 10 | verified staging/replacement/rollback/service lifecycle |
| Eggpack | planned for Phase 10 | producer-side deterministic release construction |
| Eggfetch | not currently needed | no ordinary outbound HTTP requirement in core control plane |
| Eggprobe | not currently needed | does not own authoritative WireGuard/nftables mutation |
| Eggress | not currently needed | proxy transport is outside product scope |
| Eggsact | not currently needed | deterministic agent tooling is unrelated to runtime appliance |
| Eggsearch | not currently needed | no search subsystem |
| Eggwork/Eggplan | not runtime dependencies | development orchestration may use them externally, not in the shipped appliance |

Any change to this table that adds a runtime dependency requires evidence in the owning milestone.

## 16. Verification doctrine

Network-control milestones require progressively stronger evidence:

```text
unit/domain tests
   -> mocked/fixture backend tests where useful
   -> Linux namespace integration
   -> real WireGuard kernel handshake
   -> traffic path through routes/firewall/NAT
   -> restart/reconcile preservation tests
   -> representative release-host qualification
```

Compilation or mocked netlink alone cannot close Phases 3–5.

## 17. Release doctrine

Before the first public production claim:

- no unresolved high/medium network-ownership or privilege-boundary finding;
- x86_64 and aarch64 qualified;
- migration/backup path tested;
- management service rate/session/CSRF controls qualified;
- update/rollback behavior qualified;
- release artifacts have integrity and authenticity evidence;
- active planning/architecture/operator docs agree.

## 18. Current milestone status

| Phase | Status | Owning plan/roadmap | Blocker |
|---|---|---|---|
| 1 repository/domain foundation | closed | network-control M001 | — |
| 2 privileged protocol/capabilities | closed | network-control M002 | — |
| 3 WireGuard kernel control | closed | network-control M003 | Phase 2 |
| 4 link/address/route reconciliation | closed | network-control M004 | Phase 3 |
| 5 firewall/forwarding/E2E | closed | network-control M005 | — |
| 6 durable state/restart reconciliation | closed | `plans/subsystems/durable-state-restart-reconciliation-roadmap.md` | — |
| 7 service/security substrate | closed | `plans/subsystems/management-service-security-roadmap.md` | — |
| 8 management API/UI/enrollment | closed | `plans/subsystems/product-management-enrollment-ui-roadmap.md` | — |
| 9 operational hardening | ready to plan | future operations roadmap | — |
| 10 distribution/update | proposed | future distribution roadmap | Phase 9 |
| 11 IPv6/route-policy qualification | deferred | future roadmap | stable product baseline |
| 12 advanced capabilities | deferred | separate future research | explicit product decision |
