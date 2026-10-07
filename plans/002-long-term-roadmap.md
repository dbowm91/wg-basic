# wg-basic Long-Term Roadmap

Status: canonical ordered roadmap

Authoritative companions:

- `plans/000-long-term-specification.md`
- `plans/001-terminology-and-domain-model.md`
- `plans/003-planning-process.md`
- `plans/adr/001-linux-native-control-plane.md`

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

Status: ready.

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

Status: blocked on Phase 1 closure.

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

Status: active; hard dependency Phase 4 strictly closed.

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

## 8. Phase 6 — Durable desired state and migration substrate

Status: ready to plan; implementation may overlap late Phase 5 testing.

Owned by:

- future `plans/subsystems/state-reconciliation-roadmap.md`.

Objective:

Make desired state durable and restart-reconstructable.

Expected outcomes:

- SQLite schema/migration framework;
- interface/peer/client/network policy persistence;
- secret-reference boundary;
- transactional mutations from management intent;
- startup reconciliation;
- backup/restore format and schema identity;
- clear separation of live telemetry from durable state.

## 9. Phase 7 — Service/security substrate

Status: blocked on Phase 2 and stable privileged protocol; may overlap Phase 6.

Owned by:

- future `plans/subsystems/management-service-roadmap.md`.

Objective:

Build a bounded unprivileged application service without yet claiming end-user UI completeness.

Expected outcomes:

- EggServe adoption decision implemented or explicitly rejected with evidence;
- application routing;
- session/authentication foundation;
- CSRF and request-bound policy;
- management bind policy;
- embedded static-asset pipeline;
- network-service client using only the privileged protocol;
- process/service supervision and shutdown semantics.

## 10. Phase 8 — Management API, UI, and enrollment

Status: blocked on Phases 5–7.

Objective:

Deliver the wg-easy-like user experience.

Expected outcomes:

- first-run setup;
- administrator login;
- server status;
- client create/edit/disable/delete;
- address allocation;
- standard WireGuard configuration export;
- QR generation;
- one-time enrollment capability;
- live handshake/traffic presentation;
- secret-safe audit trail;
- clear advanced-vs-default settings.

This is the first user-facing product-capability closure boundary.

## 11. Phase 9 — Operational hardening

Status: blocked on Phase 8.

Expected outcomes:

- `doctor` with actionable diagnostics;
- database backup/restore;
- explicit network disable vs state purge;
- service restart/crash recovery;
- log retention/configuration;
- resource-limit validation;
- rate limiting and authentication abuse tests;
- security review of privileged IPC and secret handling;
- upgrade migration rehearsal.

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
| 1 repository/domain foundation | ready | network-control M001 | — |
| 2 privileged protocol/capabilities | blocked | network-control M002 | Phase 1 |
| 3 WireGuard kernel control | closed | network-control M003 | Phase 2 |
| 4 link/address/route reconciliation | closed | network-control M004 | Phase 3 |
| 5 firewall/forwarding/E2E | ready | network-control M005 | Phase 4 |
| 6 durable state | ready to plan | future state roadmap | stable Phase 4/5 contracts |
| 7 service/security substrate | proposed | future management roadmap | Phase 2 + stable protocol |
| 8 management UI/enrollment | proposed | future management roadmap | Phases 5–7 |
| 9 operational hardening | proposed | future operations roadmap | Phase 8 |
| 10 distribution/update | proposed | future distribution roadmap | Phase 9 |
| 11 IPv6/route-policy qualification | deferred | future roadmap | stable product baseline |
| 12 advanced capabilities | deferred | separate future research | explicit product decision |
