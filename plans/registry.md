# wg-basic Planning Registry

Status: active

Last planning reconciliation: 2026-10-08 (Phase 9 researched/planned; M001 ready)

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
| `plans/adr/004-product-management-enrollment-and-api-semantics.md` | accepted Phase 8 product mutation/enrollment/API architecture |
| `plans/adr/005-operational-hardening-maintenance-and-recovery.md` | accepted Phase 9 diagnostics/maintenance/recovery/security architecture |

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

- unprivileged management service: HTTP/API/UI + durable application state;
- privileged network service: typed kernel/network observation and mutation over local IPC.

The privileged service does not expose arbitrary shell, command, file-write, sysctl-path, nft-script, or raw-netlink execution.

Current production code state: **Network control and Phases 6–8 are strictly closed. The authenticated product API and embedded UI provide server setup, client lifecycle, config/QR export, one-time enrollment, live telemetry, and bounded audit history.** Phase 9 implementation is active at M001: doctor now emits a bounded human/JSON report with read-only SQLite integrity/runtime, forwarding, netd reachability, and optional HTTP-policy checks. Authoritative product/convergence diagnostics, backend probes, aggregate ownership planning, and no-mutation evidence remain open; M002–M005 stay blocked in order.

## 3. Eggstack reuse disposition

Current research and planning disposition:

| Eggstack project | Disposition | Handoff note |
|---|---|---|
| EggServe | selected Phase 7 substrate | direct `eggserve-server` + `eggserve-primitives` H1 service; wg-basic owns routing/auth/CSRF/rate limits and embeds its own assets; no Tower/Axum in the baseline |
| Eggup | planned downstream reuse | Phase 10 install/update/rollback and service lifecycle; integrity substrate only, release authenticity remains wg-basic/release-policy owned |
| Eggpack | planned downstream reuse | Phase 10 producer-side deterministic release construction/draft release flow |
| Eggfetch | no current runtime need | no ordinary outbound HTTP requirement in network control |
| Eggprobe | external/reference only for Phase 9 | useful generic DNS/TCP/TLS/route diagnostics, but wg-basic doctor requires authoritative local state/ownership/netd checks that Eggprobe does not own; no runtime dependency selected |
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
| Management service/auth/security substrate | closed | `plans/subsystems/management-service-security-roadmap.md` + `plans/subsystems/management-service-post-phase7-reconciliation-addendum.md` | M001–M004 and post-Phase-7 C001 closed |
| Product management/enrollment/UI | closed | `plans/subsystems/product-management-enrollment-ui-roadmap.md` | Phase 8 M001–M005 closed |
| Operational hardening | planned | `plans/subsystems/operational-hardening-roadmap.md` | M001 ready; M002–M005 blocked in order |
| Distribution/install/update | proposed | not yet written | Phase 10; blocked behind Phase 9 closure |

Do not create the later subsystem implementation plans merely to fill the roadmap. Research/write them when their predecessor contracts are stable enough for a bounded handoff.

## 5. Ready and active implementation plans

| Subsystem | Milestone | Status | Implementation plan | Dependencies / handoff |
|---|---|---|---|---|
| Operational hardening | M001 authoritative doctor + preflight | **active** | `plans/implementation/operational-hardening/001-authoritative-doctor-and-preflight.md` | Phase 8 strict closure at `e8fd6b1`; authoritative product/network checks remain unfinished |

M001 is the sole active implementation plan. It remains read-only diagnostics/preflight work: no repair mode, state purge, service units, or updater behavior is permitted in M001.

## 6. Blocked implementation plans

| Subsystem | Milestone | Status | Implementation plan | Hard blocker |
|---|---|---|---|---|
| Operational hardening | M002 maintenance lease + disable/purge/recovery | blocked | `plans/implementation/operational-hardening/002-maintenance-disable-purge-and-recovery.md` | Phase 9 M001 |
| Operational hardening | M003 logging + housekeeping + runtime hardening | blocked | `plans/implementation/operational-hardening/003-logging-housekeeping-and-runtime-hardening.md` | Phase 9 M002 |
| Operational hardening | M004 abuse/security/dependency qualification | blocked | `plans/implementation/operational-hardening/004-abuse-security-and-dependency-qualification.md` | Phase 9 M003 |
| Operational hardening | M005 upgrade/rollback rehearsal + Phase 9 closure | blocked | `plans/implementation/operational-hardening/005-upgrade-rollback-rehearsal-and-phase9-closure.md` | Phase 9 M004 |

Phase 10 distribution/install/update remains proposed and blocked until Phase 9 M005 closes.

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
- Management-service M001 strict closure: `plans/closure/management-service/001-status.md` (head `5b57d49`).
- Management-service M002 strict closure: `plans/closure/management-service/002-status.md` (head `60d1482`).
- Management-service M003 strict closure: `plans/closure/management-service/003-status.md` (head `cfe6860`).
- Management-service M004 strict closure and **Phase 7 closure**: `plans/closure/management-service/004-status.md` (head `d5d5ca9`).
- Management-service post-Phase-7 C001 strict closure: `plans/closure/management-service/c001-status.md` (head `df1f9e7`).
- Product-management M001 strict closure: `plans/closure/product-management/001-status.md`.
- Product-management M002 strict closure: `plans/closure/product-management/002-status.md` (head `cf0717e`).
- Product-management M003 strict closure: `plans/closure/product-management/003-status.md` (implementation head `37c0ff7`).
- Product-management M004 strict closure: `plans/closure/product-management/004-status.md` (implementation head `d629103`).
- Product-management M005 strict closure and **Phase 8 closure**: `plans/closure/product-management/005-status.md` (implementation head `8b20a7c`).

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

Phase 7 research/planning is complete under ADR-003 and `plans/subsystems/management-service-security-roadmap.md`. The selected baseline is direct EggServe H1, a bounded dedicated management worker, local Argon2id credentials, opaque revocable sessions, explicit Host/Origin/CSRF enforcement, and loopback-first binding.

Phase 7 M001 is closed at `5b57d49`. It proves the ADR-003 boundary empirically rather than by assertion: `eggserve-server` 0.4.0 and `eggserve-primitives` 0.2.2 are sufficient on their own, no router framework was needed, one bounded worker owns `ManagementRuntime`, and HTTP code provably never reaches the store or netd. Three judgment calls are recorded in its closure record: EggServe rejects a zero file-stream/tunnel capacity so the surface pins the floor of 1 with no route able to consume it; the pre-Phase-7 architecture guard's blanket `tokio::` ban was replaced with a narrower and stricter rule (no web stack anywhere in management, `tokio::` only in the worker); and architecture guards now inspect code with comments stripped, because prose that names a forbidden dependency would otherwise fail its own guard.

Phase 7 M003 is closed at `cfe6860`. The surface publishes five routes — `POST /api/v1/login`, `POST /api/v1/logout`, `GET /api/v1/session`, `GET /api/v1/health`, and the unauthenticated `GET /healthz` — and no Phase 8 configuration-mutating route. Five judgment calls are recorded in its closure record. Security headers are applied *after* construction, in exactly one place at the end of `ManagementService::dispatch`, because sealing during construction would have let four separate literal constructors drift and sealing after it makes the guarantee total: a route cannot build a response that skips the headers. Trust is never inferred from a loopback listener, because a rebinding page controls `Host`; an allowed host set and a canonical origin are declared instead, and a routable bind is refused outright without an explicit acknowledgement. The `Secure` cookie attribute and the `__Host-` name follow the configured canonical origin rather than the incoming request, so a plain-HTTP loopback deployment does not emit a cookie a browser would silently drop. The login limiter runs *before* Argon2 — at ~300 ms and 19 MiB per verification under load, a limiter after the hash is a denial of service wearing a rate limit's clothes — and that ordering is enforced by an architecture guard as well as measured, because a timing test cannot catch a refactor that moves one statement. Two defects in already-closed M002 work were found and corrected: `admin set-password` failed on a fresh install because both one-shot commands used a store open that refuses a file which does not exist, and an unknown username returned in microseconds beside a wrong password's ~300 ms, which is a username oracle larger than anything a response body could leak; plan §10 required a dummy verifier for exactly that and it is now in place. No historical closure record was edited.

One corrective finding was made during M001: `ManagementHealth::netd_reachable` was derived from the convergence state, so a recorded `backend_unavailable` — which is the record of netd not answering — projected as reachable. The derivation was untested. It is now derived from the recorded disposition directly, with regression tests. No closed plan's verified surface changed, and no historical closure record was edited.

One carry-forward constraint for M002: `src/state/schema/mod.rs` currently exercises the migration runner through a `#[cfg(test)]`-only step stamped at version 2, so a genuine migration 2 collides with it. M002 must replace that harness with fixtures built from the production v1 schema.

If later implementation evidence reveals a material architecture contradiction, record it and revise the appropriate plan/ADR deliberately rather than silently altering the contract.

Phase 9 research/planning is complete under ADR-005 and `plans/subsystems/operational-hardening-roadmap.md`. The selected baseline is an authoritative read-only doctor, crash-safe service lease, durable whole-server network state, fail-closed purge, structured stderr events, bounded operational-row housekeeping, adversarial HTTP/UDS qualification, and a binary+database rollback rehearsal using Phase 8 closure `e8fd6b1` as the old-version baseline.

## 13. Closure handoff

M001–M005, network-control C001, durable-state M001–M004, and durable-state post-Phase-6 C001 are closed and their strict evidence is recorded. **Phase 6 remains closed.** Phase 7 M001, M002, M003, and M004 are all closed; **Phase 7 is closed at `d5d5ca9`** and Phase 8 is unblocked.

Phase 7 M004 closed strictly at `d5d5ca9`. The milestone delivered a self-contained embedded operator shell (12,723 bytes, compiled in, no document root, no external origin, no CSP concession), a deterministic `serve` lifecycle, sessions qualified across a real process restart over real cookies, four-way readiness differentiation, and end-to-end plus abuse/resource qualification against real processes and a real network backend. Two defects were corrected that the code alone would not have shown: `serve` died from `SIGTERM` without draining, because `ctrlc`'s `termination` feature was not enabled and only its handler covers a supervisor's signal; and `ManagementHealth::netd_reachable` could not distinguish a dead backend from an installation that had simply not applied anything yet, so an authenticated live read-only probe was added while the unauthenticated probe was deliberately left unable to dial the privileged backend. The rootful service fixture drives the management HTTP surface against a real `netd` inside a disposable namespace and qualifies real convergence in both directions — `ok` when converged, `degraded` when the backend is gone. Measured footprint is 13.34 MiB combined against the long-term 30 MiB engineering signal, with 0 idle CPU ticks for both roles over a two-second window; nothing was weakened to meet the signal, and the Argon2id parameters remain at the M002 policy, asserted with a latency *floor* so they cannot be traded for speed. No high or medium finding remains open. No historical closure record was edited.

Phase 8 M005 closed at implementation head `8b20a7c`, completing the first user-facing product boundary. The buildless embedded UI consumes the authenticated API for setup, client lifecycle, explicit credential exports, one-time link actions, live telemetry, and audit. The combined Linux-integration suite and six-test product rootful suite passed; the rootful product case configures a real client from HTTP-exported values, proves a kernel handshake and traffic, then drives disable, re-enable, and delete through HTTP. The five embedded assets total 29,811 bytes. The release footprint measured 13.54 MiB combined serve/netd RSS and zero idle CPU ticks over two seconds; no high, medium, or low finding remains open. Phase 9 is now fully planned; M001 is the sole ready implementation plan and Phase 10 remains blocked on Phase 9 closure.

At each future closure, update:

- source implementation-plan status;
- `plans/subsystems/network-control-roadmap.md` milestone table;
- `plans/subsystems/durable-state-restart-reconciliation-roadmap.md` milestone table;
- `plans/subsystems/management-service-security-roadmap.md` milestone table;
- `plans/subsystems/product-management-enrollment-ui-roadmap.md` milestone table;
- `plans/subsystems/operational-hardening-roadmap.md` milestone table;
- this registry;
- current architecture/operator docs.

Historical closure records remain immutable evidence if later corrective work is required.
