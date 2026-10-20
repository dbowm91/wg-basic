# wg-basic Planning Registry

Status: active

Last planning reconciliation: 2026-10-20 (macOS C001/C002 implemented and dispositioned **blocked (narrowed)**; C001's arm64 product path against an off-host Linux-kernel peer now closed with observed evidence and the native Intel arch of the same path recorded as environmentally blocked; C002's three-phase cold-reboot qualification written with its arm phase observed and passing on a controlled arm64 host; C003–C005 re-assessed and still blocked; macOS C001–C005 corrective handoff registered; 2026-10-13 macOS server planning added; prior release policy retained; 2026-10-11 (R001–R004a closed; R004b waived by maintainer decision — checksums-only releases, `v0.1.0` stable; solo-maintainer policy with zero required PR approvals))

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
| `plans/adr/006-distribution-install-authenticity-and-update.md` | accepted Phase 10 release/install/authenticity/update architecture |
| `plans/adr/007-ipv6-forwarding-ownership.md` | accepted Phase 11 global IPv6 forwarding ownership contract |
| `plans/adr/008-macos-headless-platform-backends.md` | accepted staged headless macOS support direction; PF/NAT remains gated by Apple TN3165 |

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

Current production code state: **Network control and Phases 6–11 are technically closed. The authenticated product API and embedded UI provide server setup, client lifecycle, config/QR export, one-time enrollment, live telemetry, bounded audit history, operational diagnostics, safe maintenance/recovery, and a proven old/new database rollback contract.** Phase 10 is release-mechanically complete: native x86_64/aarch64 systemd install, signed-fixture update/recovery, state-preserving uninstall/reinstall, and guarded purge are qualified. Phase 11 dual-stack tunnel addressing, IPv6 forwarding/firewall ownership, client route policy/product surface, and dual-stack end-to-end qualification are strictly closed. Releases are checksums-only by maintainer decision (`v0.1.0` stable, unsigned); self-update is permanently fail-closed and every release needs a fresh install.

## 3. Eggstack reuse disposition

Current research and planning disposition:

| Eggstack project | Disposition | Handoff note |
|---|---|---|
| EggServe | selected Phase 7 substrate | direct `eggserve-server` + `eggserve-primitives` H1 service; wg-basic owns routing/auth/CSRF/rate limits and embeds its own assets; no Tower/Axum in the baseline |
| Eggup | selected Phase 10 substrate | Core owns staged/integrity/ownership-safe binary replacement; acquisition + preferred curl adapter own bounded download mechanics; Eggpack adapter projects signed manifest evidence; service crate owns systemd mechanics. wg-basic still owns authenticity, two-service/state transaction, health, journal, and recovery. |
| Eggpack | selected Phase 10 producer substrate | canonical two-target release/build/qualification/manifest/bootstrap/draft-release contracts; no release signing or appliance service policy delegated to Eggpack |
| Eggfetch | alternate Phase 10 update transport only | not selected in baseline because eggup-curl keeps the shipped link graph smaller; may replace curl only with recorded host-availability/footprint evidence |
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
| Operational hardening | closed | `plans/subsystems/operational-hardening-roadmap.md` | M001–M005 closed; Phase 9 closed |
| Distribution/install/update | closed (technical) | `plans/subsystems/distribution-install-update-roadmap.md` | M001–M005 closed; production release remains blocked on signing |
| IPv6/route-policy qualification | closed | `plans/subsystems/ipv6-route-policy-roadmap.md` | M001–M004 closed; `plans/closure/ipv6-route-policy/004-status.md` |
| Release readiness and supply-chain security | closed (R004b waived; checksums-only releases) | `plans/subsystems/release-readiness-security-roadmap.md` | R001–R004a closed; waiver `004b-waiver-status.md` |
| Headless macOS native server/gateway | active; low-level M001–M004 qualified; C001/C002 product wiring implemented, C001's arm64 controlled-host product path now evidenced; M005–M007 blocked | `plans/subsystems/macos-native-server-roadmap.md` + `plans/subsystems/macos-native-server-corrective-roadmap.md` | C001 **blocked (narrowed)** 2026-10-20 — the arm64 product path against an off-host Linux-kernel peer is closed with observed evidence; the native Intel arch of the same path remains unmet. C002 **blocked (narrowed)** — the three-phase cold-reboot qualification is written and its arm phase is observed and passing on a controlled arm64 host; the reboot itself is the remaining gate. C003–C005 remain blocked. M003/M004 native runner `38524007872` does not prove product runtime; macOS MUST NOT release |

Do not create the later subsystem implementation plans merely to fill the roadmap. Research/write them when their predecessor contracts are stable enough for a bounded handoff.

## 4A. Active macOS server implementation and corrective handoff

Architecture: `plans/adr/008-macos-headless-platform-backends.md`.
Canonical new roadmap: `plans/subsystems/macos-native-server-roadmap.md`.
Baseline: `47c72b0e81d569d48396c615120453bf0cf1d46e` (Linux stable `v0.1.0` remains unchanged).
macOS M001–M004 have qualified **isolated primitives** below (M003–M004 live on hosted arm64 + Intel runners, run `38524007872`); production WireGuardBackend/ReconciliationService/FirewallService still fail closed and live tests bypass application convergence. M005–M006 carry narrowed blocked tails; M007 retains MUST-NOT-release standing. C001–C005 own product integration, least privilege, scoped routing/PF, and release requalification. No macOS release, integrated network-server or gateway claim exists.

**Update 2026-10-20 (implementation head `1806d3e`):** C001 and C002 are now *implemented*, not merely planned. The Darwin production backend (`src/wireguard/darwin_backend.rs`, `src/reconcile/backend_darwin.rs`, `src/reconcile/service_darwin.rs`, `src/firewall/service_darwin.rs`) and the least-privilege installer (`src/launchd.rs`, `src/launchd_install.rs`) are wired into the real typed paths, with the audited OS boundary isolated in the `crates/darwin-sys` workspace member. Both plans are dispositioned **blocked (narrowed)**: their implementation and their hosted native evidence exist, and a controlled arm64 host has since produced the off-host Linux-kernel peer leg of C001 and the arm phase of C002's cold-reboot qualification. What each plan's own acceptance gate still needs is evidence a hosted macOS runner cannot produce: the **native Intel** arch of C001's product path, whose peer has to be reachable from the runner, and the **reboot** of C002's armed controlled host. C003–C005 remain blocked; the M007 MUST-NOT-release standing is unchanged.

| Milestone | Status | Handoff |
|---|---|---|
| M001 portability/Cargo/build/typed platform seams | **closed 2026-10-13** | `plans/implementation/macos-native-server/001-portable-boundaries-and-darwin-build.md`; closure `plans/closure/macos-native-server/001-status.md` |
| M002 Darwin IPC, peer identity and doctor | **closed 2026-10-13** (M001 closed) | `plans/implementation/macos-native-server/002-darwin-privileged-ipc-and-capabilities.md`; closure `plans/closure/macos-native-server/002-status.md` |
| M003 wireguard-go/utun lifecycle/UAPI | **closed 2026-10-14** (hosted live arm64+Intel, run `38524007872`) | `plans/implementation/macos-native-server/003-wireguard-go-utun-backend.md`; closure `plans/closure/macos-native-server/003-status.md` — loopback handshake/traffic/counters/RSS/ownership/kill-restart both arches; off-host interop residual |
| M004 address/route ownership and Darwin reconciliation | **closed 2026-10-14** (hosted live arm64+Intel, run `38524007872`) | `plans/implementation/macos-native-server/004-darwin-interface-address-route-reconciliation.md`; closure `plans/closure/macos-native-server/004-status.md` — v4+v6 lifecycle, planner-vs-live-observation, preservation; sleep/roaming residual |
| M005 forwarding, PF/NAT and Apple policy review | **blocked** (narrowed 2026-10-14; hosted live, run `38524007872`) | `plans/implementation/macos-native-server/005-forwarding-pf-nat-and-platform-policy.md`; closure `plans/closure/macos-native-server/005-status.md` — TN3165 decision evidence-backed; anchor/forwarding/PF-cycle qualified; effective NAT + v6 egress need admin-integrated host; installer MUST NOT auto-configure PF |
| M006 launchd, installer, helper provenance and recovery | **blocked** (narrowed 2026-10-14; hosted live arm64, run `38524007872`) | `plans/implementation/macos-native-server/006-launchd-installation-distribution-and-recovery.md`; closure `plans/closure/macos-native-server/006-status.md` — bootstrap/KeepAlive/bootout/reinstall/DB-free qualified; reboot + post-reboot traffic need rebootable host |
| M007 native dual-arch E2E, security and release qualification | **blocked** (updated 2026-10-14: MUST-NOT-release stands) | `plans/implementation/macos-native-server/007-native-e2e-security-release-qualification.md`; closure `plans/closure/macos-native-server/007-status.md` — M003–M004 closed, M005–M006 narrowed, residuals enumerated (off-host interop, NAT+v6 egress, reboot, Intel launchd, release audit + authorization) |


### Active macOS corrective implementation plans — 2026-10-20

Recorded against `fc51146e811cabebd042d852449c6e7f4f854265`; source roadmap: `plans/subsystems/macos-native-server-corrective-roadmap.md`. C001 and C002 were **planning-only** handoffs at that baseline; both are now implemented at `1806d3e` with their own closure records. Historical M003–M007 closures remain untouched.

| Corrective | Status | Implementation plan / immediate gate |
|---|---|---|
| C001 production WireGuard/reconciliation/firewall host-only integration | **blocked (narrowed)** 2026-10-20 — implemented at `1806d3e`; closure `plans/closure/macos-native-server-corrective/c001-status.md` | `plans/implementation/macos-native-server/c001-production-wiring-host-only.md` — the production Darwin wiring, the joint ownership proof, and the host-only firewall refusal are done and natively evidenced; the **arm64** product path against an off-host Linux-kernel peer — handshake, dual-stack traffic, API telemetry — is now closed with observed evidence; the remaining gate is the **native Intel** arch of the same path |
| C002 privileged launchd identity/installer | **blocked (narrowed)** 2026-10-20 — implemented at `1806d3e`; closure `plans/closure/macos-native-server-corrective/c002-status.md` | `plans/implementation/macos-native-server/c002-launchd-privilege-and-install.md` — the unprivileged `serve` identity, the constrained plist renderer, the exact fs/IPC layout, and the transactional installer are done and hosted-live evidenced; the three-phase cold-reboot qualification is written with its arm phase observed and passing on a controlled arm64 host; the remaining gate is the reboot itself |
| C003 bounded routed LAN without NAT | **blocked** on C001 | `plans/implementation/macos-native-server/c003-routed-lan-no-nat.md` — forwarding, admin policy, proven return routing. C001's *implementation* is in place, but its closure gate is not met, so C003 does not yet unblock |
| C004 effective administrator-opt-in PF/NAT | **blocked** on C003 + controlled host | `plans/implementation/macos-native-server/c004-pf-nat-effective-gateway.md` — independent filter/NAT effective attachment and packet evidence; TN3165 |
| C005 E2E, Eggpack, and release authorization | **blocked** on C001+C002 and claimed-mode C003/C004 | `plans/implementation/macos-native-server/c005-release-qualification-and-reconciliation.md` — support matrix, Intel launchd/reboot, release truth; M007 MUST-NOT-release remains |

**Unblock assessment (2026-10-20):** neither C001 nor C002 unblocks its successors, because both are dispositioned **blocked (narrowed)** rather than closed — the implementation landed, but each plan's own acceptance gate is unmet and the planning process forbids closing from expected evidence. C003 therefore stays blocked on C001's closure gate; C004 stays blocked on C003 plus an external controlled host; C005 stays blocked on C001+C002 plus the claimed-mode gates. The two unmet gates are environmental, not code defects: C001's **arm64** gate was met by a controlled-host run against an off-host Linux-kernel WireGuard peer (real installer, real daemons, real authenticated HTTP surface, real handshake, dual-stack traffic, API telemetry), and what remains is the **native Intel** arch of that same path, whose peer has to be reachable from a hosted runner; C002's cold-reboot qualification is written and its arm phase is observed and passing on a controlled arm64 host, and what remains is the reboot itself — the same two residuals M003 and M006 already record. When those hosts exist, the recorded evidence is expected to satisfy the gates without further implementation, but that expectation is not closure.

**Hosted qualification (macOS run `39427791794`):** all four jobs pass — `gates-arm64`, `gates-intel`, `live-arm64`, `live-intel-tunnel`. The C001 live qualification proves the joint ownership proof, the production backend's observation of the managed device, the receipt's survival across a reader restart, and a teardown with no leaked device, socket, or receipt. The C002 live qualification runs the product's own transactional installer and observes the privileged daemon as root and the management daemon as the dedicated unprivileged account, with the privileged socket root-owned and reachable only by the management group. Linux native CI run `39427800154` passes every job except the pre-existing `dependency-audit` upstream `zip` advisory.

Staged host-only/routed capability does **not** automatically permit a macOS release: the original M007 gateway/reboot/dual-arch requirements remain binding. Any narrower release needs an explicit maintainer-approved ADR-008/M007 decision before publication; gateway still needs C004. All old Linux state, CI, artifacts, updater policy and historical closures remain unchanged.

Explicit macOS stop gate: Apple TN3165 warns PF is not an API for broad product use. PF anchor/NAT capability for advanced-admin deployments must be documented, qualified and approved separately before advertising full macOS gateway support. Do not modify foreign PF configuration automatically or accept compilation as networking evidence. Linux remains canonical and strictly qualified.

## 5. Implementation plan status (including external gates)

| Subsystem | Milestone | Status | Implementation plan | Dependencies / handoff |
|---|---|---|---|---|
| Release readiness/security | R001 workflow input/provenance hardening | **closed at `1e034d0`** | `plans/implementation/release-readiness/001-release-workflow-input-and-provenance-hardening.md` | Exact-head CI `38108270370` + Distribution `38108270368` green; live preflight deferred to R004 |
| Release readiness/security | R002 offline signing and trust root | closed (non-secret engineering) at `1e034d0` | `plans/implementation/release-readiness/002-production-trust-root-and-offline-signing-ceremony.md` | Single-maintainer ceremony; production key/draft are R004 operations |
| Release readiness/security | R003 verified first-install trust | closed (repository engineering) at `1e034d0` | `plans/implementation/release-readiness/003-bootstrap-installer-trust-and-root-execution-boundary.md` | First signed install is R004 evidence |

## 6. External readiness blockers

| Subsystem | Milestone | Status | Implementation plan | Hard blocker |
|---|---|---|---|---|
| Release readiness/security | R004a initial unsigned pre-release | **closed 2026-10-11** (`v0.1.0` public pre-release) | `plans/implementation/release-readiness/004-first-production-release-security-qualification-and-authorization.md` §4A | Release run `38115877717` + provenance `38152418203` green; digest-verified draft and public assets; closure `plans/closure/release-readiness/004a-status.md` |
| Release readiness/security | R004b signed-production gate | **waived by maintainer decision 2026-10-11** | `plans/implementation/release-readiness/004-first-production-release-security-qualification-and-authorization.md` §§4–10 (retained as future spec) | Checksums-only releases; `v0.1.0` stable; waiver `plans/closure/release-readiness/004b-waiver-status.md` |
| Distribution/install/update | Production signing and public release | R004 operation | `plans/subsystems/release-readiness-security-roadmap.md` and R002/R004 checklists | Maintainer key custody, tag, signed draft, current CI, install check, and explicit publication authorization |

The initial 2026-10-09 release-readiness review at `main@ff40f85` found shell interpolation in the generated workflow and no independent source/run proof. Eggpack M003k closed the producer finding at `1103a1affc62a210f1102a769457db80d9188bc8` (hosted run `38027470046`); it validates and resolves the release tag before checkout and freezes the selected commit. Consumer regeneration, security regressions, and settings evidence are recorded in the dated follow-up below. No production key was generated, installed or stored, and no release was staged or published.

R001–R003 repository implementation pins Eggpack M003k and regenerates the workflow with pre-checkout canonical tag resolution, rejects injection payloads, records source-run/asset provenance, adds a signer preflight, hardens and labels the convenience installer, and documents the signed first-install process. Earlier hosted CI `38022851605` and Distribution Foundation `38022853831` passed at `bd7c085`; this follow-up has local qualification but awaits exact-head hosted checks. GitHub has protected `main` (zero required approvals; maintainer merges after green checks)/immutable `v*` tag rules, selected Actions allowlist/read-only default permissions, and a single-maintainer `release-staging` approval with self-approval allowed. R001–R003 close on exact-head hosted evidence; the first live staging, key/draft, and signed install are R004 operations. No production key was generated or installed; no release was staged or published. No second reviewer is required anywhere.

M004 corrective ordering: upstream `eggstack/eggup` Service M010 owned-failed-systemd quiescence and required M011 publication are closed; wg-basic C001a, C001, and C002 have actual-updater hosted recovery evidence; M004 technical closure is recorded at `plans/closure/distribution/004-status.md`; M005 and Phase 10 are now strictly closed at `plans/closure/distribution/005-status.md`. Fixture evidence does not claim production signing or public release readiness.

M004 and its corrective slices are closed: `plans/closure/distribution/004-status.md`, `004-c001-status.md`, `004-c001a-status.md`, and `004-c002-status.md`. M005 is closed at `plans/closure/distribution/005-status.md`. Production public-release readiness additionally requires maintainer provisioning of the real release signing trust root and a production-signed draft. Fixture signing is sufficient to qualify mechanics but MUST NOT be described as production signing.

## 7. Recently closed work

- macOS C001 **blocked (narrowed)** 2026-10-20: production Darwin host-only
  wiring implemented at `1806d3e` — the Darwin `WireGuardBackend` with a
  durable runtime registry and a *joint* ownership proof (process executable
  identity + helper digest + socket owner/type + kernel device), the Darwin
  reconciliation service over the audited `getifaddrs`/`sysctl`/`ioctl`/`AF_ROUTE`
  boundary, an explicitly host-only firewall that *refuses* routed and
  masquerade policies, and the real capability surface — with the audited
  `unsafe` isolated in the `crates/darwin-sys` workspace member so the product
  crate keeps `#![forbid(unsafe_code)]`. Closure gate unmet: the plan's
  off-host Linux-kernel peer / dual-stack / API-telemetry acceptance needs a
  second kernel a hosted runner does not have. Closure
  `plans/closure/macos-native-server-corrective/c001-status.md`.
- macOS C002 **blocked (narrowed)** 2026-10-20: least-privilege launchd and a
  real installer implemented at `1806d3e` — a dedicated unprivileged
  `_wg-basic-serve` management principal (verified in the plist *and* observed
  by effective UID at runtime), a fully fixed plist renderer that takes no
  caller path, an exact fs/IPC layout with symlink and mode refusals, a
  transactional installer with rollback, and helper provenance checked at
  execution time. Closure gate unmet: the plan blocks closure when reboot
  persistence cannot be demonstrated, and a hosted runner cannot cold-reboot.
  Closure `plans/closure/macos-native-server-corrective/c002-status.md`.
- macOS M003 closed 2026-10-14: hosted live qualification on arm64 +
  Intel (`macos-15`, `macos-15-intel`, macOS 15.7.9, run `38524007872`) —
  pinned-helper spawn, utun delta mapping, hex-key UAPI set/get, dual-stack
  loopback handshake/traffic/counters/RSS (~6.2 MiB/helper), ownership
  proof + negative case, kill/restart with renumber tolerance. Two
  kernel-vs-helper wire deviations fixed in the codec (hex keys, errno
  trailer). Closure `plans/closure/macos-native-server/003-status.md`.
- macOS M004 closed 2026-10-14: v4+v6 address/alias lifecycle on live
  `utun`, pure planner verified against live observation, default route
  byte-identical, inventories scoped (counter drift excluded after one
  false-positive). Closure
  `plans/closure/macos-native-server/004-status.md`.
- macOS M005 narrowed 2026-10-14: TN3165 advanced-admin-only decision now
  evidence-backed (attachment needs system-ruleset surgery the OS guards);
  anchor lifecycle, forwarding/PF cycle with restore, unattached-inert
  proof, no-false-convergence qualified live. Effective NAT + v6 egress
  remain blocked. Closure
  `plans/closure/macos-native-server/005-status.md`.
- macOS M006 narrowed 2026-10-14: plist lint, system bootstrap/print/
  bootout, KeepAlive re-supervision, DB-free state, reinstall cycle
  qualified live on arm64. Reboot + post-reboot traffic remain blocked.
  Closure `plans/closure/macos-native-server/006-status.md`.
- macOS M007 verdict updated 2026-10-14: MUST-NOT-release stands with
  enumerated residuals (off-host Linux interop, NAT+v6 egress, reboot,
  Intel launchd, release audit + authorization). Closure
  `plans/closure/macos-native-server/007-status.md`.
- macOS M007 blocked verdict 2026-10-13: support matrix (only loopback
  management + IPC qualified on arm64), threat review, serve footprint
  (0.097s ready, 11.3 MiB RSS, 0.0% idle), docs audit, binding MUST-NOT-release
  decision + 5-step unblock checklist. Closure
  `plans/closure/macos-native-server/007-status.md`. The line is closed as far
  as unprivileged qualification can take it.
- macOS M006 blocked 2026-10-13: installation scope at `8a063de`
  (two-label plists, provenance receipts with helper hash + Darwin targets,
  explicit-root install/verify/state-preserving-uninstall fixtures; 4 unit
  tests; no signing claims). Native install/boot/reboot/recovery
  unqualified — shared privileged-host blocker. Closure
  `plans/closure/macos-native-server/006-status.md`.
- macOS M005 blocked 2026-10-13: TN3165 advanced-admin-only decision +
  anchor model at `be077d1` (installation-scoped anchors, masquerade without
  NAT66, attachment verification, drift digest, conservative teardown; 6 unit
  tests; read-only facts: pfctl root-gated, forwarding 0/0 untouched). Live
  gateway traffic unqualified — shared privileged-host blocker; installer
  MUST NOT auto-configure PF. Closure
  `plans/closure/macos-native-server/005-status.md`.
- macOS M004 blocked 2026-10-13: modeling scope at `42fa94c` (typed Darwin
  observation, pure planner with idempotence/foreign-preservation/conflict/
  global-takeover/renumber cases; 6 unit tests; purity guard). Native
  convergence unqualified — shared privileged-host blocker; no convergence
  claimed. Closure `plans/closure/macos-native-server/004-status.md`.
- macOS M003 blocked 2026-10-13: safe unprivileged scope at `b1c831c`
  (pinned wireguard-go 0.0.20250522 MIT, fixed-argv supervision, bounded UAPI
  codec, fail-closed ownership logic, audited process boundary; 9 new unit
  tests). Live utun handshake/traffic unqualified — no sudo/disposable Mac
  VM/opt-in in this session; no packet claim made. Closure
  `plans/closure/macos-native-server/003-status.md`.
- macOS M002 strict closure 2026-10-13: Darwin `getpeereid` IPC at `96075b5`
  (authorized Ping/capabilities, no root bypass, bounded framing, socket
  lifecycle, SIGTERM/restart; 6/6 native `darwin_ipc` + 10 portable socket
  unit tests). Closure
  `plans/closure/macos-native-server/002-status.md`. M003 is now ready.
- macOS M001 strict closure 2026-10-13: portable Cargo/build/typed platform
  seams at `9c99fc6` (native arm64 `cargo test` 561 passed; Intel target
  compiles; loopback admin/serve/auth/doctor smoke reports backend-unavailable
  degradation, never convergence). Closure
  `plans/closure/macos-native-server/001-status.md`. M002 is now ready.
- Release-readiness R004a closure 2026-10-11: `v0.1.0` public pre-release
  (unsigned, evaluation only) at source `7527241`. Release run
  `38115877717` (11 jobs) + provenance run `38152418203` green; RF-07
  producer tag-fetch fix (`eggstack/eggpack@a0fec98`) verified live;
  draft and public assets digest-verified byte-identical; maintainer
  staging approval + draft-to-pre-release flip. Closure
  `plans/closure/release-readiness/004a-status.md`.
- Release-readiness R004b waiver 2026-10-11: the signed-production gate is
  waived by maintainer decision; releases are checksums-only and `v0.1.0`
  was promoted to stable unsigned. Waiver
  `plans/closure/release-readiness/004b-waiver-status.md`. The release
  subsystem is now closed.

- Release-readiness R001 strict closure at `1e034d0`: Eggpack M003k pin,
  regenerated workflow, zero-approval solo-maintainer policy, exact-head
  hosted CI `38108270370` (21 passed) and Distribution Foundation
  `38108270368` green. First live staging run is an R004 operation.
- Release-readiness R002 strict closure (non-secret engineering) at
  `1e034d0`: single-maintainer ceremony, fixture negative matrix,
  fail-closed default; production key/draft are R004 operations.
- Release-readiness R003 strict closure (repository engineering) at
  `1e034d0`: authenticated install procedure, ordering regression,
  truthful convenience-mode labels; first signed-install run is R004
  evidence.
- Distribution M005 strict closure and **Phase 10 technical closure**:
  `plans/closure/distribution/005-status.md` (implementation head `c7de919`;
  full CI `37936112512`; native release/lifecycle CI `37936276064`). Public
  publication remains blocked on production signing and explicit maintainer
  authorization.
- IPv6/route-policy M001 strict closure:
  `plans/closure/ipv6-route-policy/001-status.md` (head `fa25918`; full CI
  `37945376954`; native product job `113870168633`). M002 and M003 strict
  closures are recorded below; M004 and Phase 11 are now strictly closed.
- IPv6/route-policy M002 strict closure:
  `plans/closure/ipv6-route-policy/002-status.md` (implementation head
  `306ec64`; full CI `37952330395`; rootful network-control job
  `113894015843`). M003 is strictly closed; M004 is unblocked.
- IPv6/route-policy M003 strict closure:
  `plans/closure/ipv6-route-policy/003-status.md` (implementation head
  `7bfa28f`; full CI `37955744248`; rootful product job `113905694296`).
  M004 and Phase 11 are now strictly closed under their closure record.
- IPv6/route-policy M004 strict closure and **Phase 11 technical closure**:
  `plans/closure/ipv6-route-policy/004-status.md` (implementation head
  `f72ac4d`; full CI run `37959251834`; rootful product job `113917592634`,
  network-control job `113917592920`, and systemd job `113917592267`).
- Operational-hardening M001 strict closure: `plans/closure/operational-hardening/001-status.md` (implementation commit `3e5b21c`; real-kernel doctor drift/convergence/conflict fixtures).
- Operational-hardening M002 strict closure: `plans/closure/operational-hardening/002-status.md` (implementation commit `ae60e81`; real serve lease, schema v5, network lifecycle, recovery and purge evidence).
- Operational-hardening M003 strict closure: `plans/closure/operational-hardening/003-status.md` (implementation commit `5815c59`; structured events, bounded retention, crash/resource qualification, and service-manager contract).
- Operational-hardening M004 strict closure: `plans/closure/operational-hardening/004-status.md` (implementation commits `f821e3b` and `4c326f4`; abuse-boundary tests, threat review, and pinned advisory gate).
- Operational-hardening M005 strict closure and **Phase 9 closure**: `plans/closure/operational-hardening/005-status.md` (implementation head `6a9f354`; CI run `37741533304`).
- Distribution M001 strict closure: `plans/closure/distribution/001-status.md` (implementation head `c4d4e87`; native target run `37782271310`; full CI run `37782271299`).
- Distribution M002 strict closure: `plans/closure/distribution/002-status.md` (implementation head `d1813da`; systemd qualification and full CI run `37799075225`).
- Distribution M003 historical blocked disposition: `plans/closure/distribution/003-status.md`; prerequisite re-review/unblock: `plans/closure/distribution/003-unblock-review.md`.
- Distribution M003 mechanical closure: `plans/closure/distribution/003-final-status.md` (implementation head `568d568`; native target run `37853066003`; full CI run `37853066011`).
- Distribution M004 C001 initial corrective-required disposition and superseding strict closure: `plans/closure/distribution/004-c001-status.md` (implementation head `e26e9f2`; rootful/full CI run `37900751408`).
- Distribution M004 C001a strict scoped closure: `plans/closure/distribution/004-c001a-status.md` (hosted actual-updater run `37896480910`; upstream Eggup 0.1.3 typed failed-unit adoption).
- Distribution M004 C002 strict rootful qualification: `plans/closure/distribution/004-c002-status.md` (head `0b01078`; dedicated rootful run `37929914324`).
- Distribution M004 strict technical closure: `plans/closure/distribution/004-status.md` (final qualified head `0b01078`; full CI `37929917248`; native targets `37929920418`; production signing/publication pending).

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

Phase 10 is technically closed under ADR-006 and `plans/subsystems/distribution-install-update-roadmap.md`; M001–M005 closure evidence is recorded. The selected baseline is two native Linux GNU targets, a signed Eggpack ReleaseManifest with project-owned Minisign trust, native systemd installation, Eggup-owned local binary mechanics, wg-basic-owned two-service/database orchestration, a root-owned crash-recovery journal, and state-preserving uninstall. The production private signing key remains outside repository/ordinary CI authority; public-release readiness requires maintainer provisioning of the real trust root and a production-signed draft. Phase 11 M001–M004 are strictly closed under `plans/closure/ipv6-route-policy/004-status.md`.

## 13. Closure handoff

M001–M005, network-control C001, durable-state M001–M004, and durable-state post-Phase-6 C001 are closed and their strict evidence is recorded. **Phase 6 remains closed.** Phase 7 M001, M002, M003, and M004 are all closed; **Phase 7 is closed at `d5d5ca9`** and Phase 8 is unblocked.

Phase 7 M004 closed strictly at `d5d5ca9`. The milestone delivered a self-contained embedded operator shell (12,723 bytes, compiled in, no document root, no external origin, no CSP concession), a deterministic `serve` lifecycle, sessions qualified across a real process restart over real cookies, four-way readiness differentiation, and end-to-end plus abuse/resource qualification against real processes and a real network backend. Two defects were corrected that the code alone would not have shown: `serve` died from `SIGTERM` without draining, because `ctrlc`'s `termination` feature was not enabled and only its handler covers a supervisor's signal; and `ManagementHealth::netd_reachable` could not distinguish a dead backend from an installation that had simply not applied anything yet, so an authenticated live read-only probe was added while the unauthenticated probe was deliberately left unable to dial the privileged backend. The rootful service fixture drives the management HTTP surface against a real `netd` inside a disposable namespace and qualifies real convergence in both directions — `ok` when converged, `degraded` when the backend is gone. Measured footprint is 13.34 MiB combined against the long-term 30 MiB engineering signal, with 0 idle CPU ticks for both roles over a two-second window; nothing was weakened to meet the signal, and the Argon2id parameters remain at the M002 policy, asserted with a latency *floor* so they cannot be traded for speed. No high or medium finding remains open. No historical closure record was edited.

Phase 8 M005 closed at implementation head `8b20a7c`, completing the first user-facing product boundary. The buildless embedded UI consumes the authenticated API for setup, client lifecycle, explicit credential exports, one-time link actions, live telemetry, and audit. The combined Linux-integration suite and six-test product rootful suite passed; the rootful product case configures a real client from HTTP-exported values, proves a kernel handshake and traffic, then drives disable, re-enable, and delete through HTTP. The five embedded assets total 29,811 bytes. The release footprint measured 13.54 MiB combined serve/netd RSS and zero idle CPU ticks over two seconds; no high, medium, or low finding remains open. Phase 9 M001–M005 are now strictly closed with the upgrade/rollback and clean-target recovery evidence at `plans/closure/operational-hardening/005-status.md`. Phase 10 M001 is strictly closed; M002 is ready, while installation and self-update behavior remain unimplemented.

At each future closure, update:

- source implementation-plan status;
- `plans/subsystems/network-control-roadmap.md` milestone table;
- `plans/subsystems/durable-state-restart-reconciliation-roadmap.md` milestone table;
- `plans/subsystems/management-service-security-roadmap.md` milestone table;
- `plans/subsystems/product-management-enrollment-ui-roadmap.md` milestone table;
- `plans/subsystems/operational-hardening-roadmap.md` milestone table;
- `plans/subsystems/distribution-install-update-roadmap.md` milestone table;
- this registry;
- current architecture/operator docs.

Historical closure records remain immutable evidence if later corrective work is required.
