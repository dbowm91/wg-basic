# macOS Native Server — Post-M007 Integration and Release Corrective Roadmap

Status: active corrective handoff, 2026-10-20. Source branch `plans/macos-native-support` at `fc51146e811cabebd042d852449c6e7f4f854265`. No corrective implementation or closure is claimed.

Authority: `plans/000-long-term-specification.md`; `plans/003-planning-process.md`; accepted ADR-008 and ADR-001–007; `plans/subsystems/macos-native-server-roadmap.md`; M003–M007 historical closure records. The original M007 MUST-NOT-release verdict remains binding.

## 1. Evidence-triggered correction

The successful hosted run `38524007872` on native macOS arm64 and Intel (2026-10-14) proves specific low-level operations: WireGuard-Go/utun loopback handshakes, UAPI/ownership, v4/v6 address and route fixtures, PF anchor *unattached* probes, and an arm64 launchd lifecycle test. It does **not** demonstrate end-to-end production appliance convergence.

The missing integration is observable directly at this baseline:

- `src/wireguard.rs::WireGuardBackend` returns `UnsupportedBackend` on Darwin, notwithstanding helper/UAPI logic in `src/wireguard/darwin.rs`.
- `src/reconcile/service_darwin.rs::ReconciliationService` returns `BackendFailure` for plan/apply; the pure Darwin planner and direct live `ifconfig`/`route` fixture are not wired to this service.
- `src/firewall/service_darwin.rs::FirewallService` always returns `Unsupported`, so aggregate convergence through the real typed IPC cannot succeed.
- `src/main.rs::run_darwin` rejects system installation/update; `src/launchd.rs` contains install/plist *fixtures*, not a production CLI installation path.
- `src/launchd.rs::render_plist` does not set a restricted service `UserName`/`GroupName`. A system-domain LaunchDaemon defaults to root, risking root management HTTP/SQLite.
- `src/firewall/pf.rs::attachment_verified` uses substring membership and a filter-OR-NAT predicate; neither proves effective policy attachment for both required rule classes.
- Existing `tests/wireguard_darwin_live.rs` drives low-level helpers and direct host utilities; it does not prove an HTTP → management worker → privileged IPC → helper/reconciliation → SQLite receipt loop.
- Current Eggpack/release artifacts are Linux-only. Native reboot, off-host Linux-kernel interop, externally effective IPv4 NAT, routed IPv6 egress, native Intel launchd, and release binaries remain outstanding.

Prior closures were scoped to their recorded evidence and are **not** retroactively invalidated. This corrective records the product-integration gap those narrower fixtures did not exercise. Do not edit historical closures to claim they did.

## 2. Product mode separation and release authority

Distinct capability levels, each requiring truthful observation:

1. **Host-only endpoint:** authenticated management; a managed Mac-owned tunnel and local host services; no forwarding/NAT. Supported only after C001 and C002 are evidenced; **not** automatically releasable.
2. **Routed LAN:** forwarding to specifically approved LAN prefixes and verified operator-managed upstream return routes; no NAT. C003 is an additional authorization and security gate.
3. **Internet exit gateway:** explicit administrator-integrated PF filter/NAT for IPv4; IPv6 routed without NAT66. C004; Apple TN3165 restricts this to advanced-administrator opt-in, not general consumer deployment.

C005 governs all distribution decisions. **ADR-008/M007 currently withhold every macOS release.** A separately scoped host-only or routed release requires a *new explicit maintainer decision and ADR/M007 release-criteria addendum* after its own end-to-end security/installation evidence. No implementer may silently remove the M007 IPv4 NAT/reboot/dual-arch gates or reinterpret a green CI job as release authorization. Full gateway release additionally requires C004 evidence and the existing M007 residuals.

## 3. Dependency graph and active registry

`C001 production host-only integration` (ready, no unmet hard predecessor)
  → `C003 routed-LAN integration` (hard C001)
  → `C004 administrator-integrated PF/NAT` (hard C003 + external controlled host)

`C002 launchd least-privilege/install` (interface-ready in parallel with C001; hard C001 for integrated closure)
  → `C005 native E2E / distribution / release decision` (hard C001 + C002; C003 if routed mode claimed; C004 if gateway claimed; operational external host/authorization gates).

| Corrective | Status | Primary class | Plan | Gate |
|---|---|---|---|---|
| C001 — product wiring and host-only convergence | **ready** | corrective / capability / invariant | `plans/implementation/macos-native-server/c001-production-wiring-host-only.md` | Existing M003/M004/M002 primitives |
| C002 — least-privilege launchd and CLI | **interface-ready; integrated closure blocked on C001** | corrective / invariant | `plans/implementation/macos-native-server/c002-launchd-privilege-and-install.md` | Verified service identity, no root serve |
| C003 — bounded routed LAN | **blocked on C001** | corrective / capability | `plans/implementation/macos-native-server/c003-routed-lan-no-nat.md` | Routed traffic/return-route/admin firewall evidence |
| C004 — effective opt-in PF/NAT | **blocked on C003 and admin-integrated host** | corrective / invariant | `plans/implementation/macos-native-server/c004-pf-nat-effective-gateway.md` | TN3165, effective rules and real egress |
| C005 — integrated release qualification | **blocked on C001/C002 and scoped network gates** | corrective / qualification | `plans/implementation/macos-native-server/c005-release-qualification-and-reconciliation.md` | Native E2E, reboot, architectures, provenance, maintainer authorization |

## 4. Cross-cutting invariants and non-goals

SQLite desired generation and CAS remain authoritative; transient PID, utun number, helper socket and runtime receipts are evidence, never an independent desired-state database. `serve` is unprivileged and alone owns SQLite/HTTP; `netd` alone performs typed OS mutations. No arbitrary shell/PF source/file-write/sysctl/route/exec IPC. A foreign link, route, PF anchor, launchd label, helper, or database must never be adopted by name similarity. Re-observe before destructive operations and report conflicts/degraded instead of forging convergence. A zero-rule host-only firewall result is legal *only* when explicit policy and observable host forwarding behavior prove no forwarding or NAT obligation. No Linux semantics, kernel/nft/systemd CI, pre-existing persistent schemas, or checksums-only release truth may regress.

Keep existing `wireguard-go` as the first Darwin dataplane; do not rebuild protocol crypto, select WireGuardKit/NetworkExtension without a separately accepted ADR, or introduce compulsory Homebrew/Go/runtime package manager requirements. Keep PF advanced-admin-only and never edit `/etc/pf.conf` on behalf of the application.

## 5. Qualification and closure protocol

Each corrective creates its own **new** `plans/closure/macos-native-server-corrective/c00N-status.md` only after implementation. Record final SHA, changes, exact command results and run links, OS build/architecture, user/UID permission evidence, full negative controls, network/interface/PF before/after preservation, failure/retry behavior, unresolved findings with severity, and scope-specific verdict.

Normal gates: `cargo fmt --all -- --check`, `cargo check --all-targets --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`, `cargo +1.89.0 check --all-targets --locked` on supported native targets, plus all pre-existing rootful Linux CI jobs. Run true Mac traffic tests on disposable consented hosts; no silent skips. Distinguish hosted macOS fixtures from controlled/rebootable/admin-integrated host evidence. Do not release, tag, merge as completed support, or create release assets via this planning handoff.
