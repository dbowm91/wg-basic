# macOS Native Server — Post-M007 Integration and Release Corrective Roadmap

Status: active corrective line, 2026-10-20. Source branch `plans/macos-native-support`; corrective handoff recorded at `fc51146e811cabebd042d852449c6e7f4f854265`; **C001 and C002 implemented at `1806d3e` and dispositioned `blocked (narrowed)`**; C003–C005 remain blocked. The original M007 MUST-NOT-release verdict remains binding and nothing in this line changes it.

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

**Status of the gap list above (2026-10-20, implementation head `1806d3e`):** the
gaps above are the ones **C001 and C002 were created to close**, and both plans
are now implemented against them. The Darwin production backend is wired
(no longer `UnsupportedBackend`), the Darwin reconciliation service runs the
typed planner over the real Darwin APIs (no `ifconfig`/`route` subprocess), the
Darwin firewall refuses routed/NAT policies instead of blanket-no-oping, the
launchd plist sets a restricted service identity, and `src/main.rs` exposes a
real `system install/status/uninstall` path. The `pf.rs` `attachment_verified`
weakness is C004's subject and remains open. Both plans are nonetheless
dispositioned **blocked (narrowed)**, because each plan's own acceptance gate
requires evidence a hosted macOS runner cannot produce — see §3.

## 2. Product mode separation and release authority

Distinct capability levels, each requiring truthful observation:

1. **Host-only endpoint:** authenticated management; a managed Mac-owned tunnel and local host services; no forwarding/NAT. Supported only after C001 and C002 are evidenced; **not** automatically releasable.
2. **Routed LAN:** forwarding to specifically approved LAN prefixes and verified operator-managed upstream return routes; no NAT. C003 is an additional authorization and security gate.
3. **Internet exit gateway:** explicit administrator-integrated PF filter/NAT for IPv4; IPv6 routed without NAT66. C004; Apple TN3165 restricts this to advanced-administrator opt-in, not general consumer deployment.

C005 governs all distribution decisions. **ADR-008/M007 currently withhold every macOS release.** A separately scoped host-only or routed release requires a *new explicit maintainer decision and ADR/M007 release-criteria addendum* after its own end-to-end security/installation evidence. No implementer may silently remove the M007 IPv4 NAT/reboot/dual-arch gates or reinterpret a green CI job as release authorization. Full gateway release additionally requires C004 evidence and the existing M007 residuals.

## 3. Dependency graph and active registry

`C001 production host-only integration` (**implemented at `1806d3e`; disposition blocked (narrowed)** — no unmet hard predecessor; the **arm64** closure gate is met by a controlled-host run against an off-host Linux-kernel peer, and what remains is the native Intel arch of the same path)
  → `C003 routed-LAN integration` (hard C001 closure, not merely C001 implementation)
  → `C004 administrator-integrated PF/NAT` (hard C003 + external controlled host)

`C002 launchd least-privilege/install` (**implemented at `1806d3e`; disposition blocked (narrowed)** — integrated closure is hard C001, and the plan additionally forbids closure unless reboot persistence is demonstrated)
  → `C005 native E2E / distribution / release decision` (hard C001 + C002; C003 if routed mode claimed; C004 if gateway claimed; operational external host/authorization gates).

| Corrective | Status | Primary class | Plan | Gate |
|---|---|---|---|---|
| C001 — product wiring and host-only convergence | **blocked (narrowed)** 2026-10-20; implemented at `1806d3e`; closure `plans/closure/macos-native-server-corrective/c001-status.md` | corrective / capability / invariant | `plans/implementation/macos-native-server/c001-production-wiring-host-only.md` | Existing M003/M004/M002 primitives — met. Off-host Linux-kernel peer, dual-stack off-host traffic, and API telemetry through the real authenticated HTTP path — **met on arm64** on a controlled host. Remaining: the **native Intel** arch of the same path |
| C002 — least-privilege launchd and CLI | **blocked (narrowed)** 2026-10-20; implemented at `1806d3e`; closure `plans/closure/macos-native-server-corrective/c002-status.md` | corrective / invariant | `plans/implementation/macos-native-server/c002-launchd-privilege-and-install.md` | Verified service identity, no root serve — met and observed at runtime. Remaining: cold reboot on a rebootable host, and the C001 traffic leg |
| C003 — bounded routed LAN | **blocked on C001 closure** | corrective / capability | `plans/implementation/macos-native-server/c003-routed-lan-no-nat.md` | Routed traffic/return-route/admin firewall evidence |
| C004 — effective opt-in PF/NAT | **blocked on C003 and admin-integrated host** | corrective / invariant | `plans/implementation/macos-native-server/c004-pf-nat-effective-gateway.md` | TN3165, effective rules and real egress |
| C005 — integrated release qualification | **blocked on C001/C002 and scoped network gates** | corrective / qualification | `plans/implementation/macos-native-server/c005-release-qualification-and-reconciliation.md` | Native E2E, reboot, architectures, provenance, maintainer authorization |

### Unblock assessment (2026-10-20)

**Nothing downstream unblocks.** C001 and C002 are implemented, but both are
dispositioned **blocked (narrowed)** rather than closed, so their hard
dependencies are unmet:

- **C003 stays blocked on C001.** C001's implementation satisfies the
  *engineering* predecessor; its closure gate (a second, independent
  Linux-kernel WireGuard peer reached through the real authenticated HTTP path,
  with dual-stack traffic and API telemetry on arm64 and Intel) does not. A
  hosted macOS runner has no second kernel.
- **C004 stays blocked on C003 + an admin-integrated controlled host.** Nothing
  in C001/C002 changes this; the `pf.rs` effective-attachment weakness above
  remains C004's own subject.
- **C005 stays blocked on C001 + C002**, plus the claimed-mode gates and the
  operational external-host and maintainer-authorization gates.

Both unmet gates are **environmental, not code defects**: the recorded
evidence is expected to satisfy them once the hosts exist, but the planning
process forbids closing a plan from expected evidence, so neither is claimed.
These are the same two residuals M003 (off-host interop) and M006 (reboot)
already record; the C001/C002 implementation narrows the *product* gap without
narrowing those environmental ones.

**Host-only mode (capability level 1 in §2) is implemented but not releasable.**
C001 and C002 together deliver the host-only endpoint's mechanics; the
host-only release still requires C005's release decision and the explicit
maintainer ADR/M007 addendum described in §2. Nothing here authorizes a macOS
release, a tag, a release asset, or a merge as completed support.

## 4. Cross-cutting invariants and non-goals

SQLite desired generation and CAS remain authoritative; transient PID, utun number, helper socket and runtime receipts are evidence, never an independent desired-state database. `serve` is unprivileged and alone owns SQLite/HTTP; `netd` alone performs typed OS mutations. No arbitrary shell/PF source/file-write/sysctl/route/exec IPC. A foreign link, route, PF anchor, launchd label, helper, or database must never be adopted by name similarity. Re-observe before destructive operations and report conflicts/degraded instead of forging convergence. A zero-rule host-only firewall result is legal *only* when explicit policy and observable host forwarding behavior prove no forwarding or NAT obligation. No Linux semantics, kernel/nft/systemd CI, pre-existing persistent schemas, or checksums-only release truth may regress.

Keep existing `wireguard-go` as the first Darwin dataplane; do not rebuild protocol crypto, select WireGuardKit/NetworkExtension without a separately accepted ADR, or introduce compulsory Homebrew/Go/runtime package manager requirements. Keep PF advanced-admin-only and never edit `/etc/pf.conf` on behalf of the application.

## 5. Qualification and closure protocol

Each corrective creates its own **new** `plans/closure/macos-native-server-corrective/c00N-status.md` only after implementation. Record final SHA, changes, exact command results and run links, OS build/architecture, user/UID permission evidence, full negative controls, network/interface/PF before/after preservation, failure/retry behavior, unresolved findings with severity, and scope-specific verdict.

Normal gates: `cargo fmt --all -- --check`, `cargo check --all-targets --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`, `cargo +1.89.0 check --all-targets --locked` on supported native targets, plus all pre-existing rootful Linux CI jobs. Run true Mac traffic tests on disposable consented hosts; no silent skips. Distinguish hosted macOS fixtures from controlled/rebootable/admin-integrated host evidence. Do not release, tag, merge as completed support, or create release assets via this planning handoff.

### Applied to C001/C002

Two closure records exist under `plans/closure/macos-native-server-corrective/`:
`c001-status.md` and `c002-status.md`. Both record the implementation head,
the requirement-to-evidence matrix, the exact commands and hosted run, the
security/ownership evidence, the docs evidence, the known limitations, the
findings by severity, and a scope-specific verdict. Both verdicts are
**blocked (narrowed)**.

Two rules from the qualification protocol shaped those verdicts and shape every
later corrective in this line:

1. **A hosted macOS runner is not a controlled host.** It has no second kernel
   to peer with and cannot be cold-rebooted. Evidence produced there is
   recorded as hosted fixture evidence and is never written up as the
   controlled-host evidence C001/C002's acceptance requires.
2. **A green CI job is not release authorization and not closure.** The
   M007 MUST-NOT-release decision and the §2 release-authority rule are
   unchanged by any implementation in this line.
