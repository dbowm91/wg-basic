# macOS Native Server M007 — Native macOS End-to-End, Security, and Release Qualification

Status: **blocked** — verdict recorded in `plans/closure/macos-native-server/007-status.md` (support matrix, threat review, MUST-NOT-release decision, unblock checklist); native dual-arch traffic + release readiness unqualified (shared privileged-host blocker). 2026-10-13.
Primary class: qualification / invariant
Roadmap: plans/subsystems/macos-native-server-roadmap.md M007
Baseline: main 47c72b0e81d569d48396c615120453bf0cf1d46e; reconcile with actual implementation head.
Authority: plans/000-long-term-specification.md; plans/002-long-term-roadmap.md; plans/003-planning-process.md; plans/adr/008-macos-headless-platform-backends.md; existing Linux ADRs remain in force.

## Objective

Demonstrate actual supported macOS headless WireGuard-server capability with native install, API enrollment, traffic, IPv4 NAT, routed IPv6, restart/recovery and safe foreign-state preservation on Apple Silicon and Intel. Record support boundary and future limitations without weak evidence.

## Non-goals

No treating mocked route tests or Rosetta builds as native x86 qualification, no hiding PF unsupported API warning, and no broadening advertised OS floor beyond tested platforms.

## Current repository evidence

Linux Phase 11 closure records 2 real dual-stack kernel namespace tests, 6 HTTP-exported client rootful cases and actual systemd deployment evidence. None runs Darwin. Existing test suite has architecture guards, durable restart/backup fixtures, resource limits and signed-fixture update/rollback; new macOS host tests should mirror their claim categories without pretending they're identical.

## Mandatory invariants

- No unresolved high/medium privilege or network-ownership finding before macOS release claim.
- Actual peer server-client traffic, not config export only, is required. MAC OS backend is not a WireGuard client install convenience path.
- Build/release and advertised support matrix agree with exact native host capability; fail closed for missing PF/admin permissions or unqualified networks.
- All existing Linux kernel and packaging release tests continue passing; macOS requirements do not weaken them.
- Changes after evidence collection invalidate the corresponding qualification until rerun.

## Ordered implementation work

1. Build reproducible release-like artifacts and record full SHA/release metadata + helper provenance; audit released executables/dependencies/SBOM advisories, helper license and platform privileges.
2. Test fresh non-development macOS host installation and local admin password setup (stdin), HTTP auth, server setup, client enrollment/config export, WireGuard handshake and live telemetry.
3. Exercise full-route/split-route IPv4+IPv6 interop to real Linux client; demonstrate IPv4 NAT Internet egress, IPv6 routed return and explicit no NAT66, keeping endpoint resolution/routes accurate across network change.
4. Exercise malicious local IPC client and socket/utun ownership attacks, PF rule collision, wrong binary/receipt, host Internet Sharing, another VPN, modified plist; prove foreign state unchanged and actionable refusal.
5. Crash/reboot/restores: helper killed, netd killed, serve killed, sleep/wake, network switching, disabled state, uninstall and preserved-state reinstall; compare InstallationId/client/server keys and routes; verify crash journal/lease recovery.
6. Benchmark combined RSS/CPU and startup latency; compare Linux established targets while acknowledging userspace dataplane footprint. Publish precise host prerequisite, OS version and support chart.
7. Audit docs/README/CLI/architecture for planned vs current behavior; update registry and closure; no production release if signing/distribution constraints unresolved.

## Security, persistence, protocol, failures and compatibility

Repeat threat review with new trusted helper, launchd identities, Darwin IPC, privileged route/PF operations, state backups and UAPI key exchange. No hidden shell escapes, no raw PF IPC, no accidental unauthenticated network management. Use real destructive-host tests only on disposable hosts/VMs; never operate on developer host default routing without explicit opt-in.

## Native and regression tests

Native arm64 and native x86_64 full lifecycle with exact packet/path assertions; 2+ host types/versions within supported floor if available; route/firewall diff snapshots and foreign service evidence; endpoint roaming; repeated reboot/kill/restart tests; dual-stack split vs full routes; IPv4 NAT and IPv6 no-NAT66. Full Linux CI, Linux rootful E2E, MSRV/clippy/format and release dry-run. Record failures rather than elide missing runners.

## Verification and documentation

Archive exact commands, system logs (with secrets redacted), source/tag SHA, OS build, CPU architecture, GitHub CI run IDs, before/after route/anchor snapshots, actual client handshakes/counters and latency. Update architecture/overview.md, testing-qualification.md, docs/installation.md, README and registry to claim only demonstrated macOS configurations.

## Explicit acceptance criteria

- Real approved headless macOS gateway service operates end to end with clients and authenticates management users.
- IPv4 NAT and IPv6 routed traffic, client lifecycle, disabled state, crash/restart and reinstallation all pass on both native target architectures.
- Fail-closed network/PF ownership, foreign preservation, privileged IPC, signing/provenance policy and package integrity reviewed with no unresolved high/medium findings.
- Exact version/architecture qualification and docs agree; Linux CI passes.
- Archive honest release decision; if macOS PF policy permits only advanced-admin deployment, label it accordingly, not general consumer support.

## Stop conditions

If PF TN3165 gate not resolved for intended distribution, native Intel evidence absent while claiming Intel, production trust assertions exceed checksums-only policy, native traffic/NAT fails or unrelated routing/firewall can be destroyed: do not mark full support closed.

Only after implementation write plans/closure/macos-native-server/007-status.md with exact head, commands/results, native host evidence, preservation and privilege matrix, unresolved severity-graded findings, docs, and a justified closure disposition. Do not edit historical Linux closure evidence.
