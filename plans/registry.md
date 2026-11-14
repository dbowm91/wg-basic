# wg-basic Planning Registry

Status: active

Last registry cleanup: 2026-11-14. This file is the compact planning control surface; detailed requirements, decisions, and evidence remain in their canonical plans and closure records.

## 1. Canonical planning authority

| Document | Role |
|---|---|
| `plans/000-long-term-specification.md` | product scope, architecture, security and operations end state |
| `plans/001-terminology-and-domain-model.md` | canonical vocabulary and type boundaries |
| `plans/002-long-term-roadmap.md` | macro dependency and milestone order |
| `plans/003-planning-process.md` | planning, handoff, corrective, and closure rules |
| `plans/adr/001-linux-native-control-plane.md` | Linux-native, privilege-separated architecture |
| `plans/adr/002-durable-state-generations-and-ownership.md` | persistence, generations, and ownership |
| `plans/adr/003-management-http-auth-and-worker-boundary.md` | management HTTP, auth, and worker boundary |
| `plans/adr/004-product-management-enrollment-and-api-semantics.md` | product mutations, enrollment, and API semantics |
| `plans/adr/005-operational-hardening-maintenance-and-recovery.md` | diagnostics, maintenance, and recovery |
| `plans/adr/006-distribution-install-authenticity-and-update.md` | distribution, authenticity, and update policy |
| `plans/adr/007-ipv6-forwarding-ownership.md` | global IPv6 forwarding ownership |
| `plans/adr/008-macos-headless-platform-backends.md` | staged headless macOS backends and PF policy |
| `plans/adr/009-apple-silicon-only-darwin-target.md` | Apple silicon as the only Darwin target |
| `plans/adr/010-privileged-helper-supervision.md` | privileged supervision of the WireGuard helper |

Implementation handoffs resolve conflicts in this order: canonical specification and terminology; accepted ADRs; subsystem roadmap; implementation plan; current repository evidence.

## 2. Current posture

wg-basic is a Linux-first WireGuard management appliance with a privilege-separated management service and typed network service. Keep operator documentation factual; installation and transactional self-update are not implemented. No macOS release is authorized; the M007 must-not-release decision remains in force.

## 3. Active and recent work

| Workstream | Status | Source of truth |
|---|---|---|
| Headless macOS native server/gateway | Active. C001–C010 and C012–C014 are closed; C011 is conditionally closed; C015 is ready; C005 remains blocked on its release-qualification gates and explicit maintainer authorization. No macOS release. | `plans/subsystems/macos-native-server-roadmap.md`; `plans/subsystems/macos-native-server-corrective-roadmap.md`; §4 below |
| Operator parity (Linux and Apple silicon) | Closed 2026-11-10; M001–M004 closed. Deferred roadmap items remain deferred; C015 is unchanged. | `plans/subsystems/operator-parity-roadmap.md`; `plans/closure/operator-parity/001-status.md` through `004-status.md` |
| Release readiness | R001–R003 closed; R004a closed as an unsigned release; R004b waived. Releases remain checksums-only, no trust root is planned, and production self-update stays disabled. | `plans/subsystems/release-readiness-security-roadmap.md`; `plans/closure/release-readiness/004b-waiver-status.md` |

Other closed subsystem history remains in its roadmap and closure records; it is not repeated here.

## 4. Current macOS handoffs and blockers

| Work item | Status | Handoff |
|---|---|---|
| C015 — managed-interface teardown | Ready. Darwin's observed point-to-point addresses and link-local address do not match the desired address list, so deleting the managed tunnel is refused. Correct the interface delete comparison while preserving refusals for foreign resources; do not reopen C004's firewall work. | `plans/implementation/macos-native-server/c015-macos-interface-teardown-acceptance.md`; C004 evidence in `plans/closure/macos-native-server-corrective/c004-status.md` |
| C005 — native E2E, distribution, and release decision | Blocked. The implementation plan's remaining qualification and authorization gates still apply; M007's must-not-release decision stands until they are explicitly satisfied and amended by the maintainer. | `plans/implementation/macos-native-server/c005-release-qualification-and-reconciliation.md`; `plans/closure/macos-native-server/007-status.md` |
| C017 — secret-scan corrective | Conditionally closed. Its closure records one previously reported GitGuardian incident for the workspace owner to resolve; repository changes do not clear that recorded dashboard occurrence. | `plans/closure/macos-native-server-corrective/c017-status.md` |

Operator-parity closures did not authorize a Darwin release or change C015. Its deferred items and stop conditions remain in the roadmap.

## 5. Release disposition

The maintainer waived the signed-production gate on 2026-10-11. Releases are checksums-only; no production signing key or trust root is planned, and `update check` / `update run` fail closed. `v0.1.0` is stable and unsigned. See the R004a/R004b closure records and `docs/release-signing.md` for the release evidence and limitations.

## 6. Planning hygiene

- Plans describe intended or active work; current-behavior documentation describes only implemented behavior.
- Do not create closure records before evidence exists. Historical closure records remain period-accurate when corrective work follows.
- Do not create later implementation plans merely to fill a roadmap; hand off work when its predecessor contracts are stable enough for a bounded plan.
- Detailed closed-work status belongs in its source plan or closure record, not in this registry.
