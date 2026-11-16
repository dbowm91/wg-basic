# wg-basic Planning Registry

Status: active

Last registry cleanup: 2026-11-14. This file is the compact planning control surface; detailed requirements, decisions, and evidence remain in their canonical plans and closure records.

Windows native server implementation is in the tree at the ADR-011 baseline `554de7a3b5ae83700222a290664fbbbeb3cd521a`. M001–M007 are implemented and their closure is blocked on `windows-2025` evidence. No support sentence is published.

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
| `plans/adr/011-windows-server-wireguard-nt.md` | staged Windows Server 2025 x64 direction; dataplane is pinned `wireguard-nt` 1.1; no support claim until closure evidence exists |
| `plans/adr/012-authentication-expansion-totp-oidc.md` | account settings, TOTP, OIDC/OAuth, allow-listed auto-register, password-auth disable |
| `plans/adr/013-observability-metrics-and-telemetry-history.md` | Prometheus/JSON scrape policy, cardinality labels, bounded telemetry history |
| `plans/adr/014-macos-apple-silicon-release-authorization.md` | Maintainer amendment of M007 MUST-NOT-release for Apple silicon; checksums-only; advanced-admin gateway; C015/C005 publication gates |

Implementation handoffs resolve conflicts in this order: canonical specification and terminology; accepted ADRs; subsystem roadmap; implementation plan; current repository evidence.

## 2. Current posture

wg-basic is a Linux-first WireGuard management appliance with a privilege-separated management service and typed network service. Keep operator documentation factual. Production self-update stays fail-closed (checksums-only; no trust root). **ADR-014** amends M007: Apple silicon headless server publication is maintainer-authorized under an exact matrix; operator “supported” claims wait on C015 controlled-host teardown evidence and C005 packaging/docs closure. No Intel Mac. No Darwin self-update.

## 3. Active and recent work

| Workstream | Status | Source of truth |
|---|---|---|
| Headless macOS native server/gateway | Active. C001–C010 and C012–C014 closed; C011 conditionally closed; C015 **implemented** (closure blocked on controlled-host disable evidence); C005 **active** under ADR-014 (Eggpack `aarch64-apple-darwin` contracted; helper companion + docs + C005 closure remain). Authorized-pending, not yet a published macOS support claim. | `plans/adr/014-macos-apple-silicon-release-authorization.md`; `plans/subsystems/macos-native-server-roadmap.md`; `plans/subsystems/macos-native-server-corrective-roadmap.md`; §5 below |
| Operator parity (Linux and Apple silicon) | Closed 2026-11-10; M001–M004 closed. Deferred roadmap items remain deferred; C015 is unchanged. | `plans/subsystems/operator-parity-roadmap.md`; `plans/closure/operator-parity/001-status.md` through `004-status.md` |
| Release readiness | R001–R003 closed; R004a closed as an unsigned release; R004b waived. Releases remain checksums-only, no trust root is planned, and production self-update stays disabled. | `plans/subsystems/release-readiness-security-roadmap.md`; `plans/closure/release-readiness/004b-waiver-status.md` |
| Headless Windows Server | Implemented 2026-11-10. M001–M007 closure is blocked on `windows-2025` handshake, route, and translated-echo evidence. No support claim. | `plans/subsystems/windows-native-server-roadmap.md`; `plans/adr/011-windows-server-wireguard-nt.md`; `plans/implementation/windows-native-server/` |
| Security-audit corrective (S001) | Closed 2026-11-16. PF token refusal, absolute `nft` pin, and separate `/healthz` admission landed. | `plans/closure/security-audit/001-status.md` |
| Phase 12 operator auth expansion | **Implemented** M001–M004 in tree (2026-11-16). Account password, TOTP, generic OIDC, Google/GitHub, allow-list auto-register, password-auth disable + CLI recovery. Closure records pending maintainer evidence. | `plans/subsystems/operator-auth-expansion-roadmap.md`; `plans/implementation/operator-auth-expansion/`; ADR-012 |
| Phase 12 operator UI polish | **Implemented** M001–M003 in tree (theme, sparklines, related polish). Closure records pending. | `plans/subsystems/operator-ui-polish-roadmap.md`; `plans/implementation/operator-ui-polish/` |
| Phase 12 observability metrics | **Implemented** M001–M003 in tree (Prometheus, JSON scrape, bounded telemetry history). Closure records pending. | `plans/subsystems/observability-metrics-roadmap.md`; ADR-013 |

Other closed subsystem history remains in its roadmap and closure records; it is not repeated here.

## 4. Phase 12 status (implemented in tree)

| Work item | Status | Handoff |
|---|---|---|
| Auth M001 — account password change | Implemented. | `plans/implementation/operator-auth-expansion/001-account-password-change.md` |
| Auth M002 — TOTP | Implemented. | `plans/implementation/operator-auth-expansion/002-totp-second-factor.md` |
| Auth M003 — generic OIDC | Implemented. | `plans/implementation/operator-auth-expansion/003-generic-oidc.md` |
| Auth M004 — Google/GitHub, allow-list, password disable | Implemented. | `plans/implementation/operator-auth-expansion/004-oauth-providers-allowlist-password-disable.md` |
| UI M001 — theme switcher + asset ceilings | Implemented. | `plans/implementation/operator-ui-polish/001-theme-switcher-and-asset-ceilings.md` |
| UI M002 — visual polish | Implemented. | `plans/implementation/operator-ui-polish/002-visual-polish.md` |
| UI M003 — telemetry sparklines | Implemented. | `plans/implementation/operator-ui-polish/003-telemetry-sparklines.md` |
| Observability M001 — Prometheus scrape | Implemented. | `plans/implementation/observability-metrics/001-prometheus-scrape.md` |
| Observability M002 — JSON metrics | Implemented. | `plans/implementation/observability-metrics/002-json-metrics.md` |
| Observability M003 — telemetry history | Implemented. | `plans/implementation/observability-metrics/003-telemetry-history.md` |

Milestone **closure** records remain separate; they are created only when maintainer evidence exists (`plans/003-planning-process.md` §6).

## 5. Current macOS handoffs and blockers

| Work item | Status | Handoff |
|---|---|---|
| ADR-014 — M007 release authorization | Accepted 2026-11-16. Amends MUST-NOT-release for Apple silicon only. | `plans/adr/014-macos-apple-silicon-release-authorization.md`; M007 amendment section in `plans/closure/macos-native-server/007-status.md` |
| C015 — managed-interface teardown | **Implemented** 2026-11-16. Planner accounts for Darwin `/32`/`/128` and link-local on delete. Closure blocked on controlled-host `network disable` evidence. | `plans/implementation/macos-native-server/c015-macos-interface-teardown-acceptance.md` |
| C005 — native E2E, distribution, docs | **Active** under ADR-014. Eggpack Darwin target + `macos-15` runner contracted; remaining: helper companion packaging script/docs, operator matrix, C015 host evidence, C005 closure verdict. | `plans/implementation/macos-native-server/c005-release-qualification-and-reconciliation.md` |
| S001 — PF token, absolute `nft`, health admission | Closed 2026-11-16. Did not reopen C004's anchor contract or C015. | `plans/closure/security-audit/001-status.md` |
| C017 — secret-scan corrective | Conditionally closed. Its closure records one previously reported GitGuardian incident for the workspace owner to resolve; repository changes do not clear that recorded dashboard occurrence. | `plans/closure/macos-native-server-corrective/c017-status.md` |

## 6. Release disposition

The maintainer waived the signed-production gate on 2026-10-11. Releases are checksums-only; no production signing key or trust root is planned, and `update check` / `update run` fail closed. `v0.1.0` is stable and unsigned. See the R004a/R004b closure records and `docs/release-signing.md` for the release evidence and limitations. ADR-014 authorizes Apple silicon macOS server publication under that same checksums-only policy once C015 and C005 close; it does not enable Darwin self-update.

## 7. Planning hygiene

- Plans describe intended or active work; current-behavior documentation describes only implemented behavior.
- Do not create closure records before evidence exists. Historical closure records remain period-accurate when corrective work follows.
- Do not create later implementation plans merely to fill a roadmap; hand off work when its predecessor contracts are stable enough for a bounded plan.
- Detailed closed-work status belongs in its source plan or closure record, not in this registry.
