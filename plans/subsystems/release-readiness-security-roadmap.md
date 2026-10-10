# Release Readiness, Supply-chain Security, and First Public Distribution Roadmap

Status: R001–R003 repository-owned engineering implemented; strict hosted/settings closure and production signing remain gated; R004 blocked. No public release authorization.
Repository review baseline: `dbowm91/wg-basic@0b814fe` (2026-10-10).
Primary owner: `wg-basic` release and operator trust surface; Eggpack continues to own generator/producer mechanics, Eggup the consumer-side binary/service transaction.
Governance: `plans/003-planning-process.md`; ADR-006; `plans/subsystems/distribution-install-update-roadmap.md`; `plans/002-long-term-roadmap.md`.

## 1. Purpose and ownership boundary

Convert technically qualified Phase 10 distribution and Phase 11 dual-stack appliance into **verifiably authentic, independently reviewable and explicitly authorized** first-public-release artifacts. This is a new release-readiness/security subline, not a retrospective reopening of closed M001–M005 or IPv6 M001–M004.

Eggpack owns tag-aware generated workflow, binary packaging/qualification, release manifest creation and draft staging. wg-basic owns the project trust root, sign-off/policy, first-install UX, exact native systemd product tests, signature-before-projection updater requirement and go/no-go decision. Eggup remains the already qualified local update and service substrate.

## 2. Source-backed baseline and finding classification

Current engineering qualifications are real, but historically bounded: M004 full CI `37929917248`, native target `37929920418`; M005 full CI `37936112512`, native lifecycle `37936276064`; Phase 11 final full 15-job CI `37959251834`. The repo's current merge head `ff40f85` is not automatically proven by the earlier exact-SHA results. The C001/C001a/C002, M004/M005 and IPv6 M004 closure records remain the evidence sources.

| Finding | Severity for first public release | Direct evidence | Disposition |
|---|---|---|---|
| RF-01 — shell interpolation of dispatch input in generated release workflow | High release-process risk (privileged workflow integrity); exploitability limited by manual-dispatch authorization | Historical vulnerable renderer at `eggstack/eggpack@d61ca71`; workflow regenerated from qualified `559d940af0fe6a2951eb17de1fcbecbf9e0bb6ce`; env-mediated canonical tag validation has an adversarial regression | Code corrected; exact-head hosted CI and repository release policy remain gates |
| RF-02 — source/run/tag/draft binding not independently authenticated by signing verifier alone | High release-authenticity risk if unsigned receipt is promoted to trust authority | New read-only provenance workflow plus `scripts/verify-release-signing-bundle.py`; signer checks both GitHub run records, live tag, exact draft inventory, and fresh bytes | Tooling implemented; actual production run/draft proof awaits signed-candidate availability |
| RF-03 — production trust root absent, public draft not signed | Absolute public-release blocker, intentional fail-closed state (not exploitable bypass) | `src/release.rs::PRODUCTION_PUBLIC_KEY = None`; `docs/installation.md`; no production signing/key provisioning in records | R002 operational gate |
| RF-04 — convenience installer executes network-fetched `install-exact.sh` as root before signature verification | High consequence under compromised bootstrap delivery; acknowledged lower-assurance mode under ADR-006, not a hidden invariant bypass | Wrapper labels the mode lower assurance, fixes system `PATH`, and stages privately; `docs/installation.md` verifies signed metadata/installer before root execution | Accepted convenience limitation; use signed path once production key/draft exists |
| RF-05 — first public signed-draft/installer/native lifecycle evidence absent | Release qualification blocker, not an established production bug | Phase 10/11 tests use signed fixtures; signing/release keys withheld by design | R004 final current-SHA go/no-go |
| RF-06 — release-workflow toolchain and actor settings require independent operational attestation | Medium process-review debt until verified, not evidence of misconfiguration | `release/eggpack/github-policy.json`, `release-eggpack.yml` pinned GitHub actions/tool revision; settings not source-readable | R001 repository approval/tag protection and R004 release packet |

Severity reflects pre-publication threat/consequence and evidence available, **not** proof of an exploited issue or compromise. Review did not execute attacks against CI or publish any tag. Read-only GitHub inspection on 2026-10-10 found no rulesets, `main` unprotected, and no tag-protection rules; Actions default token permissions are read-only and all actions are allowed. Observations and required maintainer settings are in `docs/release-signing.md`. Source review is not a full formal penetration test.

## 3. Invariants

- No private release key in source, ordinary CI, logs or artifacts.
- All signed manifest/installer and selected binary bytes match an immutable authorized source/tag/version/run and the independently authenticated project public key.
- Signature verification must precede treating manifest as trustworthy and must precede executing any remotely obtained script/binary in the recommended high-assurance install path.
- No release workflow evaluates untrusted dispatch input as executable shell content; only a gated minimal stage job writes draft artifacts.
- Supported Linux GNU x86_64 and aarch64 targets alone receive a release claim; kernel WireGuard/nftables/systemd prerequisites are explicit.
- Exact-owned systemd/user/binary/state and foreign host resources remain safe; default uninstall preserves VPN secrets.
- Production self-update remains disabled while `PRODUCTION_PUBLIC_KEY=None`; no fixture bypass or automatic unsigned fallback.
- Existing typed privileged IPC and loopback-first management exposure remain unchanged. TLS proxy is explicitly operator-supplied.
- Release publication is an irreversible human-approved action; a green synthetic fixture is never approval.

## 4. Capabilities, infrastructure and polish

### Release capabilities

A maintainer can independently establish tag/source/build provenance, sign approved manifest and installer out of band, verify the entire draft, ship both native targets with signed authenticator, and publish after explicit sign-off. An operator can follow an independently authenticated install path without executing unverified remote code as root.

### Infrastructure

Use the existing project Minisign verifier, `scripts/verify-signing-request.py`, Eggpack-generated workflow/pinned toolchain, Rust 1.89 and locked Cargo graph, and disposable native systemd/rootful testing. Add bounded non-secret release source/run/artifact provenance receipts and adversarial test scripts where necessary. No additional product-runtime dependency is authorized merely for release engineering.

### Polish

Public docs must distinguish unsigned convenience bootstrap from verified installation, list the canonical fingerprint source, runbook, incident/key rotation behavior and external host/runtime prerequisites without claiming unsupported architectures or public release before proof.

## 5. Non-goals

No new VPN protocol, IPv6 dataplane features, netd privilege escape, generic CLI shell, mandatory embedded Sigstore client, Docker/Node/Python runtime dependency, automatic tag creation/publishing, ARMv7/musl/Windows/macOS deployment promise, background updater daemon or automatic production key generation.

## 6. Dependency graph

```text
Phase 10 + Phase 11 technical closures [done]
              |
              +--> R001 — safe generated workflow + source/run provenance [implemented; hosted/settings gate]
              |
              +--> R002 — non-secret offline signing tooling [implemented; real key/draft blocked]
              |         \-- actual signing [R001 closure + maintainer key/approval]
              |
              +--> R003 — verified first-install UX and security checks [implemented; production proof blocked]
              |         \-- production signed-install [R002 operational closure]
              |
              \--> R004 — exact public candidate security/CI/go-no-go [BLOCKED]
                        hard: R001 closed + R002 operational + R003 production proof
                        operational: explicit maintainer publish authorization
```

Eggpack generator input interpolation was confirmed at `eggstack/eggpack@d61ca71`. Upstream CI M003j is closed at `eggstack/eggpack@559d940af0fe6a2951eb17de1fcbecbf9e0bb6ce` (hosted run `37987890305`, all required lanes green). The consumer pins and regenerates from that producer. R001's exact-head hosted run and repository protections remain outstanding; no generated YAML hand patch is used. R002's non-secret preflight and R003's install procedure are implemented, while actual production key custody/signatures remain external blockers.

## 7. Ordered milestones

### R001 — Workflow input and provenance hardening

Plan: `plans/implementation/release-readiness/001-release-workflow-input-and-provenance-hardening.md`.
Status: **implemented; strict closure pending**.
Main gate: adversarial dispatch rejection, tag/source/run/artifact checks and qualified generator pin are in place. Strict closure also requires the producer to validate canonical tags before its current `preflight` checkout (which presently only runs `cargo --version`), exact-head hosted CI, and maintainer-configured protected `main`/immutable `v*` tags. No settings have been changed.

### R002 — Offline signing and production trust root

Plan: `plans/implementation/release-readiness/002-production-trust-root-and-offline-signing-ceremony.md`.
Status: **non-secret implementation complete; operational signing blocked** on R001 strict closure, maintainer-supplied key custody/fingerprint, and approved draft.
Main gate: source/run/tag/live-asset preflight, fixture signature negative controls, and offline ceremony docs exist. Production key provisioning, embedded fingerprint, actual signing, and key custody remain maintainer work.

### R003 — High-assurance first-install bootstrap

Plan: `plans/implementation/release-readiness/003-bootstrap-installer-trust-and-root-execution-boundary.md`.
Status: **repository engineering implemented; production acceptance blocked** on R002 and signed-artifact qualification.
Main gate: signed command procedure checks manifest/installer before parsing or root execution, with tag/source/target/size/hash and root-owned rechecks. The regression asserts command order; actual production qualification awaits authenticated signatures.

### R004 — Signed production draft and release decision

Plan: `plans/implementation/release-readiness/004-first-production-release-security-qualification-and-authorization.md`.
Status: **blocked**.
Main gate: independently verified actual signed draft, exact source/tag, native x86_64+aarch64 systemd lifecycle, updated dual-stack and failed-candidate rollback/restore CI, security finding review, explicit maintainer go/no-go, final post-publication verification.

## 8. Failure, retry and incident concerns

Any unverified input or mismatched run blocks staging/signing; any invalid signature, missing public-key custody evidence, mutable tag, failed native host qualification or high/medium finding blocks publication. A partial draft/signature upload is not a release, and retry must reauthenticate all bytes. Existing installation state and backups are never touched by a planning or signing task. Security incident policy must preserve an independent route to revoked/rotated key distribution: a current installed binary cannot silently accept untrusted new release keys.

## 9. Required verification evidence

- Static generated-workflow expression/injection guard plus a test that fails on the current defect and passes on correction.
- Signed fixture identity/tamper/negative key tests and real separately authenticated production key/signature proof.
- Native x86_64 and aarch64 build/ELF/glibc-floor, real systemd installation/uninstall/reinstall, update/rollback/recover where supported, and IPv4/IPv6 full/split tunnel traffic evidence.
- Rust 1.89, locked dependency/format/clippy/unit tests, pinned cargo-audit, security review of release-specific diff.
- Actual GitHub Actions run URLs and exact source SHA/tag/digest evidence, not generically green status.
- Reviewed registry/branch/tag protection, least-privilege write actor, human signing/publishing authorization and first public release operational response.

## 10. Risks and decisions

The highest risk is treating a self-consistent release receipt or a GitHub HTTPS download as independent authenticity. The recommended release path must have separate trust anchor and actor approval. Generator-owned Bash interpolation was corrected and qualified in Eggpack CI M003j; keep the exact consumer pin and drift check. Repository tag/branch protections and a generated stage-environment reviewer gate are not configured/supported. The first public release can be staged in an unsigned draft for review but may never be marked publicly signed/authentic until all operational gates close. Future updater trust-key rotation requires a separately scoped ADR/plan if needed.

## 11. Completion definition

R001–R003 have strict technical evidence and R002/R003 operational key/signing evidence; R004 has actual current-SHA public-release source and asset checks, independent approved verification, both native host lifecycles, no high/medium issues, explicit maintainer publish approval and verified published URL/bytes. If the maintainer has not supplied a signing key or has not authorized publication, status remains **blocked externally** even when engineering preparation is complete.

## 12. Milestone status

| Milestone | Status | Implementation plan | Hard/operational blocker |
|---|---|---|---|
| R001 | consumer implementation complete; strict closure pending | `plans/implementation/release-readiness/001-release-workflow-input-and-provenance-hardening.md` | Producer preflight ordering, current-head hosted CI, maintainer branch/tag protection; stage reviewer gate needs producer support |
| R002 | non-secret engineering complete; signing blocked | `plans/implementation/release-readiness/002-production-trust-root-and-offline-signing-ceremony.md` | R001 strict closure; real key custody/fingerprint and approved signed draft |
| R003 | technical procedure implemented; production acceptance blocked | `plans/implementation/release-readiness/003-bootstrap-installer-trust-and-root-execution-boundary.md` | R002 real key/signatures and current native signed-install qualification |
| R004 | blocked | `plans/implementation/release-readiness/004-first-production-release-security-qualification-and-authorization.md` | R001 closed + R002 operational + R003 production acceptance + maintainer publish decision |

Conditional closure records for repository-owned R001–R003 implementation belong under `plans/closure/release-readiness/`. Keep external settings, trust-root, signed-draft, and publication gates open; they cannot be marked complete by fixture results.
