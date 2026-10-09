# Release Readiness R004 — First Production Release Security Qualification and Authorization

Status: blocked on R001 strict closure, R002 operational signing/trust-root completion, R003 production verified-install evidence, and explicit maintainer approval.
Repository baseline: `dbowm91/wg-basic@ff40f851508ccda52171c27cefdcdaf4ec1da2d5` (2026-10-09); rebaseline on the exact tagged candidate source and requalify at that SHA.
Source roadmap: `plans/subsystems/release-readiness-security-roadmap.md`.
Primary class: invariant / end-to-end qualification / release operation.
Authority: ADR-006; `plans/closure/distribution/001-status.md`–`005-status.md`; `plans/closure/ipv6-route-policy/004-status.md`; `plans/003-planning-process.md`.

## 1. Objective and release decision

Provide a strictly auditable **go/no-go** gate for the first publicly downloadable wg-basic release. This gate links project-controlled Minisign authenticity, immutable tagged source, reviewed CI/workflow/toolchain, independently verified draft artifact bytes, supported x86_64/aarch64 installed systemd lifecycles, IPv4/IPv6 traffic, updater/rollback/recovery, management exposure, and maintainer approval. The engineering milestone closure of Phase 10/11 does not itself authorize production publication.

This plan does not publish automatically or create a production signing key. A passing *technical* release-qualification report is not sufficient if any independent signing, human approval or production pilot gate remains blocked.

## 2. Readiness and known baseline

- Phase 10 M001–M005 are technically closed; M005 final head `c7de919` has full CI run `37936112512` and distribution foundation run `37936276064` for two GNU architectures. Phase 11 M004 closure at `f72ac4d` records full 15-job run `37959251834`, 580 ordinary tests passed, three ignored, dual-stack namespace traffic, and a published-scope management hardening architecture.
- `eggup-service = "=0.1.3"` is pinned and its owned-failed-unit quiescence mechanism is published/qualified upstream. The updated repo `main` merge head at this planning baseline is `ff40f85`; exact merge-head workflows are not independently inferred green solely from an earlier run.
- `src/release.rs::PRODUCTION_PUBLIC_KEY=None`; no maintainer signing key, signed production draft, independently verified public fingerprint or public release authorization is present in repository evidence.
- Existing installer paths include lower-assurance convenience mode, and release generated workflow contains executable interpolation of `release_tag`. R001–R003 explicitly repair/qualify these gates.
- The source package version remains `0.1.0`. First release tagging must be deliberate: exact stable release ID is an input selected and approved by the maintainer, not assumed from a template example.

## 3. Non-negotiable security invariants

1. **Authenticity**: independently authenticated public Minisign key; exact signed manifest and signed installer; full installed binary artifact digest and target binding; runtime updater signature-before-parse and strict version monotonicity; no fixture/trust override in production.
2. **Source/provenance**: frozen `vX.Y.Z` source SHA, clean reproducible source receipt, Cargo/binary/release-manifest/GitHub tag identity, exact release workflow/toolchain and build/qualification run ids; no mutable or unqualified tag/asset.
3. **Distribution privileges**: staging token scoped to a single write phase; non-stage jobs read-only; no dynamic shell dispatch input; private signing key never in repo/CI; no automatic publication.
4. **Host safety**: only exactly owned binary/service/sysusers state is installed, updated or uninstalled; foreign files/units/interfaces/routes/nftables remain untouched; default uninstall preserves database/keys; destructive purge needs explicit verified confirmation.
5. **VPN**: dual-stack WireGuard backend and client configs remain interoperable, no NAT66, IPv6 routing/forwarding ownership unchanged, server/client disable/re-enable and crash recovery preserve desired state.
6. **Management**: unprivileged `serve`, privileged `netd` only CAP_NET_ADMIN, typed peer-credential UDS, loopback by default, no direct public HTTP without a separately configured secure proxy, Host/Origin/CSRF, session/Argon2id, audit/log redaction, no leakage of private keys in release receipts/tests.
7. **Failure/rollback**: old binary never runs candidate-migrated SQLite; updater journal/service lease/backup/old generation only converge to a proved compatible pair; failed service quiescence proof from Eggup 0.1.3 remains enforced; crash recovery and re-update are qualified on disposable real systemd hosts.
8. **No silent scope expansion**: no ARMv7/musl/macOS/Windows/OpenRC claim, no package-manager auto-install, no external TLS feature claim, no automatic key rotation, no guessed support for distributions merely meeting glibc minimum.

## 4. Ordered work packages

### WP1 — Candidate freeze and independent review packet

Select stable version and authoritatively freeze tag/source SHA with reviewed source tree, clean lockfile and release workflow. Assemble a release-readiness packet including threat model and explicit findings, source/asset/attestation manifest, dependency graph and cargo audit, license/source attribution, branch/tag protection settings as verified by maintainer, runtime/minimum host requirements, release notes/version, known issues and remediation contacts. Review source diff from the most recent qualified closure head including new release security changes; do not treat historical Codex Security zero-finding scan as coverage for the new diff.

### WP2 — Static/dynamic security review on exact candidate

Perform bounded review of:
- release workflow input injection/provenance, signing receipt, installer bootstrap and root boundary, update URL/redirect bounds and signature/manifest parsing;
- root-owned paths/permissions/atomicity/symlinks/locks and service lifecycle, backup/WAL restore, retained secret-bearing snapshots;
- systemd capability allowlist and hardening, UDS peer credentials, fixed privileged operations, unprivileged HTTP/UI route surface;
- auth/session/cookie/CSRF/Origin/Host rules, rate-limit-before-Argon2id, no unauthenticated admin setup, secret-safe logs and JSON; default loopback listener and guidance for TLS proxy;
- IPv4/IPv6 policy scope and foreign kernel state preservation;
- dependency advisory and license checks, build toolchain pin, source-to-binary evidence and hidden fixture/bypass build switches.

Produce a severity-ranked finding table with proof/source, exploit preconditions, mitigations and an owner. Any confirmed high/medium security finding opens a separate corrective plan and blocks this gate, rather than being silently waved away because Phase 10/11 is closed. State clearly what was inspected/read-only versus executed.

### WP3 — Reproduce exact release CI and artifact set

At the chosen immutable tagged SHA, run full required workspace tests with Rust 1.89; clippy/format, locked dependency audit, full fifteen-or-later CI jobs, distribution foundation release contract, Eggpack generator drift, native x86_64 and aarch64 GNU glibc floor, native smoke/systemd lifecycle, product management, rootful WireGuard control, IPv4/IPv6 namespace E2E and update/rollback/recovery. Confirm candidate binary embedded key matches the independently known production public key and does not contain test-only acquisition/transport/signing controls.

Record native checks and actual artifact digest/size and runtime target; no checkbox green without exact current SHA/run URL. Prefer a current signed-updater installation/rollback rehearsal at the shipped schema (including schema v7 where now applicable), not only Phase 9 v4/v5 fixtures. If production signing cannot yet be completed, run a fixture-only dry-run but leave R004 operationally blocked.

### WP4 — Signed draft verification from independent machine

Use R002 human-approved offline ceremony. Download final GitHub draft again from a fresh trusted machine, authenticate source SHA/identity/receipt/run and both detached Minisign signatures with out-of-band key, verify target artifacts and installer digest/hash-size matches signed metadata. Reject any unsigned/missing extra asset or source/draft mismatch. Validate there are no mutable asset rewrites after signing. Run R003 high-assurance first install from **exact these signed release assets** on disposable clean hosts, without running downloaded code prior to signature verification.

### WP5 — Pilot / failure / rollback / reproducibility

Test a controlled first-install to configured client traffic on both x86_64 and aarch64 systemd hosts; verify product admin bootstrap, session and HTTP loopback defaults, client config export, WireGuard IPv4/IPv6 handshake, full/split tunnel and disabled/re-enabled path. Exercise state-preserving uninstall/reinstall, wrong owner/unit refusal, fail-closed purge, old-version/new-version update check/run, failed-candidate restore and update recover under representative interruptions. The existing extensive fixture-signed updater matrix can be referenced only for its recorded architecture/SHA; if the first production-signed candidate cannot be used in an actual eligible updater transition, document the limitation and require an additional authorized release-to-release/installed-canary plan before claiming production updates field-proven.

Capture dependency footprint, memory, cold startup and storage/backup amplification as observations, not SLAs. Establish operational support/runbook, recovery commands, security disclosure path and how to revoke a compromised key or yank/quarantine a release without weakening installed clients' verification policy.

### WP6 — Explicit publish/no-publish decision

Require a signed-off release checklist with independent reviewer/maintainer approval of every release asset, source tag, signature/fingerprint, target matrix, security finding dispositions, GitHub permissions/protection, user-facing authenticity instructions, and release notes. Only maintainer may change a verified draft to public. Post-publication fetch exact assets and signature-verify again; recheck updater canonical tag discovery on a safely controlled newer-version fixture; record where public download was verified.

Document an emergency-stop plan for wrong key, tag movement, compromised hosting/signature key, urgent binary vulnerability, and accidental unsafe system install. Avoid reissuing a tag or silently changing a signed release at the same version.

## 5. Dependency graph and execution state

R001 workflow/provenance correction -> strict close.
R002 independent signing/tooling may develop concurrently, but real production signing requires R001 provenance and maintainer key/approval -> operational close.
R003 verified installer can develop concurrently, but real signed install evidence requires R002 operational close -> operational close.
R004 begins final release qualification **only when all three are strictly accepted**; its public publication always requires explicit maintainer authorization. Phase 12 feature work remains a separate product decision and is not a blocker unless it introduces a security change in the candidate.

## 6. Tests, review and operational commands

```text
python3 scripts/test-release-workflow-security.py
python3 scripts/test-release-signing-bundle.py
python3 scripts/test-verified-install.py
python3 scripts/test-release-installer.py
python3 scripts/test-release-smoke.py
python3 scripts/test-signing-request.py
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
cargo audit
git diff --check
```

R004 additionally requires hosted `ci.yml` jobs, `distribution-foundation.yml`, `release-eggpack.yml` (stage only as authorized), native systemd artifact/install and rootful IPv4/IPv6 traffic evidence, human key/signature verification receipts. Do not run destructive rootful steps outside disposable hosts or print secret-bearing backups.

## 7. Documentation

Update `README.md`, `docs/installation.md`, `docs/release-signing.md`, `docs/operations-runbook.md`, `docs/development.md`, release notes/security disclosure policy where approved, current version/support matrix, `plans/subsystems/release-readiness-security-roadmap.md` and `plans/registry.md`. The current spec and historical Phase 10/11 records must remain period-accurate.

## 8. Acceptance criteria

R004 may close as public-release-ready only when:
- R001–R003 strict operational prerequisites closed with exact-source evidence;
- actual production key embedded/authenticated, real independent signer-controlled signatures for manifest and installer;
- read-only verifier and exact target artifacts all match source/tag/commit/Cargo/version and current green CI on both architectures;
- native verified first install, service ownership, management and IPv4/IPv6 functionality, update/recovery/rollback and uninstall/purge tested at relevant current schema;
- no unresolved high/medium vulnerability, unreviewed unsigned bootstrap presented as authentic, unqualified supported target or mutable release asset;
- explicit maintainer go approval, followed by controlled publication and verified public-download postcheck.

If publication is not explicitly authorized or key unavailable, finish the technical checklist as far as evidence allows and record **blocked**, not closed.

## 9. Stop conditions

Stop on release-tag movement, unstable source identity, unreviewed supply chain input, any unauthenticated downloaded root execution in the high-assurance path, signature mismatch, unknown key provenance, partial/mismatched draft inventory, CI/rootful/IPv6 regressions, unresolved high/medium security flaw, unsafe installation mutation, missing native target, candidate/public asset mismatch, accidental leak of private signing key, or any attempt to auto-publish.

## 10. Closure and handoff

Write `plans/closure/release-readiness/004-status.md` only after actual verification. Include full target/run digest matrix, source/lock/toolchain provenance, signed asset inventory/fingerprint (public only), individual technical controls with pass/fail/blocked, independent review record, disclosure/incident readiness, go/no-go signoff, release publication result and exact public asset verification. Preserve any blocked external keys/approvals as blockers, not defects hidden by an optimistic summary.
