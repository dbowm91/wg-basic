# Release Readiness R004 — First Production Release Security Qualification and Authorization

Status: R004a initial unsigned pre-release track is executable now (tag + staged draft + verified public pre-release, no signing key required). R004b full production signed release stays blocked until the maintainer provisions a release trust root. No second reviewer is required anywhere.
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

### WP1 — Candidate freeze and single-maintainer qualification packet

Select stable version and authoritatively freeze tag/source SHA with reviewed source tree, clean lockfile and release workflow. Assemble a release-readiness packet including threat model and explicit findings, source/asset/attestation manifest, dependency graph and cargo audit, license/source attribution, branch/tag protection settings as verified by maintainer, runtime/minimum host requirements, release notes/version, known issues and remediation contacts. The maintainer is the sole reviewer and approver; no second person is required. Review source diff from the most recent qualified closure head including new release security changes; do not treat historical Codex Security zero-finding scan as coverage for the new diff.

### WP2 — Static/dynamic security review on exact candidate

Perform bounded review of:
- release workflow input injection/provenance, signing receipt, installer bootstrap and root boundary, update URL/redirect bounds and signature/manifest parsing;
- root-owned paths/permissions/atomicity/symlinks/locks and service lifecycle, backup/WAL restore, retained secret-bearing snapshots;
- systemd capability allowlist and hardening, UDS peer credentials, fixed privileged operations, unprivileged HTTP/UI route surface;
- auth/session/cookie/CSRF/Origin/Host rules, rate-limit-before-Argon2id, no unauthenticated admin setup, secret-safe logs and JSON; default loopback listener and guidance for TLS proxy;
- IPv4/IPv6 policy scope and foreign kernel state preservation;
- dependency advisory and license checks, build toolchain pin, source-to-binary evidence and hidden fixture/bypass build switches.

Produce a severity-ranked finding table with proof/source, exploit preconditions, mitigations and an owner. Any confirmed high or actively exploitable finding opens a separate corrective plan and blocks this gate. Medium/low findings are recorded with disposition and owner; the maintainer may accept them with written rationale rather than keeping the release blocked. State clearly what was inspected/read-only versus executed.

### WP3 — Reproduce exact release CI and artifact set

At the chosen immutable tagged SHA, run full required workspace tests with Rust 1.89; clippy/format, locked dependency audit, full fifteen-or-later CI jobs, distribution foundation release contract, Eggpack generator drift, native x86_64 and aarch64 GNU glibc floor, native smoke/systemd lifecycle, product management, rootful WireGuard control, IPv4/IPv6 namespace E2E and update/rollback/recovery. Confirm candidate binary embedded key matches the independently known production public key and does not contain test-only acquisition/transport/signing controls.

Record native checks and actual artifact digest/size and runtime target; no checkbox green without exact current SHA/run URL. Prefer a current signed-updater installation/rollback rehearsal at the shipped schema (including schema v7 where now applicable), not only Phase 9 v4/v5 fixtures. If production signing cannot yet be completed, run a fixture-only dry-run but leave R004 operationally blocked.

### WP4 — Signed draft verification

Use the R002 single-maintainer offline ceremony. Download the final GitHub draft afresh on a trusted workstation, authenticate source SHA/identity/receipt/run and both detached Minisign signatures with the out-of-band key, verify target artifacts and installer digest/hash-size matches signed metadata. A separate air-gapped machine is not required; a fresh download plus out-of-band key comparison is sufficient. Reject any unsigned/missing extra asset or source/draft mismatch. Validate there are no mutable asset rewrites after signing. Run the R003 high-assurance first install from **exact these signed release assets** on a disposable clean host (or the hosted systemd lifecycle where a disposable host is unavailable), without running downloaded code prior to signature verification.

### WP5 — Install / failure / rollback check

Exercise a controlled first-install on the supported targets using the hosted systemd lifecycle plus a disposable-host install check where feasible; verify product admin bootstrap, session and HTTP loopback defaults, client config export, and WireGuard handshake. Exercise state-preserving uninstall/reinstall and at least one update/recover path (failed-candidate restore or update recover). The existing fixture-signed updater matrix and Phase 10/11 traffic evidence may be referenced for their recorded architecture/SHA instead of re-running the full dual-stack traffic pilot; record any gap and requalify it only if the release changes that surface.

Capture dependency footprint, memory, cold startup and storage/backup amplification as observations, not SLAs. Establish operational support/runbook, recovery commands, security disclosure path and how to revoke a compromised key or yank/quarantine a release without weakening installed clients' verification policy.

### WP6 — Explicit publish/no-publish decision

Require a signed-off release checklist reviewed and approved by the maintainer as sole reviewer and approver, covering every release asset, source tag, signature/fingerprint, target matrix, security finding disposition, GitHub permission/protection, user-facing authenticity instructions, and release notes. The project does not require a second reviewer. The maintainer records an explicit go/no-go decision before changing a verified draft to public. After publication, fetch the exact assets and verify signatures again; record where public download was verified.

Document an emergency-stop plan for wrong key, tag movement, compromised hosting/signature key, urgent binary vulnerability, and accidental unsafe system install. Avoid reissuing a tag or silently changing a signed release at the same version.

## 4A. Initial pre-release track (R004a) — slackened gate for `v0.1.0`

R004a ships the first downloadable build as an explicitly **unsigned GitHub
pre-release** (evaluation only), so the release blocker can be met without
inventing trust. Every relaxed requirement below is a *reduced claim*, never
a weaker check behind the same claim. The full production gate in §§4–10
becomes the R004b follow-up and is unchanged.

| Production (R004b) requirement | R004a substitution | Why it stays truthful |
|---|---|---|
| Maintainer Minisign key, signed manifest + installer | Ship unsigned; publish SHA256 checksums only; release notes state "no signatures; verify checksums out of band" | No authenticity is claimed, so none is faked. `PRODUCTION_PUBLIC_KEY=None` keeps the updater fail-closed: this build cannot self-update and the next release needs a fresh install. |
| Disposable-host signed first install | Hosted CI systemd lifecycle on both targets (release-workflow qualification) + fresh-download byte verification of every draft asset against the manifest | Install qualification is exactly the hosted evidence, labeled as such; no bare-metal claim. |
| Full WP2 security review | Focused review: candidate-vs-last-qualified diff (must be plans/docs-only or re-open review), `cargo audit`, dependency/license check | No new production code rides unreviewed; the review bound matches the diff. |
| Offline-ceremony draft verification | Fresh draft download + tag/source/manifest/digest binding via `scripts/verify-release-signing-bundle.py` signature checks recorded as expected-fail (unsigned) | The verifier's unsigned verdict is evidence, not a failure to hide. |
| Publish as stable release | Publish as GitHub **pre-release** (tick pre-release at publish time; template default stays `false` for R004b) | The pre-release flag is the honest channel for evaluation builds. |
| Maintainer key/tag/sign/install/publish sequence | Maintainer does two one-click UI actions: approve `release-staging` (creates the draft) and flip draft → public pre-release | Both actions are reversible (draft deletable, pre-release editable); no key custody is created. |

R004a execution order: land this plan → merge → confirm `main` CI green at
the merge head → tag that exact head `v0.1.0` (Cargo `0.1.0` identity holds)
→ dispatch `release-eggpack.yml` with `release_tag=v0.1.0` → maintainer
approves staging → verify draft assets afresh → maintainer flips draft to
public pre-release → re-verify public assets → write
`plans/closure/release-readiness/004a-status.md` and close R004a.

R004a acceptance: frozen tag at a green-`main` SHA; release-workflow run
green at that tag (both targets built + qualified); draft staged after
maintainer staging approval; every draft asset digest-verified against the
manifest with tag/source identity bound; release notes carry the unsigned
evaluation-only wording; maintainer flipped draft → public pre-release;
public assets re-downloaded and re-verified; no unresolved high finding.
Then R004b (production signing, §§4–10 as written) remains blocked only on
maintainer key provisioning — a smaller, explicit gate.

## 5. Dependency graph and execution state (R004b production track)

R001 workflow/provenance tooling -> closed at the tagged SHA.
R002 signing tooling/procedure -> closed at the tagged SHA; the maintainer generates custody, embeds the public key, and signs the draft as R004 operations.
R003 verified-installer procedure -> closed at the tagged SHA; the first signed-install run is R004 evidence.
R004 executes the production key/tag/sign/install/publish sequence above and records the maintainer go/no-go. Phase 12 feature work remains a separate product decision and is not a blocker unless it introduces a security change in the candidate.

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

R004b may close as public-release-ready when:
- R001–R003 are closed at the exact tagged source with current green CI;
- the production key is embedded/authenticated with real maintainer-controlled signatures for manifest and installer;
- the read-only verifier and exact target artifacts all match source/tag/commit/Cargo/version and current green CI on both architectures;
- a verified first install, service ownership, and update/recovery check are recorded (hosted lifecycle plus disposable-host install where feasible; existing Phase 10/11 traffic evidence applies unless the release changes that surface);
- no unresolved high or actively exploitable finding remains, with medium/low findings recorded and dispositioned;
- the maintainer records sole review plus explicit go approval, followed by controlled publication and verified public-download postcheck. No second review is required.

If publication is not explicitly authorized or key unavailable, finish the technical checklist as far as evidence allows and record **blocked**, not closed. R004a closes separately under §4A with `004a-status.md`; it never closes R004b.

## 9. Stop conditions

Stop on release-tag movement, unstable source identity, unreviewed supply chain input, any unauthenticated downloaded root execution in the high-assurance path, signature mismatch, unknown key provenance, partial/mismatched draft inventory, CI/rootful/IPv6 regressions, unresolved high/medium security flaw, unsafe installation mutation, missing native target, candidate/public asset mismatch, accidental leak of private signing key, or any attempt to auto-publish.

## 10. Closure and handoff

Write `plans/closure/release-readiness/004-status.md` only after actual verification. R004a writes `plans/closure/release-readiness/004a-status.md` instead (unsigned pre-release evidence: tag/SHA, release-workflow run, draft receipt, digest matrix, notes wording, staging + publish approvals, public re-verification). Include full target/run digest matrix, source/lock/toolchain provenance, signed asset inventory/fingerprint (public only), individual technical controls with pass/fail/blocked, independent review record, disclosure/incident readiness, go/no-go signoff, release publication result and exact public asset verification. Preserve any blocked external keys/approvals as blockers, not defects hidden by an optimistic summary.
