# Release Readiness R001 — Workflow Input, Tag Authority, and Build/Stage Provenance Hardening

Status: ready for implementation.
Baseline: `dbowm91/wg-basic@ff40f851508ccda52171c27cefdcdaf4ec1da2d5` (2026-10-09).
Primary class: invariant / security corrective.
Source roadmap: `plans/subsystems/release-readiness-security-roadmap.md`.
Canonical authority: `plans/adr/006-distribution-install-authenticity-and-update.md`; `plans/subsystems/distribution-install-update-roadmap.md`; `plans/003-planning-process.md`.
Related completed evidence: `plans/closure/distribution/003-final-status.md`, `004-status.md`, `005-status.md`. These technical closures stay historical and unchanged.

## 1. Objective and readiness

Eliminate shell-expression injection from the generated Eggpack `workflow_dispatch` release workflow, enforce a tightly bounded release tag/commit identity from dispatch through staged draft, and prevent the privileged staging job from acting on a mismatched or unverifiable build. Keep the release pipeline producer-owned by Eggpack and the release-signing decision owned by wg-basic's maintainer.

No new Eggup runtime features or rootful VPN implementation changes are required. R001 is independently ready; its completion is a hard prerequisite for R004 release authorization and for R002's *production signing ceremony* (R002 fixture development can proceed against its stable contract).

## 2. Verified source finding and detection gap

In `.github/workflows/release-eggpack.yml`, both the `resolve` and the final write-authorized `stage` job contain:

```yaml
run: "test -n \"${{ inputs.release_tag }}\""
```

GitHub Actions interpolates the input into generated Bash script text rather than treating it as an opaque string. Shell syntax, including command substitutions, can therefore be interpreted. A manual-dispatch trigger limits who can invoke this, but it does not make the pattern acceptable inside release and `contents: write` staging paths. Inspect the full YAML for **all** `${{ inputs.* }}` / `${{ github.event.* }}` occurrences in `run:` bodies. `env: EGGPACK_RELEASE_TAG: "${{ inputs.release_tag }}"` with subsequent `"$EGGPACK_RELEASE_TAG"` use is the safe intended form.

The existing `.github/workflows/distribution-foundation.yml` checks that the generated workflow conforms to a pinned Eggpack schema. This drift check does **not** itself assert shell-injection safety; the generated workflow is still vulnerable. The release flow currently checks out `inputs.release_tag` in many separate jobs and stages with a token having `contents: write`; tag movement, wrong-commit publication, or provenance mismatch must be explicitly rejected. The published `scripts/verify-signing-request.py` checks draft asset bytes against an unsigned staging receipt but does not independently establish that a tagged source revision is authorized.

These are review findings from source, not a claim that an unauthorized actor already executed a command or compromised a release.

## 3. Required invariants

- Dispatch input may be arbitrary adversarial UTF-8 and never enter executable `run:` script text or a shell command assembled by string concatenation. No `eval`, shell expansion of untrusted data, or unsafe `GITHUB_OUTPUT`/environment file append.
- Before any release-related source checkout, resolve a *specific* immutable source commit from a syntactically valid canonical `vX.Y.Z` tag; verify Git tag -> exact source SHA and that Cargo package version, binary `--version`, Eggpack release ID, source-revision manifest, GitHub repository and target matrix all bind to that same SHA.
- Reject unsupported tags, prerelease, leading-zero versions, branches disguised as tags, missing or moving refs, unsigned/unreviewed workflow changes, job artifacts from other run IDs/attempts, and any mismatch between dispatched tag and staged receipt.
- Read-only candidate jobs retain `contents: read`. Only the stage job may receive `contents: write`, with no private signing key or unrelated credentials in normal CI.
- A workflow job must not stage or publish a release without reviewing all exact artifacts, receipt, tests and host-target evidence.
- Generated YAML is not manually edited as a permanent divergent fork. Correct the Eggpack generator/input contract at its owner or use a reviewed supported extension point; update the pinned Eggpack revision and regenerated workflow/shape together after upstream qualification.
- Protect release tags and stage permissions at the repository settings level; document settings that cannot be asserted by code. Do not infer branch protection or secret exposure from source inspection.

## 4. Ordered work packages

### WP1 — Discriminating injection reproduction

Use an isolated parsed/executable Bash-script fixture—not the live privileged workflow or production credentials—to show that the current `test -n` expression processes a command-substitution payload. Negative control must not execute a marker after correction. Avoid outputting an actual command into users' shells; the fixture records marker-file/no-side-effect results. Scan every emitted `run` block and any template data capable of emitting Bash/YAML script bodies.

### WP2 — Fix at the correct generator boundary

Inspect pinned `eggstack/eggpack@d61ca71fc0112be63e7e8ba31ba8fa2b1ce5a628` generator for the offending interpolation. If produced upstream, create/register a bounded Eggpack corrective there and block generated workflow activation until the new qualified revision is available. If product-owned policy/template supplied it, fix only product-owned templates. Require env-mediated dispatch handling and stable SemVer validation before any untrusted value reaches shell. Re-generate `.github/workflows/release-eggpack.yml` from the corrected pinned source and update `github-policy.json`/workflow-shape contract in lockstep. No silent local patch that `eggpack ci check` would later undo.

### WP3 — Verify source and job-artifact binding

Establish or tighten a machine-readable release-intent receipt carrying canonical owner/repo, exact immutable `vX.Y.Z` ref, resolved commit OID, Cargo version, workflow revision/run ID/attempt, target artifact SHA-256/size and gate evidence. Each target job and staging job must independently compare checkout HEAD, source receipt, the candidate manifest/source, and artifact handoff; never trust only the user-selected tag string. Where GitHub ref mutation cannot be made impossible, ensure source verification detects mutation *between* resolve, build, and staging, and refuses.

Make final staging operate only on downloaded artifacts from the same authorized run/attempt; check no unexpected path, symlink, or duplicate asset appears. Retain staged manifest and receipt as immutable review evidence when publishing is eventually authorized.

### WP4 — Least-privilege and repository policy review

Prove workflow step actions are pinned to immutable commits, external tool downloads are pinned/digest-checked, normal CI/build/qualifier jobs have read-only tokens, and write-scoped stage does not execute unverified externally supplied code. Recommend tag protection/immutable release tag rules, environment reviewers, release-actor allowlist and minimal manual dispatch permissions with reproducible documented UI/API verification. Any settings changes require maintainer approval and must be recorded as operational prerequisites, not represented as performed by a planning agent.

### WP5 — Security regression and evidence

Extend `scripts/test-release-smoke.py` or add `scripts/test-release-workflow-security.py` as a non-network fixture that extracts *generated YAML* shell runs, rejects direct expression interpolation inside `run`, runs the adversarial tag test, and proves allowed stable tag -> exact SHA binding. Wire into `distribution-foundation.yml` and verify Eggpack generator drift checks still pass. Include moved-tag/stale-artifact/cross-run/incorrect-SHA rejection and a test verifying the stage job retains write scope only after prerequisite gates.

## 5. Failure/restart/compatibility

Workflow failure is a hard stop with no draft mutation. Retrying a dispatch with the same tag but changed ref or artifact digests must refuse rather than silently overwrite a draft. An existing draft is inspected for exact identity/asset collision and never overwritten on mismatch. No changes to runtime state schema, WireGuard, API, Eggup or public installer CLI.

## 6. Security and privilege review

Treat release workflow scripts as privileged code, even when the trigger is manual. No private Minisign key in GitHub Actions. Only authorized maintainer signs off-site after independent artifact verification. GitHub artifact attestations are supplementary; do not substitute them for the project's pinned Minisign release root. If Eggpack cannot express safe shell input handling with this workflow schema, stop and plan an upstream fix before staging.

## 7. Tests and verification

```text
python3 scripts/gen-release-workflow-shape.py
python3 scripts/test-release-workflow-security.py
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

Execute the repository's exact `eggpack ci check` generated-workflow/shape contract. Require current-head hosted `distribution-foundation` release-contract, both GNU native release candidates, systemd lifecycle, and complete CI. Record latest run URLs and artifact digests; do not extrapolate older green runs to changed workflow code.

## 8. Documentation

Update `release/eggpack/github-policy.json` and generated workflow as required; `docs/installation.md`, `docs/development.md`, `plans/subsystems/release-readiness-security-roadmap.md`, and `plans/registry.md`. Document exact tag/protection/release actor requirements and a human-readable run/receipt review. Do not overwrite M003/M004/M005 historical closures.

## 9. Acceptance

R001 closes only with no raw untrusted expression in shell run bodies, a *discriminating* adversarial-input test, source/tag/run/asset binding checks through actual staging preflight, green generator-drift and native CI, per-job least-privilege review, provenance and settings evidence, and a release gate that remains disabled without separate key/signing authorization.

## 10. Stop conditions

Stop if generator remediation belongs upstream and is unavailable; canonical tag cannot be frozen or checked; a write-scoped job can be driven by uncontrolled code; release assets cannot be tied to an exact source/ref/run; a fake receipt passes stage checks; or the repair requires an automatic signing key in ordinary CI.

## 11. Closure evidence

Write `plans/closure/release-readiness/001-status.md` after implementation with SHA and exact workflows, before/after adversarial result, generator upstream pointer, tag/SHA binding, job token scopes, historical and new test runs, secret-exposure review, settings requiring manual work, and the final R002/R004 release gating disposition.
