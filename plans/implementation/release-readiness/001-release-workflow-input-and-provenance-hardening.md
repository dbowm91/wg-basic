# Release Readiness R001 — Workflow Input, Tag Authority, and Build/Stage Provenance Hardening

Status: **conditionally closed for repository implementation; release readiness blocked**. Eggpack CI M003j is qualified at `eggstack/eggpack@559d940af0fe6a2951eb17de1fcbecbf9e0bb6ce` (run `37987890305`). The consumer workflow is regenerated at that pin and product provenance checks are implemented. The generated `preflight` job still checks out the dispatch ref before the resolver's canonical-tag validator; it only runs `cargo --version` and does not execute checked-out code, but strict R001 ordering requires upstream support to validate before that checkout or remove it. GitHub reports no repository rulesets and `main` is not protected; no settings were changed. Exact-head hosted gates passed; producer-ordering and maintainer-owned rulesets remain blockers for staging/public release claims.
Baseline: `dbowm91/wg-basic@0b814fe` (2026-10-10).
Primary class: invariant / security corrective.
Source roadmap: `plans/subsystems/release-readiness-security-roadmap.md`.
Canonical authority: `plans/adr/006-distribution-install-authenticity-and-update.md`; `plans/subsystems/distribution-install-update-roadmap.md`; `plans/003-planning-process.md`.
Related completed evidence: `plans/closure/distribution/003-final-status.md`, `004-status.md`, `005-status.md`. These technical closures stay historical and unchanged.

## 1. Objective and readiness

Eliminate shell-expression injection from the generated Eggpack `workflow_dispatch` release workflow, enforce a tightly bounded release tag/commit identity from dispatch through staged draft, and prevent the privileged staging job from acting on a mismatched or unverifiable build. Keep the release pipeline producer-owned by Eggpack and the release-signing decision owned by wg-basic's maintainer.

No new Eggup runtime features or rootful VPN implementation changes are required. The producer-dependent correction is closed upstream by Eggpack CI M003j at `559d940af0fe6a2951eb17de1fcbecbf9e0bb6ce`; this repository pins that revision, regenerates the workflow, and adds consumer-side provenance. Strict R001 closure remains a hard prerequisite for R004 release authorization and R002's *production signing ceremony*.

## 2. Verified source finding and detection gap

At the review baseline, `.github/workflows/release-eggpack.yml` interpolated `inputs.release_tag` into `run:` in both `resolve` and the final write-authorized `stage` job. Eggpack M003j corrected those producer sites; the repository now pins its qualified revision and regenerates the safe form. `scripts/test-release-workflow-security.py` executes the generated tag validator against a command-substitution payload and confirms it rejects the value without creating a marker.

```yaml
run: "test -n \"${{ inputs.release_tag }}\""
```

GitHub Actions interpolates the input into generated Bash script text rather than treating it as an opaque string. Shell syntax, including command substitutions, can therefore be interpreted. A manual-dispatch trigger limits who can invoke this, but it does not make the pattern acceptable inside release and `contents: write` staging paths. Inspect the full YAML for **all** `${{ inputs.* }}` / `${{ github.event.* }}` occurrences in `run:` bodies. `env: EGGPACK_RELEASE_TAG: "${{ inputs.release_tag }}"` with subsequent `"$EGGPACK_RELEASE_TAG"` use is the safe intended form.

The generated workflow checks out the selected tag in each job, binds the resolved source revision in its release plan, and validates each later checkout before using it. Build artifacts are transferred within the same Actions run and the stage job remains the only `contents: write` job after `aggregate`. A read-only `workflow_run` workflow now binds the staging receipt to the release run/attempt and workflow SHA. The signer preflight independently checks both GitHub run records, the live tag OID, the live draft asset inventory, and freshly downloaded bytes. The JSON receipts remain consistency evidence; GitHub run/tag records and independently reviewed repository settings are still required.

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

Root cause was in Eggpack's reusable resolver and write-scoped staging renderer at `d61ca71`. Upstream M003j corrected both generator sites and passed its registered CI. The consumer pin and generated output are updated together; do not apply a local generated-YAML-only patch. A separate read-only `workflow_run` consumer records source run/attempt metadata without adding scripts to Eggpack-generated output.

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

Stop if Eggpack CI M003j remains unqualified for the production build; canonical tag cannot be frozen or checked; a write-scoped job can be driven by uncontrolled code; release assets cannot be tied to an exact source/ref/run; a fake receipt passes stage checks; or the repair requires an automatic signing key in ordinary CI.

## 11. Closure evidence

`plans/closure/release-readiness/001-status.md` records exact-head hosted verification and the conditional disposition. Keep R001 blocked for release readiness until preflight ordering and repository protection gates are resolved; do not treat the conditional implementation closure as staging or publication authorization.
