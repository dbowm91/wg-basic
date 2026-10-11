# Release Readiness R001 — Strict Closure

Disposition: **closed**; first live tagged staging preflight deferred to the R004 release operation. Production signing/publication remain separately blocked under R004.
Implementation commit: `bd7c085d191ccf147e0f4dab72fde7cc8818f3fd`.
Repository baseline: `0b814fe` (`2026-10-10`).
Repository implementation head: `1e034d089ca62d9f4c22a562a3067227ad8beb9d`.
Source plan: `plans/implementation/release-readiness/001-release-workflow-input-and-provenance-hardening.md`.
Roadmap: `plans/subsystems/release-readiness-security-roadmap.md`.

## Evidence matrix

| Requirement | Evidence | Result |
|---|---|---|
| Fix at producer boundary | Consumer pin and generated workflow use qualified Eggpack `559d940af0fe6a2951eb17de1fcbecbf9e0bb6ce`; Eggpack CI M003j run `37987890305` | Pass |
| No dispatch expression in shell body | `scripts/test-release-workflow-security.py` scans generated run blocks and runs a command-substitution tag payload; no marker is created | Pass |
| Stable tag validation | Generated validator accepts canonical `v1.2.3`; rejects malformed/injection payloads from an environment variable before resolver/stage | Pass |
| Source/run/artifact binding | Per-job Eggpack source verification, same-run artifact handoffs, read-only `release-provenance.yml`, and `verify-release-signing-bundle.py` checks | Code implemented; no real tagged release run was staged or exercised |
| Write permission is isolated | Generated workflow has one `contents: write` grant, on `stage`, gated by `aggregate`; all candidate jobs are read-only | Pass |
| Generated workflow reproducibility | Pinned Eggpack `ci check` and hosted Distribution Foundation release-contract job | Pass |
| Current repository protection | GitHub API inspection found no rulesets, `main` unprotected, and no tag-protection rules | Blocked on maintainer settings |

## Exact verification run

- Local `python3 scripts/test-release-workflow-security.py`: passed.
- Local `python3 scripts/test-release-provenance.py`: passed.
- Local `python3 scripts/test-release-signing-bundle.py`: passed run/tag mismatch controls.
- Local `/tmp/wgb-eggpack-559/bin/eggpack ci check --workflow-shape release/eggpack/workflow-shape.json --contract release/eggpack/distribution.toml --github-policy release/eggpack/github-policy.json --workflow .github/workflows/release-eggpack.yml`: passed, 33,370-byte match.
- Local `cargo fmt --all -- --check`, `cargo check --all-targets --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo +1.89.0 check --all-targets --locked`, `cargo audit`, and `git diff --check`: passed.
- Local `cargo test --locked`: 351 tests passed; five `auth_sessions` worker cases timed out while unrelated Cargo builds shared the host. The exact commit's hosted CI run below passed the full Rust job.
- Hosted [CI run 38022851605](https://github.com/dbowm91/wg-basic/actions/runs/38022851605): all 16 jobs passed at the implementation SHA, including `rust`, update rollback/recovery, kernel/network namespace, durable-state, maintenance, doctor, and native install qualifications.
- Hosted [Distribution Foundation run 38022853831](https://github.com/dbowm91/wg-basic/actions/runs/38022853831): release-contract, x86_64/aarch64 native candidate, and both systemd install-lifecycle lanes passed at the implementation SHA.
- No release tag was created or moved, no draft was staged, and no production signing action was run.

## Security, settings, and limitations

The historical raw-shell dispatch interpolation is removed at the qualified
Eggpack generator boundary. No private key or signing secret is present in the
workflow or repository. The workflow `stage` job remains the sole writer and
does not publish.

Read-only settings evidence is recorded in `docs/release-signing.md`. `main`
branch protection and immutable `v*` tag rules are absent; Actions allow all
actions, with default `GITHUB_TOKEN` permissions read-only. The generated stage
job has no reviewer environment. R001 strict release-readiness therefore
remains gated on maintainer-owned repository policy and a producer-supported
preflight ordering change: the current `preflight` job checks out the dispatch
ref before the resolver validates it, although that job only runs
`cargo --version` and executes no checked-out code.

## Findings and handoff

- RF-01 shell interpolation: fixed and regression-covered (historical High).
- RF-02 independent source/run proof: consumer tooling is implemented, but a
  live run/draft chain has not been exercised (High release-authenticity gate).
- RF-06 repository actor/tag settings: unverified protections are absent by
  API inspection; maintainer action remains required (Medium process gate).

R002 may use the checked-in run-bound receipt and signer preflight after R001's
settings/producer-ordering gates are resolved. R004 remains blocked. This
conditional closure does not authorize staging, signing, or publication.

## 2026-10-11 producer, repository-policy, and consumer follow-up

The producer ordering and repository configuration blockers recorded above
have since been addressed. The status remains conditional only on exact-head
hosted CI for this consumer change; the first live tagged staging preflight
is deferred to the R004 release operation and does not keep R001 conditional.

| Requirement | New evidence | Result |
|---|---|---|
| Resolve and freeze source before checkout | Eggpack M003k merged as `1103a1affc62a210f1102a769457db80d9188bc8`; hosted run `38027470046` passed all four Linux stable/MSRV, macOS, and Windows lanes | Pass |
| Pin producer and regenerate consumer workflow | `release/eggpack/github-policy.json`, `distribution-foundation.yml`, `docs/development.md`, and generated `release-eggpack.yml` pin M003k; `eggpack ci check` reports an exact 40,658-byte match | Pass |
| Exercise tag object validation | `scripts/test-release-workflow-security.py` covers annotated/lightweight tags, changed/non-commit objects, malformed input, and shell injection rejection | Pass |
| Require repository review and protect source/tags | Ruleset `24830321` requires CI/release checks on `main` with zero required approvals (solo-maintainer merge after green checks); rulesets `24830322`/`24830324` restrict `v*` creation and prevent tag movement/deletion | Pass |
| Restrict actions and stage approval | Actions selected allowlist, read-only default token permissions; `release-staging` Environment requires the sole configured reviewer `dbowm91`, with self-review permitted | Pass |
| Run actual tagged stage preflight | No `v*` tags or releases exist in wg-basic | Not exercised; stable-version/tag decision required |

Local verification for this follow-up:

- `eggpack ci generate` and `eggpack ci check` with Eggpack M003k passed; generated workflow is 40,658 bytes and matches exactly.
- `scripts/test-release-workflow-security.py`, `test-release-provenance.py`, `test-release-signing-bundle.py`, `test-verified-install.py`, `test-release-installer.py`, `test-signing-request.py`, and `test-release-smoke.py` passed.
- `cargo fmt --all -- --check`, `cargo check --all-targets --locked`,
  `cargo clippy --all-targets --locked -- -D warnings`, and
  `cargo +1.89.0 check --all-targets --locked` passed.
- `cargo test --locked` encountered one timing-sensitive failure in
  `tests/operational_events.rs::long_running_role_events_are_stderr_only_and_json_is_line_delimited`
  (missing `serve.started`); the exact test passed on isolated rerun. Rootful
  suites were not run.
- No production key was generated, no tag/draft was created, no signing or
  publication occurred, and no rootful suite was run.

The previously recorded absent rulesets and producer ordering described the
2026-10-10 inspection and are historical. Current repository settings are
recorded in `docs/release-signing.md`. Project policy requires no second
reviewer: `main` needs zero approvals (maintainer merges after green checks)
and `release-staging` needs only the maintainer with self-approval allowed.

## 2026-10-11 strict closure at `1e034d0`

`e0c2aba..1e034d0` is docs/plans only (solo-maintainer policy, R001–R004
streamlining); no production code changed. Exact-head hosted evidence:

- Hosted CI run `38108270370` at `1e034d0`: completed success, 21 checks
  passed, 0 failed (rust, dependency-audit, GitGuardian, kernel/namespace,
  durable-state, maintenance, doctor, native install, upgrade rehearsal
  including rootful lanes).
- Hosted Distribution Foundation run `38108270368` at `1e034d0`: completed
  success (release-contract, both GNU native candidates, both systemd
  install-lifecycle lanes).
- Local: `cargo fmt -- --check`, `cargo check --all-targets --locked`,
  `cargo clippy --all-targets --locked -- -D warnings` clean;
  `cargo test --locked` 580 passed, 3 ignored;
  `cargo +1.89.0 check --all-targets --locked` clean; all seven release
  fixtures passed (`workflow-security`, `provenance`, `signing-bundle`,
  `verified-install`, `installer`, `signing-request`, `smoke`);
  `git diff --check` clean.

R001 acceptance is met: no raw untrusted expression in shell run bodies,
discriminating adversarial-input test, source/tag/run/asset binding checks,
green generator-drift and native CI at the exact head, per-job least-privilege
review, and provenance/settings evidence. The release gate stays disabled
without separate key/signing authorization. Neither this closure nor its
evidence authorizes production signing or publication.

Evidence chain to `main`: the strict-closure commit `342fec5` passed CI run
`38108935557` (21 passed, 0 failed) and Distribution Foundation run
`38108935548` at its exact head; PR #2 merged as `7b2146d`, where main CI
run `38109447380` and Distribution Foundation run `38109447352` both
completed success.
