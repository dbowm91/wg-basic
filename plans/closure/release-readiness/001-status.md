# Release Readiness R001 — Conditional Closure

Disposition: **conditionally closed**; release authorization remains blocked.
Implementation commit: `bd7c085d191ccf147e0f4dab72fde7cc8818f3fd`.
Repository baseline: `0b814fe` (`2026-10-10`).
Repository implementation head: `bd7c085d191ccf147e0f4dab72fde7cc8818f3fd`.
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
