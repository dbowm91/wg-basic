# Distribution M004 C001a — Eggup Failed-unit Recovery Adoption

Disposition: **closed** (bounded C001a scope; parent C001 remains corrective-required).

Date: 2026-10-09

## Implementation revision and baseline

- Baseline: `297af6c` on `plans/m004-update-correctives`, with C001 corrective
  disposition at `plans/closure/distribution/004-c001-status.md`.
- Implementation commits: `f9a00b3` (typed exact-owned transition stop and
  recovery behavior), `7749317` (stale restore-stage and altered `ExecStart`
  rootful negatives), `83d5b69` (operator and architecture contract).
- Qualification commit: `77493172ee5c578c8d361cd2e21004bdb7a5fe2e`.
- Final documentation/closure commit is recorded in Git history after this
  evidence was written.

## Requirement-to-evidence matrix

| Requirement | Evidence | Result |
|---|---|---|
| Published Eggup dependency and failed-unit contract | M010/M011 records and publication evidence referenced by the implementation plan; exact `eggup-service = 0.1.3` lock resolution/checksum recorded there | Pass |
| Stop only exact-owned services through typed bounded Eggup path | `src/update.rs`; lifecycle state regressions cover unknown/transitioning, completed/incomplete stop, post-state and ownership checks | Pass |
| Real updater signed-fixture recovery | Hosted rootful `signed_systemd_update_rolls_back_and_retries`; run `37895646615` passed the expanded matrix, run `37896480910` passed the further expanded matrix | Pass |
| Actual updater interruption and repeated recovery | Five selected durable cutpoints (BackupVerified, ServicesStopped, BinaryCommitted, CandidateStarted, CandidateHealthy); recovery invoked twice after each | Pass |
| Candidate migration failure and compatible rollback | Real fixture migration, forced candidate startup failure, interrupted SQLite restore, original schema/installation identity/generation/client count restored, retry to Committed | Pass |
| Tampered artifacts and ownership | Corrupted old binary and state backup, malformed journal, changed owned serve `ExecStart`; every refusal leaves both services stopped | Pass for tested cases |
| Stale restore stage cannot be overwritten | Transaction-named staging file with sentinel survives recovery byte-for-byte; recovery then completes twice | Pass |
| Operator contract | `architecture/update-rollback-contract.md` and `docs/operations-runbook.md` document exact-owned auto-restart stop and fail-closed postconditions | Pass |

The hosted test log reports 1 passed, 0 failed in 573.43 seconds on GitHub-
hosted Ubuntu 24.04.5 x86_64, kernel `6.17.0-1022-azure`, systemd
`255.4-1ubuntu8.17`. Run: https://github.com/dbowm91/wg-basic/actions/runs/37896480910.
The earlier expanded run `37895646615` also passed the selected recovery
matrix before the stale-stage/altered-unit additions.

## Verification and security review

On the implementation tree, the ordinary test suite passed (561 passed, 3
ignored), formatting, all-target check, all-target clippy with warnings denied,
feature-gated clippy, Rust 1.89 locked check, audit (211 locked dependencies),
and `git diff --check` passed. The rootful test compiled with
`cargo test --locked --features linux-integration,update-test-fixtures --test update_transaction_rootful --no-run`.
The actual destructive test was run only in the disposable hosted systemd
runner, never on the shared development host.

The exact-owned service stop uses Eggup's typed operation and requires the
completed receipt and fresh post-state specified by lifecycle classification.
No generic process execution, PID killing, `systemctl kill`, or reset-failed
fallback was added. Journal and backup evidence remain private; tampered
resources are retained and services are not left running.

## Limitations and successor status

C001a proves its focused failed-unit adoption and updater recovery handoff. It
does not assert every C001 acceptance item. In particular, the broader C001
phase crash matrix and additional wrong owner/mode/symlink, receipt, missing
lease, failed netd, and startup-timeout cases remain assigned to C001/C002
qualification. No high or medium unresolved finding was observed in this
bounded scope.

C001 remains **corrective-required**, so C002 remains **blocked** on its hard
dependency. M004 remains active and M005 remains blocked on M004 closure. This
record closes C001a only; it does not close C001, M004, Phase 10, or release
readiness. Production release trust-root provisioning remains an external
maintainer action.
