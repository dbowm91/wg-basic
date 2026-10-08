# Operational Hardening M005 — Strict Closure

Disposition: **closed**

Implementation commits:

- `911df97` — old/new v4→v5 rehearsal, rollback contract, operator runbook, and CI jobs
- `f449fec` — assert the v4→v5 operational-enabled backfill
- `67c8188` — require fresh RX/TX traffic after each restart boundary
- `dd78129` — restore onto a clean state path and fresh namespaces
- `6a9f354` — exercise candidate-startup migration under its real state lease and clarify the recovery sequence

Repository baseline: `631cc9b`  
Implementation head: `6a9f354`  
Hosted CI: [run 37741533304](https://github.com/dbowm91/wg-basic/actions/runs/37741533304), all 13 jobs successful.

## Requirement-to-evidence matrix

| Requirement | Evidence |
|---|---|
| Immutable old binary and real schema boundary | `upgrade-rehearsal` and `upgrade-rehearsal-rootful` build commit `e8fd6b1212491576f3c6bdd7468591a97d5aaf3c` from its own worktree and Cargo.lock. It is the old Phase 8 v4 binary; the candidate is built separately from the Phase 9 source. Local old binary SHA-256: `9c4cfd053dd0a411042c510e2459bd707554a22af670f5ec7216449d55b3f038`. Local candidate binary SHA-256: `076be560abeb075ba3053028f2c323dc0c8babf856a9e0d58975eb9d1a5457fa`. Both report package version `0.1.0`; commit and artifact hashes distinguish them. |
| Old product state and semantic snapshot | `tests/upgrade_rehearsal.rs` provisions an administrator using the old binary, creates a server and two labeled clients, issues a session, creates and consumes one enrollment capability, creates and revokes another, and records server/client IDs, full client DTOs, session response, audit event order, and exported config hashes. The rootful fixture also creates the v4 product state through old HTTP and proves a real client handshake and traffic before migration. |
| Explicit backup and automatic snapshot | The old binary takes the explicit v4 online backup before any candidate migration. Candidate `state verify` accepts the explicit backup; after migration it also verifies `.pre-migration-v4`. The live schema is v5, the explicit and automatic artifacts remain separate, and both are kept until the drill completes. Restore is performed from the explicit backup. Files are created in a private temporary directory and retain owner-only state/backup modes. |
| Migration compatibility and semantic preservation | Candidate migration reports schema v5. The rootful fixture reads the state immutably and asserts the v4 default `network_operational_enabled=true` is backfilled for the managed interface. Installation identity and desired generation are unchanged by migration. Rootless HTTP assertions compare full client records, session contents, audit events/order, and config hashes. Consumed and revoked enrollment tokens continue to return `410` after migration, restore, and re-upgrade. |
| Candidate failure after migration | Candidate `serve` startup itself performs v4→v5 migration under its singleton state lease while candidate netd is withheld. Candidate remains alive, `/healthz` is `degraded`, and doctor cannot report a passing release state. After stopping candidate, read-only inspection confirms schema v5 and the migration backfill; the old binary refuses the migrated DB. Replacing only the executable is therefore not rollback. |
| Ordered rollback and old pair validation | The candidate is stopped before restore. The old binary restores the explicit v4 backup before old `netd`/`serve` restart. The pre-existing session cookie and client identities remain valid; old `/healthz` and authenticated health pass. `require_handshake` records pre-restart counters and requires both RX and TX to increase after restart, proving fresh traffic rather than reusing earlier counters. |
| Candidate re-upgrade | Old roles stop before candidate starts. Candidate migrates the restored v4 state to v5 again; the same session and client/config semantics remain valid. Authenticated health, doctor required checks, and fresh RX/TX traffic pass. The second migration proves the explicit recovery artifact supports another update attempt. |
| Clean-target disaster-recovery drill | The rootful fixture creates a separate empty state path and two fresh network namespaces, initializes the target, restores the explicit v4 backup, and runs current read-only doctor before starting old service. It then starts old `netd`/`serve`, performs login, reads the same client IDs/config, checks health, configures a client from the restored export, and requires fresh handshake traffic. `durable_backup` also passes in the feature-enabled suite and independently qualifies a restored DB on a clean three-namespace forwarding/NAT fixture. |
| Doctor compatibility with restored v4 | The immutable Phase 8 binary predates doctor. Candidate doctor now projects v4's absent operational-switch table as the migration default `enabled=true` without migrating or writing. The recovery fixture requires SQLite/state/netd checks to pass and no required check to fail. Its plan-only network check can be a warning on the older kernel state; the old service then reconciles, reports healthy HTTP status, and passes fresh traffic. |
| Crash-window matrix and commit/response evidence | `architecture/update-rollback-contract.md` maps every requested window to the authoritative pair/artifact and safe next action. Migration's transactional SQLite step and the pre-migration snapshot establish recovery on a migration interruption; explicit backup verification and restore ordering are exercised. The exact instruction-level kill after a product DB commit and before HTTP response is not injected. The transaction rationale is explicit: the generation and audit row commit atomically; a lost response cannot create a partial product mutation, and retrying with the old generation is rejected as stale. `service_e2e`, `service_lease`, and product persistence tests qualify process death/restart and durable state. This closes M004-2 by rationale while retaining that exact kill point as a low evidence limitation. |
| Phase 10 handoff and secret handling | `architecture/update-rollback-contract.md` specifies the explicit backup authority, stop/start order, candidate health gate, commit marker, rollback order, crash matrix, recovery-required states, ownership revalidation, and the Eggup stage/integrity/validation/locking/replacement/rollback/lifecycle mapping. It does not assign release authenticity to Eggup. Both backups are documented as secret-bearing and retained through commit. |
| Security and dependencies | `cargo audit` succeeds with no advisory findings across 149 locked packages; no dependency was added for M005. Existing M004 abuse/security review remains in force. No high or medium finding is open. The authorized same-UID slow-peer availability window remains an accepted informational residual; local root remains outside confidentiality/availability protection. |
| Documentation and planning handoff | README, development commands, state backup/restore, operations runbook, update/rollback contract, Phase 9 roadmap, macro roadmap, registry, and this closure record are reconciled. Phase 9 is closed. Phase 10 is unblocked for research/planning only; no update implementation is claimed. |

## Verification run

Local commands passed:

```text
rtk cargo fmt --all -- --check
rtk cargo check --all-targets --locked --target-dir /tmp/wgb-m5-dev-target
rtk cargo clippy --all-targets --locked --target-dir /tmp/wgb-m5-dev-target -- -D warnings
rtk cargo +1.89.0 check --all-targets --locked --target-dir /tmp/wgb-m5-msrv-target
rtk cargo test --locked --target-dir /tmp/wgb-m5-dev-target # 526 passed, 1 ignored, 31 suites
rtk cargo audit # no advisories; 149 locked packages
rtk sudo -n env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo CARGO_TARGET_DIR=/tmp/wgb-m5-root-target cargo test --locked --features linux-integration --tests -- --test-threads=1 # all non-ignored tests passed
rtk sudo -n env "PATH=$PATH" WGB_OLD_BINARY=/tmp/wg-basic-old-target/release/wg-basic WGB_CANDIDATE_BINARY=/tmp/wgb-m5-candidate-target/release/wg-basic CARGO_HOME=/tmp/wg-basic-root-cargo CARGO_TARGET_DIR=/tmp/wgb-m5-root-target cargo test --locked --test upgrade_rehearsal -- --ignored --nocapture # passed
rtk sudo -n env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo CARGO_TARGET_DIR=/tmp/wgb-m5-root-target WGB_OLD_BINARY=/tmp/wg-basic-old-target/release/wg-basic WGB_CANDIDATE_BINARY=/tmp/wgb-m5-candidate-target/release/wg-basic cargo test --locked --features linux-integration --test upgrade_rehearsal_rootful -- --ignored --nocapture --test-threads=1 # passed, including fresh-target recovery
```

The feature-enabled `--tests` run passed all existing rootful suites: doctor, maintenance, WireGuard kernel, network reconciliation/control, durable owner/restart/backup, product management, service E2E, and the unprivileged protocol/resource suites. The two dedicated upgrade targets are ignored by default and passed separately above.

Hosted run `37741533304` is for final implementation head `6a9f354` and completed successfully for every job: Rust format/check/clippy/full tests, pinned dependency audit, all existing rootful jobs, the rootless migration rehearsal, and the rootful upgrade/clean-target recovery rehearsal.

## Crash-window disposition

The detailed table is in `architecture/update-rollback-contract.md`. The update remains uncommitted until a durable commit marker exists. Before backup promotion, retain the old live pair and do not replace the binary. After a complete backup but before replacement, the old pair remains authoritative. Before candidate start, v4 is still compatible with old; during migration, preserve both explicit and automatic snapshots and let SQLite recover its transaction before inspecting schema. After migration but before the marker, stop candidate and restore explicit v4 before old selection. If rollback stops after restore but before old startup, the restored v4/old binary pair is the next authoritative pair. A post-health, pre-marker crash is treated as uncommitted and rolls back by the same order. These latter orchestration windows are reasoned from transaction/ordering invariants; Phase 9 does not implement or claim an updater journal or injected crash seam.

## Known limitations and unresolved findings

- No high or medium security/operational finding remains open.
- M004-2's precise commit-before-response process kill is accepted as a low evidence limitation with the transaction-level rationale above; it is not claimed as a deterministic SIGKILL test.
- Doctor may classify an older restored kernel projection as repairable drift (`warn`) while old netd is in use. Release validation requires no failed required check; actual startup reconciliation, authenticated health, product reads, and fresh traffic are separately required and pass.
- The Phase 8 baseline has no doctor command. Phase 9 candidate doctor reads its v4 state read-only before old service startup.
- Phase 10 release authenticity/signing, updater journal/commit marker implementation, service installation, and update automation remain future work.

## Handoff

M005 is strictly closed and Phase 9 is closed. There are no active or blocked implementation plans. Phase 10 distribution/install/update is unblocked for research and planning only. A future bounded Phase 10 roadmap must validate the concrete Eggup API and preserve the binary+database compatibility transaction defined in `architecture/update-rollback-contract.md`.
