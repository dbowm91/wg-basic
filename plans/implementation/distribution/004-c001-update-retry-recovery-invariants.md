# Distribution M004 C001 — Update Retry and Crash-Recovery Invariants

Status: corrective required — implementation hardening is recorded in `plans/closure/distribution/004-c001-status.md`, but strict closure remains blocked on resolving Eggup's failed-service lifecycle classification and updater-level retry/crash qualification.
Repository baseline: dbowm91/wg-basic main at 7b69c75634242bf0d5c0d35374b96346c73f20c6 (2026-10-08).
Primary work class: corrective / invariant (durability, rollback safety, update retry).

## Authority and dependencies

Source milestone: plans/implementation/distribution/004-transactional-self-update-and-rollback.md (active).
Source roadmap: plans/subsystems/distribution-install-update-roadmap.md, Distribution M004.
Accepted ADR: plans/adr/006-distribution-install-authenticity-and-update.md.
Canonical runtime contract: architecture/update-rollback-contract.md.
Predecessor: Distribution M001–M003 mechanically closed, with M003 evidence at plans/closure/distribution/003-final-status.md.
This corrective precedes Distribution M004 C002 and any M004 closure; M005 remains blocked. No earlier closed milestone is reopened.

## 1. Verified baseline findings

F1 — terminal rollback prevents re-update (high functional impact). In src/update.rs, reject_unresolved_journal() only archives a Committed journal; a valid RolledBack journal is rejected. Both the normal Eggup callback rollback and an operator recovery can write RolledBack. The next update then fails despite the original installation having been restored. This directly contradicts M004 retry/recovery semantics and M005's re-update-after-rollback requirement.

F2 — interrupted restore is not demonstrably retryable (high recoverability risk). restore_state_backup() creates a deterministic .wg-basic-restore-<transaction-id>.db and refuses any existing path. A SIGKILL or error after creating the file, and before cleanup, leaves the next recover invocation unable to progress. Recovery also has multiple early-return errors after services were quiesced; some do not persist a RecoveryRequired disposition.

F3 — terminal recovery is not a complete health proof. recover() validates a terminal Committed/RolledBack binary and install receipt, then returns success without proving state-schema compatibility, expected InstallationId/generation, or a healthy compatible service pair. A post-crash missing/stopped service can therefore be reported as a terminal transaction without a usable product. Nonterminal recovery currently uses stop_owned_services(), which refuses service lifecycle states other than Running/Stopped; a failed candidate service may prevent the intended recovery path.

F4 — identity/health checks are weaker than the contract. validate_candidate_health() checks that the reported installation_id is non-null, the DB is healthy, backend reachable and convergence is the literal string converged. It does not compare InstallationId, schema, generation and other required identities to the pre-update snapshot, or explicitly qualify the intentionally disabled healthy profile. restore_state_backup() accepts a human-readable substring as the integrity proof rather than a typed exact identity/status receipt.

F5 — current tests do not cover these interleavings. The latest kill test checks durable journal writes in a child process; the Eggup callback test exercises a synthetic single-binary transaction. Neither reproduces a second update after rollback or death inside the actual SQLite restoration path. Earlier M003 CI/producer evidence is not a substitute for new M004 tests.

Treat F1 and deterministic cleanup failure as source-established defects; F3/F4 as demonstrable contract gaps; the exact reachability of every failure window still requires executable regression evidence. Record any newly disproven scenario rather than overstating it.

## 2. Objective

Make update failure, rollback, recovery and repeat update converge deterministically to a verified binary+SQLite compatibility pair. An operator may attempt another authenticated update after a fully proven terminal rollback, without permitting an unresolved or forged transaction to be overwritten. No path may report successful recovery by checking only journal phase, PID, or executable digest.

## 3. Explicit non-goals

No production trust-root provisioning, unsigned/downgrade override, arbitrary release URL, production crash flag, Cargo fallback, new WireGuard/kernel command passthrough, replacement of Eggup Core file transactions, uninstall feature, or Phase 11 feature work. No historical closure record edits.

## 4. Invariants

- Lock ownership: install, update, recover and future uninstall use the single root-owned transaction lock; re-read and revalidate the journal after lock acquisition.
- Integrity: journal, metadata, recovery artifacts, binary and backed-up DB must have exact expected owner, mode, non-symlink type, bounded size, content digest and transaction identity before they influence restoration.
- Compatibility: no old binary runs against candidate-migrated schema; the old compatible database is restored/verified before old services are started. Service order is stop serve -> stop netd; start netd -> start serve.
- Durability: a transition is committed only after file fsync, atomic namespace transition, and parent-directory fsync. Persist Committed only after candidate product-health success.
- Retry: RolledBack is terminal only after old binary, state, install metadata and services are *actually* proven; otherwise retain or transition to RecoveryRequired.
- Reentrancy: interrupted restore/recovery can be repeated safely, including after file creation, chown, SQLite restore, binary replacement, metadata write and journal write.
- Fail-closed: unknown/tampered identities, missing essential backup, active concurrent mutation or ambiguous systemd ownership never trigger adopt/overwrite/delete of foreign host state.
- Secrecy: state backup, keys and sessions remain owner-only; diagnostic receipts and journal carry safe metadata only.

## 5. Ordered work packages

### WP1 — Terminal journal disposition and clean retry

1. Redesign reject_unresolved_journal() as a terminal transaction reconciliation gate accepting Committed and RolledBack only after confirming the exact corresponding version/hash, install receipt, backup/transaction ownership and, for RolledBack, pre-update state identity plus service health or an explicit safe recovery step.
2. Allow a subsequent authenticated newer update after a verified RolledBack terminal journal. Preserve the last recovery set according to M004 retention policy, archive previous terminal evidence durably, and ensure no overwrite of an occupied archive.
3. For active, RecoveryRequired, mismatched, tampered, or missing-artifact transactions, refuse a new update with a useful recovery instruction; do not erase evidence.
4. Add regression: failed candidate -> RolledBack -> next fixture-signed update -> Committed; include crash/relaunch and mismatched receipt negatives.

### WP2 — Idempotent interrupted restore

1. Replace the deterministic restore temp-file collision with a transaction-bound, owner-verified, idempotent staging policy. Choose a unique create_new temporary candidate plus safe stale-artifact handling, or an equivalent restart-safe mechanism; never follow or truncate a pre-existing attacker-controlled path.
2. Make offline restore restartable across all substeps. Validate the backup and exact old executable before every replay; establish an authoritative source of restoration progress from journal and on-disk evidence, not assumed process completion.
3. Confirm the compatible SQLite restore path handles SQLite WAL/SHM and state-store lease rules on a truly stopped management role; verify full integrity/schema/InstallationId/DesiredGeneration against recorded pre-update evidence.
4. Prove the pre-update backup is usable before binary commit and remains intact on every failed recovery. Verify root-owned private staging and cleanup parent durability.
5. Test SIGKILL after restore temp creation, after ownership adjustment, during/after restore and before binary restoration. Re-run recover twice to show convergence and idempotence.

### WP3 — Safe lifecycle and failure classification

1. Audit Eggup-service's exact LifecycleState and Ownership classifications in the pinned version. A failed/inactive candidate must be stoppable or provably inactive without admitting unknown, foreign, or concurrently active services. Never use a generic systemctl kill/adopt fallback.
2. On any nonterminal recovery failure, preserve the journal and recovery artifacts, stop uncertain services, attempt to persist RecoveryRequired, and expose a specific failure classification. If journaling itself fails, report that explicitly; never claim a clean terminal state.
3. Classify and test durable points around Eggup's binary rollback callback, install metadata writes and phase transitions. Handle cases where Eggup already restored the old binary but candidate migration occurred.
4. Require recover() on terminal Committed/RolledBack to verify the expected installed compatibility pair and service/product health; if services are stopped, either perform an explicitly safe documented reconciliation or refuse a success claim and direct recovery. No implicit downgrade from a durable Committed marker.
5. Add negative cases for failed netd/serve, wrong binary digest, corrupt backup, wrong journal owner/mode/symlink, wrong install receipt, partially restored DB and missing service lease.

### WP4 — Typed health and state identity

1. Capture a nonsecret pre-update record of InstallationId, schema, desired generation, disabled/enabled intent and required product identity. Compare after candidate health and after rollback; allow only explicitly documented migration-compatible fields to change.
2. Prefer an existing typed read-only state/health projection; if insufficient, add a narrowly scoped secret-free local release-health/status projection. Do not use output substring matching or credentials from root to make release checks pass.
3. Qualify enabled/converged and intentionally disabled/healthy installations separately. For an enabled configured network, backend reachability, current-generation convergence and /healthz must be positive. Do not misclassify intentional disable as a failed candidate solely for lack of a live interface.
4. Ensure the health gate is bounded, validates the expected candidate process/generation rather than arbitrary local HTTP content, and retains exact systemd unit ownership enforcement.

## 6. Compatibility and security impacts

Journal on-disk schema, if changed, must explicitly parse/validate old schema-1 journals already produced by current code or fail safely with a documented manual recovery procedure. Do not silently reinterpret historical phase values. Do not change the WireGuard IPC or authenticated HTTP contract. If a new state-health API is required, it must be read-only, typed, nonsecret and usable without an administrator credential. Program files and metadata remain root-owned, the SQLite owner remains the unprivileged service identity, and only authorized services can own the netd socket.

No new external runtime dependencies without a measured justification. Preserve Rust 1.89.0 / locked registry-only dependencies and the pinned Eggup semantics.

## 7. Focused evidence and regression matrix

Required automated cases:
- prior Committed and prior RolledBack: correct archive/retention and a second update; active/RecoveryRequired/tampered journal refuses;
- every recovery phase Prepared, BackupVerified, ServicesStopped, BinaryCommitted, CandidateStarted, CandidateHealthy and RollingBack with old/candidate binary digest possibilities;
- repeated SIGKILL at restore staging, data restoration, binary restoration and journal commit, followed by 2x recover without leaked nonterminal state;
- old-schema v4 -> candidate v5 -> candidate failure -> exact original InstallationId/generation/schema after rollback;
- corrupt/symlink/foreign-owned temp, journal, backup, old binary, install metadata and unit => fail closed;
- management/netd Running/Stopped/Failed/recovering transitions per pinned Eggup-service support;
- product-health enabled-converged and disabled-healthy profiles, plus wrong identity/schema/generation negatives.

Extend existing unit/fixture tests in src/update.rs and add carefully isolated integration fixtures if needed. Do not substitute tests that only persist a synthetic journal for actual recovery validation; the full systemd/rootful/traffic gate belongs to C002.

## 8. Broad verification

Run cargo fmt --all -- --check; cargo check --all-targets --locked; cargo clippy --all-targets --locked -- -D warnings; cargo test --locked; locked Rust 1.89.0 check; cargo audit. Re-run existing Phase 9 upgrade rehearsals and M002 system-install/rootful suite without weakening prior tests. Capture exact commands, output/result, tested commit and environment; do not mark tests green merely because workflow YAML exists.

## 9. Documentation and handoff

Update architecture/update-rollback-contract.md for proven terminal/retry and crash states; add temporary artifact/recovery instructions to docs/operations-runbook.md if behavior changes; keep docs truthful about unprovisioned production signing. Do not prematurely claim M004 closed. Preserve existing M001–M003 closure records.

C001 handoff to C002 must include a phase/action/result table, typed health compatibility contract, durable artifact ownership/retention details, regression command/CI receipts, new known limits, and an implementation revision.

## 10. Acceptance criteria

C001 may close when: (1) verified RolledBack permits another update without erasing recovery evidence; (2) interrupted restore and recovery are repeatable; (3) all early errors have safe, truthful recovery disposition; (4) terminal recovery never claims success for an incompatible or stopped product; (5) pre/post identity and disabled-profile health are properly checked; (6) representative recovery negative tests and old/new schema tests pass; and (7) original Phase 6–9 correctness and privilege boundaries remain intact.

Do not close M004 from C001 alone. C002 still supplies the real signed-fixture/systemd/traffic and final docs/CLI qualification.

## 11. Stop conditions

Stop for a scoped architecture review if Eggup rollback ownership cannot be proven across a crash, state restore cannot be replayed safely under SQLite lease/WAL behavior, services require starting an incompatible binary, accepting a terminal journal would compromise evidence or trust, or a new privileged arbitrary-command/authenticity bypass is proposed. Record any finding rather than weakening assertions.

## 12. Closure evidence

Write a new C001 corrective evidence record only after implementation/testing. Include baseline/final SHA, changed files, defect-to-regression table, exact repeated-recovery matrix, ownership/secrecy review, failures found, CI/MSRV/advisory outcomes, limitations and C002 readiness. Historical distribution M004 plan and prior closure records remain period-accurate.

### 12.1 Implementation review disposition (2026-10-09)

The source changes and available regression evidence are recorded in
`plans/closure/distribution/004-c001-status.md`. Terminal journal/archive and
typed identity checks, unique restore staging, failure classification, and
state restore replay coverage have landed. Strict C001 closure is not claimed:
the pinned Eggup-service 0.1.2 adapter maps systemd `ActiveState=failed` to
`LifecycleState::Unknown` and its stop confirmation only accepts `inactive`;
the full signed-fixture updater rollback/retry and in-restore SIGKILL matrix has
not been run. Do not unblock C002 or M005 from this partial evidence.
