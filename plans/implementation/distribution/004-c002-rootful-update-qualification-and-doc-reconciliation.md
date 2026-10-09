# Distribution M004 C002 — Rootful Transaction Qualification and Operator-Contract Reconciliation

Status: active — M004 C001 strict closure is recorded in `plans/closure/distribution/004-c001-status.md`; systemd/traffic, docs, and M004 qualification are underway.
Repository baseline: dbowm91/wg-basic main at 7b69c75634242bf0d5c0d35374b96346c73f20c6 (2026-10-08). Rebase/re-review at C001's verified implementation head.
Primary work class: corrective / capability qualification / documentation polish.

## Authority and dependency

Source milestone: plans/implementation/distribution/004-transactional-self-update-and-rollback.md.
Roadmap: plans/subsystems/distribution-install-update-roadmap.md, M004.
Architecture: plans/adr/006-distribution-install-authenticity-and-update.md; architecture/update-rollback-contract.md; architecture/service-hardening.md.
Previous closure: plans/closure/distribution/003-final-status.md (mechanical release producer).
Hard predecessor: plans/implementation/distribution/004-c001-update-retry-recovery-invariants.md closes with supported rollback/recovery state machine and exact state-identity contract.
Successor: Distribution M005 remains blocked until M004 strict technical closure.

CLI decision: retain the implemented explicit `wg-basic update check`,
`wg-basic update run`, and `wg-basic update recover` forms as the single
canonical operator contract. `run` and `recover` require effective root and
never invoke sudo; `check` is read-only. Do not add `update`/`update --check`
aliases in this corrective, which avoids changing the established clap
surface while keeping each operation unambiguous.

## 1. Verified gap and cause

A. The code at baseline implements src/update.rs::apply, recover and check and a SIGKILL test around an artificial journal-writer process. This does not prove an installed system can be updated with real systemd units or recover after a candidate schema migration.
B. src/update.rs release tests use fixture acquisition/signatures and an Eggup callback test in a scratch directory. They do not run the full locked two-service/database update.
C. .github/workflows/ci.yml retains Phase 6–9 kernel, upgrade and systemd installation jobs, but has no dedicated rootful signed-update/rollback/recovery job. Existing .github/workflows/distribution-foundation.yml and release-eggpack.yml cover producer mechanics rather than updater lifecycle.
D. src/release.rs::PRODUCTION_PUBLIC_KEY is intentionally None. Production update/check fail closed, so the full signed-fixture transaction needs an explicitly non-shipping trust/transport fixture seam. Never loosen the shipped release verifier to make an E2E test possible.
E. CLI implementation uses `wg-basic update check|run|recover`; the M004 plan and architecture docs describe `wg-basic update --check`, `wg-basic update`, and `wg-basic update recover`. README still claims update is not implemented; plans/002-long-term-roadmap.md says Phase 10 is only planned; docs/operations-runbook.md still assumes no installed systemd units. Operator documentation and actual CLI need reconciliation.
F. M004's stated required enabled/disabled healthy gates, release-identity binding, root-owned artifacts, rollback ordering, footprint and host requirements have yet to be accepted on real installed fixtures. These are evidence debts, not proof of failure.

## 2. Objective

Prove the real updater's signed release acquisition, binary+database transaction, systemd ordering, rollback and SIGKILL recovery against disposable Linux installations with traffic. Align shipped operator CLI/docs with implemented and qualified behavior. Produce evidence sufficient for an honest M004 closure decision, keeping public publication explicitly blocked until a real maintainer-provisioned trust root and release authorization exist.

## 3. Non-goals

Do not implement M005 uninstall/reinstall, auto-publish a release, add a production signature bypass, accept arbitrary update URLs, create a writable generic privileged IPC, use a Cargo/source fallback on target installations, rework Eggpack producer architecture, or start Phase 11 IPv6. No historical closure record rewrites.

## 4. Non-shipping fixture design

1. Prefer an integration harness that invokes the actual `apply` transaction with injected `AcquisitionTransport` and a fixture-generated Minisign verification key, using a separately compiled test-only dependency-injection entrypoint or test support module that cannot be linked/exposed by a normal release build.
2. The signed fixture MUST use the production authenticity/parsing/projection, Eggup acquisition, ownership, binary commit, SQLite restore, journal and systemd paths without replacing their semantics. Avoid a fake apply routine that only exercises a subset.
3. Create old and candidate fixture binaries at strictly increasing stable SemVer versions and corresponding signed manifest/asset hashes. Prefer stable history fixtures (e8fd6b1 v4 and current candidate v5), or scratch version changes in isolated worktrees as already documented in M005; do not alter project history/tags or supply fixture private keys to production builds.
4. The canonical production CLI remains bound to its embedded project public key. A fixture key may enter only test code/child processes executed in a disposable VM. Verify release builds contain no fixture public-key fallback, arbitrary URL/key arguments, or test fault-injection switches.
5. Host update transport must stay bounded and HTTPS-only. If a local fixture server is used, inject it through an integration-test-only transport without weakening the production allowlist; assert exact selected URLs/target/version and that tampered metadata is rejected before binary or service mutation.
6. Inspect test-host prerequisites explicitly: actual systemd system manager, kernel WireGuard, nftables, root/CAP_NET_ADMIN, required safe absolute curl/runuser paths, declared glibc floor, x86_64/aarch64 architecture. A missing prerequisite is a clear skipped/not-qualified result, not a pass.

## 5. Ordered implementation work

### WP1 — Full systemd success transaction

On a clean disposable x86_64 systemd VM/runner, install an exact owned old fixture binary and services with production M002 system installation, initialize state, set admin credentials, configure server + client using the authenticated product API, and establish real namespace WireGuard handshake and traffic. Snapshot InstallationId, schema, DesiredGeneration, peer/server identities, endpoint/address and state digests.

Run an authenticated fixture-signed candidate update through the same updater transaction. Observe durable phases externally; verify netd/serve stop and start order, candidate identity, migration, ownership/capabilities and product-health gate. Verify Committed journal and updated install receipt, same managed client identity and fresh successful post-update traffic. Assert old binary+DB recovery evidence existed through commit. Do not mistake successful process start for traffic proof.

### WP2 — Failed-candidate rollback and retry

Cause a *post-commit* candidate start/product-health failure using a disposable host/environment fixture (e.g., a required owned unit/device temporarily unavailable), not a production flag. Require evidence candidate reached binary commit and, in the v4->v5 path, candidate migration.

Assert candidate serve/netd stopped; original compatible DB restored and verified before old binary/service start; installed binary and metadata digests match old release; old admin/product state and InstallationId/generation survive; traffic with the original client config resumes. Journal reaches RolledBack or a properly classified RecoveryRequired with a proven blocked condition. After clean rollback remove fault and perform a new signed update to Committed, showing C001 terminal retry is functional.

### WP3 — Actual updater SIGKILL/recovery

Use external observation of root-owned journal durability (with bounded polling) and SIGKILL the real updater at representative BackupVerified, ServicesStopped, BinaryCommitted, CandidateStarted, CandidateHealthy. Include post-migration cutpoints, and a distinct crash during actual database restoration/rollback as authorized by C001. No production crash switch.

For each cutpoint restart `wg-basic update recover`, repeat once, and verify terminal journal/receipt, exact executable hash and compatible database schema, service ownership/running state, and fresh real client traffic. Confirm no old service ever boots against the migrated new schema. Deliberately corrupt/replace backup, journal, binary and units to confirm safe no-overwrite/no-start behavior and retained evidence.

### WP4 — Health/disabled-state and adversarial matrix

Qualify both enabled healthy configuration (reachable netd, converged current generation, /healthz ok) and intentionally whole-network-disabled but healthy configuration. Test wrong InstallationId, schema, generation, release selection, binary digest, manifest/key signature, artifact size, owned-unit status, unsafe metadata permissions/symlinks, missing backup, failing restart and startup timeout. Ensure after each failure either the compatible previous pair is proven healthy or the services remain safely stopped with explicit recoverability and artifacts retained.

Prove successful old/new transaction does not change session/admin policy or expose secrets in logs, journals, stdout, subprocess arguments or environment. Check that runtime old binary copy/backup paths and metadata are protected and have bounded retention.

### WP5 — Operator CLI and documentation reconciliation

Resolve the actual CLI contract deliberately. Canonical recommendation is `wg-basic update` (mutating), `wg-basic update --check` (read-only), and `wg-basic update recover`; optionally retain existing `update run` and `update check` as documented compatibility aliases. If clap syntax or compatibility merits a different choice, document a single canonical operator contract and amend the active implementation plan explicitly, with unit/CLI integration tests. Never conflate `update recover` with another update or make `--check` mutating.

Update README, plans/002-long-term-roadmap.md (status snapshot only), architecture/cli-roles.md, architecture/overview.md, architecture/update-rollback-contract.md, docs/operations-runbook.md, docs/development.md, and installation/update guidance to state:
- current Phase 10 M001–M003 closed / M004 qualified or active / M005 blocked status;
- exact real CLI commands, required root permissions and lock contention behavior;
- systemd service layout/host prerequisites and currently supported x86_64/aarch64 Linux GNU targets;
- default immutable release trust root absence and fixture vs production signing;
- explicit crash-recovery operator steps and refusal states;
- backup secrecy, retention, compatibility, restore, and limits;
- exact evidence for success, rollback and disabled healthy profile;
- supported release transport and convenience bootstrap trust caveat.
Keep historical closure records unchanged; do not claim uninstall/first public release exists.

### WP6 — Automated CI/qualification and performance

Add a dedicated M004 workflow/job for rootful update transaction and SIGKILL recovery on a truthful systemd-capable isolated runner/VM; do not rely solely on the current generic Ubuntu runner unless its manager properties are empirically proven. Share/extend the existing system_installation.rs fixture where sensible without weakening it. Use a dedicated isolation/cleanup strategy: destructive root tests require a disposable clean host; no tests mutate a developer's real /usr/local/bin, service units or state.

Make fixture version/signature/manifest generation repeatable, record exact scripts/commands/artifacts, pin external tool versions and seed dependencies to avoid implicit network in the qualification step. Test against supported Rust 1.89.0, locked dependency graph and both GNU candidate architectures; native execute/qualify both, with full rootful update on at least one host and any unsupported other-architecture systemd evidence explicitly deferred to M005.

Compare Eggup curl vs alternative transport link/footprint/host availability as required by M004; record binary bytes, per-service RSS, startup/readiness, storage amplification during backup/rollback and idle CPU. Do not weaken Argon2id, root/service capability separation, authenticity, or TLS restrictions to hit footprint targets.

The actual updater fixture uses schema-v4/product source `3e5b21c` and its
locked release-mode artifact as the old installation. It receives the exact
Phase 9 M002 `ServiceLease` module from `ae60e81` plus the small serve-entry
acquisition call needed to prove the current updater's lease contract. The
scratch-only patch also adds the three M002 unit CLI requirements (`state init`,
`netd --allow-user`, and `doctor --allow-warnings`, accepting its legacy
`unknown` lease diagnostic; `state verify` is also exposed over the fixture's
existing read-only candidate validator). It adds `state identity` compatibility
output needed to prove the restored v4 database. Its v4 network-enabled
projection is true when interfaces are configured, matching the current
state reader's legacy-schema compatibility behavior.
State and doctor behavior remain from v4 source; the candidate is built from
C002 source in a scratch archive with version 0.1.1 and test-only fault hooks.
For v4 identity assertions, the rootful fixture stages a temporary controller
copy inside the service-owned state directory, because the hosted runner's
Cargo target directory is not traversable by the management user. The helper
is removed after qualification. None of these fixture adaptations alter
repository history or production binaries.

Rootful rollback qualification showed that terminal journal validation treated
the pre-update product identity as immutable forever. That rejected later
normal product changes after a successful rollback and prevented retry. A
terminal transaction now pins InstallationId and the compatible schema while
allowing generation/network/product changes after its completion. Immediate
rollback qualification still asserts exact pre-update identity before any
subsequent product mutation. The bounded startup-timeout fixture also pipes
the updater's diagnostics so it asserts the actual service-start failure. The
identity reader uses a dedicated read-only SQLite path so verification never
applies migrations; a regression test keeps v4 and live WAL at v4 across
inspection.

The rootful startup-timeout case also proved candidate restarts can exhaust
systemd's per-unit start limit before old-generation recovery. Recovery now
resets the failed-start counter only after revalidating exact ownership of the
unit, using a bounded literal systemctl operation through Eggup's executor.
Hosted recovery diagnostics showed that Eggup's normal stop re-inspects
ownership before issuing `systemctl stop`; that inspection can remain blocked
behind the candidate's timed-out systemd start job until its entire transition
deadline expires. For the `Transitioning` state only, recovery now requests
`systemctl --system stop --no-block` for the exact Eggup-owned unit through its
bounded executor. Recovery then re-inspects ownership/state: it accepts an
inactive unit, or delegates a resolved running/failed state to Eggup's normal
stop path (including its failed-unit cgroup/process quiescence proof). If
Eggup proves a failed unit quiescent while the lifecycle projection remains
`Unknown`, that typed proof is retained through the final ownership check. The
service lease or socket postcondition is then confirmed. Candidate start and
updater health checks retain their existing 30-second bound.

Transport comparison at C002 implementation head `f5988c4` (x86_64 Linux,
Rust 1.89.0, locked release profile): the current curl-linked `wg-basic` executable is
12,218,768 bytes (SHA-256
`a67304092fbb9276a28dc4b777b7b8078e0b07996691d5d5269a5ca5ecf56729`). A
disposable source archive replacing only the acquisition adapter with
`eggup-eggfetch 0.1.3` and the same 10s connect / 300s total / five-redirect
limits builds to 14,002,368 bytes (SHA-256
`b70158b3489309ca1f644b29cb5d99f8e5dcd73c73940cfce1f4e59d38aa4196`), an
increase of 1,783,600 bytes (14.6%). The resolved normal dependency graph is
176 unique package/version lines for the current locked application and 241
for that alternative build. This is a whole-application comparison using the
same host toolchain and release profile, with an isolated re-resolved
alternative lockfile; it is not a shipping lockfile proposal. The hosted
rootful updater selected `/usr/bin/curl`; on the measured host it is a root
owned, non-writable regular executable (mode 0755). The curl adapter remains
selected for the smaller release binary/dependency graph. Eggfetch would
remove the runtime curl package assumption but increase static linked size and
dependency surface; production transport policy is unchanged.

Release service footprint on the local x86_64 Linux host at the same source
head: serve 9.81 MiB RSS, netd 5.48 MiB RSS, combined 15.29 MiB; cold serve
readiness 56.6 ms, median `/healthz` 1.11 ms, authenticated API health 20.2
ms, login including Argon2id 66.4 ms, and zero idle CPU ticks for both
services over two seconds. The rootful fixture emits exact live state, verified
backup, old/candidate binary, journal, and runtime recovery-copy byte counts
both after post-migration rollback and at the durable `BinaryCommitted`
startup-timeout cutpoint, where the complete peak recovery set is present.
Storage amplification is measured from the real update transaction rather than
inferred.

## 6. Verification gates and responsibility split

C002 is a systemd/update qualification slice, not M005 full clean-install/uninstall release-lifecycle qualification. The latter keeps its separate acceptance gate. Re-run:
- cargo fmt --all -- --check
- cargo check --all-targets --locked
- cargo clippy --all-targets --locked -- -D warnings
- cargo test --locked
- Rust 1.89.0 locked check and cargo audit
- existing system-installation, product rootful, durable backup, full Phase 9 old/new upgrade rehearsal, kernel network/control and maintenance jobs
- added M004 signed-fixture rootful success, post-migration failure/rollback/re-update, interrupted recovery, and security refusal jobs
- .github/workflows/distribution-foundation.yml release contract and both native candidate targets

Record exact workflow URLs/job results and tested commit rather than asserting pass based on green older commits or YAML existence. On a missing target/host gate, mark blocked/unqualified, never pass by simulation.

## 7. Security, compatibility and operational effects

Only root-owned update transaction metadata and service lifecycle may change. SQLite remains writable by the management service identity, netd database-free, management API auth/CSRF unchanged, bounded root subprocess policy preserved. No new trust root or signing key is distributed by these tests. Journal/backups must remain owner-private and not become export routes.

When changing CLI, avoid ambiguous compatibility: define exact default, read-only and recovery invocations and test their observed effects (read-only check must not lock services/mutate state). Old journal schema-1 compatibility is owned by C001. For a supported enabled network, never treat a degraded backend as success; intentionally disabled network follows a separately qualified documented profile.

## 8. Acceptance and stop conditions

C002 can close only if actual end-to-end signed-fixture systemd update preserves identity/traffic, failed candidate restores the compatible DB+binary and traffic, representative real-updater SIGKILL windows recover correctly, a retry succeeds after rollback, owner/foreign resource negatives fail closed, both health profiles are qualified, complete current-head test/CI and target evidence are recorded, and CLI/docs accurately describe working behavior.

If required systemd fixtures are not available, signing seam cannot be test-only without exposing a production bypass, crash restore is non-replayable, Eggup discards rollback evidence before durable journal commit, or an old binary must touch migrated state, stop and write a bounded follow-up corrective rather than declaring closure.

C002 completion alone does not automatically authorize the first public release. Any M004 technical closure disposition must distinguish fixture-proven mechanics from absent maintainer-provisioned production public key, draft signatures and publication authorization. If the accepted M004 plan genuinely requires trust-root provisioning for strict rather than mechanical closure, record M004 as technically qualified but operationally blocked; do not silently relax that gate.

## 9. Closure evidence and next handoff

After implementation, write C002 evidence with implementation baseline/final commit, defect/evidence mapping, test fixture binaries/versions/target manifest digests, old-v4/candidate-v5 migration path, rootful systemd journal/traffic receipts, forced-failure and SIGKILL matrix, 2x recover/re-update, transport+footprint measurements, exact CI/run URLs, redaction/security findings, documentation and CLI version, unresolved severity classification, release trust-root disposition, and M004/M005 readiness.

If both C001 and C002 pass, write the separate canonical M004 closure record per plans/003-planning-process.md. Do not register M005 as ready until that disposition supports it.
