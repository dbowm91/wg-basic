# Distribution M004 — Transactional Self-Update and Rollback

Status: blocked on Distribution M003 closure

Source roadmap:

- `plans/subsystems/distribution-install-update-roadmap.md#8-m004--transactional-self-update-and-rollback-orchestration`

Canonical architecture:

- `plans/adr/006-distribution-install-authenticity-and-update.md`
- `architecture/update-rollback-contract.md`

Primary class: update transaction / recovery / release consumption

Hard dependency:

- Distribution M003 strict closure;
- a production release public key must be provisioned before production update is enabled.

## 1. Objective

Implement authenticated self-update for an already-owned system installation using Eggup for local artifact mechanics while wg-basic retains authority over:

- release selection/authenticity;
- two-service lifecycle ordering;
- secret-bearing state snapshot;
- SQLite migration compatibility;
- product health;
- durable update journal/commit marker;
- crash recovery;
- rollback sequencing.

No Cargo/source fallback exists.

## 2. Required runtime dependencies

Use only the exact registry-only graph qualified in M001.

Expected:

- `eggup-core`;
- `eggup-acquisition`;
- `eggup-curl` preferred;
- `eggup-eggpack`;
- `eggup-service`;
- M001 Minisign verify-only crate.

If exact registry versions have changed by implementation time, re-run the external fixture and pin/update deliberately.

No Git dependencies in production release builds.

## 3. CLI surface

Add:

```text
wg-basic update --check
wg-basic update
wg-basic update recover
```

Optional explicit version selection may be added only for a strictly newer stable release:

```text
wg-basic update --version X.Y.Z
```

Do not add:

- downgrade flag;
- force-unsigned;
- skip-signature;
- skip-health;
- Cargo fallback;
- arbitrary release URL.

All mutating update/recovery operations require root.

## 4. Update transaction lock

Use the root-owned system transaction lock introduced by M002.

Only one of:

- install;
- update;
- update recovery;
- uninstall

may mutate system installation state at a time.

The lock is advisory/kernel-held and crash-released; journal contents are not the lock.

## 5. Release discovery

Canonical origin:

```text
https://github.com/dbowm91/wg-basic
```

or the repository owner/name canonicalized by the M003 release contract.

Discovery selects a stable candidate only.

Allowed implementation shapes:

- bounded GitHub Releases API response;
- exact redirect-safe `releases/latest` metadata resolution.

Policy:

1. HTTPS only;
2. bounded metadata body;
3. no credentials/cookies;
4. no prerelease/draft;
5. parse stable SemVer;
6. candidate strictly newer than installed;
7. after selection, use exact `vX.Y.Z` URLs only.

Discovery metadata remains untrusted until signed manifest verification.

A malicious discovery result may cause refusal/DoS but must not authorize bytes.

## 6. Transport policy

Preferred adapter: `eggup-curl`.

Use Eggup's allowlisted/bounded curl adapter contract.

wg-basic policy:

- resolve only an allowlisted absolute curl executable such as `/usr/bin/curl` after host qualification;
- no shell/PATH fallback after selection;
- HTTPS only;
- strict redirect downgrade denial;
- finite connect timeout;
- finite total timeout;
- small metadata/signature body caps;
- artifact size cap tightened to the signed manifest exact size;
- no response body/URL credential leakage in errors.

M004 must measure binary size/dependency delta against `eggup-eggfetch` and record why curl remains selected.

If supported target hosts cannot reliably provide a safe curl executable, stop and amend ADR-006 before switching.

## 7. Signed metadata order

Required order:

1. acquire bounded manifest bytes;
2. acquire bounded detached signature;
3. verify signature with embedded production public key;
4. only then parse/trust:
   - product;
   - release ID;
   - target inventory;
   - artifact name;
   - artifact size;
   - artifact hash;
5. require selected version/target match local policy;
6. use `eggup-eggpack` projection;
7. construct exact artifact acquisition URL.

Unsigned manifest fields cannot choose a local destination or executable.

## 8. Artifact acquisition and candidate validation

Use Eggup acquisition + adapter:

- private root-owned staging;
- exact signed size cap;
- no-clobber destination;
- SHA-256 via Eggup Core after acquisition;
- executable permission intent.

Candidate validation:

- exact `wg-basic X.Y.Z` output;
- selected version;
- same canonical target;
- bounded execution with cleared/minimal environment;
- candidate must not contact services/state during identity validation.

The candidate is not trusted merely because it runs.

## 9. Owned installation preflight

Before backup/replacement verify again:

- install metadata root-owned/private/valid;
- current binary path/digest/version match metadata;
- unit files root-owned and exact digest match metadata;
- sysusers definition digest match;
- Eggup-service classifies both units `Owned`;
- state path and InstallationId match metadata expectations where recorded;
- no existing unresolved update journal;
- serve service lease/lifecycle can be quiesced;
- destination ownership verifier approves exact current binary.

Any external modification aborts update before state backup or service stop where possible.

## 10. Update transaction directory

Create a unique root-owned private directory:

```text
/var/lib/wg-basic-system/rollback/<transaction-id>/
```

At minimum retain:

- `old-wg-basic`;
- `state-pre-update.db`;
- safe metadata/digests needed for recovery.

Why this exists:

Eggup provides in-process rollback evidence but does not claim a crash-durable updater journal/old-generation store across arbitrary updater process death.

The outer wg-basic transaction therefore keeps its own verified recovery binary and DB until durable commit.

Requirements:

- old binary copied from the currently verified installed path;
- copy is regular, root-owned, executable/private as appropriate;
- SHA-256 equals install metadata;
- file `sync_all`;
- directory sync;
- backup DB created through the current compatible wg-basic state backup path and verified;
- backup digest recorded.

Do not rely solely on Eggup's internal backup directory for crash recovery.

## 11. Update journal

Canonical:

```text
/var/lib/wg-basic-system/update-journal.json
```

Root-owned 0600, safe regular file, atomic replace.

Journal includes only safe metadata.

Required state machine:

```text
Prepared
BackupVerified
ServicesStopped
BinaryCommitted
CandidateStarted
CandidateHealthy
Committed
RollingBack
RolledBack
RecoveryRequired
```

Each phase transition:

1. write a new private temp file in same directory;
2. `sync_all` temp;
3. atomic no-clobber/replace under owned target contract;
4. fsync parent directory;
5. only then perform the next irreversible step.

The durable `Committed` state is the Phase 9 update commit marker.

## 12. Why not Eggup commit_with_lifecycle

wg-basic has:

- one binary;
- two services with ordering;
- one secret-bearing DB that may migrate.

Eggup-service's single-service lifecycle helper is not the complete transaction abstraction.

M004 uses:

- `eggup-service::SystemdManager` for explicit netd/serve ownership and stop/start;
- `eggup-core` for the single installed binary transaction;
- wg-basic's journal/state backup/product health for outer orchestration.

Do not duplicate Eggup Core's file replacement/ownership logic.

## 13. Service quiescence order

Pre-commit:

1. stop `wg-basic.service` first;
2. confirm stopped/lease released;
3. stop `wg-basic-netd.service`;
4. confirm stopped/socket inactive.

Record `ServicesStopped` durably only after both are confirmed.

Do not leave serve running against a netd being replaced/restarted.

## 14. Binary commit

Build an Eggup Core `InstallPlan` for exactly one member:

```text
/usr/local/bin/wg-basic
```

Ownership:

- custom verifier or composition proves the current destination is exactly the owned binary recorded by install metadata;
- absent destination is not acceptable for update;
- permission executable;
- candidate SHA-256 from signed manifest.

Run Eggup integrity + exact candidate validators.

Use the Core post-commit failure policy `RollBack`.

Once Core has committed the candidate binary:

- write `BinaryCommitted` journal state;
- old binary remains additionally available in the outer transaction directory.

## 15. Candidate service start

After candidate binary commit:

1. start netd;
2. confirm service ownership/running;
3. start serve;
4. allow candidate's ordinary startup migration;
5. record `CandidateStarted`.

The candidate owns schema migration through existing StateStore code.

Do not pre-migrate with a separate SQL tool.

## 16. Product-owned health gate

Run entirely local checks without administrator credentials.

Required:

- both service registrations still `Owned`;
- both services running;
- candidate `doctor --json` has no required Fail;
- local `/healthz` exactly `ok` when operational network is enabled and healthy;
- management/state safe read proves current generation/schema/InstallationId;
- current generation converged/backend reachable when an enabled configured network requires it.

For an intentionally whole-network-disabled installation:

- health gate must use the documented disabled healthy profile rather than forcing interface creation;
- doctor/status must show disabled state as intentional, not backend failure.

M004 should add a product-owned non-secret local release-health command if composing these checks through existing commands is fragile, but it must remain read-only.

No admin password/session is required.

## 17. Commit marker ordering

The most important ordering invariant:

```text
candidate health succeeds
 -> write+fsync journal Committed
 -> return success to Eggup Core post-commit callback
 -> Eggup may finalize/delete its old-generation backup
```

Never return Eggup post-commit success before the journal commit marker is durable.

Update receipt success is emitted only after this point.

## 18. In-process rollback

If candidate start/health fails after DB migration:

1. journal `RollingBack`;
2. stop candidate serve;
3. stop candidate netd;
4. prove serve lease free;
5. restore `state-pre-update.db` using compatible restore logic **before old binary is restarted**;
6. verify schema/InstallationId/generation/digest;
7. return the post-commit failure to Eggup Core so it rolls installed binary back;
8. verify installed binary digest/version equals old metadata;
9. start old netd;
10. start old serve;
11. run old-version-compatible health/status validation;
12. record `RolledBack`.

If any critical step cannot be proven, record `RecoveryRequired`, leave recovery artifacts intact, and do not guess/start incompatible generations.

## 19. Crash recovery

`wg-basic update recover` reads only a root-owned valid journal and recovery directory.

It follows the Phase 9 crash-window matrix.

Examples:

### Prepared / BackupVerified

- candidate not authoritative;
- restore/continue old installed pair after validating current binary/state.

### ServicesStopped

- old binary/state should still be authoritative;
- either safely resume update from verified inputs or restart old services after operator-selected rollback policy.

### BinaryCommitted / CandidateStarted / CandidateHealthy without Committed

Treat as uncommitted.

- stop candidate;
- restore recorded pre-update DB;
- restore old binary from outer recovery artifact through Eggup/Core-owned replacement semantics;
- start old services;
- validate;
- record RolledBack.

### Committed

Candidate is authoritative; recovery command performs cleanup/status only and must not silently roll back.

Never infer phase from PID/systemd state.

## 20. Recovery binary restoration

Crash recovery cannot depend on Eggup's in-memory transaction object.

Use the outer verified old binary to create a new Eggup Core rollback/install transaction.

Before restoration:

- recovery artifact digest matches journal/install metadata;
- live destination identity matches an expected candidate/known state or is classified safely;
- services stopped;
- root-owned paths safe.

If destination ownership cannot be proven, return RecoveryRequired without overwriting.

## 21. Update check

`update --check` is read-only.

Output:

- installed version;
- canonical target;
- latest selected stable version;
- update available yes/no;
- release manifest signature status/key ID;
- no artifact download unless required by policy;
- no service/state mutation.

If production trust root is not provisioned, report hard unavailable rather than treating an unsigned release as informationally acceptable.

## 22. Installation metadata update

On successful commit:

- update binary digest/version;
- release source/tag/manifest digest;
- signing key ID;
- unit/sysusers digests if unchanged;
- preserve state path/service identities.

Installation metadata write must be durable and coordinated with the journal commit.

Recommended ordering:

1. candidate health;
2. atomically write new install metadata;
3. journal Committed;
4. Eggup callback success.

If metadata write fails, rollback before Eggup finalizes old binary.

## 23. Recovery artifact cleanup

After durable successful commit and Eggup finalization:

- retain recovery artifacts for a short documented safety period or remove immediately only if the chosen policy is justified;
- cleanup is never allowed to turn a committed update into “failed”;
- failed cleanup is a warning/recovery-retention outcome.

Never delete operator backups.

For Phase 10 baseline, prefer retaining the immediately previous update recovery set until the next successful update or explicit cleanup.

Bound total retained generations, e.g. previous one only.

## 24. Security tests

Signed release:

- wrong key;
- tampered manifest;
- wrong product;
- wrong release;
- wrong target;
- downgrade;
- artifact tamper;
- artifact size mismatch.

Installation ownership:

- binary modified;
- unit modified;
- install metadata modified/permissive/symlink;
- foreign service registration;
- update journal symlink/foreign owner.

Transaction:

- failure before backup;
- stop failure;
- binary commit failure;
- migration failure;
- netd start failure;
- serve start failure;
- doctor/health failure;
- install-metadata write failure;
- commit-marker write failure;
- rollback DB failure;
- rollback binary failure.

Every failure gets a deterministic terminal/RecoveryRequired disposition with no secret in logs.

## 25. Process-kill recovery qualification

Use child-process/update-journal fixtures to kill the updater after representative durable phases:

- BackupVerified;
- ServicesStopped;
- BinaryCommitted;
- CandidateStarted;
- CandidateHealthy.

Tests should observe the journal phase externally and SIGKILL the updater after the phase is durable.

Do not add a production CLI “crash here” switch.

A test-only internal synchronization seam is acceptable if it is unavailable in normal builds.

Restart `update recover` and prove the expected compatible pair.

## 26. Rootful/systemd update E2E

On systemd-capable disposable host/VM:

- install old fixture generation;
- configure real product/client and pass traffic;
- signed newer fixture selected;
- update succeeds;
- state/network identity preserved;
- traffic resumes;
- service hardening remains intact.

Failure case:

- sabotage candidate health after migration (for example controlled netd unavailability);
- update automatically restores old DB and binary;
- old services return;
- fresh real client traffic passes.

Do not weaken candidate code with a production fault flag solely for the test.

## 27. Acceptance criteria

M004 closes only when:

1. release discovery cannot authorize unsigned metadata;
2. signed exact manifest drives target/artifact selection;
3. no Cargo/source fallback exists;
4. Eggup Core owns live binary replacement mechanics;
5. Eggup-service owns bounded systemd operations but wg-basic owns two-service ordering;
6. explicit pre-update DB backup and outer old-binary recovery artifact are durable before mutation;
7. update journal/commit marker is crash-durable;
8. candidate health precedes durable commit;
9. DB restore precedes old binary/service rollback after migration;
10. representative updater SIGKILL phases recover correctly;
11. failed candidate returns old real traffic;
12. successful candidate preserves product identity/traffic;
13. update check is read-only;
14. all prior CI/MSRV/security/rootful suites remain green.

## 28. Stop conditions

Stop/write corrective/ADR amendment if:

- Eggup Core backup/finalization ordering prevents a durable wg-basic commit marker before old generation is discarded;
- systemd service ordering cannot be composed safely around one binary transaction;
- crash recovery would require trusting Eggup in-memory state;
- production update would require an admin password;
- curl availability is not dependable on supported hosts and no documented transport switch exists;
- an update path must start an old binary against a newer schema;
- an unsigned or downgrade override is proposed.

## 29. Closure evidence

Record:

- exact Eggup crates/APIs;
- transport selection/footprint comparison;
- release discovery/auth policy;
- update journal schema/fsync evidence;
- outer recovery artifact contract;
- service stop/start ordering;
- Eggup Core transaction receipt behavior;
- successful candidate E2E;
- failed candidate DB+binary rollback E2E;
- process-kill recovery matrix;
- install metadata/commit marker ordering;
- secret/redaction scan;
- CI/MSRV;
- M005 readiness.
