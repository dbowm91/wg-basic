# Distribution M004 C001 — Implementation Disposition

Disposition: **corrective required** (implementation work landed; strict C001
acceptance is not yet proven).

Date: 2026-10-09

## Baseline and implementation revision

- Repository branch: `plans/m004-update-correctives`.
- Baseline: `237f5f4` (`plans: sequence M004 corrective prerequisites in distribution roadmap`).
- Implementation revision: `e3ff649d063a6ce54560e012a7b14cf2697f3421` (`fix(distribution): harden update recovery retry invariants`).
- Production release trust root remains unprovisioned; production `update check`
  and `update run` remain fail-closed.

## Requirement and evidence matrix

| Defect/requirement | Change and observed evidence | Result |
|---|---|---|
| F1: RolledBack prevents a retry | Terminal reconciliation now accepts Committed and RolledBack only after checking transaction artifacts, install receipt, binary digest, typed state identity, owned running services, and product health. Previous terminal journals are durably archived and retained. | Code path implemented; signed-fixture rollback → second update regression was not run. |
| F2: deterministic restore staging collision | Restore staging names include a fresh transaction-bound UUID, so a stale name cannot prevent a subsequent restore. The staged file is ownership/mode checked and validated with the old compatible binary before restore; state and parent directory are synced. | State restore replay regression passed twice against a real SQLite database. SIGKILL cutpoints inside updater restore were not run. |
| F3: terminal recovery is not a health proof | Terminal recovery now verifies the selected binary/receipt, state compatibility, current service ownership/running state, and management product-health projection. It refuses success when services are stopped or ambiguous. | Implemented; terminal paths lack the dedicated real-systemd M004 test matrix. |
| F4: weak health and identity checks | Added a secret-free typed `state identity` projection binding installation ID, schema, desired generation, network enabled intent, and digest of product identifiers. Candidate/rollback checks compare the projection; enabled and intentionally disabled health profiles are distinguished. | Unit profile checks passed. Wrong identity/schema/generation and real disabled-profile M004 cases remain unqualified. |
| F5: insufficient interleaving coverage | Added SQLite restore replay and enabled/disabled health projection regressions. Existing Phase 9 schema migration and rollback rehearsals were rerun. | The actual updater signed-fixture second-update and recovery crash matrix remains outstanding. |
| WP3: service lifecycle states | Audited locked `eggup-service` 0.1.2. Its systemd parser maps `ActiveState=failed` to `LifecycleState::Unknown`; stop confirmation only accepts `is-active` state `inactive`. wg-basic refuses to treat Unknown/Transitioning as stopped and keeps the journal unresolved. | **Blocking limitation.** No safe typed Eggup action currently proves/stops this state. No generic systemctl kill/adopt fallback was added. |

## Artifact and secrecy review

- Journal schema remains 1. `old_state_identity` is optional on parse so old
  schema-1 journals remain readable; a historical terminal journal without that
  identity cannot be accepted as a proven rollback and requires operator
  recovery/review.
- Transaction files remain root-owned and private; the SQLite backup remains
  root-owned mode `0600` outside the service-writable state directory.
- Restore staging is service-owned mode `0600`, unique per recovery attempt,
  and contains the same secret-bearing database contents. No state rows, keys,
  session contents, or credentials are added to the journal or identity output.
- The prior terminal transaction and recovery set are retained after a retry;
  no prior set is recursively deleted by update success.
- No IPC or authenticated HTTP contract, privilege boundary, external runtime
  dependency, or release trust behavior changed.

## Verification executed

Commands were run from the repository root against the implementation working
tree based on `237f5f4`:

| Command | Result |
|---|---|
| `rtk cargo fmt --all -- --check` | Passed |
| `rtk cargo check --all-targets --locked` | Passed |
| `rtk cargo clippy --all-targets --locked -- -D warnings` | Passed |
| `rtk cargo test --locked` | Passed: 559 passed, 3 ignored, 34 suites |
| `rtk cargo +1.89.0 check --all-targets --locked` | Passed |
| `rtk cargo audit` | Passed; scanned 211 locked crate dependencies against 1,295 loaded advisories |
| `rtk proxy bash -c 'WGB_OLD_BINARY=/tmp/wg-basic-phase8-c001-target/release/wg-basic WGB_CANDIDATE_BINARY=/tmp/wg-basic-c001-candidate-target/release/wg-basic cargo test --locked --test upgrade_rehearsal -- --ignored --nocapture'` | Passed: 1 real v4→v5 migration/rollback/re-upgrade test |
| `sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo CARGO_TARGET_DIR=/tmp/wg-basic-upgrade-rootful-target WGB_OLD_BINARY=/tmp/wg-basic-phase8-c001-target/release/wg-basic WGB_CANDIDATE_BINARY=/tmp/wg-basic-c001-candidate-target/release/wg-basic cargo test --locked --features linux-integration --test upgrade_rehearsal_rootful -- --ignored --nocapture --test-threads=1` (run via `rtk proxy bash -c`) | Passed: 1 real v4 product traffic/rollback/re-upgrade test |
| Rootful `system_installation` | Not run. Its documented procedure mutates `/usr/local/bin`, systemd units, accounts, and `/var/lib`; this shared workspace host is not a disposable VM. |

The Phase 9 rehearsal verifies its own existing database rollback contract. It
does not substitute for the M004 signed-fixture updater qualification owned by
C002. No C001 updater-level SIGKILL/2x-recover run or signed-fixture retry run
was claimed.

Environment for both Phase 9 rehearsals: Linux `6.8.0-146-generic`, x86_64,
systemd 255 (`255.4-1ubuntu8.17`); the rootful namespace test ran with effective
root and the listed kernel/network prerequisites.

## Changed files

- `src/update.rs`
- `src/main.rs`
- `src/state/backup.rs`
- `architecture/update-rollback-contract.md`
- `architecture/cli-roles.md`
- `docs/operations-runbook.md`
- `plans/implementation/distribution/004-c001-update-retry-recovery-invariants.md`
- `plans/subsystems/distribution-install-update-roadmap.md`
- `plans/registry.md`

## Failure classification, limitations, and handoff

The primary unresolved item is the pinned Eggup-service failed-unit behavior
described above. Its typed API cannot confirm an `ActiveState=failed` unit as
stopped, and its lifecycle poll does not accept that state after a stop request.
Recovery remains fail-closed and does not start an incompatible binary or claim
terminal success. Resolving this requires a scoped review of the selected
service-manager contract or a qualified Eggup-service change, plus regression
tests for Failed/Unknown/Transitioning ownership states.

The M004 signed-fixture updater harness, actual update rollback/re-update case,
and updater crash matrix (including SIGKILL during state restoration) are also
outstanding. C002's hard dependency on C001 strict closure is therefore still
unsatisfied. C002 remains **blocked**, M005 remains **blocked on M004 closure**,
and no successor implementation plan is eligible to begin from this evidence.
M004 itself is not closed.

## C001a progress addendum — upstream prerequisite resolved (2026-10-09; not closure)

Eggup Service M010 closed with a required runtime correction at source
`0bde3fefbda07019529ad7566c02e6e4ec141fd6`; hosted run `37875012280` passed
the real-systemd failed-unit matrix and all other required lanes. Service M011
published `eggup-service 0.1.3` from
`feb6ae5aea4c9b61c4051957f3662ca49d845f9e`, registry SHA-256
`9f7f7ea854577158e66aa202709ab1c97a3aedcf00b06c1ab914d25b132124dc`; hosted
post-publication run `37883703334` passed all five lanes. The upstream records
are `eggstack/eggup` `plans/closure/service-lifecycle/010-status.md` and
`011-status.md`.

wg-basic now pins the exact published 0.1.3 package. The local stop path
implementation is commit
`87320c73bd28d05d20dbfa7a9169ed66661c3e98` (`fix(distribution): adopt Eggup
failed-unit quiescence`). It retains the pre-mutation Owned check, calls
Eggup's typed stop for an Owned `Unknown` lifecycle observation, requires its
completed receipt, rechecks exact ownership, and accepts the still-Unknown
post-state only for that successful path. It also proves the serve lease is
released and netd's socket is inactive
before subsequent database rollback. A focused transition-matrix regression
rejects transition states and incomplete stop results. No generic process or
systemctl fallback was added. Because update runs as root while the lease file
belongs to the `wg-basic` account, the lease probe validates the expected
management UID rather than incorrectly comparing it with root's effective UID.

Current local evidence: `cargo fmt --all -- --check`, `cargo check
--all-targets --locked`, `cargo clippy --all-targets --locked -- -D warnings`,
`cargo test --locked` (560 passed, 3 ignored, 34 suites), `cargo +1.89.0 check
--all-targets --locked`, `cargo audit` (211 locked dependencies),
`cargo tree -i eggup-service --locked`, and `git diff --check` passed on the
C001a implementation tree. The lockfile resolves `eggup-service 0.1.3` from
crates.io with the checksum above.

This addendum does **not** close C001. The required C001a real updater signed-
fixture rollback/retry, updater-process SIGKILL/recover-twice cutpoints,
post-migration SQLite restore interruption, and negative rootful service/unit
fixtures have not been run or added to isolated CI. The local host is not a
disposable systemd VM, so destructive suites were not run here. C001 remains
`corrective required`; C002 remains blocked on C001 closure; M005 remains
blocked on M004 closure. Exact next work is to add/run C001a's isolated actual-
updater systemd fixture and record its disposable runner, systemd/kernel,
cutpoints, state-identity checks, and immutable CI run before deciding closure.
