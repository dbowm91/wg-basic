# Operational Hardening M002 — Strict Closure

Disposition: **closed**

Implementation commit: `ae60e81` (`feat: add operational network maintenance and recovery`)

Repository baseline: `2661a6c`  
Implementation head: `ae60e81`  
Closure-record head: recorded by the commit that adds this record.

## Requirement-to-evidence matrix

| Requirement | Evidence |
|---|---|
| Single serve owner with safe crash release | `src/state/service_lease.rs` holds an exclusive nonblocking `nix::fcntl::Flock<File>` on `<state>.serve.lock`; validates regular-file ownership/mode/no-follow; PID/start text is written only after locking and is informational. `serve` acquires before binding. `tests/service_lease.rs` starts real serve children, rejects a duplicate and restore while held, SIGKILLs the owner, then proves restore and restart proceed. No project `unsafe` was added. |
| Maintenance exclusion and online backup | `StateStore::backup` uses a shared `<state>.maintenance.lock`; restore and purge use an exclusive lock while all restore/purge operations also require the service lease free. Unit tests cover shared/exclusive contention. Lock files persist after release; purge retains them to avoid unlinking a locked inode and allowing a second lock domain. |
| Immutable schema v5 migration | `src/state/migrations/005_network_operational_state.sql` backfills every configured interface as enabled. Migration tests prove v4→v5 preserves installation identity, generation, and product state and takes the pre-migration snapshot; a forced v5 collision proves rollback preserves user_version 4. The v1-to-head test proves upgrades reach schema v5. |
| Durable whole-network disable and exact re-enable | Product mutation writes one operational flag and a bounded `network_disable`/`network_enable` audit event without deleting server/client rows or changing peer/address identity. Runtime projects the disabled interface, policy, addresses, routes, and admin state absent. `product_management_rootful::disabling_removes_the_real_peer_and_re_enabling_restores_the_same_one` and the real exported-config handshake test exercise CLI disable, actual interface/peer removal, restart while disabled, and re-enable of the same client identity and traffic. |
| Committed-but-degraded disable if netd is unavailable | `product_management_rootful::a_backend_outage_after_commit_is_committed_but_degraded_and_restart_converges_it` stops real netd, runs CLI network disable, verifies the durable disabled flag and bounded not-enforced report, commits a client while offline, restarts netd/management, verifies disabled remains, then enables and observes convergence. |
| Read-only backup verification | `state verify` reports candidate path, identity, generation, schema, integrity/FK verdict, migration/too-new state, and secret warning. Candidate opens use immutable read-only SQLite URI mode; sidecars are rejected before inspection. `state_backup_restore` verifies candidate bytes and sidecar absence after inspection. |
| Backup self-validation | `StateStore::backup` verifies the staged private file, quick check, foreign keys, schema, installation ID and exact generation before promotion/receipt. `state_backup_restore` covers consistent snapshot receipt, invalid candidate, and failed-restore preservation. |
| Restore refuses live serve and succeeds after death | `tests/service_lease.rs` verifies live restore refusal and successful restore after SIGKILL, then reacquires the lease with a restarted serve process. Restore retains the existing same-process open-store check. |
| Purge is fail-closed and deletes only explicit state artifacts | `state purge` verifies confirmation ID, disabled state, converged generation, and a fresh netd plan with no owned actions. It builds an exact list for the DB, sidecars, known snapshots, retained pre-restore DB, and validated numeric-PID backup/restore artifacts; it refuses symlinks, foreign ownership, permissive modes, and unsafe types. `maintenance_rootful` proves enabled refusal, no-op-plan requirements, dry-run non-removal, exact purge, and preservation of operator backup and lock files. |
| Docs and CI | `docs/state-backup-restore.md`, `docs/development.md`, and `architecture/state-store.md` describe implemented behavior. CI has a rootful `maintenance-rootful` job; the existing product rootful job covers actual network disable/enable and degraded netd behavior. |

## Verification run

All listed commands passed against the implementation tree:

```text
rtk cargo fmt --all -- --check
rtk cargo check --all-targets --locked
rtk cargo clippy --all-targets --locked -- -D warnings
rtk cargo test --locked                         # 508 passed, 27 suites
rtk cargo +1.89.0 check --all-targets --locked
rtk cargo test --locked --test service_lease --test state_backup_restore -- --test-threads=1
rtk cargo test --locked --test product_management
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test maintenance_rootful -- --test-threads=1 --nocapture
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test product_management_rootful -- --test-threads=1 --nocapture
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test durable_backup -- --test-threads=1
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test durable_owner -- --test-threads=1
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test durable_restart -- --test-threads=1
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test doctor_readonly -- --test-threads=1
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test wireguard_kernel -- --test-threads=1
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test network_reconcile -- --test-threads=1
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test network_control_e2e -- --test-threads=1
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test service_rootful_e2e -- --test-threads=1
```

The rootful targets used real disposable namespaces, WireGuard, RTNETLINK, nftables, traffic, process termination/restart, and host/operator-state preservation. During qualification, ordinary read-only SQLite opening was found to create WAL sidecars on a candidate; inspection was changed to immutable mode and regression evidence now asserts no sidecars are created.

## Known limitations and unresolved findings

No high, medium, or low severity finding remains open. The service and maintenance lease files remain on disk after release and purge by design: deleting a locked inode can let another process lock a newly created inode for the same path. Lease contents are never ownership proof. Purge fails closed when state sidecars, unsafe artifacts, unavailable netd, unknown ownership, or pending owned network actions prevent a read-only proof.

## Handoff

M002 is strictly closed. M003's only hard dependency is M002, so M003 is unblocked and active. M004 remains blocked on M003 closure and M005 remains blocked on M004 closure. Phase 10 remains blocked on M005/Phase 9 closure.
