# Operational Hardening M002 — Maintenance Lease, Network Disable/Purge, and Recovery UX

Status: closed

Source roadmap:

- `plans/subsystems/operational-hardening-roadmap.md#6-m002--operational-state-lifecycle-and-recovery-ux`

Canonical architecture:

- `plans/adr/005-operational-hardening-maintenance-and-recovery.md`

Primary class: operations / safety / persistence

Hard dependency: Operational Hardening M001 strict closure.

## 1. Objective

Make maintenance operations unambiguous and fail-closed:

- exactly one live serve process per database;
- “disable networking but keep my VPN configuration”;
- “verify this backup without restoring it”;
- “destroy wg-basic state only after proving owned network state is gone”.

## 2. Service singleton lease

Add an advisory lease tied to the state path, such as `state.db.serve.lock`.

Requirements:

- regular file, no symlink;
- owned by management user;
- non-group/world writable;
- kernel advisory exclusive nonblocking lock;
- held for full `serve` lifetime;
- automatically released on graceful exit and SIGKILL;
- stale file contents never treated as ownership proof.

The file may contain safe informational PID/start metadata only after the lock is held.

A second `serve` fails before binding HTTP or owning the DB.

Use safe Rust/nix APIs; do not add `unsafe`.

## 3. Maintenance exclusion

Offline destructive commands require the serve lease to be free.

At minimum:

- state restore;
- state purge;
- network enable/disable.

Read-only status/doctor and online backup remain allowed unless their own storage contract says otherwise.

Restore's current same-process in-use check remains defense in depth but is no longer the sole exclusion mechanism.

## 4. Schema migration 5

Add immutable `005_network_operational_state.sql`.

Preferred shape:

- `operational_enabled INTEGER NOT NULL DEFAULT 1` on `interface_product_settings`, or equivalent one-row product-operational state keyed by InterfaceId.

Migration v4→v5:

- every existing configured server becomes enabled=true;
- DesiredGeneration does not change merely because schema migrated;
- client/key/address/product semantics remain identical.

Qualify the pre-migration snapshot and failure rollback.

## 5. Disabled projection

When the primary server is operationally disabled:

- managed interface projects absent;
- network policy projects absent;
- server/client/product rows remain;
- client enabled flags remain separate;
- keys and assigned addresses remain;
- advertised endpoint/settings remain.

Disabled state persists across serve/netd/host restart.

Enable restores the same network identity and client state.

## 6. Local network maintenance CLI

Add:

- `wg-basic network status`;
- `wg-basic network disable`;
- `wg-basic network enable`.

Mutating commands:

- require serve lease free;
- load current generation;
- perform one typed product mutation;
- append secret-safe audit event;
- reconcile through netd;
- report generation + enforcement truth;
- never escalate privilege or spawn netd.

If netd is unavailable after commit, report committed-but-not-enforced exactly as Phase 8 does.

## 7. Rootful disable/re-enable qualification

Required sequence:

1. configured server/client passes real traffic;
2. stop serve for offline maintenance command;
3. disable network;
4. owned firewall state removed;
5. interface removed;
6. client traffic stops;
7. DB still contains server/client configuration;
8. restart serve/netd;
9. network remains disabled;
10. enable network;
11. same server public identity returns;
12. same client config handshakes and passes traffic again.

Unrelated host state remains untouched.

## 8. State verify

Add `wg-basic state verify <candidate>`.

Read-only output:

- path;
- installation ID;
- desired generation;
- schema version;
- integrity/foreign-key verdict;
- whether current binary would migrate it;
- whether schema is too new;
- secret-bearing warning.

It MUST NOT migrate or alter the candidate.

## 9. Backup self-validation

A successful `state backup` verifies the promoted result before reporting success:

- regular/private;
- quick_check;
- foreign keys;
- schema;
- installation ID;
- exact desired generation matches receipt.

If verification fails, the operation is failure, not a successful backup receipt.

## 10. Restore exclusivity

Before restore:

- prove serve lease free;
- preserve all existing candidate/target validation;
- stage/migrate/replace atomically as today.

Test that restore refuses while a real serve child holds the lease and succeeds after graceful exit or SIGKILL.

## 11. Purge CLI

Add:

`wg-basic state purge --confirm-installation-id <uuid> [--dry-run]`

plus state/socket options.

Purge preconditions:

1. serve lease free;
2. state validates;
3. exact InstallationId confirmation matches;
4. configured server operational state is disabled;
5. current DesiredGeneration equals last converged generation;
6. project disabled desired state;
7. ask netd for PLAN only;
8. plan proves no owned interface/firewall mutation remains;
9. no ownership conflict or unknown backend state.

If netd is unavailable, purge fails closed.

## 12. Purge deletion set

Build an explicit list; do not broad-glob.

Eligible owned artifacts:

- live DB;
- exact WAL/SHM sidecars;
- deterministic pre-migration snapshots;
- exact pre-restore retained DB;
- temporary artifacts only when their deterministic name/type/owner proves wg-basic ownership;
- lease file after lock release.

Do not remove arbitrary operator backups, binary, config/service units, symlinks, or foreign-owned files.

Unsafe target metadata causes failure rather than unlink.

## 13. Purge dry-run and receipt

Dry run prints InstallationId, preconditions, exact removal paths, preserved paths, and unmet requirements.

Actual purge prints only safe identifiers/path outcomes.

No secrets.

## 14. Tests

Unprivileged:

- lease exclusivity and child-process death release;
- path/symlink/owner checks;
- v4→v5 migration;
- disabled projection persistence;
- state verify;
- backup self-verification;
- restore blocked by live serve;
- purge confirmation/path/refusal matrix.

Rootful:

- disable/enable traffic lifecycle;
- restart while disabled;
- netd-down committed/degraded disable;
- purge refuses with live owned state;
- purge succeeds only after disabled+converged+plan-no-op;
- unrelated host state survives.

## 15. Acceptance criteria

M002 closes only when duplicate serve ownership is prevented; process death releases ownership without trusted PID cleanup; schema v5 is qualified; disable is durable and preserves configuration; enable restores the same network identity; backup verification works without restore; restore is cross-process exclusive; purge cannot orphan owned network state; purge deletes only explicit owned artifacts; and all prior CI/MSRV/rootful tests remain green.

## 16. Stop conditions

Stop/ADR if the lease requires unsafe platform primitives, disabling would require deleting authoritative product rows, purge cannot prove network absence read-only, or restore exclusivity would break online backup.

## 17. Closure evidence

Record lease path/semantics, schema v5 migration, disable/re-enable real traffic, restart-disabled behavior, state verify sample, backup self-check, purge dry-run/deletion matrix, foreign-state preservation, CI/MSRV, and M003 readiness.
