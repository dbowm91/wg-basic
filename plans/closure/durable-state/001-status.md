# Durable State M001 Closure

Status: closed

Planning baseline: `3f9bfaa` (C001 closure)
Final implementation head: `88f10f9`
Qualification run: GitHub Actions CI run [`37619412663`](https://github.com/dbowm91/wg-basic/actions/runs/37619412663), commit `88f10f9`

## Outcome

M001 is strictly closed. wg-basic now has an authoritative unprivileged application-state store: hardened bundled SQLite storage, an ordered migration runner, one stable installation identity, a monotonic desired generation with compare-and-swap mutation, and deterministic projection into the existing kernel intent types.

M001 does **not** yet reconcile the kernel. Startup reconciliation and recovery remain M003, and durable owner tags plus generation-aware protocol fields remain M002.

## Requirement-to-evidence matrix

| Requirement | Evidence |
|---|---|
| Bundled SQLite on Rust 1.89 | `rusqlite 0.40.2` with `default-features = false, features = ["bundled"]`, resolving `libsqlite3-sys 0.38.2` and bundled SQLite **3.53.2** (`SQLITE_VERSION_NUMBER 3053002`). `cargo +1.89.0 check --all-targets --locked` passes and `rust-toolchain.toml` pins 1.89.0, so every routine gate in this record already ran on the MSRV. |
| Centralized, tested connection initialization | `src/state/schema.rs::open_connection` is the only opener. Flags are `READ_WRITE`, `CREATE` (initialize only), `NO_MUTEX`, `NOFOLLOW`, and deliberately **no** URI flag. Tests: `the_opened_database_enforces_the_hardened_pragma_contract` reads back `foreign_keys=1`, `trusted_schema=0`, `journal_mode=wal`, `synchronous=2` (FULL), `mmap_size=0`, and asserts a five-second busy timeout is set. |
| File ownership and mode | The database file is created `0600` before SQLite writes to it, so it is never briefly world-readable and its WAL sidecars inherit the mode. `a_freshly_created_database_is_owner_only` asserts `0o600`. A group/world-accessible mode is **narrowed** rather than merely refused once ownership is proven (`a_group_or_world_accessible_database_is_narrowed_when_ownership_is_proven`); a foreign-owned file or a permissive parent is refused (`a_database_owned_by_another_uid_is_rejected`, `a_group_or_world_writable_parent_directory_is_rejected`). Symlink and non-regular-file paths are refused. |
| Migration 1 creates the complete initial schema | `migrations/001_initial.sql` is embedded with `include_str!` and immutable. `migration_zero_to_one_creates_the_initial_schema` asserts `user_version = 1` and the presence of all 13 tables. The runner applies pending steps in order inside one `IMMEDIATE` transaction and runs `PRAGMA foreign_key_check` after each. |
| Newer `user_version` rejected | `a_schema_newer_than_the_binary_is_rejected` sets `user_version = 9999` and expects `SchemaTooNew { found: 9999, supported: 1 }`. Negative versions are rejected as `SchemaVersionInvalid`. |
| Foreign keys enforced | `foreign_keys = ON` plus `PRAGMA foreign_key_check` after each migration. `foreign_key_constraints_are_rejected_by_sqlite` proves a row for an unknown peer is refused. |
| Reopen into identical typed desired state | `desired_state_round_trips_through_the_store_with_every_relationship` compares the full snapshot after a store/reload cycle, including private key, peer private key, preshared key, endpoint, and route gateway. `reopen_preserves_the_installation_identity_and_generation` reopens from disk and confirms the installation id and generation survive. `projection_is_deterministic_across_reopen_and_store_cycles` proves projection is stable across a reopen. |
| Generation CAS prevents stale overwrite | `generation_starts_at_one_and_increments_monotonically`, `generation_advances_by_exactly_one_per_committed_mutation`, `a_stale_writer_is_refused_and_changes_nothing` (expects `StaleGeneration { expected: 1, actual: 2 }` and byte-identical state), `an_unchanged_snapshot_still_advances_the_generation`, `invalid_or_tampered_storage_values_are_rejected`, and `generation_never_wraps_at_the_storage_ceiling`. |
| Failed validation/transaction does not advance the generation | `validation_failure_performs_no_row_changes_and_does_not_advance_generation`, `an_update_closure_error_rolls_the_whole_mutation_back`, and `a_multi_table_mutation_commits_entirely_or_not_at_all` (removing a peer still referenced by a client is rejected with the snapshot byte-identical; a valid multi-table change commits every table together). |
| Application and kernel models remain distinct | The kernel-facing `DesiredManagedInterface`/`DesiredNetworkPolicy` are unchanged in shape and meaning. The application model gained the fields needed for restart reconstruction. The five shared intent value types (`OwnershipDeclaration`, `LinkLifecycle`, `ResourcePresence`, `DesiredAddress`, `ManagedRoute`) moved to `domain::intent` so the unprivileged side can persist them, and `reconcile` re-exports them — no public or wire item changed. |
| Live telemetry is not persisted | No column exists for handshake, observed endpoint, RX/TX counters, ifindex, route handle, or nftables handle/counter. `the_schema_contains_no_live_telemetry_columns` scans the created schema for each forbidden term. The desired-state API is type-level unable to accept an observation: `domain::ObservedInterface` is not part of `DesiredState`. |
| Secret values absent from diagnostics | Secrets use the existing redacting wrappers. `secret_values_never_appear_in_store_diagnostics` asserts neither key appears in the store's `Debug` or in a private key's `Debug`. `error.rs::database` collapses every `rusqlite::Error` to a stable message; `database_errors_never_carry_sql_text_or_bound_values` feeds it a failure whose message contains a literal `INSERT ... 'hunter2'` and asserts the rendered error contains neither the value nor the SQL. `StateStore`'s `Debug` is deliberately opaque. |
| Deterministic projection | `project()` is pure and returns the existing kernel types. `projection_is_deterministic_across_repeated_calls`, `projection_produces_the_existing_kernel_intent_types`, `absent_links_project_without_wireguard_configuration`, and `projection_refuses_ipv6_policy_prefixes_before_privileged_work` (an IPv6 policy prefix is refused as a state error before any privileged call). |
| No netd/protocol/kernel semantic change | `PROTOCOL_VERSION` is still 1 and the architecture guards pin it. No operation, framing, socket, reconciliation, or nftables behavior was touched. The three rootful suites passed unchanged. |

## Dependency decision

| Item | Value |
|---|---|
| Crate | `rusqlite 0.40.2` |
| Features | `default-features = false`, `bundled` |
| SQLite | bundled **3.53.2** (`libsqlite3-sys 0.38.2`) |
| Transitive additions | `bitflags`, `fallible-iterator`, `fallible-streaming-iterator`, `libsqlite3-sys`, `hashlink`; build-time `cc`, `pkg-config`, `vcpkg` |
| Dependency diff | `Cargo.toml` +1 line, `Cargo.lock` +77 lines |

`default-features = false` keeps extension loading, threads, and other defaults off, so `sqlite3_load_extension` is not linked at all — a build-time guarantee rather than a runtime check. `extension_loading_is_absent_from_the_dependency_configuration` asserts this against `Cargo.toml`.

The `backup` feature was deliberately **not** enabled: M001 has no backup consumer, and it belongs to M004.

The plan's stop conditions were not triggered. rusqlite compiles on Rust 1.89; bundled SQLite does not break the release strategy (prebuilt release artifacts remain the canonical easy install); every added persistent field has canonical domain meaning; nothing pressured the design toward opaque kernel snapshots; no Phase 7 auth/session semantics were invented; and no migration framework dependency was added.

## Test totals

| Suite | Result |
|---|---|
| Library unit tests | 63 passed |
| Binary test | 1 passed |
| `tests/architecture_guards.rs` | 9 passed (2 new: the state store never reaches a privileged boundary; the privileged service never opens the state database) |
| `tests/state_store.rs` | 26 passed |
| `tests/privileged_protocol.rs` | 2 passed |

## Documentation

`architecture/state-store.md` documents scope, the privilege boundary, the secret-bearing warning, desired-generation semantics, installation identity, schema and migration ownership, the connection contract, projection, the sync API and the future async-adapter rule, and what is deferred to M002–M004. `architecture/overview.md` and `README.md` were updated; the README still states that startup reconciliation is not complete.

## Unresolved findings

No unresolved high- or medium-severity finding remains.

- One real defect was found and fixed during implementation, and is covered by regression tests: SQLite creates a database file with the process umask (typically `0644`), so the store's own permission check rejected a database the store itself had just created. The fix creates the file `0600` up front and narrows (rather than refuses) a permissive mode once ownership is proven.
- The plan's "safe narrowing" option was taken deliberately; the alternative (refusing to open a world-readable file) would have made a newly initialized store unusable.
- `StateError::ConstraintViolation` and `StateError::Busy` are distinct operator-facing outcomes but both collapse to a stable message; a future milestone that wants to surface them differently can do so without changing secret handling.

Deferred and recorded: DNS server persistence has no consumer, so no table was created; `convergence_state` exists with the right columns but M001 does not drive kernel reconciliation from it; full encrypted-at-rest key management remains deferred because no independent key-protection domain exists yet.

Disposition: `closed`.

## Successor readiness and plan queue

M001 closes Phase 6's storage and generation contract. Its hard blocker is satisfied, so `plans/implementation/durable-state/002-durable-ownership-and-generation-reconcile.md` is promoted to ready/active. M003 remains blocked behind M002 and M004 behind M003.

M002 can rely on: a hardened and tested connection contract, an immutable migration 1, a monotonic generation with working CAS, transactional full-snapshot validation, and a pure deterministic projector. M002 still owns adding durable owner tags and generation/installation fields to the privileged protocol, which M001 deliberately did not do.
