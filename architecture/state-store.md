# Durable state store

## Scope

The state store is the authoritative unprivileged application state for wg-basic. SQLite desired state is authoritative; kernel state is derivative and is only ever observed.

This document describes the store created by Phase 6 milestone M001. M001 provides storage, migrations, installation identity, the monotonic desired generation, and deterministic projection. It does **not** yet reconcile the kernel on startup — durable owner tags and generation-aware protocol fields belong to M002, and startup reconciliation/recovery belongs to M003.

## Privilege boundary

Only the unprivileged management role opens the database. `netd` is database-free and revalidates projected domain state and host ownership markers independently.

The state module depends on `crate::domain` only. It does not depend on the protocol server, socket implementation, `reconcile`, `firewall`, or `wireguard`. The kernel/network modules do not depend on `rusqlite`. This is enforced by a source assertion in `tests/state_store.rs`.

## Secret-bearing files

> **The state database contains server private keys, client private keys, and preshared keys. It and any backup of it are secret-bearing.**

- The file is created with mode `0600`, owner-only, before SQLite ever writes to it.
- On reopen, a group/world-accessible mode is narrowed to `0600` only after ownership is proven. A database owned by another uid is refused outright.
- A symbolic link in place of the database, or a non-regular file, is refused.
- The parent directory must exist, be a real directory, be owned by the expected uid, and not be group/world writable.
- Secrets use the existing redacting wrappers (`PrivateKey`, `PresharedKey`). Their `Debug` and `Display` render `[REDACTED]`, including inside a derived-`Debug` aggregate.
- `rusqlite::Error` is collapsed to a stable operator-facing message so SQL text and bound values never reach a log.
- There is no environment-variable or argv key transport.

Default production direction is `/var/lib/wg-basic/state.db`. Phase 10 owns installation and service layout; this path is a documented direction, not a frozen contract.

## Desired generations

- A new store starts at generation **1** (`INITIAL_DESIRED_GENERATION`).
- Every committed desired-state mutation advances the generation by exactly one.
- The generation is monotonic and never moves backward. A kernel-apply failure does not roll it back and does not cause it to be reused.
- A generation identifies a *committed mutation*, not a distinct payload: re-committing an unchanged snapshot still advances it.
- The generation is stored in a SQLite `INTEGER` and is range-checked on both write and read. `0` and negative values are corruption and are never accepted as authoritative; the schema `CHECK` constraint rejects them and the reader rejects them independently. There is no wraparound at `i64::MAX`.

Mutations use compare-and-swap. A writer supplies the generation it believes is current; if the store has moved on, the write is refused with `StaleGeneration` and nothing changes:

```text
mutate(expected_generation, |desired| -> Result<new_desired>)
    -> CommittedDesiredState { generation: N+1, state }
```

Validation runs inside the same `IMMEDIATE` write transaction that advances the generation, so a validation failure or a write fault performs no row changes and leaves the generation where it was.

## Installation identity

`InstallationId` is a random UUID generated once when a store is created. It is stable across reopen, backup, and restore, and is deliberately not derived from hostname, interface, path, MAC address, or public key. It is an ordinary non-secret identifier — a correctness and provenance marker, never an authorization token.

## Schema and migrations

Migrations live in `src/state/migrations/` as embedded SQL, are applied in exact version order, and are immutable once shipped. Each step carries an integer version and a stable name. The runner:

1. reads `PRAGMA user_version`;
2. rejects a negative or newer-than-binary version;
3. begins one `IMMEDIATE` transaction;
4. applies pending migrations in order;
5. runs `PRAGMA foreign_key_check` after each step;
6. sets `user_version` and commits.

The initial schema is created entirely by migration 1. Singleton rows are enforced structurally with `CHECK (singleton = 1)`.

### Table families

| Table | Contents |
|---|---|
| `installation` | singleton: installation id, desired generation, timestamps |
| `managed_interfaces` | identity, name, ownership, lifecycle, admin-up, private key, listen port, `manage_all_peers` |
| `interface_tunnel_prefixes` | normalized tunnel prefixes |
| `interface_addresses` | exactly managed addresses and presence |
| `managed_routes` | destination, optional gateway, presence |
| `peers` | identity, public key, optional private/preshared key, keepalive, endpoint |
| `peer_allowed_ips` | server-side WireGuard AllowedIPs only |
| `clients` | identity, owning interface, peer, assigned tunnel address |
| `client_route_prefixes` | client-side route policy, deliberately separate from server AllowedIPs |
| `client_global_route_prefixes` | client routes not attached to a single client |
| `network_policy` | singleton IPv4 forwarding/NAT/egress intent |
| `network_policy_source_prefixes` | explicit policy prefixes |
| `convergence_state` | reconciliation evidence, not yet driven by M001 |

DNS server storage is deferred until a consumer exists. It must never be overloaded into a route table.

### Live telemetry is not persisted

There is deliberately no column for latest handshake, observed peer endpoint, RX/TX counters, ifindex, kernel route handle, or nftables handle/counter. Those are observed from the kernel and are never authoritative configuration. `the_schema_contains_no_live_telemetry_columns` asserts this against the created schema.

## Connection contract

Every open goes through one canonical initializer:

- flags `READ_WRITE`, `CREATE` for initialization, `NO_MUTEX`, `NOFOLLOW`; the URI flag is not used;
- `foreign_keys = ON`, `trusted_schema = OFF`, `journal_mode = WAL`, `synchronous = FULL`, `mmap_size = 0`;
- a five-second busy timeout;
- each pragma is read back so a typo or unsupported setting fails loudly instead of silently leaving the database weaker than intended;
- SQLite extension loading is not enabled (the `load_extension` feature is off), so extension entry points are not linked at all.

## Projection

`state::project` converts a persisted snapshot into the existing kernel-facing intent types (`DesiredManagedInterface`, `DesiredNetworkPolicy`). It is pure: no I/O, no connection, no privileged call. Ordering follows the snapshot exactly, so projection is deterministic and stable across reopen.

Projection errors are state validation errors and must be raised before any privileged call.

## Convergence evidence

The store also records what happened when a generation was applied. Three methods are conditioned on the generation they describe:

- `record_attempt_start(generation)` marks that an apply began;
- `record_attempt_result(generation, disposition)` records how it ended;
- `record_converged_if_current(generation)` advances `last_converged_generation` **only if the store still holds that generation**.

The third is the important one. An apply can still be in flight when a newer generation commits. If its receipt advanced convergence unconditionally, an older generation would claim convergence on behalf of a newer one. Instead the generation is re-checked inside the same write transaction; when the store has moved on, the receipt is kept with the outcome `superseded` and convergence is left alone.

Outcomes are stored as **categories**, never messages. A reconcile error string can carry kernel detail, so persisting it would risk accumulating sensitive text in the database. The categories are `converged`, `partial_failure`, `verification_failed`, `failed_before_mutation`, `superseded`, `state_conflict`, `backend_unavailable`, `unauthorized`, and `rejected`.

The evidence is a record of a past apply, not a claim about the present kernel: the network may have drifted while the product was stopped. Startup therefore reconciles unconditionally rather than skipping work when the evidence looks complete. See [startup reconciliation and crash/restart recovery](startup-recovery.md).

## Concurrency and the sync API

The store is synchronous by design. It owns exactly one `rusqlite::Connection` behind a single `Mutex`; `Connection` is never part of the public API and there are no async traits.

> Phase 7 must cross into this blocking store through a bounded blocking-worker adapter. It must not make this API async and must not block HTTP executor threads on rusqlite.

## Deferred to later milestones

- backup, restore, and migration qualification (M004);
- encrypted-at-rest key management, which stays deferred until an independent key-protection domain exists.