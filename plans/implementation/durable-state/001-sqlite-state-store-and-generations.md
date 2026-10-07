# Durable State M001 — SQLite State Store and Desired Generations

Status: active

Unblocked by: network-control C001 strictly closed at `0e74a40` (`plans/closure/network-control-post-foundation-reconciliation/c001-status.md`)

Production-code baseline: `1b17d49bf208a7ef3b72f0028241ae77299fe207`

Planning baseline:

- ADR-002 accepted;
- durable-state roadmap registered;
- network-control C001 is closed; durable-state M001 is now the sole ready implementation plan.

Source roadmap:

- `plans/subsystems/durable-state-restart-reconciliation-roadmap.md#6-milestone-m001--sqlite-state-store-and-desired-generation-contract`
- `plans/002-long-term-roadmap.md#8-phase-6--durable-desired-state-and-migration-substrate`

Canonical requirements:

- `plans/000-long-term-specification.md#12-durable-storage`
- `plans/adr/002-durable-state-generations-and-ownership.md`

Primary class: infrastructure / invariant

Hard dependency:

- network-control C001 strictly closed — satisfied at `0e74a40`.

## 1. Objective

Create the authoritative unprivileged application-state store for wg-basic.

M001 establishes:

- hardened bundled SQLite storage;
- ordered migrations;
- one stable installation identity;
- one monotonic desired generation;
- generation-CAS mutations;
- typed persistence of the currently implemented application/network model;
- deterministic projection into the existing M004/M005 network-control types.

M001 MUST NOT change netd/kernel ownership semantics yet.

## 2. Dependency selection

Add `rusqlite` using a version proven to compile on Rust 1.89.

Preferred feature shape:

```toml
rusqlite = { version = "0.40", default-features = false, features = ["bundled"] }
```

If required for connection APIs, add only narrowly needed features.

The `backup` feature belongs to M004 unless implementation evidence shows enabling it now avoids a lockfile churn without meaningful footprint cost.

Do NOT add:

- SQLx;
- Diesel;
- SeaORM;
- latest `rusqlite_migration` while it exceeds MSRV;
- SQLCipher;
- an async database framework.

Record exact bundled SQLite version in closure evidence.

## 3. Storage module boundary

The C001 module layout has settled. Introduce the management-side state module as:

```text
state/
  mod.rs
  model.rs
  store.rs
  schema.rs
  migrations/
    001_initial.sql
  projection.rs
  error.rs
```

Exact names may vary.

The state module MUST NOT depend on protocol server/socket implementation details.

The kernel/network modules MUST NOT depend on rusqlite.

## 4. Core identifiers

Add/complete typed:

- `InstallationId`;
- `DesiredGeneration`.

### InstallationId

Requirements:

- generated cryptographically/randomly once for a new store;
- stable across reopen, backup, and restore;
- not derived from hostname, interface, path, MAC, or public key;
- ordinary non-secret identifier;
- serialized in canonical UUID/string form or another stable compact format.

### DesiredGeneration

Requirements:

- starts at a documented initial value;
- monotonic;
- representable safely in SQLite signed integer;
- no wraparound;
- not reused after failed application reconcile;
- only advances on committed desired-state mutation.

## 5. Initial schema

Use migration 1 for all initial schema creation.

Expected table families:

### installation

One row containing at least:

- installation ID;
- desired generation;
- created timestamp;
- optional last-updated timestamp.

Enforce singleton semantics structurally or through store invariants.

### interfaces

At least:

- interface ID;
- interface name;
- lifecycle/enabled state;
- admin-up state;
- listen port;
- server private key;
- any server endpoint field already represented by product state.

### interface_tunnel_prefixes

Normalized tunnel prefixes.

### interface_addresses

Exact managed interface addresses/presence needed by current M004 intent.

### managed_routes

Destination, optional gateway, presence.

### peers

At least:

- peer ID;
- interface ID;
- public key;
- optional private key when generated/retained by wg-basic;
- optional preshared key if current types support it;
- keepalive;
- endpoint if current types support it;
- lifecycle/enabled state if represented.

### peer_allowed_ips

Server-side WireGuard AllowedIPs only.

### clients

At least:

- client ID;
- peer ID;
- assigned tunnel address;
- label only if a canonical label type is introduced in M001.

### client_route_prefixes

Client-side route policy, separate from server AllowedIPs.

### client_dns_servers

Only if M001 extends the persistent application domain to DNS now. It is acceptable to defer the table until the first consumer, but do not overload route tables for DNS.

### network_policy

Current IPv4 forwarding/NAT/egress intent.

### network_policy_source_prefixes

Explicit policy prefixes if not deterministically derived.

### convergence_state

Initial columns sufficient for later milestones:

- last_attempted_generation nullable;
- last_converged_generation nullable;
- last_attempt_timestamp nullable;
- last outcome category nullable.

M001 does not yet drive kernel reconciliation from this table.

## 6. Domain-model reconciliation

The repository currently has both:

- higher-level `domain::DesiredState/DesiredInterface/DesiredPeer/DesiredClient`;
- kernel-facing `DesiredManagedInterface` and `DesiredNetworkPolicy`.

Do not persist the kernel-facing structs as one JSON blob.

M001 should reconcile the higher-level persistent model so it can express every currently supported kernel configuration required for restart reconstruction.

Add narrowly needed durable fields/types rather than deleting the application/kernel separation.

The projector owns conversion to:

- `DesiredManagedInterface`;
- optional `DesiredNetworkPolicy`.

Projection MUST be deterministic.

## 7. Secret fields

Database fields containing server private keys, client private keys, and preshared keys are secret-bearing.

Requirements:

- use existing redacting secret wrapper types at Rust boundaries;
- SQL errors/logging never print bound secret values;
- no `Debug` derive on row structs that exposes raw secret strings/blobs;
- backups are documented as secret-bearing;
- no environment-variable or argv key transport.

Encoding may be base64 text for compatibility with existing wrappers or 32-byte blobs if implemented cleanly. Do not invent cryptography merely to change representation.

## 8. Secure database open

Implement a single canonical connection initializer.

Before/open-time checks:

- explicit state path;
- parent directory exists/is created only through an explicit init path;
- parent is a real directory, expected owner, not group/world writable;
- existing DB is a regular file, not symlink;
- expected owner;
- reject unsafe permissions or safely narrow them only if ownership is proven.

Open flags:

- READ_WRITE;
- CREATE where initialization permits;
- NO_MUTEX;
- NOFOLLOW;
- no URI flag unless explicitly justified.

After open, configure and verify:

```text
PRAGMA foreign_keys = ON;
PRAGMA trusted_schema = OFF;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA mmap_size = 0;
```

Set a bounded busy timeout through the rusqlite API.

Read back important pragmas so a typo/unsupported pragma does not silently pass.

Do not enable extension loading.

## 9. Migration runner

Own a tiny runner.

Each migration has:

- integer version;
- stable name;
- embedded SQL via `include_str!` or equivalent.

Behavior:

1. read `PRAGMA user_version`;
2. reject negative/invalid/newer-than-binary;
3. if pending migrations exist, begin IMMEDIATE transaction;
4. apply in exact order;
5. run foreign-key/schema checks appropriate to the migration;
6. set user_version to target;
7. commit.

The initial database is created through migration 1.

Migration SQL that has shipped must be treated as immutable.

M001 tests migration mechanics now even though there is only one schema version.

## 10. Typed store API

Expose application-level operations, not SQL.

Minimum API:

- initialize/open;
- read installation metadata;
- load current desired snapshot + generation;
- replace/modify desired state with expected generation;
- read current generation.

Mutation API concept:

```text
mutate(expected_generation, |desired| -> Result<new_desired>)
    -> CommittedDesiredState { generation: N+1, snapshot }
```

Exact Rust API may use explicit command types rather than a closure if that is easier to test/serialize.

The critical contract is full-state validation inside the same write transaction before generation commit.

## 11. CAS semantics

Required tests:

- initial read returns N;
- mutation with expected N commits N+1;
- second mutation still expecting N fails with typed stale-generation conflict;
- stale failure performs no row changes;
- validation failure performs no row changes and does not increment generation;
- a multi-table logical mutation either commits entirely or rolls back entirely.

Use IMMEDIATE write transactions so a read-then-write update does not encounter an avoidable snapshot upgrade race.

## 12. Projection

Add a pure function:

```text
PersistedDesiredState -> ResolvedNetworkIntentDraft
```

M001 projection does not yet add durable owner tags/generation to the wire protocol; M002 owns that.

It must produce the existing M004/M005 desired types exactly enough that synthetic state round-trips can compare expected network intent.

Projection errors are state validation errors and MUST occur before privileged calls.

## 13. Live telemetry exclusion

No schema column for:

- latest handshake;
- observed peer endpoint;
- RX/TX counters;
- ifindex;
- current kernel route handle;
- nftables handle/counter.

Unit tests should explicitly demonstrate that observed telemetry objects cannot be accidentally written through the desired-state API.

## 14. Connection ownership/concurrency

Use one store-owned rusqlite connection behind one synchronization boundary.

Do not make `Connection` a public API.

Do not add async traits.

Document that Phase 7 must cross into this blocking store through a bounded blocking-worker adapter.

## 15. State-file lifecycle

M001 may expose development CLI options such as an explicit `--state PATH` only if needed for testing.

Do not yet freeze the final installed path/service CLI; Phase 10 owns installation.

Default production direction remains `/var/lib/wg-basic/state.db`.

Tests use temp directories with restrictive permissions.

## 16. Tests

Required focused coverage:

- new-store initialization;
- unsafe parent permissions rejected;
- symlink DB rejected;
- existing safe DB reopen;
- migration 0 -> 1;
- newer user_version rejected;
- foreign key constraints enabled;
- trusted_schema observed OFF;
- WAL and synchronous FULL observed;
- state CRUD round-trip;
- every identifier relationship;
- server AllowedIPs vs client route policy remain separate;
- secret Debug/error redaction;
- generation CAS/stale writer;
- transaction rollback on validation/SQL fault injection;
- deterministic projection.

Add an on-disk reopen test, not only `:memory:`.

## 17. Verification

Routine:

```text
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
```

Run dependency inspection and record:

```text
cargo tree --locked
```

C001's rootful tests should remain green in hosted CI even though M001 does not require new rootful fixtures.

## 18. Documentation

Add:

- `architecture/state-store.md`;
- schema/migration ownership;
- secret-bearing database warning;
- desired-generation semantics;
- sync API / future async adapter rule.

Update architecture overview and registry after closure.

README should still state that startup reconciliation is not complete until M003.

## 19. Acceptance criteria

M001 closes only when:

1. bundled SQLite works on Rust 1.89;
2. secure connection initialization is centralized/tested;
3. migration 1 creates the complete initial schema;
4. database reopens into identical typed desired state;
5. generation CAS prevents stale overwrite;
6. failed validation/transaction does not advance generation;
7. application-vs-kernel desired models remain distinct;
8. live telemetry is not persisted;
9. secret values remain absent from diagnostics;
10. routine/MSRV/CI gates pass;
11. no netd/protocol/kernel semantic change occurred.

## 20. Stop conditions

Stop/research rather than broaden if:

- current rusqlite cannot satisfy Rust 1.89;
- bundled SQLite materially breaks target release strategy;
- a required persistent product field has no canonical domain meaning;
- persistence pressures code toward storing opaque kernel snapshots;
- schema design requires inventing Phase 7 auth/session semantics;
- a migration framework dependency would require raising MSRV.

## 21. Closure evidence

Record:

- selected rusqlite/libsqlite version and features;
- final schema/migration list;
- file ownership/mode/open flags;
- pragma read-back;
- generation/CAS tests;
- transaction rollback evidence;
- projection fixture;
- dependency diff;
- routine/MSRV/hosted CI;
- known deferred fields;
- recommendation on M002 readiness.