# ADR-002 — Durable desired state, generations, and restart-safe ownership

Status: accepted

Date: 2026-10-07

Canonical references:

- `plans/000-long-term-specification.md`
- `plans/001-terminology-and-domain-model.md`
- `plans/adr/001-linux-native-control-plane.md`
- `plans/subsystems/network-control-roadmap.md`

## 1. Context

M001–M005 established a working Linux network-control substrate:

- typed privileged Unix-domain protocol;
- kernel WireGuard control;
- RTNETLINK link/address/route reconciliation;
- bounded nftables/forwarding/NAT ownership;
- real rootful namespace qualification.

The remaining ownership gap is persistence.

Today, `OwnershipDeclaration::Managed` is request-scoped. It tells netd that a caller intends to manage a resource, but it is not durable evidence that a link observed after process restart belongs to this wg-basic installation. Desired network state also exists only in request memory, so a management-process crash after changing kernel state cannot reconstruct intent.

Phase 6 must make durable desired state authoritative while preserving ADR-001's privilege separation: the unprivileged management role owns application state; netd owns privileged observation/mutation and does not become a database service.

## 2. Forces

The selected design should provide:

- restart reconstruction after either process exits;
- a durable answer to “what does this installation intend to own?”;
- stale-write protection for the future concurrent HTTP service;
- a safe relationship between database commit and kernel reconciliation;
- host-side ownership evidence stronger than an interface name;
- low runtime/dependency overhead;
- single-binary distribution with no system SQLite requirement;
- power-loss durability appropriate to configuration/secret state;
- backup/restore and ordered migrations;
- no privileged SQLite access;
- no need for a background high-frequency reconciliation loop.

## 3. Persistence alternatives

### A. Flat TOML/JSON files

Advantages:

- minimal dependencies;
- human-readable.

Disadvantages:

- atomic multi-object updates become custom filesystem transaction logic;
- migrations and referential integrity are project-owned;
- future sessions/tokens/audit data fit poorly;
- concurrent management requests require a custom locking/CAS layer;
- backup consistency is harder once several files exist.

Rejected as authoritative storage.

### B. Async SQLx + SQLite

Advantages:

- future HTTP service could await database operations directly;
- compile-time query support;
- mature SQLite driver.

Disadvantages:

- current SQLx 0.9 release policy tracks a very recent Rust MSRV and is not compatible with wg-basic's Rust 1.89 baseline;
- substantially larger framework surface than this small appliance requires;
- future async HTTP does not require the storage core itself to be async.

Rejected for the Phase 6 baseline.

### C. rusqlite + bundled SQLite

Advantages:

- small direct SQLite API;
- current rusqlite 0.40.x supports the repository's Rust 1.89 baseline;
- bundled SQLite eliminates a host SQLite runtime/version dependency;
- direct transactions, open flags, backup API, and pragma control;
- suitable for a small single-host appliance.

Disadvantages:

- blocking API must not later run directly on an async HTTP executor;
- bundled SQLite introduces a C compile at source-build time.

Selected.

Prebuilt wg-basic release binaries remain self-contained from the operator's perspective.

## 4. Migration alternatives

The latest `rusqlite_migration` 2.6.0 requires Rust 1.95, above wg-basic's Rust 1.89 MSRV.

Phase 6 therefore owns a deliberately small migration runner:

- ordered embedded SQL migrations;
- monotonic integer schema version;
- SQLite `PRAGMA user_version`;
- one `BEGIN IMMEDIATE` transaction per migration batch;
- reject a database whose version is newer than the binary;
- migration files are immutable once released;
- migration tests run from every retained fixture version to current.

No general migration DSL or external CLI is required.

A later dependency may replace the runner only if it preserves MSRV, upgrade semantics, and evidence.

## 5. Decision: authoritative state

SQLite is the authoritative durable store.

The management role is the only runtime role that opens the database.

netd MUST NOT:

- open SQLite;
- infer desired state from a configuration file;
- persist desired state;
- persist authentication/application records.

Kernel state remains observed state.

The ordering is:

```text
management transaction commits desired generation N
                    |
                    v
        request reconcile generation N
                    |
                    v
         netd observes current kernel
                    |
                    v
      netd plans/applies/verifies N
                    |
                    v
 management conditionally records convergence N
```

A failed kernel apply does not roll the database back to the old desired state. The database records what the operator wants; restart/retry continues toward that intent.

## 6. Desired generation

Each installation owns a monotonic `DesiredGeneration`.

Generation properties:

- stored durably with the current desired state;
- incremented exactly once for each successful desired-state mutation transaction;
- never decremented or reused;
- bounded to signed SQLite integer range;
- returned with reads;
- supplied as an expected-generation compare-and-swap token for mutations;
- attached to every aggregate netd plan/apply request and receipt.

A stale caller that submits expected generation N after the store has advanced to N+1 receives a conflict and does not overwrite newer intent.

This becomes the concurrency primitive for the later HTTP/API layer.

## 7. State projection boundary

The persistent application model and privileged kernel model remain distinct.

Durable application state contains product concepts such as:

- installation identity;
- interfaces;
- server/private key material;
- peers;
- managed clients;
- client-assigned addresses;
- client route/DNS policy;
- server endpoint settings;
- managed routes;
- firewall/NAT policy.

A deterministic projector derives the privileged network intent:

```text
PersistedDesiredState
      |
      v
ResolvedNetworkIntent {
    generation,
    owner_tag,
    managed_interface,
    network_policy,
}
```

Live handshake, endpoint, RX/TX, ifindex, nft handles, and other kernel observations never become authoritative stored configuration.

## 8. Durable ownership identity

Each database contains one stable random `InstallationId`.

Each managed interface has its stable `InterfaceId`.

Phase 6 introduces an owner tag derived from both:

```text
wg-basic:v1:<installation-id>:<interface-id>
```

The exact compact encoding may change if Linux's interface-alias length requires it, but the tag MUST retain version + installation + interface identity.

### Link ownership

wg-basic-created WireGuard links MUST carry the owner tag in Linux `IFLA_IFALIAS`.

On restart:

- missing link: create and tag;
- matching owner tag: eligible for owned reconciliation;
- absent/different owner tag: conflict for destructive/authoritative mutation;
- duplicate matching owner tags: conflict.

Interface name alone is never durable proof.

### Firewall ownership

The nftables table ownership marker becomes installation-specific rather than only product-specific.

The marker MUST bind the owned table to the same `InstallationId`.

A table with the wg-basic table name but another/missing installation marker is a conflict.

### Untaggable resources

Addresses and supported routes remain structurally owned through the tagged managed interface plus exact desired resource identity.

Host-wide `net.ipv4.ip_forward` remains intentionally non-exclusive and is never treated as tagged ownership.

## 9. Aggregate netd reconciliation

Phase 6 adds an installation-level network intent operation.

Conceptually:

```text
PlanInstallationNetworkIntent {
    generation,
    installation_id,
    interface_id,
    desired_interface,
    network_policy,
}

ApplyInstallationNetworkIntent { ... }
```

Exact wire names are implementation details.

netd applies one generation under one outer mutation serialization boundary.

Ordering:

- enable/present path: interface/WireGuard/address/routes first, then firewall/forwarding;
- disable/absent path: firewall removal first, then interface teardown;
- a prerequisite-layer failure prevents later dependent mutation.

The receipt contains the same generation and layer-specific receipts.

The kernel cannot provide an ACID transaction across netlink, nftables, and sysctl. The aggregate receipt therefore remains truthful about partial completion and fresh retry.

## 10. In-process stale-generation defense

netd remains intentionally non-durable, but during one netd lifetime it SHOULD remember:

- active installation identity;
- highest apply generation observed.

It MUST reject an apply for:

- a different installation identity after one has been established for the process;
- a generation lower than the highest accepted generation.

Equal-generation reapply is permitted and must remain idempotent.

This does not replace database authority or host owner tags. It prevents an out-of-order concurrent management request from reverting newer intent during one process lifetime.

## 11. Database connection hardening

The selected SQLite baseline is:

- rusqlite 0.40.x or a compatible version proven on Rust 1.89;
- bundled SQLite;
- backup feature when backup work lands;
- `SQLITE_OPEN_READ_WRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NO_MUTEX | SQLITE_OPEN_NOFOLLOW`;
- no URI interpretation unless a concrete feature requires it;
- parent state directory owned by the management identity and not group/world writable;
- database file regular, owned, and mode 0600;
- `PRAGMA foreign_keys=ON`;
- `PRAGMA trusted_schema=OFF`;
- `PRAGMA journal_mode=WAL`;
- `PRAGMA synchronous=FULL`;
- bounded busy timeout;
- memory-mapped I/O disabled unless later measurement justifies it.

Configuration writes are infrequent, so power-loss durability is preferred over maximum write throughput.

## 12. Storage concurrency

The Phase 6 store exposes a synchronous typed API over one owned rusqlite connection protected by one application-level serialization boundary.

This is deliberate.

The future async HTTP layer MUST call the storage API through a blocking-worker boundary rather than sharing a `rusqlite::Connection` directly across async request tasks.

Phase 7 may refine the adapter but MUST NOT bypass desired-generation CAS semantics.

## 13. Secret storage decision

The SQLite database and its backups are secret-bearing artifacts.

Initial Phase 6 protection is:

- restrictive state-directory/database permissions;
- no secret values in logs/errors/Debug;
- no secrets in process arguments;
- database open/path hardening;
- backups created with restrictive permissions and explicit secret warning.

Phase 6 does not claim that colocating an encryption key beside the database protects against root or management-service compromise.

Application-level envelope encryption or SQLCipher is deferred pending a threat model that identifies a distinct key-protection domain. Adding nominal encryption without an independent key authority would increase complexity without materially protecting against the principal local compromise threat.

## 14. Backup/restore decision

Backups use SQLite's online backup API through rusqlite.

A completed backup is a consistent database snapshot.

Backup output:

- is treated as secret material;
- is created without following an existing symlink;
- must not silently overwrite an existing file;
- has restrictive permissions.

Restore is an explicit offline/exclusive state-store operation:

1. open candidate read-only/no-follow;
2. validate SQLite integrity and supported schema;
3. copy into a private temporary database;
4. migrate/validate the copy if required;
5. atomically replace the inactive target using safe file ownership semantics;
6. next management startup reconciles restored desired state to kernel state.

Restore never assumes the current kernel matches the backup.

## 15. Startup reconciliation

Management startup always loads and validates the current desired generation and attempts reconciliation, even when the stored last-converged generation matches.

Reason: kernel state may drift or disappear while both processes are stopped.

The stored convergence generation is evidence/history, not permission to skip observation.

No aggressive periodic repair loop is introduced in Phase 6.

## 16. Consequences

Positive:

- crash/restart reconstructs intent;
- interface ownership survives process restart with host-side evidence;
- future HTTP writes receive a clean optimistic-concurrency contract;
- netd remains small and privilege-separated;
- configuration persistence does not require Docker or a system SQLite package;
- backup/migration semantics become explicit.

Costs:

- bundled SQLite adds a native build dependency for source builds;
- protocol gains aggregate generation-aware operations;
- M004/M005 ownership markers require a Phase 6 evolution;
- future HTTP must bridge blocking storage carefully.

## 17. Verification consequences

Phase 6 must prove:

- schema/migrations on Rust 1.89;
- file/path/permission hardening;
- generation CAS under concurrent stale writers;
- power/process crash-oriented commit semantics where testable;
- owner-tag creation/observation/conflict in real Linux namespaces;
- installation-specific nft ownership;
- generation-aware aggregate apply/retry;
- management restart reconstructing a deleted/drifted kernel state;
- backup snapshot consistency;
- restore validation and subsequent reconciliation;
- unrelated host state preservation remains intact.

Historical M001–M005 closure records are not rewritten.