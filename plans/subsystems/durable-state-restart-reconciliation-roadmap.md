# Durable State and Restart Reconciliation Roadmap

Status: closed. Phase 6 is complete; M001-M004 are all closed. A separate post-Phase-6 corrective line is active under `plans/subsystems/durable-state-post-phase6-reconciliation-addendum.md` and does not reopen this roadmap.

Canonical references:

- `plans/000-long-term-specification.md`
- `plans/001-terminology-and-domain-model.md`
- `plans/002-long-term-roadmap.md`
- `plans/003-planning-process.md`
- `plans/adr/001-linux-native-control-plane.md`
- `plans/adr/002-durable-state-generations-and-ownership.md`

Network-control predecessor:

- M001–M005 strict closure under `plans/subsystems/network-control-roadmap.md`;
- C001 contract-preserving cleanup under `plans/subsystems/network-control-post-foundation-reconciliation-addendum.md`.

## 1. Purpose and ownership boundary

This subsystem makes the management side of wg-basic authoritative across process and host restarts.

It owns:

- SQLite application-state storage;
- schema versioning/migrations;
- installation identity;
- monotonic desired-state generations;
- optimistic/CAS mutation semantics;
- persistent application-level interface/peer/client/network policy state;
- deterministic projection from application state to netd network intent;
- durable ownership provenance;
- aggregate generation-aware reconciliation;
- startup recovery/reconciliation;
- reconciliation status/evidence persistence;
- database backup/restore.

It does not own:

- HTTP routing/UI/authentication;
- session cookies/CSRF;
- package installation/update;
- general audit-log retention;
- periodic kernel drift monitoring;
- IPv6 production qualification.

## 2. Core invariants

1. SQLite desired state is authoritative; kernel state is derivative/observed.
2. Only the unprivileged management role opens the database.
3. netd remains database-free and validates privileged intent independently.
4. Every committed configuration mutation advances exactly one monotonic desired generation.
5. Stale writers cannot overwrite a newer generation.
6. A kernel-apply failure never rolls durable desired state backward.
7. Startup always observes/reconciles current desired state.
8. Live peer telemetry is never persisted as authoritative configuration.
9. Interface name alone is not ownership proof.
10. Destructive interface reconciliation requires a matching durable host owner tag.
11. nftables ownership is bound to the current installation identity.
12. Database files/backups are secret-bearing and use restrictive filesystem semantics.
13. Migration failure leaves the original database usable/unmodified or produces an explicitly recoverable state.
14. Backup/restore never bypasses schema/domain validation.
15. No Phase 6 operation broadens the privileged protocol into generic execution.

## 3. Current-state research

### 3.1 Storage engine

Current rusqlite 0.40.x is a small direct SQLite wrapper, supports bundled SQLite, and fits the repository's Rust 1.89 floor. Bundling is preferred so release binaries do not depend on the host SQLite package/version.

Current SQLx 0.9 is not selected: its release/MSRV policy tracks recent Rust and is materially broader than required for this small appliance.

### 3.2 Migration tooling

Current `rusqlite_migration` 2.6.0 requires Rust 1.95, above wg-basic's MSRV.

Phase 6 therefore owns a small migration runner built directly on rusqlite and `PRAGMA user_version`.

### 3.3 SQLite operating mode

For low-frequency but security/availability-relevant configuration writes:

- WAL mode;
- `synchronous=FULL`;
- foreign keys enabled;
- trusted schema disabled;
- bounded busy timeout;
- no mmap;
- no-follow DB open.

The objective is durable intent, not write benchmark performance.

### 3.4 Host ownership markers

Linux exposes a persistent interface alias through `IFLA_IFALIAS`. This provides a kernel-visible owner tag for wg-basic links.

The nftables table marker is installation-specific: it carries `wg-basic:v1:<installation id>`, so ownership of the table is provable and a table belonging to another installation is refused rather than adopted.

## 4. Target architecture

```text
                  management process
                         |
          +--------------+--------------+
          |                             |
          v                             v
   StateStore                    State Projector
   SQLite                        current generation
   generation/CAS                -> network intent
          |                             |
          +--------------+--------------+
                         |
                         v
               Reconcile Coordinator
                         |
                         | typed UDS request
                         v
                       netd
                 one outer apply lock
                         |
             +-----------+-----------+
             |                       |
             v                       v
 interface/WG/address/route    firewall/forwarding
             |                       |
             +-----------+-----------+
                         |
                         v
                    Linux kernel

Startup:
SQLite desired state -> project -> reconcile -> record convergence evidence
```

## 5. Dependency graph

```text
network-control M001–M005 closed
              |
              v
network-control C001 refactor/cleanup
              |
              v
M001 — SQLite store, schema, generation/CAS
              |
              v
M002 — durable owner tags + aggregate generation-aware netd reconcile
              |
              v
M003 — startup reconciliation + crash/restart recovery
              |
              v
M004 — backup/restore + migration/recovery qualification
```

C001 was a hard implementation dependency for Phase 6 M001 so the state layer would be built against final post-foundation module boundaries rather than creating avoidable merge/refactor conflict. C001 closed at `0e74a40`, M001 was unblocked at that point, and the state module follows the settled `reconcile/`, `firewall/`, and `protocol/` boundaries.

All four milestones are now closed and Phase 6 is complete; see §22 and the closure records under `plans/closure/durable-state/`.

## 6. Milestone M001 — SQLite state store and desired-generation contract

Status: closed at `88f10f9`. Closure record: `plans/closure/durable-state/001-status.md`.

Primary class: infrastructure / invariant.

Implementation plan:

- `plans/implementation/durable-state/001-sqlite-state-store-and-generations.md`

Objective:

Create the authoritative application-state store without yet changing kernel ownership semantics.

Expected outcomes:

- rusqlite bundled SQLite dependency selected/qualified on Rust 1.89;
- hardened state-directory/database open;
- project-owned ordered migration runner;
- initial normalized schema;
- stable `InstallationId`;
- monotonic `DesiredGeneration`;
- generation-CAS mutation API;
- typed load/save of persistent interface/peer/client/network policy state;
- deterministic projection to current M004/M005 desired network types;
- live telemetry excluded;
- in-memory/temp-database test coverage.

Exit conditions:

- stale generation write fails;
- failed DB transaction does not advance generation;
- successful compound desired-state edit is atomic;
- reopen reproduces the same typed desired state;
- schema/domain corruption is rejected;
- no netd/kernel behavior changes yet.

## 7. Milestone M002 — Durable ownership and aggregate netd reconciliation

Status: closed at `65339b8`. Closure record: `plans/closure/durable-state/002-status.md`.

Primary class: invariant / capability.

Implementation plan:

- `plans/implementation/durable-state/002-durable-ownership-and-generation-reconcile.md`

Objective:

Bind persistent installation/interface identity to host network resources and apply one desired generation through one netd orchestration boundary.

Expected outcomes:

- owner-tag domain type;
- WireGuard link `IFLA_IFALIAS` observation/set;
- matching-tag required for authoritative mutation/deletion of existing links;
- installation-specific nftables owner marker;
- aggregate `Plan/ApplyInstallationNetworkIntent` protocol operation;
- one outer netd mutation lock across interface and firewall layers;
- generation echoed in plan/receipt;
- in-process stale generation rejection;
- correct enable/disable layer ordering;
- preservation/conflict tests updated.

Exit conditions:

- restart-equivalent fresh netd can identify a matching tagged link/table from durable intent;
- same-name untagged/foreign-tag resources fail closed;
- equal-generation reapply is idempotent;
- lower-generation apply is rejected within one netd lifetime;
- partial aggregate apply yields truthful layer receipts and fresh retry converges.

## 8. Milestone M003 — Startup reconciliation and crash/restart recovery

Status: closed at `6a9cbc7`. Unblocked by durable-state M002 strict closure at `65339b8`. Closure record: `plans/closure/durable-state/003-status.md`.

Primary class: capability / invariant.

Implementation plan:

- `plans/implementation/durable-state/003-startup-reconciliation-and-recovery.md`

Objective:

Make the management role reconstruct and converge kernel state from SQLite after process/host-level loss of runtime state.

Expected outcomes:

- state-owning management runtime initialization;
- startup database validation/migration;
- deterministic state projection;
- automatic current-generation reconcile through netd;
- last-attempt/last-converged generation evidence;
- compare-and-set convergence update;
- bounded retry behavior;
- stale completion cannot mark a newer generation converged;
- tests for management crash between DB commit and netd apply;
- tests for netd restart between layers/attempts;
- tests for deleted/drifted owned kernel resources;
- real namespace restart qualification.

Exit conditions:

- desired DB commit survives management crash before apply and converges on next startup;
- deleting an owned tagged link while stopped causes it to be recreated;
- foreign replacement of the link/table fails closed;
- startup does not skip kernel observation solely because generations match;
- no aggressive periodic reconciliation loop is introduced.

## 9. Milestone M004 — Backup, restore, migration, and Phase 6 qualification

Status: closed at `772203d`. Unblocked by durable-state M003 strict closure at `6a9cbc7`. Closure record: `plans/closure/durable-state/004-status.md`. Phase 6 closes with this milestone.

Primary class: capability / operational invariant.

Implementation plan:

- `plans/implementation/durable-state/004-backup-restore-and-migration-qualification.md`

Objective:

Close the durable-state subsystem with reproducible upgrade and recovery operations.

Expected outcomes:

- online SQLite backup;
- secret-safe backup permissions/no-overwrite behavior;
- restore candidate integrity/schema/domain validation;
- offline/exclusive atomic restore;
- migration fixtures from retained schema versions;
- pre-migration backup/recovery behavior;
- corrupted/newer database refusal;
- restored desired state reconciles to kernel after startup;
- operational CLI/library surface for backup/restore/state status;
- documentation of secret-bearing backup semantics.

Exit conditions:

- backup represents one consistent generation;
- restore into a clean host recreates equivalent desired/kernel state;
- failed restore leaves original state intact;
- migration tests cover all retained schema versions;
- database newer than binary fails closed;
- Phase 6 rootful restart + backup/restore qualification passes.

## 10. Initial schema direction

The first schema SHOULD remain normalized enough to enforce relationships and evolve without storing one opaque JSON document as the authoritative model.

Expected table families:

```text
installation
interfaces
interface_tunnel_prefixes
interface_addresses
managed_routes
peers
peer_allowed_ips
clients
client_route_prefixes
client_dns_servers
network_policy
network_policy_source_prefixes
convergence_state
```

The exact M001 schema may omit fields not yet represented by implemented product types, but it MUST NOT collapse server-side AllowedIPs and client-side route policy.

Secrets may be stored as secret-bearing database fields in Phase 6 under the ADR-002 filesystem/security policy. They must never appear in ordinary diagnostics.

## 11. Generation mutation semantics

A mutating state operation conceptually accepts:

```text
expected_generation: N
mutation: typed application mutation
```

Inside one immediate transaction:

1. read current generation;
2. reject if current != N;
3. validate the resulting full desired state;
4. apply all rows for the logical mutation;
5. set generation N+1;
6. commit.

The caller receives the new generation and a complete typed snapshot/projection.

There is no “last write wins” path that silently ignores an expected generation.

## 12. Reconciliation evidence

Durable convergence evidence is intentionally small.

Store at least:

- current desired generation;
- last attempted generation;
- last successfully converged generation;
- last attempt completion timestamp;
- last safe high-level disposition/failure category.

Do not persist live kernel snapshots or secret-bearing full protocol receipts merely for convenience.

Detailed audit/event history belongs to the later management/audit subsystem unless Phase 6 evidence demonstrates a recovery need.

## 13. State/path security

The state layer must verify:

- state directory exists or is safely created by an explicit initialization path;
- directory is owned by expected management UID and not group/world writable;
- database is not a symlink;
- existing database is a regular file with expected owner;
- database mode is restrictive;
- backup/restore source/target rules reject symlink substitution;
- errors do not include secret SQL parameter values.

Do not rely on later systemd packaging to make unsafe paths acceptable.

## 14. Migration policy

Migration files are append-only after release.

On open:

- reject negative/invalid `user_version`;
- reject version newer than compiled schema;
- run pending migrations under an immediate transaction;
- enforce foreign keys;
- run domain/schema validation;
- M004 adds automatic pre-migration snapshot policy before any upgrade that changes an existing user database.

The initial M001 schema migration is still represented as migration 1 rather than special-case CREATE statements spread through code.

## 15. Backup/restore boundary

A backup is a SQLite snapshot containing secret material.

It is not a sanitized export.

A future user-facing “export configuration without secrets” is a separate feature.

Restore preserves the backed-up `InstallationId`; this permits a restored host to recreate resources with the same durable owner identity. Conflicting host resources remain conflicts and are not silently adopted.

## 16. Failure/recovery model

Important crash points:

### After desired-state commit, before netd request

DB generation is ahead of convergence evidence. Restart retries current generation.

### During netd aggregate apply

Kernel may be partially changed. netd returns/loses a partial receipt. Restart re-observes and derives remaining work.

### After netd convergence, before DB convergence update

DB may show convergence evidence behind current desired state. Restart safely performs an idempotent reapply and then records convergence.

### After a newer generation commits while an older apply completes

The completion update is conditional on current desired generation. An old receipt cannot mark the newer generation converged.

## 17. Concurrency

State mutation concurrency is controlled primarily through desired-generation CAS.

Kernel mutation concurrency is controlled by netd's aggregate apply lock and in-process generation monotonicity.

The management service SHOULD serialize its own apply coordinator, but correctness must not rely solely on HTTP request arrival order.

## 18. Security considerations

- SQLite is opened only by unprivileged management code.
- A copied database or backup exposes VPN secret material; docs and permissions must say so.
- No SQL text originates from HTTP/user input beyond bound parameters.
- Do not enable SQLite extension loading.
- Use `trusted_schema=OFF`.
- Database corruption/tampering must produce fail-closed startup rather than invoking privileged reconciliation from unvalidated rows.
- netd independently revalidates projected domain state and host ownership markers.
- Owner tags are correctness/provenance markers, not cryptographic authorization tokens.

## 19. Verification direction

Routine Rust/MSRV gates continue.

M001 adds database-unit/integration fixtures without root.

M002 adds rootful owner-tag + aggregate reconcile tests.

M003 adds process restart/crash-oriented namespace tests.

M004 adds backup/restore/migration fixture qualification.

Phase 6 closure requires re-running the existing M003–M005 kernel/network suites to prove persistence work did not weaken network-control behavior.

## 20. Risks and deferred work

- SQLite bundled builds require a C compiler for source builds; prebuilt release artifacts remain the canonical easy install.
- Future HTTP code must not block EggServe/Tokio executor threads on rusqlite.
- Interface alias ownership can be altered by root; owner tags prevent accidents, not a hostile-root threat.
- Full encrypted-at-rest key management remains deferred because no independent key-protection domain exists yet.
- Multi-interface UI semantics are deferred, though the schema should not make them impossible.
- Continuous external-drift event watching is deferred.
- Restore while services are active remains prohibited until a later service-lifecycle milestone can coordinate it safely.

## 21. Milestone status

| Milestone | Status | Implementation plan | Hard blocker |
|---|---|---|---|
| M001 SQLite store + generations | closed | `plans/implementation/durable-state/001-sqlite-state-store-and-generations.md` | — |
| M002 durable ownership + aggregate reconcile | closed | `plans/implementation/durable-state/002-durable-ownership-and-generation-reconcile.md` | — |
| M003 startup reconciliation + recovery | closed | `plans/implementation/durable-state/003-startup-reconciliation-and-recovery.md` | — |
| M004 backup/restore + migration qualification | closed | `plans/implementation/durable-state/004-backup-restore-and-migration-qualification.md` | — |


## 22. Post-Phase-6 corrective handoff

Phase 6 remains closed.

A bounded corrective/polish/evidence pass is registered separately:

- `plans/subsystems/durable-state-post-phase6-reconciliation-addendum.md`;
- `plans/implementation/durable-state/c001-post-phase6-reconciliation-and-pre-phase7-hardening.md`.

Its scope is limited to current-state documentation reconciliation, the one remaining real-kernel disable-path fault-injection qualification gap carried from M002/M003, and contract-preserving management/state module cleanup before Phase 7 consumes those APIs.

The corrective MUST NOT change ADR-002, desired-generation semantics, durable ownership, aggregate reconciliation ordering, or backup/restore contracts.

It is closed. Closure record: `plans/closure/durable-state-post-phase6-reconciliation/c001-status.md` (head `635a130`, CI run `37638334930`). All three obligations are discharged: the current-state docs now agree Phase 6 is closed, the disable path is qualified against a real netd process and a real kernel interface when the firewall layer refuses, and management/state are split by subject with the public surface unchanged. The M002/M003 evidence debt is retired, so **Phase 7 planning and implementation are both unblocked**.
