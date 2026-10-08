# Product Management M001 Closure — Product Model and Generation-Safe Mutations

Status: closed.

Planning baseline: `plans/implementation/product-management/001-product-model-and-generation-safe-mutations.md`.
Planning repository baseline: `3a1b6d3`.
Repository baseline at implementation start: `df1f9e7`.
Final implementation head: recorded in the registry reconciliation below.
Disposition: **closed**.

## Outcome

M001 is strictly closed. The product model exists in durable state, mutations are
atomic with their audit rows, a receipt can distinguish *committed* from
*enforced*, and **no HTTP CRUD route exists**.

Five findings are recorded rather than glossed over. Three are defects this
milestone introduced and then fixed, one is a design correction the plan called
for, and one is a false lead that would have produced a test incapable of
failing.

## Dependency evidence

| Crate | Change | Reason |
|---|---|---|
| *(none)* | — | `Cargo.toml` and `Cargo.lock` are untouched |

**No dependency was added.** `cargo +1.89.0 check --all-targets --locked`
passes, so the MSRV is unchanged from C001's baseline.

One *move* rather than an addition: `src/wireguard/keys.rs` became
`src/domain/keys.rs`. Key generation is pure X25519 arithmetic with no Linux
dependency, and the product service must generate server and client identities
from an unprivileged module that is not behind the `wireguard` platform gate. An
`Arc`-free `crate::domain::generate_keypair` is now the canonical path;
`wg_basic::wireguard::generate_keypair` remains as a re-export so kernel-facing
call sites are unchanged. `tests/architecture_guards.rs` was updated to register
the new path, and the guard still proves it never touches `crate::state` or
`rusqlite`.

## Requirement-to-evidence matrix

### §2 Schema migration 3

`src/state/migrations/003_product_management.sql` is purely additive. The proven
network schema from migration 1 is not rewritten, renamed, or dropped, so a
rollback is a table drop rather than a data rescue.

| Structure | Contents |
|---|---|
| `interface_product_settings` | `interface_id` PK/FK, `advertised_host`, `advertised_port` CHECK 1–65535 |
| `client_product_settings` | `client_id` PK/FK, `label` CHECK length 1–128, `enabled` CHECK 0/1, nullable bounded `client_keepalive_seconds`, `created_at`, `updated_at` |
| `client_dns_servers` | `client_id` FK, `position`, ordered address, composite PK `(client_id, position)` |
| `audit_events` | event id, timestamp, nullable principal FK, bounded action/kind/outcome, nullable resource id and generation window, `CHECK` that both generations are present or both absent |

The backfill gives **every** existing client a metadata row with `enabled = 1` and
a label derived from the stable `ClientId` (`client-<short-id>`), so the same
client derives the same label on every host that runs the migration. Timestamps
come from the installation row, making the backfill deterministic per database.
No key, address, or route changes, and `desired_generation` does not move because
a schema migrated.

`audit_events` has **no message, detail, or payload column**, and
`the_audit_table_has_no_column_that_could_hold_a_free_form_message` asserts the
absence of those names so the invariant cannot be lost by a future migration.

### §3 New domain types

`src/product/model.rs` — `AdvertisedEndpoint`, `ClientLabel`, `ClientEnabled`,
`ClientProductSettings`, `ProductClient`, `ProductServer`, `AuditEventId`,
`AuditAction`, `AuditResourceKind`, `AuditOutcome`, `DegradedCategory`,
`EnforcementState`, `ProductMutationReceipt`.

`AdvertisedEndpoint` is deliberately **not** a `SocketAddr`: a server is
routinely published as a DNS name. It accepts a validated DNS host, IPv4, or IPv6
literal, rejects whitespace, control characters, scheme, path, query, fragment,
and userinfo, and refuses a second port smuggled into the host field. IPv6
brackets are applied exactly once, proven by a test that parses, renders, and
re-parses without accumulating brackets.

`ClientLabel` accepts ordinary Unicode and rejects ASCII and Unicode line
separators plus both control ranges — the failure mode being designed against is
a label breaking out of the single config line it is rendered on.

**No type in this module can hold a private or preshared key.** A
`ProductClient`/`ProductServer` summary is therefore secret-safe by construction
rather than by remembering to redact a field, and two tests assert the database's
real private key appears in neither the summary nor its `Debug` form.

### §4/§5 Managed-client metadata and projection

`ClientVisibility` is the projector input: an explicit set of peer identifiers to
withhold. Keeping it a set of peer IDs rather than reading product state inside
the projector is what keeps the projector pure.

| Case | Evidence |
|---|---|
| enabled → disabled removes exactly that peer | `a_disabled_client_leaves_projected_intent_...` |
| disabled → enabled restores the same peer, same public key | same test, asserted on `peers[0].public_key` |
| two clients never share a peer or client id | `two_clients_never_share_a_peer_or_a_client_identifier` |
| one disabled client does not affect others | `disabling_one_client_leaves_the_others_and_their_addresses_alone` |
| disabled state survives reopen | `product_state_survives_reopen_including_disabled_clients` |

A disabled client keeps its row, its peer, its key, and its address reservation;
only its presence in `DesiredWireGuardConfiguration.peers` changes.

### §6/§7 Product service and mutation receipts

`src/product/service.rs` sits behind `ManagementRuntime`, not inside HTTP.

`ProductService` **borrows** the store rather than holding an `Arc`. The worker
owns exactly one `StateStore` for the process lifetime, so an `Arc` would imply a
second authority that does not exist.

`ManagementRuntime::reconcile_after_commit` is the new method the plan asked for,
and it exists because the pre-existing `commit_and_reconcile` semantics cannot
answer a product mutation's question. A backend that is unreachable, refusing,
or rejecting produces a **`Degraded` receipt, not an error** — reporting "the
backend is down" to a caller that has already committed would tell an operator
their change did not happen when it did. Only a state or projection failure is
still an error, and it is an error about the reconcile, not about the commit.

`reconcile_current`'s existing behaviour is unchanged; this is an addition, not a
silent change.

### §8 Audit atomicity

`StateStore::mutate_product` performs the whole §8 contract in one IMMEDIATE
transaction: verify the generation, load both snapshots, apply the typed
mutation, validate, write desired and product rows, append one bounded audit
event, advance the generation, commit.

`every_committed_mutation_appends_exactly_one_audit_row` asserts exactly one row
per committed mutation and that every row's generation window advances.
`a_refused_mutation_appends_no_audit_row_and_does_not_advance_the_generation`
asserts the inverse.

**A cascade hazard was found and closed.** `write_desired` replaces `clients`
and `peers` wholesale, and both product tables cascade from `clients`. A plain
non-product commit would therefore have silently erased an operator's labels,
enable bits, and DNS lists. Both write paths now read the product snapshot and
write it back in the same transaction, and
`product_rows_survive_a_plain_non_product_mutation` proves it.

### §9 Deterministic IPv4 allocator

`src/product/allocator.rs` is a pure gap scan over `u32`. Network and broadcast
are reserved, every server and client address inside the prefix is reserved, a
requested address fails on conflict or reservation, and automatic allocation
returns the lowest usable free address. It never walks the address space.

Twelve cases qualify it: `/30`, `/24`, `/16`, `/0`, exhausted pool, server address
in the middle, disabled-client reservation, requested-address conflict,
out-of-prefix request, network and broadcast refusal, duplicates, determinism,
IPv6 refusal, and `/31`/`/32` refusal.

### §10–§14 Setup, create, update, enable/disable, delete

All five services are implemented and covered. `setup_server` rejects a second
server, generates the server keypair internally, allocates the first usable
server address, and returns a summary with no private key. `create_client`
allocates, generates the client key internally, and returns no private key while
retaining it in durable state for M003's explicit export. `update_client` never
rotates a key, and address reassignment is one atomic mutation.
`set_client_enabled` and `delete_client` complete the vocabulary.

Delete collects peer identifiers **before** removing client rows — a client is
what points at its peer, so removing the client first leaves nothing to look the
peers up by. The first implementation had this backwards and failed its own
test with `ClientPeerMissing`.

### §15 Worker commands

`ProductSnapshot`, `SetupServer`, `CreateClient`, `UpdateClient`,
`SetClientEnabled`, `DeleteClient`, each carrying `PrincipalId` and an expected
generation. No command accepts SQL, JSON, raw WireGuard config, nft source, or a
generic mutation closure from HTTP.

Reconciliation happens in the **worker**, not the product service, because the
worker is the only component that can talk to the kernel. `run_product_mutation`
commits and then reconciles, and the replies carry the *reconciled* receipt.

A `ProductFailure` closed set replaces error strings at that boundary, and
`WorkerError::Product(ProductFailure)` was added so a refused product command is
never reported as `Rejected`, which means "the credentials were not accepted".

### §16 Safe projections

Summaries expose ids, label, enabled, assigned address, route policy, DNS,
keepalive, public key, generation, and timestamps. They contain no private key,
preshared key, or server private key — structurally, because the types have no
such fields.

### §17 Tests

Unprivileged (`tests/product_management.rs`, 25 cases): v2→v3 migration and
recovery, label/endpoint validation, allocator matrix, audit atomicity,
expected-generation stale conflict, setup one-time semantics, create, update,
disable/enable projection, delete, persistence across reopen, CAS serialisation,
identifier independence, and secret absence from summaries and audit.

Rootful (`tests/product_management_rootful.rs`, 4 cases, registered in CI):

| Case | Result |
|---|---|
| a created client becomes a real kernel peer | pass |
| disable removes the real peer; re-enable restores the same one | pass |
| delete removes the real peer | pass |
| backend outage after commit → committed-but-degraded, restart converges | pass |

### §19 Acceptance criteria

All thirteen criteria are met. Criterion 13 is enforced by the absence of any
product route: `src/http/service.rs` routing is unchanged and no product path is
registered.

## Findings

1. **An allocator overflow found by its own test.** `usable_bounds` computed a
   `/0` prefix's last address as `base + size as u32 - 1`, and `size as u32`
   truncates `2^32` to `0`, so the subtraction underflowed and the largest legal
   prefix panicked. The bounds are now computed in `u64` and narrowed.

2. **A cascade hazard that would have erased product data.** Described in §8
   above. This is the most consequential finding in the milestone: the bug would
   not have shown up in any product test, because every product mutation also
   rewrites the product rows. It only appears when something *else* commits.

3. **The committed-vs-enforced ambiguity was still present after the first
   implementation.** `reconcile_after_commit` originally used `?` on
   `reconcile_current()`, so an unreachable backend still surfaced as an error and
   the rootful outage test failed with `Rejected`. The rootful test is what caught
   it; the unprivileged suite passed throughout. This is precisely the ambiguity
   §7 exists to remove, and it was only removed once a real outage produced a real
   receipt.

4. **The historical-fixture approach had to change.** `commit_snapshot_at_v2`
   used `StateStore::mutate` to fill a version-1 file. Once `mutate` writes the v3
   product tables, that is impossible — the tables do not exist at v1. The
   fixture now seeds rows with plain SQL, which is more faithful anyway: a genuine
   historical database was written by a binary that had never heard of those
   tables, so "the upgrade preserved the data" is now a claim about an older
   writer's rows rather than about this one.

5. **A false lead, recorded because the test could not have failed.**
   `the_in_flight_ceiling_holds_under_a_slow_client_flood` was first "fixed" by
   pinning `max_in_flight_requests` to 8 and asserting the flood must shed the
   excess. Instrumenting the flood showed the distribution was `401: 64` —
   nothing was shed — because the worker serialises the logins, so roughly one
   request is ever in flight. Pinning the ceiling lower would have made the
   assertion fail for a reason unrelated to the transport. The approach was
   reverted and the real defect fixed; see the C001 closure record.

Two environment facts that shaped the rootful suite: `ip wg` is not present on
every runner, so peer observation goes through the crate's own netd protocol
(`ObserveWireGuardDevice`) rather than a missing userspace tool; and the
management worker, not the product service, is the component that reconciles, so
the rootful tests drive mutations through `WorkerClient`.

## Verification

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo check --all-targets --locked` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo +1.89.0 check --all-targets --locked` | pass |
| `cargo test --locked` | 419 tests, 0 failed |
| `wireguard_kernel` (rootful) | 2 passed |
| `network_control_e2e` (rootful) | 2 passed |
| `network_reconcile` (rootful) | 2 passed |
| `durable_owner` (rootful) | 10 passed |
| `durable_restart` (rootful) | 9 passed |
| `durable_backup` (rootful) | 2 passed |
| `service_rootful_e2e` (rootful) | 3 passed |
| `product_management_rootful` (rootful, new CI job) | 4 passed |

## M002 readiness

M002's hard dependency — M001 closed on a green baseline — is satisfied.

M002 may begin. The contracts it needs are closed and qualified:

* the worker vocabulary already carries `ProductSnapshot`, `SetupServer`,
  `CreateClient`, `UpdateClient`, `SetClientEnabled`, and `DeleteClient`, so M002
  is a translation layer from JSON onto existing commands and adds no new
  durable concept;
* `ProductFailure` is already a closed category set, so a route can select a
  status without inspecting an error string;
* `ProductMutationReceipt` is already the committed-vs-enforced answer M002 must
  render, and `WorkerError::Product` already exists so a refusal is not reported
  as an authentication failure;
* M003's explicit secret export is the only remaining secret-bearing path, and
  `client private key` is already retained in durable state for it.

M002 must **not** add state. If it needs a new durable fact, that is an M001
scope finding and must be reconciled rather than absorbed.