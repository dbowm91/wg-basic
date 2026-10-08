# Product Management M001 — Product Model and Generation-Safe Mutations

Status: closed. Evidence: `plans/closure/product-management/001-status.md`.

Repository planning baseline: `3a1b6d3aa9c842088dc5d3e3d127d26990c5fde7`

Source roadmap:

- `plans/subsystems/product-management-enrollment-ui-roadmap.md#5-m001--product-model-schema-v3-and-generation-safe-mutations`

Canonical architecture:

- `plans/adr/004-product-management-enrollment-and-api-semantics.md`

Primary class: product foundation / invariant

Hard dependency:

- management-service post-Phase-7 C001 strict closure on green current-head CI.

## 1. Objective

Build the Phase 8 product application model and generation-safe mutation services before exposing any configuration-mutating HTTP route.

M001 must make setup/client management correct at the worker/runtime/state layer first.

## 2. Schema migration 3

Add immutable production migration:

```text
003_product_management.sql
```

Prefer additive side tables to destructive rewrites of the proven network schema.

Required structures:

### interface_product_settings

- interface_id FK/PK;
- advertised_host;
- advertised_port.

### client_product_settings

- client_id FK/PK;
- label;
- enabled;
- client_keepalive_seconds nullable;
- created_at;
- updated_at.

### client_dns_servers

- client_id FK;
- ordered DNS IP string;
- position;
- composite PK.

### audit_events

At least:

- event_id TEXT PK;
- occurred_at INTEGER;
- principal_id nullable;
- action TEXT;
- resource_kind TEXT;
- resource_id TEXT nullable;
- generation_before INTEGER nullable;
- generation_after INTEGER nullable;
- outcome TEXT.

Use bounded/category values; no raw payload/message field.

Migration of existing clients:

- create metadata row for every existing client;
- enabled=true;
- deterministic label derived from stable ClientId, e.g. `client-<short-id>`;
- timestamps from installation/update metadata or a deterministic migration timestamp policy;
- no key/address/route change;
- no DesiredGeneration advance merely because the schema migrates.

M001 must qualify real v2→v3 upgrade, recovery snapshot, rollback/failure preservation, and semantic state equality.

## 3. New domain types

Add narrowly typed:

- `AdvertisedEndpoint`;
- `ClientLabel`;
- `ClientProductSettings`;
- `ProductClient` or equivalent safe application projection;
- `AuditEventId`;
- `AuditAction`;
- `AuditResourceKind`;
- `EnforcementState`;
- `ProductMutationReceipt`.

### AdvertisedEndpoint

Requirements:

- bounded host length;
- accepts validated DNS host, IPv4, or IPv6 literal;
- UDP port 1..65535;
- rejects whitespace/control characters/scheme/path/query/userinfo;
- deterministic client-config rendering;
- IPv6 rendering brackets exactly once.

Do not reuse `SocketAddr`: DNS names are valid advertised endpoints.

### ClientLabel

Requirements:

- non-empty after trim;
- bounded UTF-8 bytes;
- reject ASCII/control line separators;
- allow ordinary Unicode display text;
- never used as command/config directive syntax.

## 4. Managed-client metadata

The existing `DesiredClient`/persistent model must gain or compose:

- label;
- enabled state;
- optional ordered DNS IPs;
- optional client-side persistent keepalive;
- created/updated timestamps.

Keep server-side peer keepalive distinct from client-side exported keepalive.

Do not overload `DesiredPeer.endpoint` for the server's advertised endpoint.

## 5. Projection semantics for disabled clients

Update deterministic projection.

For each durable peer:

- if it belongs to an enabled managed client: project normally;
- if it belongs to a disabled managed client: omit it from `DesiredWireGuardConfiguration.peers`;
- if it is not associated with a managed client: preserve existing peer behavior.

Disabled client address reservation and metadata stay in durable state.

Tests:

- enabled→disabled removes exactly that peer from projected intent;
- disabled→enabled restores it with identical public key/AllowedIPs;
- two clients cannot share a peer ID;
- one disabled client does not affect unrelated peers;
- disabled state survives restart/backup/restore.

## 6. Product state service

Create an application/product service behind `ManagementRuntime`, not inside HTTP.

Candidate boundary:

```text
product/
  model.rs
  validation.rs
  allocator.rs
  audit.rs
  service.rs
```

The service consumes typed commands and produces safe product projections/mutation receipts.

It may use `ManagementRuntime::commit_and_reconcile` semantics but must correct the current ambiguity where a post-commit reconciliation error is returned as a single error.

## 7. Mutation receipt semantics

Introduce a result that preserves durable truth:

```text
ProductMutationReceipt {
    generation,
    enforcement:
      Converged
      Pending
      Degraded { category }
}
```

The application service must be able to say:

```text
database commit succeeded
kernel enforcement did not
```

without turning that into a pre-commit failure.

If necessary, add a new runtime method instead of silently changing the behavior of existing `commit_and_reconcile`.

Required tests:

- DB mutation commits, injected netd outage follows, receipt is committed+degraded;
- generation is advanced;
- restart later reconciles it;
- stale writer never commits;
- pre-commit validation/storage failure returns no mutation receipt.

## 8. Audit atomicity

Add `StateStore::mutate_product` / equivalent that, in one IMMEDIATE transaction:

1. verifies expected generation;
2. loads current desired/product state;
3. applies typed product mutation;
4. validates full state;
5. writes desired/product rows;
6. appends one bounded audit event;
7. advances DesiredGeneration;
8. commits.

The audit event records generation before/after.

If audit insertion fails, the desired mutation must roll back.

Reconcile outcome may be recorded later in a separate category/event if useful; do not pretend kernel state is inside the SQLite transaction.

## 9. Deterministic IPv4 address allocator

Implement a pure allocator.

Inputs:

- one selected IPv4 tunnel prefix;
- configured interface addresses;
- every managed client assigned address, including disabled clients;
- optional requested address.

Rules:

- assigned address must be a /32 host inside prefix;
- reserve network/broadcast where meaningful;
- reserve all server/interface addresses inside prefix;
- reserve all existing client addresses;
- requested address fails on conflict/reservation;
- automatic allocation returns the lowest usable free address;
- no full address-space scan.

Preferred algorithm:

- convert prefix bounds and used IPv4 addresses to `u32`;
- sort/deduplicate used values;
- find first gap inside usable bounds.

Qualify /30, /24, /16, very large prefixes, exhausted pool, server address in middle, disabled-client reservation, requested-address conflict.

Phase 8 M001 is IPv4-only for allocation.

## 10. Authenticated server setup service

Add typed service/worker command, but no HTTP route yet.

Input:

- principal ID;
- expected generation;
- interface name;
- IPv4 tunnel prefix;
- optional explicit server address;
- listen port;
- advertised endpoint;
- egress interface;
- NAT/forwarding choice;
- default client route policy.

Behavior:

- reject if a Phase 8 primary server is already configured;
- generate server WireGuard keypair internally;
- choose first usable server address if omitted;
- create stable InterfaceId;
- configure link present/admin-up/managed;
- set tunnel prefix/address;
- set global/default client route policy;
- set network policy;
- persist interface product settings;
- append audit event;
- reconcile;
- return safe server summary + mutation receipt.

No private server key appears in reply/debug/audit.

## 11. Client create service

Input:

- principal ID;
- expected generation;
- interface ID;
- label;
- optional requested IPv4;
- optional route policy override;
- optional DNS IP list;
- optional client keepalive.

Behavior:

1. validate interface/product setup;
2. allocate address;
3. generate WireGuard client keypair;
4. create PeerId and ClientId;
5. peer server-side AllowedIPs contains assigned /32;
6. peer endpoint is normally None;
7. server-side keepalive remains independent;
8. retain client private key for export;
9. persist product settings enabled=true;
10. append audit;
11. advance generation;
12. reconcile;
13. return safe client summary + receipt.

Ordinary reply MUST NOT contain client private key.

## 12. Client update service

Support typed updates:

- label;
- route policy;
- DNS;
- client keepalive;
- optional explicit reassignment of address.

Do not rotate keys implicitly.

Address reassignment is one atomic mutation and preserves uniqueness.

## 13. Enable/disable service

Disable:

- set enabled=false;
- generation advances;
- projected peer disappears;
- address remains reserved;
- audit action `client_disable`;
- reconcile.

Enable:

- set enabled=true;
- projected peer restored;
- audit action `client_enable`;
- reconcile.

A degraded disable receipt must state enforcement is not confirmed.

Rootful evidence is required in M001 because enabled state changes kernel authorization semantics even though HTTP is absent.

## 14. Delete service

Delete:

- remove product metadata/client;
- remove associated managed peer;
- release address after commit;
- audit action `client_delete`;
- reconcile.

No physical-erasure claim.

Outstanding enrollment capabilities do not exist until M003; schema/FKs should not make later cascade difficult.

## 15. Worker commands

Extend the internal closed command vocabulary with product commands approximately:

- `ProductSnapshot`;
- `SetupServer`;
- `CreateClient`;
- `UpdateClient`;
- `SetClientEnabled`;
- `DeleteClient`.

Every mutation command carries `PrincipalId` and expected generation.

No command accepts SQL, JSON, raw WireGuard config, nft source, or generic mutation closures from HTTP.

## 16. Safe product projections

List/detail summaries may include:

- IDs;
- label;
- enabled;
- assigned address;
- route policy;
- DNS;
- keepalive;
- public key if useful;
- generation;
- timestamps.

They MUST NOT include:

- private key;
- preshared key;
- server private key.

M003 owns explicit secret export.

## 17. Tests

Required unprivileged:

- v2→v3 migration;
- recovery snapshot/failed migration;
- label/endpoint validation;
- allocator matrix;
- product audit atomicity;
- expected-generation stale conflict;
- setup one-time semantics;
- client create;
- update;
- disable/enable projection;
- delete;
- post-commit reconcile failure receipt;
- secrets absent from safe summaries/audit/debug.

Required rootful:

- create client becomes real kernel peer;
- disable removes real peer;
- re-enable restores same peer;
- delete removes peer;
- backend outage after commit is reported degraded and later restart converges.

## 18. Verification

All existing routine/MSRV and rootful suites remain green.

Add a dedicated `product_management` rootful suite if that keeps evidence clear.

## 19. Acceptance criteria

M001 closes only when:

1. real schema v3 is qualified from v2;
2. product metadata is durable and secret-safe;
3. allocator is deterministic/gap-based/CAS-safe;
4. setup generates server identity internally;
5. create generates client key internally;
6. disabled clients are absent from real kernel peers but remain durable/reserved;
7. re-enable restores the same peer;
8. delete removes the desired peer;
9. mutation receipts distinguish committed from enforced;
10. audit + desired mutation are atomic;
11. safe projections expose no private/PSK data;
12. Rust 1.89 and all regression/rootful CI pass;
13. no HTTP CRUD route exists yet.

## 20. Stop conditions

Stop/research if:

- disabled-client semantics require duplicating peer secrets in a second authority;
- current schema cannot represent product metadata without destructive rewrite;
- runtime cannot preserve commit-vs-enforcement truth;
- address allocation needs a host/network query outside existing product state;
- M001 pressures HTTP/UI design into the state layer.

## 21. Closure evidence

Record:

- migration v3 DDL/backfill;
- model/type changes;
- allocator algorithm/fixtures;
- mutation receipt semantics;
- audit atomicity;
- worker vocabulary;
- rootful enable/disable/delete evidence;
- degraded enforcement evidence;
- dependency diff;
- routine/MSRV/CI;
- M002 readiness.
