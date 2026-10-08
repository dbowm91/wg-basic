# Product Management, Enrollment, and UI Roadmap

Status: active; M001 closed, M002 unblocked

Canonical references:

- `plans/000-long-term-specification.md`
- `plans/001-terminology-and-domain-model.md`
- `plans/002-long-term-roadmap.md`
- `plans/003-planning-process.md`
- `plans/adr/001-linux-native-control-plane.md`
- `plans/adr/002-durable-state-generations-and-ownership.md`
- `plans/adr/003-management-http-auth-and-worker-boundary.md`
- `plans/adr/004-product-management-enrollment-and-api-semantics.md`

Predecessor state:

- Phase 6 closed;
- Phase 7 closed;
- post-Phase-7 C001 ready to restore green deterministic HEAD.

## 1. Purpose

Phase 8 turns the qualified service/security substrate into the first complete wg-basic product experience.

It owns:

- authenticated server setup;
- managed-client product metadata;
- generation-safe client CRUD;
- deterministic address allocation;
- enable/disable semantics;
- audit events for product mutations;
- standard WireGuard config export;
- QR presentation;
- one-time enrollment capability;
- live client telemetry;
- actual embedded management UI.

It does not own:

- arbitrary wg-quick hooks;
- OIDC/TOTP/RBAC;
- direct TLS/ACME;
- IPv6 production qualification;
- install/update/systemd;
- per-client firewall policy beyond the already-defined global network-control baseline;
- multi-interface product UX.

## 2. Core invariants

1. Every product mutation uses expected DesiredGeneration.
2. No HTTP route mutates SQLite directly; the worker remains the only state path.
3. A durable commit is distinct from kernel convergence.
4. Disable/delete may be committed while enforcement is degraded; the API/UI must say so.
5. A disabled client remains reserved/re-enableable but its peer is absent from kernel intent.
6. Address allocation happens inside the same generation-CAS mutation as client creation.
7. Client labels never become executable text.
8. No product route introduces arbitrary WireGuard/wg-quick hooks.
9. Config/QR/enrollment artifacts are credentials and are never cached/logged.
10. One-time enrollment stores only a digest of a 256-bit secret and consumes atomically once.
11. Live telemetry remains non-durable.
12. All unsafe product HTTP routes retain Host + Origin + session + CSRF enforcement.
13. The product UI remains embedded/self-contained with no external runtime/build requirement.

## 3. Current-state research

### 3.1 Existing wg-basic substrate

The current durable state already contains:

- managed interface;
- peers;
- managed clients;
- client assigned address;
- per-client route policy;
- retained client private key when available;
- server private key/listen port;
- network policy;
- desired-generation CAS.

The current privileged API already exposes `ObserveWireGuardDevice` with live handshake/endpoint/RX/TX, so Phase 8 telemetry should reuse it rather than expand privileged vocabulary.

### 3.2 Product-model gaps

The durable model still lacks:

- client label;
- enabled/disabled state;
- client DNS policy;
- client-side keepalive policy;
- advertised server endpoint;
- product audit events;
- one-time enrollment state.

These belong to the application model/schema, not kernel telemetry.

### 3.3 Current ecosystem/prior art

Current wg-easy 15.4 and other WireGuard managers converge on the same operator-critical product loop:

```text
setup server
 -> create client
 -> assign address
 -> export config / QR
 -> enable/disable/delete
 -> inspect handshake/traffic
```

wg-basic follows that UX loop but keeps its own security/ownership model.

### 3.4 QR implementation

Preferred initial QR dependency: `qrcodegen` 1.8.x.

Reasons:

- encoder only;
- raw matrix output;
- no image stack required;
- small dependency surface;
- can be rendered by wg-basic as fixed SVG.

Implementation still must compile/qualify it under Rust 1.89 before adoption.

## 4. Dependency graph

```text
post-Phase-7 C001
        |
        v
M001 — product model + schema v3 + setup/client mutation service
        |
        v
M002 — authenticated setup/client CRUD HTTP API
        |
        v
M003 — config export + QR + one-time enrollment
        |
        v
M004 — live telemetry + audit/query/status product surface
        |
        v
M005 — full embedded management UI + Phase 8 product E2E
```

All dependencies are hard for implementation.

Research/planning may proceed before C001 closes.

## 5. M001 — Product model, schema v3, and generation-safe mutations

Status: closed. Evidence: `plans/closure/product-management/001-status.md`.

Implementation plan:

- `plans/implementation/product-management/001-product-model-and-generation-safe-mutations.md`

Primary class: product foundation / invariant.

Objective:

Create the product-facing application model and worker/runtime mutation services before publishing any configuration-mutating HTTP route.

Expected outcomes:

- real schema migration 2→3;
- advertised endpoint;
- client label/enabled/DNS/client-side keepalive metadata;
- audit events;
- deterministic IPv4 address allocator;
- authenticated setup command at worker/service layer;
- create/update/enable/disable/delete client commands;
- client key generation;
- projection filters disabled managed-client peers;
- mutation receipt distinguishing durable commit from enforcement;
- stale-generation conflict handling;
- no new HTTP CRUD route yet.

## 6. M002 — Authenticated server/client CRUD HTTP API

Status: ready; M001 closed.

Implementation plan:

- `plans/implementation/product-management/002-authenticated-product-crud-api.md`

Primary class: capability / security.

Objective:

Publish the generation-safe product model through the existing Phase 7 HTTP perimeter.

Expected outcomes:

- setup/status routes;
- server summary;
- client list/detail;
- create/update;
- enable/disable;
- delete;
- explicit per-route body bounds;
- stable safe JSON shapes;
- 200/201 vs 202 committed/degraded semantics;
- 409 stale generation before commit;
- no secret private key in ordinary list/detail responses;
- no config/QR/enrollment route yet.

## 7. M003 — Standard export, QR, and one-time enrollment

Status: blocked on M002.

Implementation plan:

- `plans/implementation/product-management/003-export-qr-and-one-time-enrollment.md`

Primary class: capability / secret handling.

Objective:

Deliver the easy onboarding artifact path while keeping secret exposure bounded.

Expected outcomes:

- deterministic standard WireGuard client config renderer;
- authenticated config download;
- authenticated QR SVG;
- `qrcodegen` qualification;
- real schema migration 3→4 for enrollment capabilities;
- 256-bit digest-only one-time tokens;
- short expiry/revocation;
- fragment-based share URLs;
- static non-consuming enrollment landing page;
- atomic single-use consume endpoint;
- separate enrollment limiter;
- no-store/referrer-safe secret responses.

## 8. M004 — Live telemetry and audit/status surface

Status: blocked on M003.

Implementation plan:

- `plans/implementation/product-management/004-live-telemetry-and-audit-surface.md`

Primary class: capability / observability.

Objective:

Expose live peer state and secret-safe mutation history without making telemetry authoritative.

Expected outcomes:

- worker/runtime telemetry observation through existing `ObserveWireGuardDevice`;
- mapping by peer public key to PeerId/ClientId;
- latest handshake/endpoint/RX/TX;
- safe “recently active” projection if useful;
- no telemetry persistence;
- authenticated telemetry endpoint;
- paginated/bounded audit endpoint;
- no secret-bearing audit payloads.

## 9. M005 — Embedded product UI and Phase 8 qualification

Status: blocked on M004.

Implementation plan:

- `plans/implementation/product-management/005-embedded-product-ui-and-phase8-qualification.md`

Primary class: product closure / qualification.

Objective:

Deliver the wg-easy-like operator loop through the self-contained embedded UI and close the first user-facing product boundary.

Expected outcomes:

- login-aware application shell;
- authenticated first-server setup wizard;
- server/dashboard summary;
- client create/edit/enable/disable/delete;
- config download;
- QR modal;
- one-time share-link workflow;
- live handshake/traffic display;
- audit/status view;
- bounded polling rather than mandatory WebSocket;
- no Node/build runtime;
- rootful product E2E driven through real HTTP and exported client configuration;
- complete regression of Phase 6–7 security/network suites.

## 10. Schema v3 direction

M001 owns the first product-model migration after auth.

Prefer additive side tables where they preserve the proven core network schema cleanly.

Expected structures:

### interface_product_settings

One row per managed interface, containing at least:

- interface_id FK;
- advertised endpoint host;
- advertised endpoint UDP port.

### client_product_settings

One row per managed client, containing at least:

- client_id FK;
- display label;
- enabled flag;
- client-side keepalive seconds nullable;
- created_at;
- updated_at.

### client_dns_servers

Ordered optional DNS IPs per client.

### audit_events

Append-only event rows containing:

- event ID;
- timestamp;
- principal ID nullable where an unauthenticated capability event is legitimate;
- action category;
- resource kind;
- resource ID;
- generation_before nullable;
- generation_after nullable;
- bounded outcome category.

Do not store raw JSON request bodies.

Migration from an existing client without product metadata should create a deterministic non-secret label derived from its stable ID rather than failing the database upgrade.

## 11. Schema v4 direction

M003 owns enrollment capability state:

```text
enrollment_capabilities
```

Fields:

- capability ID;
- client ID FK;
- token SHA-256 digest;
- created_at;
- expires_at;
- consumed_at nullable;
- revoked_at nullable;
- creator principal ID.

Raw token never persisted.

Client deletion cascades or otherwise invalidates outstanding enrollment capabilities.

## 12. Product application types

Expected additions:

- `AdvertisedEndpoint`;
- `ClientLabel`;
- `ClientEnabled` or boolean with typed service semantics;
- `ClientDnsPolicy`;
- `ProductMutationReceipt`;
- `EnforcementState`;
- `AuditEventId`;
- `AuditAction`;
- `EnrollmentCapabilityId`;
- secret-redacted `EnrollmentToken`.

Do not expose row structs as HTTP contracts.

## 13. Setup mutation

The M001 setup service is valid only when no primary managed server interface is configured through the Phase 8 product model.

Inputs:

- expected generation;
- interface name;
- tunnel IPv4 prefix;
- server address or deterministic default;
- listen UDP port;
- advertised endpoint;
- egress interface;
- masquerade/forwarding;
- client default route policy.

The service generates the server key itself.

Do not accept a shell hook, nft source, or raw netlink input.

## 14. Client create mutation

Inputs:

- expected generation;
- interface ID;
- label;
- optional requested host address;
- client route policy or use default;
- optional DNS IPs;
- optional client keepalive.

The service:

1. validates label/policy;
2. selects/reserves address;
3. generates client WireGuard keypair;
4. creates stable PeerId and ClientId;
5. creates server-side host AllowedIP;
6. persists private key as secret-bearing client artifact state;
7. writes an audit event atomically;
8. advances one generation;
9. attempts reconcile;
10. returns safe client summary + mutation receipt.

Private key is not returned from ordinary create/list responses. Enrollment/export is M003.

## 15. Update mutation

Editable Phase 8 client fields may include:

- label;
- route policy;
- DNS;
- client keepalive;
- enabled state;
- assigned address only through explicit validation/reallocation.

Do not silently rotate keys on edit.

Key rotation may be added later as an explicit security action.

## 16. Delete mutation

Delete is irreversible at the product level unless restored from backup.

It removes product client and associated managed peer desired state.

Outstanding one-time enrollment capabilities must become unusable.

The response must distinguish:

- committed + enforced;
- committed + enforcement pending/degraded.

UI wording for degraded delete/disable must explicitly state that network access may remain until reconciliation succeeds.

## 17. Config rendering contract

The config renderer consumes validated durable application types and emits only standard fields.

It never parses/render arbitrary extra directives.

Ordering is deterministic for stable tests.

For an IPv4 Phase 8 client:

- `Address` is a host prefix;
- server public key derives from server private key;
- endpoint comes from `AdvertisedEndpoint`;
- `AllowedIPs` comes from client route policy;
- DNS is optional;
- PersistentKeepalive is optional;
- PSK is optional and included only when one exists.

## 18. One-time enrollment abuse model

Threats:

- brute force;
- link scanners;
- accidental repeated retrieval;
- URL/log leakage;
- database theft;
- stale links after delete;
- endpoint hammering.

Controls:

- 256-bit random token;
- SHA-256 digest only in DB;
- short expiry;
- one atomic consume;
- explicit revoke;
- fragment rather than query/path secret;
- landing GET does not consume;
- token POST has small body;
- per-peer/global bounded limiter;
- no-store;
- no-referrer;
- no admin session minted;
- capability scope exactly one client artifact.

## 19. Telemetry contract

Telemetry reads current kernel state through netd.

A missing peer for an enabled durable client is a degraded/drift observation, not a reason to overwrite desired state.

A disabled client should normally have no matching observed peer.

Do not persist traffic counters to SQLite.

No “connected” boolean is authoritative. UI may derive a bounded “recently active” state from handshake age and current time while still displaying the timestamp.

## 20. UI structure

Keep the embedded buildless approach.

Suggested views:

```text
/login
/setup (authenticated when no server exists)
/dashboard
/clients
/client/:id
/audit
```

The application can remain one embedded shell with client-side route/view switching.

No framework dependency is required.

## 21. First user-facing closure test

Phase 8 closure should qualify the actual operator story:

```text
admin bootstrap
 -> login
 -> authenticated server setup
 -> create client
 -> config export / QR
 -> configure real client namespace from exported values
 -> real WireGuard handshake
 -> traffic passes
 -> telemetry shows handshake/RX/TX
 -> disable client
 -> access stops
 -> re-enable
 -> access resumes
 -> one-time enrollment consumes exactly once
 -> delete client
 -> access revoked
```

The test must exercise the real HTTP perimeter and bounded worker, not call StateStore directly.

## 22. Security regression posture

Every new unsafe route receives explicit negative tests for:

- foreign Host;
- missing/foreign Origin;
- missing/wrong CSRF;
- unauthenticated session;
- stale generation;
- oversized body;
- malformed resource ID.

Secret routes additionally assert:

- no cache;
- no secret in logs/errors;
- no secret in audit;
- no secret in ordinary client list/detail.

## 23. Milestone status

| Milestone | Status | Implementation plan | Hard blocker |
|---|---|---|---|
| M001 product model + mutations | closed | `plans/implementation/product-management/001-product-model-and-generation-safe-mutations.md` | post-Phase-7 C001 (closed) |
| M002 authenticated CRUD API | ready | `plans/implementation/product-management/002-authenticated-product-crud-api.md` | M001 (closed) |
| M003 export/QR/enrollment | blocked | `plans/implementation/product-management/003-export-qr-and-one-time-enrollment.md` | M002 |
| M004 telemetry/audit surface | blocked | `plans/implementation/product-management/004-live-telemetry-and-audit-surface.md` | M003 |
| M005 embedded product UI/closure | blocked | `plans/implementation/product-management/005-embedded-product-ui-and-phase8-qualification.md` | M004 |
