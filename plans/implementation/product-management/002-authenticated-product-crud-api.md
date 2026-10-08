# Product Management M002 — Authenticated Product CRUD API

Status: closed. Evidence: `plans/closure/product-management/002-status.md`.

Source roadmap:

- `plans/subsystems/product-management-enrollment-ui-roadmap.md#6-m002--authenticated-serverclient-crud-http-api`

Canonical architecture:

- `plans/adr/003-management-http-auth-and-worker-boundary.md`
- `plans/adr/004-product-management-enrollment-and-api-semantics.md`

Primary class: capability / security

Hard dependency: Product Management M001 strict closure.

## 1. Objective

Expose the Phase 8 setup/client application model through the existing authenticated HTTP perimeter without adding enrollment secrets yet.

The API is a thin transport over typed worker commands. It does not allocate addresses, generate keys, manipulate state rows, or decide reconciliation semantics itself.

## 2. Route inventory

Add authenticated routes under `/api/v1`:

```text
GET    /api/v1/server
POST   /api/v1/setup

GET    /api/v1/clients
POST   /api/v1/clients
GET    /api/v1/clients/<client-id>
PATCH  /api/v1/clients/<client-id>
POST   /api/v1/clients/<client-id>/enable
POST   /api/v1/clients/<client-id>/disable
DELETE /api/v1/clients/<client-id>
```

Exact use of PATCH vs PUT may be adjusted only if the typed update model remains explicit.

No config, QR, one-time enrollment, telemetry, or audit query endpoint in M002.

## 3. Dynamic route parsing

Extend routing deliberately rather than introducing a framework.

Requirements:

- canonical UUID only;
- exact segment counts;
- no percent-decoded filesystem semantics;
- no prefix match that accepts suffix garbage;
- unknown/malformed resource ID gives bounded 404/400 policy;
- method mismatch remains 405 only for a known route shape.

Add route-unit tests for near misses and malformed IDs.

## 4. Existing security perimeter remains total

Every route still crosses the single pipeline:

```text
transport/body bound
 -> Host
 -> route
 -> method
 -> Origin for unsafe
 -> session
 -> CSRF for unsafe authenticated
 -> handler
 -> single response header seal
```

Do not special-case “local” product routes around Host/Origin/CSRF.

No CORS.

## 5. Request body bounds

Choose route-specific bounds rather than inheriting login or global limits accidentally.

Recommended initial ceilings:

- setup: <= 8 KiB;
- create client: <= 8 KiB;
- patch client: <= 8 KiB;
- enable/disable/delete: empty body or <= a very small expected-generation JSON body.

All remain below `MAX_MANAGEMENT_BODY_BYTES`.

Reject incorrect Content-Type for JSON routes.

## 6. Generation contract

Every unsafe product request carries `expected_generation` in its JSON body or an equivalent route-specific typed request.

Read responses carry current generation.

Do not infer expected generation from a stale browser session.

Stale generation:

- no state change;
- 409;
- bounded safe body;
- may include the current generation because the caller is authenticated.

## 7. Mutation response contract

Render the M001 mutation receipt truthfully.

### Committed + converged

- create: 201;
- updates/enable/disable/delete/setup: 200.

### Committed + pending/degraded enforcement

- 202;
- body includes generation + bounded enforcement category;
- for disable/delete the body explicitly marks revocation/enforcement unconfirmed.

### No commit

- stale conflict: 409;
- validation: 422;
- unavailable before commit: 503;
- auth/security refusal: existing Phase 7 statuses.

Never render a post-commit netd failure as if the durable state rolled back.

## 8. Safe JSON projections

Server summary may include:

- configured/not configured;
- interface ID/name;
- tunnel prefix/server address;
- listen port;
- advertised endpoint;
- egress/NAT summary;
- current generation;
- convergence summary.

Client summary/detail may include:

- ClientId/PeerId;
- label;
- enabled;
- assigned address;
- route policy;
- DNS;
- client keepalive;
- public key;
- timestamps.

Must not include:

- client private key;
- preshared key;
- server private key;
- enrollment token.

## 9. Setup behavior

`POST /api/v1/setup` is authenticated and CSRF protected.

A fresh DB with an admin but no server can be configured.

An already configured server returns conflict rather than replacing the interface.

No unauthenticated setup route is added.

## 10. CRUD semantics

### Create

Calls worker create command and returns safe client + mutation receipt.

### Update

Only typed editable fields. No implicit key rotation.

### Enable/disable

Dedicated route/action for UX clarity.

### Delete

Requires expected generation and returns enforcement truth. No body should claim “revoked” if the receipt is degraded.

## 11. Response privacy/security

All product API responses:

- pass through Phase 7 header seal;
- no-store;
- no server/framework metadata;
- bounded JSON;
- no backend raw errors;
- no SQL/netlink text.

Unknown client IDs must not produce internal details.

## 12. Tests

Required wire-level:

- setup success/stale/repeated;
- create/list/detail;
- patch;
- disable/enable;
- delete;
- malformed UUIDs;
- stale generation 409/no mutation;
- 202 committed-but-degraded case;
- safe response excludes all secret markers;
- oversized bodies;
- wrong content type;
- Host/Origin/CSRF/session negative matrix on at least every unsafe route family;
- security headers present;
- no CORS.

Rootful API tests:

- HTTP create results in kernel peer;
- HTTP disable removes peer;
- HTTP enable restores peer;
- HTTP delete removes peer;
- netd-down disable returns 202 and reports not enforced.

## 13. Acceptance criteria

M002 closes only when:

1. all listed routes work over real EggServe;
2. every unsafe route inherits Phase 7 perimeter;
3. generation CAS is visible and load-bearing over HTTP;
4. post-commit degraded enforcement is 202, not rollback fiction;
5. ordinary projections contain no enrollment secrets;
6. dynamic routing is exact/bounded;
7. no config/QR/enrollment route exists yet;
8. all Phase 6–7 regressions and Rust 1.89 pass.

## 14. Stop conditions

Stop if:

- HTTP needs direct StateStore access;
- a route must accept raw desired-state JSON;
- dynamic routing requires weakening Host/origin/security sealing;
- delete/disable semantics cannot distinguish commit from enforcement.

## 15. Closure evidence

Record route matrix, body bounds, generation/status matrix, security negative matrix, rootful CRUD results, secret scan, CI/MSRV, and M003 readiness.
