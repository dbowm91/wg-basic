# Product Management M004 — Live Telemetry and Audit Surface

Status: closed; Product Management M003 and M004 closed.

Source roadmap:

- `plans/subsystems/product-management-enrollment-ui-roadmap.md#8-m004--live-telemetry-and-auditstatus-surface`

Canonical architecture:

- `plans/adr/004-product-management-enrollment-and-api-semantics.md`

Primary class: observability / capability

Hard dependency: Product Management M003 strict closure.

## 1. Objective

Expose live peer state and product mutation history without making either an alternate source of configuration truth.

## 2. Reuse existing privileged observation

Use the existing:

```text
RequestOperation::ObserveWireGuardDevice
```

Do not add privileged protocol vocabulary unless real implementation evidence proves the current observation lacks a required safe field.

ManagementRuntime gets a typed observation method.

Worker gets a bounded command such as:

```text
ObserveClientTelemetry { interface_id }
```

HTTP never talks to netd directly.

## 3. Telemetry mapping

Join observed peers to durable product clients by public key, then project stable IDs.

Per client safe telemetry:

- ClientId;
- PeerId;
- observed endpoint nullable;
- latest handshake timestamp/age nullable;
- RX bytes;
- TX bytes;
- observation status: present/missing.

Do not expose any private/PSK material.

An enabled client missing from the kernel is drift/degraded observation.

A disabled client with an observed peer is also drift and should be surfaced.

## 4. Time semantics

Verify `nl-wireguard`'s `last_handshake` representation and normalize it into one documented API representation.

Prefer absolute Unix seconds plus optional derived age.

Do not serialize Rust `Duration` implementation details directly to the public API.

A derived “recently_active” flag may use a documented short threshold but is UI convenience only, not authoritative connection state.

## 5. No telemetry persistence

No migration for:

- handshake;
- observed endpoint;
- RX;
- TX.

Architecture guard should continue proving these names/fields do not enter desired-state tables.

A page refresh obtains a fresh observation.

## 6. Telemetry HTTP route

Add authenticated safe route, e.g.:

```text
GET /api/v1/clients/telemetry
```

or a server-scoped equivalent.

Requirements:

- session required;
- Host validated;
- GET no CSRF needed;
- live netd observation through worker;
- no-store;
- bounded response count/size;
- 503/degraded safe response when netd unavailable.

No WebSocket required.

## 7. Audit query surface

Use M001 audit events.

Add authenticated:

```text
GET /api/v1/audit
```

Bounded pagination:

- fixed/default page size;
- hard maximum;
- opaque/stable cursor or timestamp+ID cursor;
- newest-first default.

Filters may include action/resource category if simple.

No free-form SQL/search expression.

## 8. Audit event projection

Safe fields:

- event ID;
- timestamp;
- principal ID where applicable;
- action;
- resource kind/ID;
- generation before/after;
- outcome.

No secret/config/request content.

Enrollment consume events may have no admin principal but can name the scoped client/capability resource safely.

## 9. Product/server status

Extend authenticated server summary if useful with:

- current desired generation;
- last converged generation;
- current backend probe;
- number enabled/disabled clients;
- number observed peers;
- setup configured.

Do not fold telemetry into persistent server state.

## 10. Tests

Required:

- live telemetry maps public keys to IDs;
- missing/extra peer behavior;
- disabled-but-observed drift;
- latest handshake time normalization;
- RX/TX exact;
- backend unavailable safe response;
- no telemetry DB persistence after repeated reads;
- bounded 4096-peer backend cannot create unbounded HTTP response;
- audit pagination/order;
- no secret markers in audit JSON;
- Host/session/security headers for routes.

Rootful:

- real client handshake appears in telemetry;
- traffic increments RX/TX;
- disable removes observed peer;
- re-enable restores observation after handshake.

## 11. Acceptance criteria

M004 closes only when:

1. existing ObserveWireGuardDevice is sufficient or any extension is separately justified;
2. telemetry is fresh/read-only/non-durable;
3. client mapping is stable-ID based;
4. time semantics are documented;
5. audit query is bounded/secret-safe;
6. real handshake/traffic appears through authenticated HTTP;
7. no WebSocket/background polling service is required;
8. all prior CI/MSRV/rootful suites pass.

## 12. Stop conditions

Stop if telemetry requires database authority, if HTTP must directly invoke netlink, if a protocol extension starts returning raw kernel structures, or if audit query needs raw request/config payloads.

## 13. Closure evidence

Record protocol reuse/extension decision, telemetry mapping/time semantics, DB non-persistence proof, audit pagination/privacy, rootful handshake/traffic evidence, CI, and M005 readiness.
