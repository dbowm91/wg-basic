# ADR-004 — Product Management Model, Enrollment, and Phase 8 API Semantics

Status: accepted

Date: 2026-10-07

Canonical references:

- `plans/000-long-term-specification.md`
- `plans/001-terminology-and-domain-model.md`
- `plans/002-long-term-roadmap.md`
- `plans/adr/001-linux-native-control-plane.md`
- `plans/adr/002-durable-state-generations-and-ownership.md`
- `plans/adr/003-management-http-auth-and-worker-boundary.md`

Predecessor state:

- network-control foundation closed;
- Phase 6 durable state closed;
- Phase 7 service/security substrate closed;
- post-Phase-7 C001 is a bounded CI/evidence corrective and does not change product contracts.

## 1. Context

Phase 8 is the first user-facing product-capability closure boundary.

The substrate already provides:

- authoritative desired state with generation CAS;
- restart-safe kernel reconciliation;
- client/peer identifiers and retained generated client private keys;
- live WireGuard observation containing endpoint, latest handshake, RX, and TX;
- an authenticated CSRF/Origin/Host-protected HTTP service;
- a bounded worker that is the only HTTP path to `ManagementRuntime`;
- embedded self-contained assets;
- local administrator/session semantics.

Phase 8 must turn those primitives into an easy WireGuard appliance without moving correctness into JavaScript or weakening the privilege boundary.

## 2. Current prior-art findings

Current wg-easy 15.4 remains the primary UX reference. Its client surface includes:

- labels/names;
- enable/disable;
- assigned addresses;
- client-side AllowedIPs;
- server-side AllowedIPs;
- DNS;
- persistent keepalive;
- config download/QR;
- one-time configuration links.

Its current documentation also exposes hook fields for wg-quick clients. wg-basic will not copy that capability: arbitrary PreUp/PostUp/PreDown/PostDown commands remain outside the product state.

Recent wg-easy vulnerabilities reinforce two Phase 8 constraints:

- client-controlled/display metadata must never become executable configuration;
- one-time enrollment secrets must be high-entropy, expiring, single-use, and rate-limited.

## 3. Decision: product model versus kernel model

The durable application model remains authoritative.

Phase 8 extends managed-client/product metadata while preserving the distinction:

```text
durable product desired state
      |
      | validate + generation CAS
      v
resolved network intent
      |
      v
netd / kernel
```

Product fields may influence projection without becoming raw kernel fields.

In particular, an administratively disabled client remains durable application state but its associated peer is omitted from the resolved WireGuard peer set.

A disabled client is therefore not “a peer with empty AllowedIPs”; it is an administratively retained client whose kernel authorization is absent.

## 4. Decision: Phase 8 baseline scope

The Phase 8 baseline supports one primary managed WireGuard server interface in the product UI.

The schema/domain should not make multiple interfaces impossible, but Phase 8 does not need multi-interface UX.

The baseline is IPv4-first. Production IPv6 qualification remains Phase 11.

No arbitrary wg-quick hooks are introduced.

No direct TLS is introduced.

## 5. Decision: authenticated first-run setup

“First-run setup” means the authenticated creation of the first WireGuard server configuration after the local administrator has been provisioned.

It does NOT mean unauthenticated administrator bootstrap.

The safe sequence remains:

```text
local CLI creates/resets administrator
    -> browser login
    -> authenticated server setup wizard
```

There is no first-browser-wins administrator race.

The first setup operation creates, in one generation mutation:

- server keypair;
- managed interface identity/name;
- IPv4 tunnel prefix;
- server tunnel address;
- listen port;
- advertised endpoint;
- egress interface;
- forwarding/NAT policy;
- default client route policy.

Recommended UX defaults:

- interface: `wgb0`;
- tunnel: `10.8.0.0/24`;
- server address: first usable address, normally `10.8.0.1/24`;
- listen port: 51820;
- masquerade/IPv4 forwarding: enabled for the ordinary road-warrior profile;
- client route policy: full IPv4 tunnel unless the operator selects split tunnel.

The advertised endpoint host and egress interface are explicit operator inputs in the baseline. wg-basic does not add an outbound “what is my IP” dependency.

## 6. Decision: advertised endpoint

Introduce a typed `AdvertisedEndpoint` distinct from:

- an observed peer endpoint;
- a server-side peer endpoint;
- the HTTP canonical origin.

It contains:

- host: bounded validated DNS name, IPv4, or IPv6 literal;
- UDP port.

Rendering brackets IPv6 literals correctly.

The advertised endpoint is application configuration used only when generating client artifacts.

## 7. Decision: managed-client fields

A Phase 8 managed client carries at least:

- `ClientId`;
- associated `PeerId`;
- bounded display label;
- enabled/disabled state;
- assigned tunnel host address;
- client-side route policy;
- optional client DNS server list;
- client-side persistent keepalive policy;
- created/updated timestamps.

The associated durable peer retains:

- public key;
- retained generated private key when available;
- optional preshared key;
- server-side AllowedIPs;
- any server-side peer settings.

Client labels are data only. They are never emitted into executable hook syntax.

## 8. Decision: disabling and deleting

### Disable

Disabling a client:

- keeps its durable IDs, keys, address assignment, route/DNS/export policy;
- advances DesiredGeneration;
- causes projection to omit its peer from the kernel desired set;
- preserves its address reservation so another client cannot receive it.

Re-enable restores that peer from durable state.

### Delete

Deleting a managed client removes its client record and associated managed peer from desired state in one transaction.

The address becomes available only after the delete commits.

A failed kernel reconciliation after the durable delete means the peer may remain active in the kernel temporarily. The API/UI MUST report this as **committed but not yet enforced**, never as a completed revocation.

The project makes no physical-secure-erasure claim for secret bytes already present in SQLite WAL/pages or historical backups. Revocation is a network authorization property, not a promise to erase every previous storage copy.

## 9. Decision: address allocation

The allocator is deterministic, transaction-local, IPv4-first, and does not scan the whole address space.

For one selected IPv4 tunnel prefix it reserves:

- network address where applicable;
- broadcast address where applicable;
- every configured server/interface address inside the prefix;
- every assigned client address, including disabled clients.

It chooses the lowest available usable address.

Implementation should operate over sorted used integer addresses and gaps, so a large prefix does not imply iterating every possible host.

Prefixes with no usable client host address fail validation.

Allocation happens inside the same generation-CAS mutation that inserts the client so two concurrent stale writers cannot obtain the same address.

## 10. Decision: generation-safe product mutations

Every product mutation carries an explicit `expected_generation`.

The HTTP JSON contract uses generation fields rather than making ETag semantics authoritative.

A stale generation returns a conflict and performs no mutation.

A successful durable mutation returns a **mutation receipt** that separates:

- durable commit;
- current generation;
- reconciliation/enforcement state.

Conceptually:

```text
ProductMutationReceipt {
    generation,
    committed: true,
    enforcement:
      converged
      pending
      degraded(category)
}
```

For create/update/setup, a committed-but-degraded result is still durable.

For disable/delete, a committed-but-degraded result MUST be presented conspicuously because access may not yet be revoked in the kernel.

HTTP semantics:

- 200/201 when committed and converged/no network work;
- 202 when committed but enforcement is pending/degraded;
- 409 for stale generation or pre-commit conflict;
- 422 for validation;
- 503 only when no durable commit occurred and the service cannot process the request.

A post-commit reconcile failure MUST NOT be mapped to a response implying that the database transaction rolled back.

## 11. Decision: audit trail

Phase 8 introduces a secret-safe append-only application audit trail.

Product-changing state mutations record an audit event in the same SQLite transaction as the desired-state mutation.

An audit event contains only bounded metadata such as:

- event ID;
- timestamp;
- principal ID where applicable;
- action category;
- resource kind and stable ID;
- generation before/after;
- committed outcome.

It MUST NOT contain:

- private/preshared keys;
- enrollment tokens;
- complete client configs;
- passwords/session tokens/CSRF tokens;
- raw request bodies;
- backend error strings.

Reconciliation result may be recorded as a separate bounded outcome event after the commit; it cannot be part of the same ACID transaction as kernel mutation.

## 12. Decision: standard client configuration export

wg-basic generates ordinary WireGuard-compatible client configuration.

Baseline output:

```ini
[Interface]
PrivateKey = <client private key>
Address = <assigned client host address>
DNS = <optional comma-separated DNS IPs>

[Peer]
PublicKey = <server public key>
PresharedKey = <optional PSK>
Endpoint = <advertised host>:<port>
AllowedIPs = <client route policy>
PersistentKeepalive = <optional client keepalive>
```

No hooks are emitted.

No product-only metadata is required for the exported config to work.

Export is unavailable when wg-basic does not retain the client private key.

Config rendering is deterministic and bounded.

Every config/QR response is secret-bearing and MUST use `Cache-Control: no-store`.

## 13. Decision: QR generation

QR generation remains inside the Rust binary.

Preferred initial candidate: `qrcodegen` 1.8.x because it is a compact encoder with raw module access and no image/runtime dependency. Implementation must verify Rust 1.89.

wg-basic renders the module matrix to its own minimal SVG:

- fixed SVG vocabulary;
- no script;
- no external resources;
- no user-controlled markup;
- bounded dimensions/output.

The QR encodes the exact standard client configuration text.

If a configuration exceeds the selected QR capacity, the API returns “QR unavailable/config too large” while ordinary config download remains available.

## 14. Decision: one-time enrollment capability

A one-time enrollment capability is separate from an admin session.

Creation:

- admin-authenticated + CSRF protected;
- bound to exactly one ClientId;
- random 256-bit secret;
- store only a SHA-256 digest;
- finite short expiry;
- revocable;
- raw secret returned exactly once.

### Fragment-based share URL

The share URL uses a non-secret capability ID in the path and the secret in the URI fragment:

```text
https://vpn.example/enroll/<capability-id>#token=<secret>
```

The fragment is not transmitted in the HTTP request.

`GET /enroll/<id>` serves only a static self-contained enrollment page and does not consume the capability. This avoids link scanners/previews consuming the secret.

The page:

1. reads the fragment locally;
2. removes it from visible browser history with `history.replaceState`;
3. POSTs the token in a bounded same-origin request to the consume endpoint.

The consume endpoint atomically verifies:

- capability ID;
- token digest;
- not expired;
- not revoked;
- not previously consumed;

and marks it consumed exactly once.

Capability consumption is rate-limited before database work.

A capability authorizes only retrieval of that client's enrollment artifact. It does not create an admin session and cannot mutate product state.

## 15. Decision: live telemetry

Live peer telemetry remains read-only and non-durable.

The existing privileged `ObserveWireGuardDevice` operation already returns:

- observed endpoint;
- latest handshake;
- RX bytes;
- TX bytes.

Phase 8 does not add a new privileged protocol operation unless implementation evidence shows the existing one is insufficient.

Management maps observed peer public keys to stable PeerId/ClientId values.

The UI displays:

- latest handshake;
- RX/TX;
- observed endpoint where useful.

It should prefer “last handshake” / “recently active” language over claiming a durable “connected” session state.

No telemetry is written into authoritative desired-state tables.

## 16. Decision: product HTTP API

All product routes remain behind the Phase 7 perimeter.

Every unsafe route requires:

- allowed Host;
- exact Origin;
- live admin session;
- CSRF token;
- bounded body.

Dynamic resource paths parse only canonical UUID identifiers and have no filesystem meaning.

The API is versioned under `/api/v1`.

The first Phase 8 CRUD surface should include server/setup and client management, followed by enrollment and telemetry/audit routes in later milestones.

No CORS is added.

## 17. Decision: UI technology

Phase 8 extends the existing embedded shell using plain HTML/CSS/JavaScript modules.

No Node runtime, package manager, bundler, SPA framework, CDN, external font, or external script is required.

The UI is a consumer of the typed HTTP API; it does not own validation, allocation, key generation, generation CAS, or security decisions.

Telemetry uses bounded polling while the relevant page is visible rather than adding WebSockets solely for charts.

## 18. Decision: mutation/resource rate limits

The login limiter remains dedicated to Argon2 and is not reused for CRUD.

Product mutations pass through:

- authenticated-session admission;
- the bounded management worker;
- explicit per-route body limits;
- optional small mutation limiter only if measured costs justify it.

Do not lower the login limiter or Argon2 policy to make room for CRUD.

Enrollment capability consumption receives its own cheap bounded limiter because it is unauthenticated/capability-authenticated.

## 19. Consequences

Positive:

- the first UI cannot bypass durable-generation semantics;
- disabled clients remain re-enableable while absent from kernel authorization;
- one-time links avoid weak tokens and avoid scanner-triggered consumption;
- QR/config artifacts are ordinary WireGuard configs;
- telemetry remains observed state;
- the product remains a single self-contained binary;
- Phase 8 does not introduce shell hooks or another privileged path.

Costs:

- schema migration 3 is a real product-model expansion;
- projection must become aware of client enabled state;
- one-time enrollment requires another bounded secret-bearing state table;
- the API must model “committed but not enforced” truthfully;
- the UI cannot assume a mutation succeeded merely because SQLite committed.

## 20. Verification consequences

Phase 8 must prove:

- migration 2→3 preserves current installations;
- disabled client peer is removed from a real kernel interface and re-enable restores it;
- address allocation is deterministic and race-safe under generation CAS;
- stale product writes fail without side effects;
- audit event and desired mutation are atomic;
- generated configs match the intended WireGuard fields and carry a real handshake in an E2E fixture;
- QR is generated from the exact config;
- one-time capabilities are high-entropy, digest-only, expiring, revocable, and atomic single-use;
- a GET/link preview cannot consume an enrollment capability;
- live telemetry is read from netd and not persisted;
- every Phase 8 unsafe route remains behind Host/Origin/session/CSRF;
- product UI remains fully embedded and self-contained.
