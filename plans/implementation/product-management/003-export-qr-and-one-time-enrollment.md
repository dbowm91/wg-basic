# Product Management M003 — Export, QR, and One-Time Enrollment

Status: blocked on Product Management M002 closure

Source roadmap:

- `plans/subsystems/product-management-enrollment-ui-roadmap.md#7-m003--standard-export-qr-and-one-time-enrollment`

Canonical architecture:

- `plans/adr/004-product-management-enrollment-and-api-semantics.md`

Primary class: capability / secret handling

Hard dependency: Product Management M002 strict closure.

## 1. Objective

Add the client enrollment artifact path: standard WireGuard config, QR, and secure one-time sharing.

## 2. Config renderer

Create a pure renderer over validated product state.

Required fields:

```ini
[Interface]
PrivateKey = ...
Address = ...
DNS = ...        # only when configured

[Peer]
PublicKey = ...
PresharedKey = ...  # only when configured
Endpoint = ...
AllowedIPs = ...
PersistentKeepalive = ... # only when configured
```

Requirements:

- deterministic ordering/newlines;
- no hooks;
- no comments required for correctness;
- no arbitrary extra fields;
- IPv6 endpoint host bracket rendering correct;
- bounded output size;
- refuse when client private key is unavailable.

The renderer must never log/debug the rendered text.

## 3. Authenticated artifact routes

Add:

```text
GET /api/v1/clients/<id>/config
GET /api/v1/clients/<id>/qr
POST /api/v1/clients/<id>/enrollment-links
DELETE /api/v1/enrollment-links/<capability-id>
```

All admin routes require session; unsafe create/revoke also Origin+CSRF.

Config response:

- `text/plain; charset=utf-8`;
- attachment filename derived safely from bounded label/ID;
- `Cache-Control: no-store`;
- no content sniffing.

QR response:

- `image/svg+xml`;
- no-store;
- fixed generated SVG vocabulary.

## 4. QR dependency

Evaluate and, if qualified under Rust 1.89, adopt:

```text
qrcodegen = 1.8.x
```

Render SVG locally from the raw module matrix.

Do not add `image`, browser canvas generation, external QR service, or shell out to `qrencode`.

SVG renderer:

- fixed XML/SVG elements/attributes;
- integer coordinates only;
- no embedded text/config;
- no script/event attributes;
- quiet zone;
- bounded module/output count.

Test QR generation against fixed config fixtures and size failures.

## 5. Schema migration 4

Add immutable:

```text
004_enrollment_capabilities.sql
```

Table fields:

- capability_id TEXT PK;
- client_id FK;
- token_digest TEXT UNIQUE;
- creator_principal_id FK;
- created_at;
- expires_at;
- consumed_at nullable;
- revoked_at nullable.

Checks:

- expiry > creation;
- consumed/revoked timestamp sanity where practical.

Raw token never stored.

Migration v3→v4 gets full recovery/migration qualification.

## 6. Capability token

Generate:

- 256 random bits from OS CSPRNG;
- URL-safe encoding without ambiguity;
- SHA-256 digest stored;
- raw token returned exactly once.

Default expiry should be short; select/document a concrete default such as 10 minutes with a bounded operator-selectable maximum no longer than 24 hours.

No weak numeric/random IDs.

## 7. Fragment-based share URL

Admin creation response returns:

```text
<canonical-origin>/enroll/<capability-id>#token=<secret>
```

Only capability ID is sent to the server on GET.

The raw token exists only after `#`, so normal HTTP request logs and Referer do not carry it.

The enrollment landing document is embedded and self-contained.

On load it:

1. reads token from fragment;
2. validates expected shape locally;
3. removes fragment using `history.replaceState`;
4. POSTs JSON token to consume route;
5. presents/downloads returned config.

Do not consume on GET.

## 8. Consume route

Add unauthenticated capability route:

```text
GET  /enroll/<capability-id>
POST /api/v1/enroll/<capability-id>/consume
```

The POST is capability-authenticated, not admin-session-authenticated.

It still requires:

- allowed Host;
- exact same canonical Origin because the landing page is same-origin;
- small JSON body;
- dedicated global/raw-peer enrollment limiter before DB work.

It does not require admin CSRF/session because the capability secret itself is the authorization and the requester is intentionally not an administrator.

No CORS.

## 9. Atomic single use

State operation must atomically:

1. find capability ID;
2. compare token digest;
3. verify not expired;
4. verify not revoked;
5. verify not consumed;
6. load enough validated client data to render one artifact;
7. set consumed_at;
8. append secret-safe audit event;
9. commit.

A second attempt returns gone/not available and no artifact.

A wrong token does not consume.

GET/previews never consume.

Client deletion invalidates via FK/cascade or explicit revoke.

## 10. Capability audit/privacy

Audit:

- capability created;
- revoked;
- consumed.

Audit contains ID/resource/timestamp only, no token/config/private key.

The consume response and landing page use no-store and Referrer-Policy no-referrer.

No token in logs/errors.

## 11. Security tests

Required:

- raw token absent from SQLite;
- token absent from logs/audit;
- config/QR no-store;
- GET landing does not consume;
- token in fragment is not present in server request target;
- first correct consume succeeds;
- second correct consume fails;
- wrong token does not consume;
- expired fails;
- revoked fails;
- deleted client invalidates;
- limiter precedes DB token lookup where measurable/guardable;
- foreign Host/Origin refused;
- no CORS;
- admin create/revoke still require CSRF.

## 12. Interoperability E2E

Use generated config values to configure a real client namespace and prove:

- handshake;
- address;
- route policy;
- endpoint;
- optional PSK/keepalive semantics where configured.

Do not require production `wg`/`wg-quick`.

Optionally qualify syntax with wireguard-tools in CI if available, but it is not a runtime dependency.

## 13. Acceptance criteria

M003 closes only when:

1. standard config is deterministic/interoperable;
2. ordinary config download works only for retained client private keys;
3. QR is local Rust-generated SVG from exact config;
4. schema v4 migration is qualified;
5. tokens are 256-bit/digest-only/expiring/revocable/single-use;
6. GET scanner cannot consume;
7. consume is atomic and rate-limited;
8. no enrollment secret reaches logs/audit/cache;
9. real client handshake succeeds from exported semantics;
10. Rust 1.89/all prior CI pass.

## 14. Stop conditions

Stop if:

- QR crate breaks MSRV or pulls an unnecessary image stack;
- one-time token would need to appear in query/path;
- capability consume cannot be atomic with consumed state;
- config renderer requires wg-quick hooks;
- export needs direct netd access from HTTP.

## 15. Closure evidence

Record config fixtures, qrcodegen version/MSRV/dependency diff, SVG constraints, schema v4, token entropy/storage proof, one-time negative matrix, real exported-client handshake, CI, and M004 readiness.
