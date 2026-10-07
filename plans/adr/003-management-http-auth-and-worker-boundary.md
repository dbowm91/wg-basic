# ADR-003 — Management HTTP Service, Authentication, and Async/Blocking Boundary

Status: accepted

Date: 2026-10-07

Canonical references:

- `plans/000-long-term-specification.md`
- `plans/001-terminology-and-domain-model.md`
- `plans/002-long-term-roadmap.md`
- `plans/adr/001-linux-native-control-plane.md`
- `plans/adr/002-durable-state-generations-and-ownership.md`

Predecessor evidence:

- network-control M001–M005 and C001 strictly closed;
- durable-state M001–M004 and post-Phase-6 C001 strictly closed.

## 1. Context

Phase 6 leaves wg-basic with a stable unprivileged management runtime:

- SQLite is authoritative desired state;
- `ManagementRuntime` owns the state store and netd reconciliation;
- `ManagementHealth` is the single safe/non-secret health projection;
- netd remains the only privileged network authority;
- all state-store operations are synchronous and deliberately blocking;
- the durable store documents that a future async HTTP surface must cross through a bounded blocking-worker adapter.

Phase 7 must add the HTTP/security substrate without allowing an Internet/LAN request path to become a direct SQLite or privileged-kernel call path.

The target remains a small appliance, not a general Rust web framework application.

## 2. Research findings

### 2.1 EggServe

Current EggServe direct crates fit wg-basic's Rust 1.89 baseline:

- `eggserve-server` 0.4.0, Rust 1.89;
- `eggserve-primitives` 0.2.2, Rust 1.89.

The direct server already owns:

- HTTP/1 parsing/framing;
- request/body ceilings;
- timeouts;
- connection/in-flight bounds;
- lifecycle/cancellation;
- graceful shutdown;
- generic sanitized runtime errors;
- suppressed Server metadata by default;
- application `Service` without exposing Hyper as the application contract.

EggServe intentionally does not own application authentication, authorization, per-user/per-IP rate limits, CSRF, or product routing.

For wg-basic's small H1 control service, direct `eggserve-server` + `eggserve-primitives` is sufficient. Tower/Axum and `eggserve-core` add no necessary capability to the Phase 7 baseline.

### 2.2 Password hashing

Current RustCrypto `argon2` 0.6.0 declares Rust 1.85 and provides Argon2id plus PHC/password-hash support.

OWASP's current baseline recommends Argon2id with at least:

- 19 MiB memory;
- 2 iterations;
- parallelism 1.

That is appropriate for an infrequent appliance-admin login and remains modest on SBC-class hosts.

### 2.3 Sessions

Opaque high-entropy server-side sessions are a better fit than JWTs:

- immediate revocation;
- password reset can revoke all sessions;
- no bearer claims become long-lived authorization state;
- no token signing/rotation policy is required;
- the existing SQLite store is already the authoritative secret-bearing application store.

A 256-bit random session token is returned to the browser once; only a SHA-256 digest is stored.

### 2.4 Browser request security

Recent admin-interface failures continue to demonstrate that loopback/private admin services still need explicit browser-origin boundaries.

Phase 7 therefore treats all of these as separate defenses:

- exact Host allowlisting;
- exact Origin validation on unsafe browser methods;
- SameSite=Strict session cookies;
- synchronizer CSRF tokens;
- no CORS by default;
- clickjacking/content-sniffing/referrer/permissions security headers;
- login throttling before Argon2 work.

SameSite is defense in depth, not a substitute for CSRF tokens or Origin validation.

## 3. Decision: HTTP runtime

Phase 7 will depend directly on:

```text
eggserve-server = "0.4"
eggserve-primitives = "0.2.2"
```

or the compatible current patch releases proven by the implementation milestone.

No Tower or Axum dependency is added in Phase 7 unless implementation evidence demonstrates the direct EggServe `Service` contract cannot support a required bounded route cleanly.

No `eggserve-static` dependency is required: Phase 7/8 assets are embedded into the wg-basic binary and returned through the application service.

The management HTTP service is HTTP/1 only in Phase 7.

Direct TLS termination is deferred. The supported Phase 7 deployment shapes are:

1. loopback HTTP, canonical default;
2. loopback HTTP behind an explicitly configured HTTPS reverse proxy;
3. explicit non-loopback HTTP only behind a conspicuous insecure-development/operator override.

## 4. Decision: process topology

The canonical runtime becomes:

```text
                EggServe async H1 runtime
                         |
                         v
               wg-basic HTTP service
          routing/auth/CSRF/security policy
                         |
                bounded async channel
                         |
                         v
             dedicated blocking worker
                owns ManagementRuntime
                owns SQLite StateStore
                owns netd client calls
                         |
                         v
                       netd
                         |
                         v
                 Linux networking
```

The HTTP task MUST NOT call rusqlite or `ManagementRuntime` methods directly.

The worker is one dedicated OS thread with one bounded request queue. Tokio handlers send typed commands through a bounded `tokio::sync::mpsc` channel and await one-shot replies.

This preserves:

- one management/state serialization authority;
- no SQLite blocking on async executor threads;
- bounded backpressure;
- a small Phase 8 API seam.

The worker may block on Argon2 or netd because login/mutation admission is independently bounded and the queue is bounded. If measured authentication latency later harms management responsiveness, a separate bounded crypto worker may be introduced by a future plan without changing HTTP/session semantics.

## 5. Decision: service readiness

Service startup follows:

1. open/validate/migrate the state store;
2. start the management worker;
3. attempt the mandatory startup reconciliation required by ADR-002;
4. start the HTTP listener even if netd is unavailable or current desired state has an operator-resolvable ownership conflict;
5. expose degraded state through authenticated health.

A database/path/migration failure is fatal because the service has no authoritative application state.

A netd/backend/conflict failure is not fatal to HTTP administration; the operator needs the management surface to diagnose/fix it.

The public liveness endpoint remains minimal and secret-free.

## 6. Decision: authentication model

Phase 7 supports one local administrator account as the product-visible policy, represented internally by a stable `PrincipalId`.

The storage schema SHOULD be extensible to multiple principals later, but Phase 7 authorization treats exactly one enabled local administrator as the supported state.

Credential rules:

- Argon2id PHC string;
- independent random salt;
- baseline parameters at least m=19456 KiB, t=2, p=1;
- no plaintext/reversible password storage;
- no password in argv, environment, log, error, URL, or database outside the Argon2 verifier;
- no composition rules;
- bounded minimum/maximum UTF-8 byte length;
- password reset revokes all existing sessions.

The initial administrative credential is created/reset only through a local CLI/state operation, not through an unauthenticated browser bootstrap.

Phase 8 may design a first-run UX, but it must not introduce a first-browser-wins race.

## 7. Decision: session model

A session consists of:

- stable `SessionId`;
- principal ID;
- SHA-256 digest of a 256-bit random bearer token;
- 256-bit random CSRF token;
- creation time;
- absolute expiry;
- optional future metadata that does not become authorization truth.

The raw session token is never persisted.

The CSRF token may be stored as secret-bearing session state because possession without the session cookie does not authenticate the request.

Phase 7 uses an absolute finite session lifetime and no indefinite “remember me” session.

Login creates a new session.

Logout revokes the current session.

Password reset revokes every session for that principal.

Expired sessions fail closed and are removed/ignored.

## 8. Decision: cookies

Session cookie:

- HttpOnly;
- SameSite=Strict;
- Path=/;
- no Domain;
- bounded Max-Age consistent with server-side expiry.

For an HTTPS canonical origin:

- Secure is mandatory;
- use a `__Host-` cookie name.

For direct loopback HTTP:

- do not falsely claim HTTPS;
- use a host-only non-prefixed cookie with HttpOnly + SameSite=Strict;
- service startup/output must identify the transport as local-only HTTP.

Non-loopback insecure HTTP is an explicit unsafe override and never the default.

## 9. Decision: CSRF and browser-origin policy

Every authenticated unsafe browser method MUST satisfy all of:

1. valid session cookie;
2. exact allowed Host;
3. exact configured Origin;
4. valid synchronizer CSRF token supplied in a dedicated header.

The CSRF token is returned only through an authenticated same-origin session endpoint.

Unsafe requests with missing/foreign Origin fail closed.

No wildcard CORS policy is emitted.

Login itself has no session/CSRF token yet, but still requires allowed Host and exact Origin.

If `Sec-Fetch-Site` is present, cross-site values SHOULD be rejected as defense in depth.

## 10. Decision: Host / DNS-rebinding boundary

The service maintains an explicit canonical origin and allowed Host set.

Default loopback mode accepts only the configured loopback origin/host values.

A reverse-proxy/public deployment must configure the externally visible origin explicitly.

Arbitrary Host values are not accepted merely because the socket is bound to loopback.

Forwarded/X-Forwarded-* headers remain untrusted in Phase 7.

## 11. Decision: login throttling

EggServe does not implement application-auth quotas, so wg-basic owns them.

Login admission happens before Argon2 hashing.

The implementation uses bounded in-memory throttling with:

- one global limiter;
- one raw transport-peer limiter where useful;
- bounded key/cardinality state;
- 429 + bounded Retry-After behavior;
- no persistent account lockout that an attacker can make permanent.

When running behind a reverse proxy, the raw peer may be the proxy; Phase 7 therefore does not pretend it knows end-client identity from forwarded headers.

## 12. Decision: HTTP route scope

Phase 7 is security/service substrate, not the full product API.

Required baseline routes are intentionally small:

```text
GET  /healthz
POST /api/v1/login
POST /api/v1/logout
GET  /api/v1/session
GET  /api/v1/health
GET  /
GET  /assets/...
```

- `/healthz` is unauthenticated and returns only liveness/readiness-safe information.
- `/api/v1/health` exposes only `ManagementHealth` after authentication.
- Phase 7 does not implement peer/client CRUD or configuration export; those belong to Phase 8.

## 13. Decision: assets

Assets are compiled into the binary.

Phase 7 needs only a minimal self-contained shell proving:

- embedded serving;
- deterministic MIME/content length;
- no external fonts/scripts/styles;
- strict CSP compatibility;
- no filesystem static root.

Phase 8 will replace/extend the shell into the actual management UI.

No Node/JS runtime becomes a deployment dependency.

## 14. Decision: response/security headers

The application service owns product headers on top of EggServe framing/privacy policy.

At minimum:

- `Content-Security-Policy` with a self-contained restrictive policy;
- `X-Content-Type-Options: nosniff`;
- `Referrer-Policy: no-referrer`;
- `X-Frame-Options: DENY` as legacy defense in depth alongside CSP frame-ancestors;
- restrictive `Permissions-Policy`;
- `Cache-Control: no-store` on authentication/session/API-secret responses.

HSTS is emitted only when the canonical external origin is HTTPS.

## 15. Decision: dependency additions

Expected Phase 7 dependency families:

- EggServe direct server/primitives;
- Tokio sync/runtime features required for the service;
- `argon2` 0.6;
- `sha2` 0.11;
- `cookie` 0.18.1;
- a direct CSPRNG dependency such as `getrandom` if not supplied through an already-direct audited API.

Each exact version must pass Rust 1.89 in the owning milestone.

No JWT, OAuth/OIDC, template engine, SPA framework, database pool, or general router framework is required for Phase 7.

## 16. Consequences

Positive:

- HTTP parsing/runtime hardening is reused rather than reimplemented;
- SQLite never blocks an async executor thread;
- server-side sessions remain revocable;
- browser security boundaries are explicit;
- no unauthenticated bootstrap race;
- Phase 8 receives a stable, narrow service/worker/auth substrate;
- no Node runtime or container is introduced.

Costs:

- the project owns a small router/auth/session layer;
- loopback HTTP cannot claim the cookie guarantees of HTTPS;
- a reverse-proxy deployment needs an explicit canonical external origin;
- one dedicated blocking worker serializes application state operations.

## 17. Verification consequences

Phase 7 closure must prove:

- EggServe application service works without Tower/Axum;
- worker queue saturation is bounded and returns a safe service-unavailable response;
- async handlers do not access rusqlite directly;
- actual v1→v2 authentication-schema migration succeeds and preserves Phase 6 state;
- Argon2 policy/MSRV qualification;
- opaque session token never appears in SQLite/logs;
- Host and Origin attacks fail;
- CSRF is enforced independently of SameSite;
- login throttling precedes password hashing;
- secure/insecure cookie variants are correct for their origin mode;
- server restart preserves valid sessions until expiry/revocation;
- password reset revokes sessions;
- graceful HTTP/worker shutdown completes;
- all existing rootful network/durable suites remain green.
