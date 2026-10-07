# Management Service M003 — Authenticated HTTP Security Perimeter

Status: ready. M002 is closed (`plans/closure/management-service/002-status.md`).

Source roadmap:

- `plans/subsystems/management-service-security-roadmap.md#7-m003--authenticated-http-perimeter`

Canonical requirement:

- `plans/adr/003-management-http-auth-and-worker-boundary.md`

Primary class: security / capability

Hard dependency: M002 strict closure — **satisfied** at `60d1482`, closed 2026-10-07.

Carry-forward from the M002 closure: measured Argon2id cost is ~300 ms per
verification at m=19 MiB, t=2, p=1. With one worker thread and a 5-second reply
deadline that is roughly sixteen concurrent verifications inside the deadline.
Login throttling must therefore be decided **before** a command is admitted to
the worker queue, sized against per-attempt cost rather than request rate, with
the queue bound kept as a second line of defence. Throttling after hashing is
forbidden and is now measurably an availability defect.

## 1. Objective

Expose the minimal authenticated browser API and close the HTTP security perimeter before Phase 8 adds configuration-mutating product routes.

## 2. Cookie support

Adopt `cookie` 0.18.x if Rust 1.89 verification passes.

Session cookie:

- HttpOnly;
- SameSite=Strict;
- Path=/;
- no Domain;
- finite Max-Age matching server expiry.

HTTPS external origin:

- Secure;
- `__Host-` name.

Direct loopback HTTP:

- host-only non-prefixed cookie;
- no false Secure claim;
- explicit local-only documentation.

## 3. Routes

### POST /api/v1/login

Small JSON body.

Requires:

- allowed Host;
- exact Origin;
- login rate-limit admission.

On success:

- issues session cookie;
- returns bounded session metadata/CSRF token.

On failure:

- generic 401;
- no username/password distinction.

### POST /api/v1/logout

Requires session + Host + Origin + CSRF.

Revokes current session and expires cookie.

### GET /api/v1/session

Requires session.

Returns:

- safe principal/session identity;
- expiry;
- CSRF token.

Never returns password hash or session bearer token.

### GET /api/v1/health

Requires session.

Returns exactly the safe `ManagementHealth` projection, not raw receipts/errors.

### GET /healthz

Remains unauthenticated/minimal.

No peer/client CRUD in M003.

## 4. Host validation

Every request must carry an allowed Host.

Default local mode should allow only configured loopback host/origin values.

Unknown/malformed Host fails before route side effects.

Do not derive trust from arbitrary Host merely because the listener is loopback.

## 5. Origin / CSRF policy

Unsafe browser methods require exact configured Origin.

Authenticated unsafe requests additionally require the synchronizer CSRF token in a dedicated header.

Session cookie + SameSite alone is insufficient.

Reject:

- missing unsafe Origin;
- foreign Origin;
- invalid CSRF;
- missing CSRF;
- cross-site Sec-Fetch-Site when present.

No wildcard CORS. Prefer no CORS headers at all.

## 6. Login throttling

Implement bounded in-memory token-bucket/leaky-bucket semantics before Argon2 work.

At least:

- global limiter;
- raw transport-peer limiter;
- bounded peer map/cardinality;
- 429 + Retry-After.

No persistent account lockout.

Test ordering so throttled requests do not invoke password hashing.

## 7. Bind / canonical origin configuration

Default loopback bind.

Add explicit canonical external origin.

Rules:

- loopback HTTP works by default;
- reverse-proxy HTTPS uses explicit HTTPS external origin while listener may remain loopback;
- forwarded headers remain untrusted;
- non-loopback HTTP requires explicit unsafe acknowledgement;
- startup output states effective bind/origin mode.

Do not implement direct TLS in M003.

## 8. Security headers

Apply centrally to application responses.

Required:

- `Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`;
- `X-Content-Type-Options: nosniff`;
- `X-Frame-Options: DENY`;
- `Referrer-Policy: no-referrer`;
- restrictive `Permissions-Policy`;
- `Cache-Control: no-store` on API/auth/session responses;
- HSTS only for HTTPS canonical origin.

Do not expose framework/server versions.

## 9. Request/response bounds

Per-route body limits must be below the EggServe hard ceiling.

Login JSON should be only large enough for bounded username/password fields.

Reject wrong Content-Type for JSON routes.

No multipart/form-data.

No request-derived file path.

## 10. Auth failure timing

Use a fixed dummy Argon2 verifier when:

- no admin is configured;
- username does not match.

This keeps gross username/account-existence timing differences out of the browser surface.

Do not claim perfect constant-time HTTP behavior.

## 11. Tests

Wire-level HTTP tests must cover:

- login success/failure;
- missing/foreign Host;
- missing/foreign Origin;
- session cookie flags under HTTP vs HTTPS external origin;
- unauthenticated protected route;
- CSRF missing/wrong/correct;
- logout revocation;
- session expiry;
- no CORS;
- all security headers;
- login limiter saturation;
- limiter before Argon2;
- large body/wrong content type;
- generic errors;
- health exposes only ManagementHealth.

Include a DNS-rebinding-style Host mismatch case.

## 12. Acceptance criteria

M003 closes only when:

1. login/session/logout/health routes work over real EggServe;
2. opaque session cookie policy is correct;
3. Host validation is universal;
4. Origin validation covers unsafe methods;
5. CSRF is independently enforced;
6. login rate limiting precedes Argon2;
7. no CORS trust is introduced;
8. security headers are centralized/tested;
9. non-loopback insecure HTTP is explicit opt-in only;
10. no Phase 8 CRUD route exists;
11. Rust/MSRV/all prior CI passes.

## 13. Stop conditions

Stop if forwarded headers become required for correctness, public/non-loopback mode cannot be made explicit without service-manager/install decisions, auth/session behavior requires a SPA/UI implementation, or a framework is proposed to solve only routing/header convenience.

## 14. Closure evidence

Record route/security matrix, cookie variants, Host/Origin/CSRF negative tests, limiter parameters/order, bind/origin profiles, security headers, dependency/MSRV, HTTP integration results, and M004 readiness.
