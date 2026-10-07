# Management Service and Security Substrate Roadmap

Status: planned; M001 ready

Canonical references:

- `plans/000-long-term-specification.md`
- `plans/001-terminology-and-domain-model.md`
- `plans/002-long-term-roadmap.md`
- `plans/003-planning-process.md`
- `plans/adr/001-linux-native-control-plane.md`
- `plans/adr/002-durable-state-generations-and-ownership.md`
- `plans/adr/003-management-http-auth-and-worker-boundary.md`

Predecessor closure:

- network-control M001–M005 + C001 closed;
- durable-state M001–M004 + post-Phase-6 C001 closed.

## 1. Purpose

Phase 7 creates the unprivileged management-service/security substrate that Phase 8 will use for the actual wg-easy-like API/UI.

This subsystem owns:

- EggServe HTTP runtime integration;
- async-to-blocking management worker;
- local administrator credentials;
- server-side sessions;
- CSRF/origin/host security;
- authentication throttling;
- bind/external-origin policy;
- security headers;
- minimal embedded asset pipeline;
- process readiness/shutdown/supervision.

It does not own:

- peer/client CRUD HTTP API;
- QR/config export;
- first-run web wizard;
- OIDC/TOTP/RBAC;
- direct TLS/ACME;
- systemd/install/update;
- full management UI.

## 2. Core invariants

1. HTTP code never calls rusqlite directly.
2. HTTP code never gains CAP_NET_ADMIN or direct netlink/nft access.
3. netd remains database-free.
4. one bounded worker owns `ManagementRuntime`.
5. unauthenticated HTTP exposes no desired state, keys, IDs, generations, or backend diagnostics.
6. no unauthenticated browser bootstrap creates the administrator.
7. passwords are Argon2id hashes only.
8. raw session bearer tokens are never persisted.
9. every authenticated unsafe browser request requires session + Host + Origin + CSRF.
10. no wildcard CORS.
11. loopback is the default bind.
12. non-loopback insecure HTTP requires explicit unsafe acknowledgement.
13. application-auth throttling occurs before Argon2 work.
14. static assets are embedded and self-contained.
15. Phase 7 does not implement Phase 8 configuration CRUD.

## 3. Research conclusions

### EggServe

Adopt direct crates:

- `eggserve-server` 0.4.x;
- `eggserve-primitives` 0.2.x.

Do not adopt Tower/Axum unless M001 proves direct Service routing is insufficient.

Do not add `eggserve-static`; assets are embedded.

EggServe owns HTTP correctness/resource ceilings; wg-basic owns product routing/auth/security.

### Blocking boundary

Use one bounded Tokio MPSC queue plus one-shot replies to one dedicated OS thread owning `ManagementRuntime`.

This is preferable to one `spawn_blocking` per request because SQLite/netd ordering remains explicit and queue growth is bounded.

### Auth dependencies

Current versions compatible with Rust 1.89:

- RustCrypto `argon2` 0.6;
- RustCrypto `sha2` 0.11;
- `cookie` 0.18.1.

### Browser policy

Host allowlisting + exact Origin + synchronizer CSRF are mandatory. SameSite=Strict is additional defense, not the sole CSRF mechanism.

## 4. Dependency graph

```text
Phase 6 + post-Phase-6 C001 closed
              |
              v
M001 — EggServe runtime + bounded management worker
              |
              v
M002 — local admin credentials + sessions + real schema v2
              |
              v
M003 — authenticated HTTP perimeter
       Host/Origin/CSRF/cookies/rate limits
              |
              v
M004 — embedded shell + lifecycle + Phase 7 E2E qualification
```

All dependencies are hard.

## 5. M001 — EggServe runtime and bounded management worker

Status: ready.

Plan:

- `plans/implementation/management-service/001-eggserve-runtime-and-management-worker.md`

Objective:

Turn `wg-basic serve` into a real loopback HTTP service without adding authentication-sensitive endpoints yet.

Expected outcomes:

- direct EggServe dependencies;
- bounded worker thread owning `ManagementRuntime`;
- typed worker command/reply contract;
- startup reconciliation attempted before readiness;
- degraded-but-running HTTP state for netd/conflict failures;
- fatal startup for DB/path/migration failure;
- `GET /healthz` minimal endpoint;
- exact small router;
- bounded request bodies/queue/timeouts;
- clean HTTP + worker shutdown;
- no state mutation endpoint.

## 6. M002 — Local administrator and session persistence

Status: blocked on M001.

Plan:

- `plans/implementation/management-service/002-local-admin-and-session-persistence.md`

Objective:

Add credential/session primitives entirely behind the management worker/state authority.

Expected outcomes:

- real schema migration 1→2;
- stable `PrincipalId`/`SessionId`;
- Argon2id credential storage/verification;
- 256-bit opaque session tokens with SHA-256 digest persistence;
- CSRF token per session;
- finite expiry;
- password reset revokes all sessions;
- local CLI bootstrap/reset using stdin, never argv/env;
- actual historical migration fixture over the production v1 schema.

## 7. M003 — Authenticated HTTP perimeter

Status: blocked on M002.

Plan:

- `plans/implementation/management-service/003-authenticated-http-security-perimeter.md`

Objective:

Expose the minimal browser authentication/session/health API with the complete security envelope.

Expected outcomes:

- login/logout/session/health routes;
- exact Host allowlist;
- canonical Origin validation;
- synchronizer CSRF;
- SameSite/HttpOnly host-only cookies;
- Secure + __Host cookie under HTTPS external origin;
- no CORS;
- login throttling before Argon2;
- generic auth failures;
- security headers;
- loopback default bind;
- explicit non-loopback/insecure override policy;
- no peer/client CRUD.

## 8. M004 — Embedded shell, process lifecycle, and Phase 7 qualification

Status: blocked on M003.

Plan:

- `plans/implementation/management-service/004-service-lifecycle-and-phase7-qualification.md`

Objective:

Close Phase 7 as a production-credible service substrate without prematurely implementing Phase 8 UI/product APIs.

Expected outcomes:

- minimal embedded self-contained HTML/CSS shell;
- no filesystem asset root or external fonts/scripts;
- serve role owns EggServe + worker lifecycle;
- graceful signal shutdown;
- HTTP service restart preserves sessions until expiry/revocation;
- password reset invalidates old sessions;
- queue/body/rate-limit saturation evidence;
- real HTTP integration against real state + netd;
- current rootful network/durable suites remain green.

## 9. Schema direction

M002 owns migration 2.

Expected tables:

```text
admin_principals
admin_sessions
```

`admin_principals` should include:

- principal id;
- unique username;
- Argon2 PHC verifier;
- enabled/disabled;
- created/updated times.

`admin_sessions` should include:

- session id;
- principal id;
- session-token SHA-256 digest;
- secret CSRF token;
- created time;
- absolute expiry.

Do not store raw bearer session tokens.

Do not put auth data in the desired-generation tables: authentication/session mutation does not represent desired kernel state and MUST NOT advance `DesiredGeneration`.

## 10. Worker command boundary

The bounded worker evolves additively.

Candidate internal commands:

```text
Health
Authenticate
ResolveSession
Logout
SetPassword
Shutdown
```

Phase 8 later adds typed desired-state operations.

The worker command enum is internal, not a public network protocol.

No worker command accepts SQL or raw netd operations.

## 11. HTTP routing policy

Phase 7 routes remain explicit and small.

Unknown methods/paths return generic 404/405.

Request bodies are buffered only under route-specific small limits.

No generic file upload/multipart parser is introduced.

No WebSocket/tunnel is accepted.

## 12. Bind/origin profiles

### Local default

- bind loopback;
- HTTP permitted;
- canonical origin printed explicitly;
- host-only HttpOnly SameSite=Strict session cookie.

### Reverse-proxy HTTPS

- wg-basic still binds loopback;
- operator configures external HTTPS origin;
- Host/Origin are checked against that origin;
- Secure + __Host session cookie;
- forwarded headers remain untrusted in Phase 7.

### Explicit insecure non-loopback

- must require explicit unsafe acknowledgement;
- never advertised as production-safe;
- startup warning;
- no Secure cookie claim.

## 13. Security headers

Application responses should include:

- strict CSP;
- frame-ancestors 'none';
- X-Frame-Options DENY;
- nosniff;
- Referrer-Policy no-referrer;
- restrictive Permissions-Policy;
- no-store for auth/session/API responses.

HSTS only for HTTPS external origin.

## 14. Error/privacy policy

HTTP errors expose stable categories/status codes, not:

- SQL errors;
- filesystem paths;
- protocol receipts;
- netlink errors;
- password/session/CSRF values.

Detailed diagnostics stay in sanitized logs/operator surfaces.

## 15. Test strategy

Progressive evidence:

```text
unit routing/security primitives
 -> HTTP service integration over loopback
 -> real schema v1→v2 migration
 -> auth/session restart tests
 -> Host/Origin/CSRF negative matrix
 -> throttling/saturation tests
 -> real serve + management worker + netd/state integration
 -> regression of all existing rootful suites
```

## 16. Risks

- Argon2 can become a CPU/latency DoS if throttling is applied after hashing; M003 forbids that ordering.
- reverse-proxy deployments can tempt trust in spoofable forwarded headers; Phase 7 does not consume them.
- direct loopback HTTP cannot provide HTTPS cookie guarantees; docs must state the boundary plainly.
- worker queue saturation must not block EggServe tasks indefinitely.
- auth/session state is a real schema migration and must not advance DesiredGeneration.

## 17. Milestone status

| Milestone | Status | Plan | Blocker |
|---|---|---|---|
| M001 EggServe + management worker | ready | `plans/implementation/management-service/001-eggserve-runtime-and-management-worker.md` | — |
| M002 admin/session persistence | blocked | `plans/implementation/management-service/002-local-admin-and-session-persistence.md` | M001 |
| M003 authenticated HTTP perimeter | blocked | `plans/implementation/management-service/003-authenticated-http-security-perimeter.md` | M002 |
| M004 lifecycle + Phase 7 qualification | blocked | `plans/implementation/management-service/004-service-lifecycle-and-phase7-qualification.md` | M003 |
