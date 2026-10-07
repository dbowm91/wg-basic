# Management Service M002 — Local Administrator and Session Persistence

Status: closed. See `plans/closure/management-service/002-status.md`.

Source roadmap:

- `plans/subsystems/management-service-security-roadmap.md#6-m002--local-administrator-and-session-persistence`

Canonical requirement:

- `plans/adr/003-management-http-auth-and-worker-boundary.md`

Primary class: security / persistence

Hard dependency: M001 strict closure — **satisfied** at `5b57d49`, closed 2026-10-07.

## 1. Objective

Add the persistent local-administrator and server-side session primitives that the M003 HTTP perimeter will consume.

M002 is the first real production schema upgrade after Phase 6.

## 2. Dependencies

Evaluate/currently prefer:

- `argon2` 0.6;
- `sha2` 0.11;
- direct CSPRNG support compatible with Rust 1.89.

Do not add JWT libraries.

Cookie parsing/serialization may wait until M003.

## 3. Domain types

Add typed/redacted:

- `PrincipalId`;
- `SessionId`;
- `SessionToken`;
- `CsrfToken`;
- `PasswordVerifier` or equivalent.

Raw password/session/CSRF values MUST redact Debug/Display.

## 4. Schema migration 2

Add a real `002_auth_sessions.sql` migration.

Expected tables:

### admin_principals

- principal ID primary key;
- unique username;
- Argon2 PHC verifier;
- enabled;
- created_at;
- updated_at.

Phase 7 supports one enabled local admin; schema may remain extensible.

### admin_sessions

- session ID primary key;
- principal ID FK;
- token_digest unique;
- CSRF token;
- created_at;
- expires_at.

Authentication/session changes MUST NOT modify `desired_generation`.

The existing migration runner must create a pre-migration recovery snapshot for a real v1 store.

## 5. Password policy

Use Argon2id.

Minimum parameters:

- memory 19 MiB;
- iterations 2;
- parallelism 1.

Store the PHC string so algorithm/parameters/salt are self-describing.

Password requirements:

- no arbitrary composition rules;
- minimum length appropriate to an administrator credential;
- explicit upper bound for input resource control;
- Unicode handled consistently as UTF-8 bytes;
- no silent truncation.

Credential failure must not expose whether username or password was wrong.

## 6. Local bootstrap/reset

Add a local operator command such as:

```text
wg-basic admin set-password --password-stdin
wg-basic admin status
```

Requirements:

- password never accepted as a CLI argument;
- no environment-variable password;
- stdin path requires explicit flag;
- password reset revokes all sessions;
- output never prints verifier/token.

A hidden TTY prompt may be added only if a small MSRV-compatible dependency is justified; it is not required for M002 closure.

## 7. Session issuance

On successful authentication:

1. generate 256-bit random session bearer token;
2. hash it with SHA-256;
3. generate 256-bit random CSRF token;
4. persist digest + CSRF + expiry;
5. return raw session token and CSRF to the trusted caller once.

Raw session token never enters SQLite.

Session lifetime is finite and bounded. No indefinite remember-me mode.

## 8. Session lookup/revocation

Provide worker/state operations:

- authenticate local principal;
- create session;
- resolve session token;
- revoke current session;
- revoke all principal sessions;
- remove/reject expired session.

Lookup hashes the presented bearer token before querying.

## 9. Worker integration

Extend the M001 internal worker with typed auth/session commands.

HTTP still does not gain routes in M002.

The worker owns Argon2 verification and auth/session DB calls. Queue remains bounded.

## 10. Tests

Required:

- real migration v1→v2 preserves InstallationId, DesiredGeneration, desired state, convergence state;
- pre-migration recovery snapshot contains v1 state;
- migration rollback/failure preserves original DB;
- Argon2 PHC round-trip and policy parameters;
- password hash never equals plaintext;
- session token digest stored, raw token absent;
- CSRF token redaction;
- expiry;
- logout/revoke;
- password reset revokes all sessions;
- auth/session operations do not advance DesiredGeneration;
- disabled principal fails;
- password/session values absent from Debug/errors.

## 11. Performance evidence

Record Argon2 verification latency and configured memory on CI.

If an ARM64/SBC runner is available, capture advisory evidence, but do not weaken the minimum security parameters merely to hit an arbitrary latency target.

Throttling is M003 and is required before browser login exposure.

## 12. Acceptance criteria

M002 closes only when:

1. production migration 2 exists and is qualified from v1;
2. Rust 1.89 passes with auth deps;
3. Argon2id policy is explicit;
4. raw passwords are never persisted;
5. raw session tokens are never persisted;
6. revocation/expiry works;
7. password reset revokes sessions;
8. DesiredGeneration is unchanged by auth/session writes;
9. worker owns auth/state operations;
10. no HTTP login route exists yet.

## 13. Stop conditions

Stop if an auth dependency raises MSRV above 1.89, migration would change Phase 6 desired-state semantics, session design starts requiring JWT/signing infrastructure, or password bootstrap requires argv/env secrets.

## 14. Closure evidence

Record dependency versions/MSRV, schema v2, real v1→v2 migration, Argon2 parameters/latency, session-token storage proof, DesiredGeneration invariance, CLI secret-input behavior, CI, and M003 readiness.
