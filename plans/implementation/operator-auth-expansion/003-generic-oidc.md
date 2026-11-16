# Operator auth expansion M003 — Generic OIDC

Status: planned (hard dependency: M002 closed)

Repository baseline: set at M002 closure head when this plan becomes ready.

Source roadmap: `plans/subsystems/operator-auth-expansion-roadmap.md` M003

Canonical requirements and ADRs: ADR-012 §2.4–2.5, §2.9; ADR-003 (perimeter carveout).

Primary work class: capability / perimeter

Hard dependencies: operator-auth-expansion M002 closed.

## Objective

Enable a single **generic OIDC** provider (Authelia/Authentik-class) with PKCE, durable settings, authorize/callback/link routes, and a narrow cookie/origin carveout — without Google/GitHub helpers yet.

## Explicit non-goals

- No Google/GitHub convenience providers (M004).
- No auto-register, domain allow-list enforcement beyond storing the fields, or password-auth disable (M004 may add settings columns here if cleaner — prefer M004 for behavior).
- No JWT product sessions.
- No env-var authoritative config.

## Current repository evidence

- After M002: password + TOTP login works; account page exists.
- Architecture guard still forbids broad `oauth`/`openid` substrings until this milestone rewrites it.
- Canonical external origin already exists for reverse-proxy HTTPS deployments.

## Invariants

- OIDC may be enabled only when canonical external origin is HTTPS.
- Authorization Code + PKCE; scopes `openid email profile`; `client_secret_post`.
- Callback validates `state` and PKCE verifier; mints normal digest session (and still requires TOTP challenge if that principal has TOTP enabled — IdP satisfaction of first factor does not skip TOTP unless a later decision says otherwise; **default: still require TOTP when enabled**).
- Link route requires an existing authenticated session.
- Client secret redacted in ordinary reads; never logged.
- Rewrite architecture guard: forbid JWT/session-oauth middleware; allow the chosen OIDC client crate by explicit allowlist comment/test.

## Expected production changes

1. Schema: provider settings (issuer, client id, secret, display name, enabled), IdP subject link table (principal id, issuer, subject, email).
2. Admin API to read/update generic OIDC settings (CSRF).
3. Routes: start login, callback, start link, link callback under `/api/v1/auth/oidc/...`.
4. Login page button when enabled.
5. Dependency addition + guard rewrite.
6. Fake OIDC fixture for CI.

## Ordered work packages

1. ADR-012 carveout implementation sketch in HTTP service (Lax one-shot vs same-origin POST completion) — pick one, test both success and that product cookies stay Strict.
2. Store + worker.
3. Routes + login UI affordance.
4. Guard rewrite + tests + docs.

## Privilege and security effects

Unprivileged. Callback is unauthenticated by session but bound by state/PKCE. Separate limiter for auth callbacks. No `netd` involvement.

## Persistence, protocol, and configuration compatibility

Additive migrations. Backup/restore includes provider secrets — document sensitivity in state backup docs after land.

## Failure, cancellation, restart, and contention

- Provider down / invalid token: fail closed; no session.
- Restart mid-flow: in-flight PKCE state lost; user retries.
- Clock skew on ID token `exp`: refuse.

## Focused tests

- Happy path against fake OIDC: login creates/links session.
- Bad state / bad code → no session.
- Enable refused on non-HTTPS external origin.
- Product unsafe route still requires Strict session + CSRF.
- Guard test updated and still forbids `jsonwebtoken` session usage patterns.

## Linux and network-namespace integration evidence

None.

## Broad verification commands

Ordinary gates; no rootful.

## Documentation updates

`architecture/authentication.md`, `architecture/management-http.md` (carveout), operations runbook IdP setup (redirect URIs).

## Acceptance criteria

1. Operator can configure generic OIDC and log in via it when HTTPS origin is set.
2. Existing password/TOTP paths still work.
3. Architecture guards reflect the new dependency policy.

## Stop conditions

- Session JWT as the product credential.
- Enabling OIDC on loopback HTTP external origin.
- Applying `SameSite=Lax` to ordinary product session cookies.

## Closure evidence requirements

Per planning process §6, including explicit carveout description and fake-OIDC test commands.
