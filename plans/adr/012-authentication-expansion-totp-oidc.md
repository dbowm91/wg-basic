# ADR-012 — Authentication expansion (account settings, TOTP, OIDC/OAuth)

Status: accepted

Date: 2026-11-16

Canonical references:

- `plans/000-long-term-specification.md` §§3, 19–20 (optional later identity; security model)
- `plans/001-terminology-and-domain-model.md` (administrator principal)
- `plans/002-long-term-roadmap.md` §14 Phase 12
- `plans/adr/003-management-http-auth-and-worker-boundary.md` (amended by this ADR for identity expansion only)
- `plans/003-planning-process.md`

Maintainer decisions recorded 2026-11-16:

1. Aim for **auth parity with wg-easy** (account password change, TOTP, Google, GitHub, generic OIDC).
2. Auto-registration follows **wg-easy behavior with an allow-list** (domain allow-list; auto-created principals are full administrators until a later RBAC milestone exists).
3. **Password authentication may be disabled** only after at least one administrator is successfully linked to an external IdP, with **CLI recovery** documented and implemented.

## 1. Context

Phase 7 shipped a single local administrator, Argon2id verifiers, opaque digest-only sessions, Host/Origin/CSRF perimeter, and CLI-only password bootstrap/reset. Architecture guards forbid OAuth/OpenID/JWT session crates. Operator-parity deferred TOTP/OIDC/browser password change to an auth review.

wg-easy exposes:

- Account password change and TOTP enroll/verify/disable;
- OAuth providers `google`, `github`, and generic `oidc` (PKCE, `openid email profile`, `client_secret_post`);
- `OAUTH_AUTO_REGISTER`, `OAUTH_ALLOWED_DOMAINS`, `OAUTH_AUTO_LAUNCH`, `DISABLE_PASSWORD_AUTH`;
- Redirect URIs for login callback and account linking.

wg-basic must gain equivalent operator capability without abandoning: CLI break-glass, revocable server-side sessions, no unauthenticated admin bootstrap, and privilege separation.

## 2. Decision

### 2.1 Local password remains the recovery root

- `wg-basic admin set-password --password-stdin` continues to create or reset a local administrator and revokes every session.
- A new CLI recovery path MUST be able to re-enable password authentication and clear or reset IdP-only lockout without the HTTP surface.
- Unauthenticated HTTP MUST NOT create the first administrator.

### 2.2 Account settings over HTTP (session-authenticated)

After login, the operator MAY:

- change their own password (current password + new password; success revokes other sessions for that principal, or all sessions — milestone chooses the stricter of “all sessions for principal” and MUST document it);
- enroll, verify, and disable TOTP.

Password change and TOTP mutations use the existing Host + Origin + CSRF rules.

### 2.3 TOTP second factor

- TOTP secrets are stored only for principals that enroll; raw secrets never appear in summaries, audit rows, logs, or telemetry.
- Login becomes a two-step flow when TOTP is enabled: password (or IdP) success yields a short-lived, single-use **pre-session** challenge that can only complete TOTP verification into a normal session.
- Disable requires current password when password auth is enabled; when password auth is disabled, disable requires a valid TOTP code plus an authenticated session, or CLI recovery.

### 2.4 External identity (OIDC/OAuth)

- Supported providers for parity: **generic OIDC**, **Google**, **GitHub**.
- Provider configuration is **durable product/auth settings in SQLite** (appliance authority), editable by an authenticated administrator API and/or CLI. Environment variables are not the authoritative store.
- Authorization Code + **PKCE** is required. Default scopes: `openid email profile`. Token endpoint auth: `client_secret_post` for generic OIDC (wg-easy parity).
- Client secrets are secret-bearing store fields: redacted in projections, absent from logs/audit detail, exported only through explicit admin read-of-own-config paths that the milestone bounds.
- Callback and link routes live under a closed prefix (for example `/api/v1/auth/<provider>/callback` and `.../link`). They are the only routes allowed to complete an external login.

### 2.5 Cookie and Origin carveout (narrow)

ADR-003's session cookie profile (`HttpOnly`, `SameSite=Strict`, path `/`, no `Domain`, `Secure` from origin policy) remains the default for product sessions.

External login requires a **narrow carveout**:

- IdP redirects are cross-site GETs. The callback MAY set a one-shot **login completion** cookie with `SameSite=Lax` (or complete via a same-origin intermediate POST that upgrades to the normal Strict session cookie). Product API cookies stay Strict.
- Canonical **external HTTPS origin** is required when any external provider is enabled. Loopback-only demos may refuse to enable providers.
- CSRF for ordinary unsafe product routes is unchanged. OAuth `state` (+ PKCE `code_verifier`) binds the callback; it is not a substitute for product CSRF.

### 2.6 Auto-register and allow-list (wg-easy-aligned)

- `auto_register` defaults to **false**.
- When true, a successful IdP login whose email is not yet linked MAY create a new `admin_principals` row. Until RBAC exists, that principal is a **full administrator** (same capability as the local admin). Document the risk the way wg-easy does.
- `allowed_domains` restricts which email domains may log in or auto-register. When the list is non-empty, emails outside it are refused. When empty and auto-register is true, any IdP email may create an admin — operators MUST set domains for production.
- Linking an IdP identity to an existing principal is allowed when emails match, independent of auto-register (wg-easy parity).

### 2.7 Disable password authentication

- Password login MAY be disabled only when **at least one enabled administrator has a linked external identity** that has successfully completed a login or link flow.
- Attempting to disable password auth without that precondition returns a conflict and changes nothing.
- With password auth disabled, the login page offers only configured providers (and optional auto-launch).
- CLI recovery MUST re-enable password auth and set a password without requiring HTTP.

### 2.8 Multi-principal without RBAC

- Schema already keys `admin_principals`. This expansion MAY create multiple full-admin principals via allow-listed auto-register or explicit admin creation.
- Fine-grained RBAC remains a later Phase 12 candidate and is **out of scope** for the auth-expansion roadmap.

### 2.9 Dependencies and architecture guards

- A reviewed OIDC client dependency (and only what it needs for ID-token/userinfo verification) MAY be added.
- JWT libraries remain forbidden as a **session** mechanism. Architecture guards MUST be rewritten to forbid session JWTs / OAuth-session middleware while allowing the explicit OIDC login client.
- No Tower session middleware, no PASOTO/JWT cookie sessions, no unauthenticated bootstrap.

## 3. Alternatives considered

| Alternative | Why rejected |
|---|---|
| Env-var-only provider config like wg-easy | Conflicts with SQLite as authoritative appliance state and complicates backup/restore. |
| Replace opaque sessions with IdP JWTs | Breaks immediate revocation and password-reset semantics; contradicts ADR-003. |
| Defer Google/GitHub; ship generic OIDC only | Rejected by the maintainer parity decision; sequence still lands generic OIDC before branded providers. |
| Forbid auto-register entirely | Rejected; maintainer chose wg-easy-aligned allow-list behavior. |
| SPA/auth.js SDK from a CDN | Conflicts with embedded self-contained UI and “no third-party assets where able.” |

## 4. Consequences

Positive:

- Operators can match wg-easy’s identity workflows behind the existing reverse-proxy HTTPS origin model.
- CLI break-glass and digest sessions remain.
- Allow-list makes auto-register operable without pretending RBAC exists.

Costs:

- Auth surface and schema grow (TOTP, IdP links, pre-sessions, provider settings).
- Architecture guards and ADR-003 perimeter text need coordinated amendment.
- Enabling IdP forces HTTPS external origin; local demo stays password-oriented.
- Auto-register still creates full admins; operators must treat domain allow-list as load-bearing.

## 5. Compatibility and migration

- Additive schema migrations only; DesiredGeneration does not advance for auth-only tables.
- Existing single-admin deployments keep working with password-only login until the operator configures more.
- Old binaries refuse newer schema heads (existing opener rule).

## 6. Ownership

Subsystem roadmap: `plans/subsystems/operator-auth-expansion-roadmap.md`.
