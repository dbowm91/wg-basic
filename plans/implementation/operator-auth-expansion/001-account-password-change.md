# Operator auth expansion M001 — Account settings and browser password change

Status: **ready**

Repository baseline: `0119227ae2849937a8921016fb42984838634e15`

Source roadmap: `plans/subsystems/operator-auth-expansion-roadmap.md` M001

Canonical requirements and ADRs:

- `plans/adr/012-authentication-expansion-totp-oidc.md` §2.1–2.2
- `plans/adr/003-management-http-auth-and-worker-boundary.md`
- `plans/000-long-term-specification.md` §§19–20

Primary work class: capability

Hard dependencies: ADR-012 accepted (done). No prior auth-expansion milestone.

## Objective

Give a signed-in administrator an account settings surface that can change their password over HTTP with the same Argon2id policy as CLI bootstrap, revoke sessions appropriately, and leave a clear place for M002 TOTP controls.

## Explicit non-goals

- No TOTP, OIDC, auto-register, or password-auth disable.
- No unauthenticated password reset email/flow.
- No multi-admin invite UI beyond showing the current principal.
- No CDN/auth widgets.

## Current repository evidence

- Password set/reset only via `wg-basic admin set-password --password-stdin`.
- `POST /api/v1/login` issues sessions; no `PATCH` password route.
- Embedded UI has login + product pages; no account section.

## Invariants

- Current password must verify before a change commits.
- New password obeys existing length policy (12–1024 UTF-8 bytes) and Argon2id parameters.
- On success, revoke **all sessions for that principal** except optionally the completing session (milestone SHOULD keep the current session and revoke siblings; document the choice in closure).
- Host + Origin + CSRF required.
- No password material in audit detail or logs.

## Expected production changes

1. Authenticated account read (safe GET) returning username, whether password auth is enabled (always true until M004), and placeholders for later TOTP/IdP flags (false/absent).
2. Authenticated password-change mutation (unsafe) with current + new password JSON, 8 KiB body ceiling.
3. Embedded account UI: entry from the top bar, form, success/failure banners.
4. Audit event `admin_password_changed` (principal id only).

## Ordered work packages

1. Worker commands + store method to verify current verifier and replace it.
2. HTTP routes + CSRF/session wiring.
3. Embedded account page section and navigation.
4. Focused tests; architecture docs after land.

## Privilege and security effects

Unprivileged only. Failed current-password attempts spend the same login-style limiter or a dedicated account-mutation limiter before Argon2 (prefer reusing login limiter peer map or an account limiter — pick one and test flood behavior).

## Persistence, protocol, and configuration compatibility

No schema required if verifier update fits existing `admin_principals` columns. Additive API only.

## Failure, cancellation, restart, and contention

- Wrong current password: `401`/`403` opaque failure; no oracle on policy details beyond existing login practice.
- Concurrent changes: last writer wins; both revoke sessions.
- Restart: new verifier remains; revoked sessions stay revoked.

## Focused tests

- Change succeeds with correct current password; old password fails login; sibling session cookie rejected.
- Wrong current password changes nothing.
- CSRF/Origin missing → refuse.
- Unauthenticated → refuse.
- Audit row has no secret fields.

## Linux and network-namespace integration evidence

None. Unprivileged HTTP/state only.

## Broad verification commands

Ordinary gates in `docs/development.md` (`fmt`, `check`, `clippy`, `test`, MSRV). No rootful suites.

## Documentation updates

After land: `architecture/authentication.md`, brief operator note in `docs/operations-runbook.md` that browser password change exists and CLI reset still revokes all sessions.

## Acceptance criteria

1. Signed-in admin can change password in the UI and via API.
2. Old password cannot mint new sessions; sibling sessions die per the documented revoke rule.
3. CLI `admin set-password` still works and remains the break-glass path.

## Stop conditions

- Any design that stores a plaintext password or returns the new password in JSON.
- Unauthenticated reset endpoint.

## Closure evidence requirements

Requirement-to-evidence matrix, exact test commands, confirmation architecture docs match shipped behavior, disposition.
