# Operator auth expansion M002 — TOTP second factor

Status: planned (hard dependency: M001 closed)

Repository baseline: set at M001 closure head when this plan becomes ready.

Source roadmap: `plans/subsystems/operator-auth-expansion-roadmap.md` M002

Canonical requirements and ADRs: ADR-012 §2.3; ADR-003; long-term spec §§19–20.

Primary work class: capability / secret handling

Hard dependencies: operator-auth-expansion M001 closed.

## Objective

Match wg-easy’s TOTP account flow: enroll with QR + verify code, require TOTP on password login when enabled, and disable with the documented authenticator proof.

## Explicit non-goals

- No WebAuthn/passkeys.
- No OIDC (M003).
- No SMS OTP.
- No third-party QR CDN; reuse local SVG QR approach already used for client configs where practical, or an equivalent first-party renderer.

## Current repository evidence

- After M001: account settings page and password-change API exist.
- Login is single-step username/password → session.

## Invariants

- TOTP secret stored encrypted-at-rest or as raw secret bytes with the same redaction discipline as other secrets; never in summaries/audit/logs.
- Enablement requires a successful verification code against the pending secret.
- When TOTP is enabled, password login returns a short-lived **pre-session** (or challenge token) that can only complete TOTP; it is not a product session.
- Pre-sessions expire quickly (≤ 5 minutes), are single-use, digest-stored, and rate-limited.
- Disable: with password auth enabled, require current password (+ optional TOTP); document exact shape in closure.

## Expected production changes

1. Schema: TOTP secret + enabled flag on `admin_principals` (or side table); pre-session table.
2. Account API: begin enroll (returns otpauth URI + local QR), confirm enroll, disable.
3. Login flow: password success → if TOTP enabled, challenge; `POST` verify → normal session.
4. Account UI controls mirroring wg-easy’s enable/configure/disable steps.
5. Audit: `admin_totp_enabled`, `admin_totp_disabled` without secrets.

## Ordered work packages

1. Migration + store APIs for TOTP and pre-sessions.
2. Worker login split + account enroll/disable commands.
3. HTTP routes; limiter before TOTP verify.
4. UI; tests; docs after land.

## Privilege and security effects

Unprivileged. Brute-force on TOTP codes must be rate-limited before verification work. Failed codes do not mint sessions.

## Persistence, protocol, and configuration compatibility

Additive migration; DesiredGeneration unchanged. Old clients without TOTP UI still work for principals that have not enabled TOTP; principals with TOTP enabled cannot finish login on an old UI (acceptable: assets ship with binary).

## Failure, cancellation, restart, and contention

- Restart mid-enroll: pending secret discarded or expired; enabled flag unchanged until confirm.
- Clock skew: document ±1 step window; no NTP detection (same posture as client expiry).

## Focused tests

- Enroll → confirm → login requires TOTP; wrong code fails; correct code issues session.
- Disable restores password-only login.
- Pre-session expiry and single-use.
- Secret absent from account GET JSON and audit.

## Linux and network-namespace integration evidence

None.

## Broad verification commands

Ordinary `docs/development.md` gates.

## Documentation updates

`architecture/authentication.md`; operations runbook account/2FA section.

## Acceptance criteria

1. Operator can enable and disable TOTP from the account page.
2. Enabled TOTP gates password login.
3. No TOTP secret leaves the server except the one-time enroll display.

## Stop conditions

- Product session minted before TOTP success when TOTP is enabled.
- Secret logged or returned on ordinary account GET.

## Closure evidence requirements

Per `plans/003-planning-process.md` §6.
