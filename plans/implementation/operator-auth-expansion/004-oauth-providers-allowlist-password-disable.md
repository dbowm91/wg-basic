# Operator auth expansion M004 — Google/GitHub, allow-list auto-register, password disable

Status: implemented (pending closure evidence)

Repository baseline: set at M003 closure head when this plan becomes ready.

Source roadmap: `plans/subsystems/operator-auth-expansion-roadmap.md` M004

Canonical requirements and ADRs: ADR-012 §2.6–2.8; maintainer decisions 2026-11-16.

Primary work class: capability

Hard dependencies: operator-auth-expansion M003 closed.

## Objective

Complete wg-easy auth parity: **Google** and **GitHub** providers, **auto-register with domain allow-list**, optional **auto-launch**, and **disable password authentication** with **CLI recovery**.

## Explicit non-goals

- No RBAC (all auto-registered users are full admins — document risk).
- No SCIM.
- No generic OAuth1/non-OIDC providers beyond Google/GitHub as implemented against their OAuth/OIDC surfaces.

## Current repository evidence

- After M003: generic OIDC login/link works; settings and subject-link tables exist.

## Invariants

- `auto_register` default false.
- Non-empty `allowed_domains`: emails outside the list cannot login or register via IdP.
- Empty domains + auto_register true: any IdP email may create a full admin (wg-easy-aligned; operations docs MUST warn).
- Auto-register creates `admin_principals` rows that are full administrators.
- Password auth disable requires ≥1 enabled principal with a successfully linked external identity; otherwise conflict/no-op.
- CLI recovery re-enables password auth and sets a password (stdin), revoking sessions as with today’s reset.
- Linking by matching email to an existing principal works even when auto_register is false (wg-easy parity).

## Expected production changes

1. Provider settings for `google` and `github` (client id/secret, enabled) alongside generic OIDC.
2. Settings: `auto_register`, `allowed_domains`, `auto_launch` provider key, `password_auth_enabled`.
3. Login page: provider buttons; optional auto-redirect with escape (`?auto_launch=false` or equivalent).
4. Authenticated admin API to toggle password auth (CSRF) with precondition check.
5. CLI: `admin` subcommands for re-enable password auth + set-password (may extend existing set-password to imply re-enable).
6. Audit events for auto-register, link, password-auth toggled.

## Ordered work packages

1. Schema/settings fields + domain matching helper (case-insensitive domain compare).
2. Google/GitHub auth adapters reusing M003 PKCE/callback machinery.
3. Auto-register + allow-list enforcement on callback.
4. Password disable API + CLI recovery.
5. UI + docs + tests.

## Privilege and security effects

Unprivileged. Auto-register is the highest risk control; defaults off; docs stress allow-list.

## Persistence, protocol, and configuration compatibility

Additive. Existing single-admin password deployments unchanged until settings flip.

## Failure, cancellation, restart, and contention

- Disable password with no linked IdP: refuse.
- All IdPs disabled while password disabled: CLI recovery only — HTTP login shows recovery guidance without creating a bootstrap hole.
- Domain list parse errors: refuse settings save.

## Focused tests

- Auto-register off: unknown email cannot create principal.
- Auto-register on + allow-list: matching domain creates admin; other domain refused.
- Link existing email without auto-register.
- Password disable precondition true/false.
- CLI re-enable + set-password restores password login.
- Google/GitHub happy paths against fakes.

## Linux and network-namespace integration evidence

None.

## Broad verification commands

Ordinary gates.

## Documentation updates

Operations runbook: IdP setup, redirect URIs, allow-list, password disable risks, CLI recovery. `architecture/authentication.md`.

## Acceptance criteria

1. Google, GitHub, and generic OIDC can be enabled independently.
2. Allow-listed auto-register matches wg-easy’s safety story (default off, domains recommended).
3. Password auth can be disabled only after IdP link success, and CLI can recover.

## Stop conditions

- Leaving password auth disabled with no CLI recovery path.
- Auto-register defaulting to true.
- Creating non-admin principals without an RBAC design (do not invent half-RBAC).

## Closure evidence requirements

Per planning process §6; include CLI recovery demonstration commands.
