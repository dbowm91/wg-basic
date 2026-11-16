# Operator auth expansion roadmap

Status: planned 2026-11-16. Phase 12 workstream. No implementation has landed.

Date: 2026-11-16

Repository baseline: `0119227ae2849937a8921016fb42984838634e15` (`main` tip at planning time; S001 closed).

Canonical references:

- `plans/000-long-term-specification.md` §§3, 19–20
- `plans/001-terminology-and-domain-model.md`
- `plans/002-long-term-roadmap.md` §14
- `plans/003-planning-process.md`
- `plans/adr/003-management-http-auth-and-worker-boundary.md`
- `plans/adr/012-authentication-expansion-totp-oidc.md`

Related work this roadmap does not own:

- Fine-grained multi-admin RBAC (still a later Phase 12 candidate).
- Prometheus, JSON metrics, sparkline history (`plans/subsystems/observability-metrics-roadmap.md`).
- General UI polish and theme switcher (`plans/subsystems/operator-ui-polish-roadmap.md`), except account/login views required by auth milestones.
- macOS/Windows release claims.

## 1. Purpose

Bring administrator authentication to **wg-easy parity** under ADR-012: browser password change, TOTP, generic OIDC, Google/GitHub, allow-listed auto-register, and password-auth disable with CLI recovery — without replacing opaque sessions or CLI break-glass.

## 2. Ownership boundary

Owns:

- account settings HTTP API and embedded account UI;
- TOTP enroll/challenge/disable;
- durable IdP provider settings and client secrets;
- OAuth/OIDC authorize, callback, and link routes;
- allow-listed auto-register of full-admin principals;
- password-auth enable/disable gates;
- CLI recovery for password re-enable / lockout break-glass;
- architecture-guard rewrite for “no JWT sessions; OIDC client allowed.”

Does not own:

- RBAC roles beyond “full administrator”;
- metrics Bearer secrets;
- theme switcher or chart widgets;
- changing Argon2id parameters except where TOTP/IdP storage needs adjacent columns.

## 3. Invariants

1. Unauthenticated HTTP never creates the first administrator.
2. Sessions remain opaque server-side digests; password reset / CLI set-password still revokes sessions as today (extended to all principals when that is the operation’s scope).
3. Host + Origin + CSRF remain required for ordinary unsafe product and account mutations.
4. IdP enablement requires a configured canonical external HTTPS origin.
5. Password auth disable requires at least one enabled principal with a successfully linked external identity.
6. TOTP secrets, OIDC client secrets, and raw session tokens never appear in summaries, audit detail, logs, or telemetry.
7. Auto-register creates full administrators only; non-empty `allowed_domains` is the production control.
8. No privileged protocol widening; `netd` stays out of auth.

## 4. Current repository evidence

- Single local admin via `admin_principals` / `admin_sessions` (schema 2); Phase 7/8 closed.
- `POST /api/v1/login`, logout, session; CLI `admin set-password` / `admin status`.
- Architecture guard `the_management_surface_ships_no_token_or_oauth_dependency` forbids `oauth` / `openid` substrings in `Cargo.toml`.
- Embedded shell has login but no account page, TOTP, or IdP buttons.
- Schema head is version 10.

## 5. Dependency graph

```text
ADR-012 accepted
        |
        v
M001  account settings + browser password change     [ready]
        |
        v
M002  TOTP second factor                             [ready after M001]
        |
        v
M003  generic OIDC (PKCE) + perimeter carveout       [ready after M002]
        |
        v
M004  Google/GitHub, allow-list auto-register,
      password-auth disable + CLI recovery           [ready after M003]
```

M001 is ready for handoff. M002–M004 have hard predecessors as shown. RBAC is not on this graph.

## 6. Milestones

| Milestone | Class | Status | Plan |
|---|---|---|---|
| M001 account password change | capability | **ready** | `plans/implementation/operator-auth-expansion/001-account-password-change.md` |
| M002 TOTP | capability / secret handling | planned (hard: M001) | `plans/implementation/operator-auth-expansion/002-totp-second-factor.md` |
| M003 generic OIDC | capability / perimeter | planned (hard: M002) | `plans/implementation/operator-auth-expansion/003-generic-oidc.md` |
| M004 providers + allow-list + password disable | capability | planned (hard: M003) | `plans/implementation/operator-auth-expansion/004-oauth-providers-allowlist-password-disable.md` |

## 7. Cross-cutting concerns

- **Secrets.** TOTP and IdP client secrets use the same redaction discipline as WireGuard keys.
- **Audit.** Password change, TOTP set/clear, IdP link/unlink, auto-register, and password-auth toggle emit audit events without secret material.
- **Compatibility.** Additive migrations only; DesiredGeneration unchanged by auth tables.
- **UI budget.** Account/login controls may grow the embedded shell; UI polish roadmap raises ceilings. Auth milestones MUST NOT pull CDN scripts.
- **Failure.** Misconfigured IdP fails closed at login; CLI recovery remains.

## 8. Integration evidence

Auth milestones are unprivileged HTTP/state tests plus architecture-guard updates. No new rootful network topology. OIDC tests use a local fake authorization server or recorded fixture flows — not the public Internet in CI.

## 9. Deferred

| Item | Disposition |
|---|---|
| Fine-grained RBAC | Later Phase 12 candidate |
| Passkeys / WebAuthn | Out of wg-easy parity scope for this roadmap |
| Email magic links | Out of scope |
| SCIM / directory sync | Out of scope |

## 10. Risks

- Auto-register without domains creates unbounded admins — M004 docs and defaults must make domains load-bearing.
- Lax callback cookies mis-applied to product APIs — M003 stop condition.
- Password disable without CLI recovery boxes operators out — M004 acceptance requires the CLI path.
