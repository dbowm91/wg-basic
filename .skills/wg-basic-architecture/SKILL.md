---
name: wg-basic-architecture
description: "Navigate wg-basic's architecture docs and invariants: overview as index, per-component deep dives, planning authority, current-vs-planned rule, privilege-separation and state-authority invariants every change must preserve. Triggers: wg-basic architecture, where is, how does X work, add feature, modify netd/serve/state, planning, which doc."
---

# wg-basic architecture navigation

## Start here

`architecture/overview.md` is the bird's-eye view **and the index**: ASCII
privilege-domain diagram, the two load-bearing invariants, a
module-to-deep-dive table, and operator capabilities. Every discrete
module has its own deep dive in `architecture/`:

| Area | Deep dive |
|---|---|
| Value types, generations, owner tags | `domain-model.md` |
| SQLite store, migrations, leases | `state-store.md` |
| UDS protocol, peer auth | `privilege-boundary.md` |
| WireGuard backend (Generic Netlink) | `wireguard-control.md` |
| IPv4 policy, nft boundary | `firewall.md` |
| RTNETLINK lifecycle, receipts | `reconciliation.md` |
| Ownership proof, aggregate rules | `ownership.md` |
| Runtime, HTTP boundary, lifecycle | `startup-recovery.md`, `management-http.md` |
| Credentials, sessions, CSRF | `authentication.md` |
| Product API, enrollment, UI | `product-management.md` |
| Doctor, events, maintenance ops | `diagnostics-maintenance.md` |
| All CLI roles and contracts | `cli-roles.md` |
| Suites, rootful fixtures, guards | `testing-qualification.md` |
| systemd profile (recommended, not shipped) | `service-hardening.md` |
| Update transaction (contract only) | `update-rollback-contract.md` |

## Invariants no change may break

- **State authority.** SQLite desired state is authoritative; kernel
  state is derivative. Startup reconciles unconditionally. A late
  receipt must never mark a newer generation converged.
- **Privilege separation.** Only unprivileged `serve` opens the
  database (`netd` is database-free). Only `netd` touches the kernel,
  through typed operations only. No shell, no generic exec, no raw
  netlink/file/sysctl/nft-string execution anywhere in the protocol.
- **Enforced by tests.** `tests/architecture_guards.rs` pins these as
  static source-text assertions; a change that trips a guard is wrong
  until proven otherwise.

## Planning authority (read before implementing)

1. `plans/registry.md` — control surface, milestone order, and the
   current ready/active/blocked implementation plans.
2. `plans/003-planning-process.md` — handoff/closure rules.
3. Subsystem roadmap under `plans/subsystems/`, then the milestone
   implementation plan, then current repository evidence.

## Documentation rules

- Current behavior docs stay factual; planned behavior belongs in
  `plans/`, never in `architecture/` or `docs/` as if shipped.
- Installation, transactional self-update, and state-preserving uninstall
  are implemented and technically qualified under Phase 10. Production
  release/update authority remains blocked until the maintainer provisions
  the trust root, signs a draft, and authorizes publication.
- Operator procedures: `docs/development.md` (gates, local
  netd/serve, fixtures), `docs/operations-runbook.md`,
  `docs/state-backup-restore.md`, `docs/client-enrollment.md`.
- `README.md` is the operator entry point; keep it a summary, not a
  second manual.
