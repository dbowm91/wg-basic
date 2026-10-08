# Repository guidance

- Follow the canonical requirements and milestone order in `plans/registry.md`, `plans/003-planning-process.md`, and the linked subsystem roadmap.
- Keep current behavior docs factual; planned behavior belongs in plans.
- Run the commands in `docs/development.md` for Rust changes.
- Do not add host-network mutation, generic process execution, or speculative architecture outside an active implementation plan.

## Architecture index

- `architecture/overview.md` is the bird's-eye view and the index; each discrete module has its own deep dive in `architecture/` (domain-model, state-store, privilege-boundary, wireguard-control, firewall, reconciliation, ownership, startup-recovery, management-http, authentication, product-management, diagnostics-maintenance, cli-roles, testing-qualification, service-hardening, update-rollback-contract).
- Load `.skills/wg-basic-architecture/SKILL.md` before changing `serve`/`netd`/state/protocol behavior; it lists the invariants (`tests/architecture_guards.rs` pins them) and the planning authority order.
- Load `.skills/wg-basic-gates/SKILL.md` before running tests; it has the gate order and the rootful `sudo`/`CARGO_HOME` invocation form. Never run rootful suites unprompted.

## Operator docs

- `README.md` is the operator entry point (summary only, not a second manual).
- Procedures live in `docs/development.md` (gates, local netd/serve, fixtures), `docs/operations-runbook.md`, `docs/state-backup-restore.md`, and `docs/client-enrollment.md`.
- Installation and transactional self-update are not implemented (Phase 10 planned, M001 ready); never document them as available.
