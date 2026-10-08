# Operational Hardening M001 — Authoritative Doctor and Preflight

Status: ready

Repository baseline: `e8fd6b1212491576f3c6bdd7468591a97d5aaf3c`

Source roadmap:

- `plans/subsystems/operational-hardening-roadmap.md#5-m001--authoritative-doctor-and-preflight`

Canonical architecture:

- `plans/adr/005-operational-hardening-maintenance-and-recovery.md`

Primary class: operations / diagnostics / invariant

## 1. Objective

Replace the current capability-dump `doctor` with a read-only diagnostic report that explains whether the complete appliance can operate safely and what an operator should fix when it cannot.

Doctor must not mutate kernel or durable state.

## 2. CLI contract

Extend `wg-basic doctor` with:

- `--state <path>`;
- `--socket <path>`;
- `--json`;
- optional `--http-bind <addr>`;
- optional `--canonical-origin <origin>`;
- `--allow-non-loopback` with the same semantics as serve.

Use the same defaults as the runtime roles.

Human output is concise and ordered by check group. JSON output is one complete typed report and writes no extra prose to stdout.

## 3. Result model

Add typed `DoctorReport`, `DoctorCheck`, `DoctorDisposition::{Pass,Warn,Fail,Unknown}`, and stable `DoctorCheckId`.

Each check carries bounded summary, evidence, and remediation. Do not put arbitrary backend error strings into the report.

## 4. Exit behavior

Recommended:

- 0: all required checks pass;
- 1: warnings/unknowns require attention but no hard failure;
- 2: one or more required checks fail or invocation is invalid.

Document and test the exact behavior.

## 5. State diagnostics

When state exists, check without mutation:

- regular-file/no-symlink;
- expected owner/mode and parent safety;
- schema version/not-newer-than-binary;
- `PRAGMA quick_check`;
- foreign-key check;
- InstallationId and DesiredGeneration;
- convergence evidence;
- safe product snapshot validation;
- automatic recovery artifacts.

Do not initialize a DB from doctor.

## 6. SQLite runtime diagnostic

Report `sqlite_version()` and `sqlite_source_id()`.

Add a policy guard that the supported bundled runtime is not older than SQLite 3.51.3 because the WAL-reset bug affected WAL mode through 3.51.2.

At the baseline, locked `libsqlite3-sys` 0.38.2 contains SQLite 3.53.2.

Do not switch to system SQLite.

## 7. netd/capability diagnostics

Reuse typed local IPC.

Check:

- netd reachable/protocol accepted;
- effective UID/GID;
- CAP_NET_ADMIN;
- runtime-directory safety;
- kernel release/architecture;
- WireGuard Generic Netlink usable via read-only probe;
- RTNETLINK usable via bounded read-only observation;
- nftables usable via bounded `nft --version` plus read-only query in the existing process boundary.

No shell and no mutation.

## 8. Forwarding diagnostic

Read exactly `/proc/sys/net/ipv4/ip_forward`.

If desired product state requires forwarding and it is disabled, report failure/warning with remediation. Do not write it.

## 9. Ownership/drift diagnostic

When a managed server exists:

1. load desired state;
2. project current generation;
3. request `PlanInstallationNetworkIntent`;
4. never request Apply;
5. classify no-op, repairable owned drift, ownership conflict, or backend unavailable.

Repairable drift is a warning. Ownership conflict is a failure.

## 10. Interface/listen-port diagnostic

Use plan/observation for interface conflicts.

For UDP port conflicts, report only what can be proven read-only:

- owned active interface using the configured port: pass;
- another observed WireGuard interface demonstrably using it: fail;
- best-effort local bind may be used only when no managed interface is active and its limits are documented;
- ambiguity: Unknown.

Do not mutate an interface to test a port.

## 11. HTTP configuration diagnostic

When HTTP options are supplied, validate the same `ServeConfig` policy without binding:

- loopback/off-host acknowledgement;
- canonical origin syntax;
- Host/origin relationship;
- secure-cookie profile.

## 12. Service lease seam

M001 defines the check ID/rendering for service singleton state.

Until M002 implements the lease, report this check as Unknown/not available; do not claim uniqueness is enforced.

## 13. Remediation quality

Warnings/failures must state an actionable next step and never recommend deleting an unknown network resource automatically.

## 14. Tests

Unit tests cover report aggregation/order, exit codes, JSON, bounded strings, secret exclusion, corrupt/newer state, SQLite version parsing, and HTTP config validation.

Integration/rootful tests cover netd absent/present, real backend probes, converged state, repairable drift, owner conflict, and forwarding mismatch.

Snapshot kernel state before/after doctor to prove it is read-only.

## 15. Architecture guards

Prove doctor:

- calls no Apply operation;
- executes no shell;
- writes no StateStore state;
- prints no private/PSK/session/enrollment secrets;
- exposes no raw backend errors.

## 16. Verification

Run ordinary Rust/MSRV and every existing rootful suite plus a dedicated doctor integration target if useful.

## 17. Acceptance criteria

M001 closes only when doctor covers state, SQLite, netd, WireGuard, RTNETLINK, nftables, forwarding, ownership drift, and HTTP policy; all checks are read-only; human/JSON output is bounded and secret-safe; remediation is actionable; SQLite runtime identity is reported and >=3.51.3; and all prior CI remains green.

## 18. Stop conditions

Stop/write a corrective if a required diagnostic can only be made truthful by mutating state, if listen-port checking would overclaim certainty, or if capability probing would require generic privileged execution.

## 19. Closure evidence

Record check inventory, exit-code contract, SQLite runtime/source ID, probe methods, no-mutation proof, drift/conflict fixtures, JSON example, dependency diff, CI/MSRV, and M002 readiness.
