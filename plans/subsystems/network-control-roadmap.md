# Network Control Foundation Roadmap

Status: active planning; M001 closed, M002 active

Canonical references:

- `plans/000-long-term-specification.md`
- `plans/001-terminology-and-domain-model.md`
- `plans/002-long-term-roadmap.md`
- `plans/003-planning-process.md`
- `plans/adr/001-linux-native-control-plane.md`

## 1. Purpose and ownership boundary

This subsystem owns the Linux privileged/network foundation required to make wg-basic a real WireGuard appliance.

It owns:

- process-role and privileged-protocol foundation needed by network control;
- Linux capability/preflight observation;
- WireGuard kernel configuration and telemetry;
- link/address/route observation and mutation;
- reconciliation planning/application;
- nftables/filter/NAT ownership;
- host forwarding semantics;
- Linux network-namespace integration fixtures and preservation evidence.

It does not own:

- SQLite/application persistence;
- administrator authentication;
- HTTP routing/UI;
- one-time enrollment tokens;
- release/update tooling;
- general host firewall administration;
- userspace WireGuard dataplane.

Those are downstream consumers of the contracts established here.

## 2. Core invariants

1. Kernel WireGuard is the initial production dataplane.
2. No milestone introduces arbitrary shell execution or arbitrary privileged command forwarding.
3. Public/untrusted HTTP is never required to run with `CAP_NET_ADMIN`.
4. Desired state and observed state remain distinct.
5. Interface name is not durable identity.
6. WireGuard configuration, link/address/route state, firewall state, and forwarding state remain distinct typed domains.
7. Network mutation is serialized at the smallest safe ownership scope.
8. Unrelated host links, routes, addresses, nftables objects, and forwarding consumers are preserved.
9. A partial failure produces enough evidence for safe retry; it is never silently reported as convergence.
10. Real-kernel claims require real Linux kernel integration evidence.

## 3. Non-goals

This roadmap does not:

- implement the management UI;
- implement database schemas;
- build a generic netlink library;
- reimplement WireGuard cryptography;
- support macOS/Windows/BSD;
- support multiple arbitrary firewall backends in the first pass;
- provide arbitrary `wg-quick` compatibility;
- add endpoint discovery or DDNS;
- add OIDC/TOTP/RBAC.

## 4. Current repository state

At the planning baseline, wg-basic is a fresh repository with planning documents and no Rust production workspace.

There is therefore no compatibility obligation to existing code.

Current ecosystem research shows several viable Rust approaches to Linux WireGuard control, including high-level WireGuard control crates and lower-level Generic Netlink packet APIs. Selection is intentionally deferred to M003 so the repository foundation and privileged boundary do not prematurely inherit one networking crate's API.

Eggstack research establishes:

- EggServe is useful downstream for the unprivileged HTTP service, not this subsystem's kernel authority;
- Eggup/Eggpack are downstream distribution primitives;
- no current Eggstack crate should be inserted between this subsystem and authoritative WireGuard/RTNETLINK/nftables control merely for consistency.

## 5. Target architecture

```text
management process (later)
       |
       | PrivilegedProtocol v1
       v
network service
       |
       +--> capability observer
       |
       +--> WireGuardBackend
       |       `--> Generic Netlink / supported high-level wrapper
       |
       +--> LinkRouteBackend
       |       `--> RTNETLINK
       |
       +--> FirewallBackend
       |       `--> nftables / NETLINK_NETFILTER
       |
       `--> ForwardingBackend
               `--> narrowly owned host forwarding policy

             |
             v
      Reconciliation Engine
 observe -> validate -> plan -> apply -> observe -> verify
```

Backend traits/contracts SHOULD exist where they improve deterministic testing, but abstraction is not a goal by itself. Linux-native semantics remain authoritative.

## 6. Dependency graph

```text
M001 — repository, domain, and runtime-role foundation
  |
  v
M002 — privileged protocol and host capability boundary
  |
  v
M003 — WireGuard kernel control and telemetry
  |
  v
M004 — link/address/route reconciliation
  |
  v
M005 — nftables/forwarding/NAT + end-to-end namespace qualification
```

All dependencies above are hard.

## 7. Milestone M001 — Repository, domain, and runtime-role foundation

Status: closed.

Primary class: infrastructure / invariant.

Implementation plan:

- `plans/implementation/network-control/001-repository-domain-runtime-foundation.md`

Objective:

Create the minimal Rust workspace and typed contracts needed by later privileged/kernel work without yet mutating host networking.

Expected outcomes:

- root Cargo workspace/package shape;
- MSRV/toolchain/lint policy;
- executable CLI skeleton with process-role dispatch;
- typed IDs and network-domain value objects;
- secret-safe key wrappers/formatting;
- address/route validation;
- desired/observed/reconcile domain shells;
- error taxonomy;
- test fixture boundaries;
- baseline local/hosted verification.

Exit conditions:

- workspace builds/tests on Linux;
- domain invariants are unit tested;
- no host-network mutation exists;
- no generic command-execution helper enters the production architecture;
- unsafe Rust denied workspace-wide except future documented narrow exceptions;
- M002 can add IPC without redesigning domain types.

## 8. Milestone M002 — Privileged protocol and host capability boundary

Status: active.

Primary class: invariant / infrastructure.

Implementation plan:

- `plans/implementation/network-control/002-privileged-protocol-and-capability-boundary.md`

Objective:

Make privilege separation real before adding broad kernel mutation.

Expected outcomes:

- `serve` and `netd` runtime-role separation;
- Unix-domain socket listener/client;
- versioned bounded typed protocol;
- socket filesystem permissions;
- peer-credential validation where available;
- graceful shutdown and connection cancellation;
- capability/preflight observation;
- read-only `doctor` substrate;
- systemd-oriented privilege contract documented;
- protocol negative tests.

Exit conditions:

- authorized test client can request read-only capability snapshot;
- unauthorized/malformed client is denied safely;
- protocol has no generic privileged escape hatch;
- network service can run independently of HTTP/UI;
- M003 can add typed WireGuard operations without changing transport ownership.

## 9. Milestone M003 — WireGuard kernel control and live telemetry

Status: blocked on M002.

Primary class: capability / invariant.

Implementation plan:

- `plans/implementation/network-control/003-wireguard-kernel-control-and-telemetry.md`

Objective:

Establish correct kernel WireGuard ownership through typed Rust APIs.

Expected outcomes:

- dependency/backend selection documented from current crate/API evidence;
- WireGuard interface observation;
- key/listen-port configuration;
- peer set/replace/update/remove;
- AllowedIPs and keepalive;
- endpoint/latest-handshake/RX/TX observation;
- conflict validation;
- secret redaction;
- real Linux network-namespace integration;
- no `wg` or `wg-quick` runtime dependency.

Exit conditions:

- isolated peers complete a kernel WireGuard handshake through the backend;
- configuration round-trip is observed from the kernel;
- telemetry changes after test traffic;
- unrelated peer/device state used by preservation fixtures is not removed;
- M004 can treat WireGuard state as one reconciled layer.

## 10. Milestone M004 — Link, address, route, and reconciliation engine

Status: blocked on M003.

Primary class: infrastructure / invariant.

Implementation plan:

- `plans/implementation/network-control/004-link-address-route-reconciliation.md`

Objective:

Create deterministic desired/observed reconciliation for WireGuard link lifecycle, tunnel addresses, and managed routes.

Expected outcomes:

- RTNETLINK observation/mutation;
- typed reconcile planner;
- ownership/conflict validation;
- deterministic mutation ordering;
- idempotence;
- plan/dry-run representation;
- partial-failure receipt;
- re-observe/verify;
- serialized mutation;
- preservation tests for unrelated links/addresses/routes.

Exit conditions:

- converged desired state produces zero mutations;
- repeated apply remains converged;
- injected partial failure can be retried safely;
- unrelated network state survives;
- namespace fixture can route between tunnel endpoints before firewall/NAT work.

## 11. Milestone M005 — nftables, forwarding, NAT, and end-to-end qualification

Status: blocked on M004.

Primary class: capability / invariant.

Implementation plan:

- `plans/implementation/network-control/005-firewall-forwarding-end-to-end.md`

Objective:

Complete the minimum road-warrior VPN host path without taking ownership of the host firewall.

Expected outcomes:

- dedicated wg-basic nftables namespace/table;
- filter/forward policy;
- masquerade/NAT mode;
- forwarding-state semantics;
- safe disable/reconcile behavior;
- native netfilter backend or explicitly bounded internal `nft` transition backend consistent with ADR-001;
- preservation of unrelated nftables state;
- real end-to-end namespace traffic through WireGuard plus forwarding/NAT;
- restart/reapply/no-op evidence.

Exit conditions:

- an isolated client can handshake and pass traffic through the server according to desired policy;
- NAT mode works in the fixture;
- disable removes only wg-basic-owned objects;
- unrelated rules survive byte/semantic comparison appropriate to the fixture;
- forwarding teardown cannot blindly break another consumer;
- no unresolved high/medium ownership finding remains.

M005 closes the network-control foundation and unblocks durable state + product service integration.

## 12. Cross-cutting failure and recovery requirements

All mutating milestones must:

- classify errors before/after mutation where practical;
- avoid claiming rollback when only partial recovery is possible;
- expose stable machine-readable error categories internally;
- keep kernel error details available for operators without leaking secrets;
- bound waits/timeouts;
- terminate cleanly on shutdown;
- avoid detached mutation tasks;
- document what happens if the process dies between mutation and verification.

The reconciliation engine ultimately repairs owned drift after restart; it must never “repair” unowned host state.

## 13. Concurrency

Initial design SHOULD serialize reconciliation per installation/interface unless evidence justifies finer concurrency.

WireGuard telemetry reads may occur concurrently with mutation if the backend/kernel contract permits it and tests prove coherent behavior.

Firewall replacement and link/route mutation must avoid two concurrent writers in one wg-basic ownership domain.

## 14. Security

- privileged IPC is an authorization boundary;
- private keys/preshared keys never implement `Debug`/logging as raw material;
- peer labels never become command/script input;
- kernel-returned interface/endpoint data is untrusted input for presentation;
- netlink parsing/library failures are handled as errors, not panics in the service loop;
- systemd hardening recommendations belong in M002/M005 evidence once required capabilities are known.

## 15. Verification direction

Expected routine Rust gates:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

MSRV gates begin in M001.

Linux namespace/kernel integration tests SHOULD be feature/test-class gated so ordinary unit iteration remains fast, but M003–M005 closure requires those tests actually run on a suitable Linux host/CI runner.

No plan should introduce a large CI matrix before a concrete qualification need exists.

## 16. Risks and decisions to revisit

- high-level WireGuard crates may trail kernel/UAPI changes or impose cross-platform abstractions; M003 selects based on current evidence;
- lower-level netlink code increases project maintenance burden; prefer proven crates while preserving domain isolation;
- nftables Rust libraries may be less mature than invoking `nft`; M005 may choose a bounded transitional backend under ADR-001 constraints;
- user/network namespaces can be restricted in CI; closure must use a runner that can exercise the real kernel rather than weakening evidence;
- host-wide forwarding sysctls lack natural per-application ownership; preserve/diagnose rather than blindly revert;
- CAP_NET_ADMIN may still be broad; systemd sandboxing reduces but does not eliminate network-service authority.

## 17. Milestone status

| Milestone | Status | Implementation plan | Closure record | Blockers |
|---|---|---|---|---|
| M001 repository/domain/runtime foundation | closed | `plans/implementation/network-control/001-repository-domain-runtime-foundation.md` | `plans/closure/network-control/001-status.md` | — |
| M002 privileged protocol/capabilities | ready | `plans/implementation/network-control/002-privileged-protocol-and-capability-boundary.md` | — | — |
| M003 WireGuard control/telemetry | blocked | `plans/implementation/network-control/003-wireguard-kernel-control-and-telemetry.md` | — | M002 |
| M004 link/address/route reconciliation | blocked | `plans/implementation/network-control/004-link-address-route-reconciliation.md` | — | M003 |
| M005 firewall/forwarding/E2E | blocked | `plans/implementation/network-control/005-firewall-forwarding-end-to-end.md` | — | M004 |
