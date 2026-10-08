# Architecture overview

wg-basic is a Linux-native WireGuard management appliance: one small Rust
executable with two separated privilege domains. The Linux kernel owns the
WireGuard dataplane. This document is the bird's-eye view and the index for
the per-component deep dives in this directory. Those files describe
**current implemented behavior**; planned work belongs in `plans/`.

## Bird's-eye view

```text
operator / browser
      │  HTTPS via reverse proxy, or loopback HTTP
      ▼
serve (unprivileged management role) ── owns ──► SQLite state store (authoritative)
  │  embedded EggServe HTTP surface          monotonic desired generation + CAS
  │  one bounded worker thread holds         installation identity, owner tags,
  │  ManagementRuntime; HTTP code never      convergence evidence, credentials,
  │  touches the store or netd directly      product metadata, audit history
  │                                              │
  │  typed request over local UDS socket         │  one aggregate intent per
  │  (SO_PEERCRED authorized, no shell,          │  generation, projected from
  │   no raw netlink/nft/sysctl/file ops)       │  the committed snapshot
  ▼                                              ▼
netd (privileged network role, CAP_NET_ADMIN) ◄── ManagementRuntime::reconcile
  │  typed WireGuard observation/patch (Generic Netlink, nl-wireguard)
  │  typed link/address/route reconcile (RTNETLINK, rtnetlink)
  │  typed IPv4 forwarding/NAT/firewall policy (bounded nft subprocess)
  │  ownership proven per resource (IFLA_IFALIAS tags, table markers)
  └──► kernel state (derivative — only ever observed, never authoritative)
```

Two invariants shape everything:

- **State authority.** SQLite desired state is authoritative; kernel state is
  derivative. Startup reconciles unconditionally because the kernel may have
  drifted while stopped. A late receipt can never mark a newer generation
  converged.
- **Privilege separation.** Only the unprivileged management role opens the
  database (`netd` is database-free). Only `netd` touches the kernel, and only
  through typed operations. There is no arbitrary shell, command, file-write,
  sysctl-path, nft-script, or raw-netlink execution anywhere in the protocol.

## Discrete modules and where to dive deeper

| Source subtree | Owns | Deep dive |
|---|---|---|
| `src/domain/` | typed identifiers, interface-name validation, IP prefix values, key/secret wrappers, generation, owner tags, intent/state shells | [domain-model](domain-model.md) |
| `src/state/` | hardened SQLite store, ordered migrations, installation identity, CAS generations, projection, convergence evidence, backup/restore, service/maintenance leases | [state-store](state-store.md) |
| `src/protocol/` | versioned UDS protocol: framing, peer-credential auth, capability inspection, dispatch, typed client | [privilege-boundary](privilege-boundary.md) |
| `src/wireguard/` | kernel WireGuard backend over Generic Netlink (device/peer observe/patch, telemetry) | [wireguard-control](wireguard-control.md) |
| `src/firewall/` | typed IPv4 forwarding/NAT policy, planner, bounded `nft` service, owned-table model | [firewall](firewall.md) |
| `src/reconcile/` + `src/aggregate.rs` | deterministic link/address/route planner, Linux applier, aggregate coordinator, receipts | [reconciliation](reconciliation.md) |
| ownership markers | `IFLA_IFALIAS` owner tags, `inet wg_basic` table markers, aggregate generation monotonicity, fail-closed rules | [ownership](ownership.md) |
| `src/management/` | runtime lifecycle, bounded worker, reconcile coordinator, health projection, credential/session operations | [startup-recovery](startup-recovery.md), [management-http](management-http.md), [authentication](authentication.md) |
| `src/http/` | EggServe surface: routing, Host/Origin/CSRF perimeter, security headers, rate limits, readiness, embedded assets, `serve` lifecycle | [management-http](management-http.md) |
| `src/management/auth.rs` + `src/domain/auth.rs` | Argon2id credentials, opaque digest-only sessions, cookie/CSRF profile, login/logout/session routes | [authentication](authentication.md) |
| `src/product/` | server setup, client lifecycle, address allocation, config/QR export, one-time enrollment, telemetry, audit, embedded product UI | [product-management](product-management.md) |
| `src/doctor.rs` + `src/operational.rs` + maintenance | read-only doctor/preflight, structured stderr events, service/maintenance leases, disable/enable/purge, backup/restore ops | [diagnostics-maintenance](diagnostics-maintenance.md) |
| `src/main.rs` CLI roles | `serve`, `netd`, `reconcile`, `health`, `doctor`, `admin`, `state`, `network` command surface | [cli-roles](cli-roles.md) |
| `tests/` + fixtures | unprivileged suites, rootful namespace fixtures, static architecture guards, upgrade rehearsal | [testing-qualification](testing-qualification.md) |
| service contract | recommended systemd hardening profile (no unit files shipped yet) | [service-hardening](service-hardening.md) |
| update contract | binary+database transaction rule, rollback order, crash-window matrix (contract only — no updater shipped) | [update-rollback-contract](update-rollback-contract.md) |

## Tools and capabilities (operator view)

- **Serve the appliance:** `wg-basic serve` (unprivileged HTTP + worker),
  `wg-basic netd` (privileged UDS backend). Loopback by default; routable binds
  and HTTPS origins are explicit, acknowledged deployments. See
  [cli-roles](cli-roles.md) and [management-http](management-http.md).
- **Administer credentials:** `wg-basic admin set-password --password-stdin`
  (stdin only, never argv/env), `wg-basic admin status` (safe projection).
  See [authentication](authentication.md).
- **Inspect and recover state:** `state status|backup|restore|verify`,
  `network status|disable|enable`, `state purge` (guarded, needs
  disabled+converged+no-op plan), `health`, `doctor` (read-only,
  exit 0/1/2). See [cli-roles](cli-roles.md) and
  [diagnostics-maintenance](diagnostics-maintenance.md).
- **Run the product:** login/session/health, one-time server setup, managed
  client CRUD with `expected_generation` compare-and-swap (`200`/`201`
  enforced vs `202` pending), explicit config/QR export, one-time enrollment
  links, live telemetry, bounded audit pages, embedded UI. See
  [product-management](product-management.md).
- **Qualify a change:** ordinary `cargo test`, rootful namespace suites with
  `--features linux-integration`, static guards in
  `tests/architecture_guards.rs`. See
  [testing-qualification](testing-qualification.md) and
  [development](../docs/development.md).

## Status

Network control, durable state/restart reconciliation (Phases 6),
management/auth substrate (Phase 7), product/enrollment/UI (Phase 8), and
operational hardening (Phase 9) are closed. Installation and transactional
self-update are **not implemented**; Phase 10 (distribution/install/update) is
researched and planned with M001 ready. Implementation status lives in
[the planning registry](../plans/registry.md).

## Full deep-dive index

- [domain-model](domain-model.md) — value types, secrets, generations, owner tags
- [state-store](state-store.md) — durable SQLite store, migrations, leases
- [startup-recovery](startup-recovery.md) — startup sequence, coordinator, retry, drift repair
- [privilege-boundary](privilege-boundary.md) — UDS protocol, peer auth, intended service contract
- [wireguard-control](wireguard-control.md) — backend selection, M003 contract, key/error handling
- [reconciliation](reconciliation.md) — RTNETLINK lifecycle, ordering, receipts
- [firewall](firewall.md) — IPv4 policy, nftables boundary, disable/preservation
- [ownership](ownership.md) — interface/firewall ownership proof, aggregate rules
- [management-http](management-http.md) — HTTP boundary, worker, pipeline, limits, lifecycle
- [authentication](authentication.md) — credentials, sessions, cookies, CSRF, limiter
- [product-management](product-management.md) — product API, enrollment, telemetry, audit, UI
- [diagnostics-maintenance](diagnostics-maintenance.md) — doctor, events, leases, maintenance ops
- [cli-roles](cli-roles.md) — every `wg-basic` subcommand and its contract
- [testing-qualification](testing-qualification.md) — suites, rootful fixtures, guards
- [service-hardening](service-hardening.md) — Phase 10 systemd contract (recommended, not shipped)
- [update-rollback-contract](update-rollback-contract.md) — update transaction (contract only)
