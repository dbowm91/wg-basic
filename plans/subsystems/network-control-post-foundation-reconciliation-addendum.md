# Network Control Post-Foundation Reconciliation and Refactor Addendum

Status: active; C001 ready

Canonical references:

- `plans/000-long-term-specification.md`
- `plans/001-terminology-and-domain-model.md`
- `plans/003-planning-process.md`
- `plans/adr/001-linux-native-control-plane.md`
- `plans/subsystems/network-control-roadmap.md`

Historical closure references:

- `plans/closure/network-control/001-status.md`
- `plans/closure/network-control/002-status.md`
- `plans/closure/network-control/003-status.md`
- `plans/closure/network-control/004-status.md`
- `plans/closure/network-control/005-status.md`

## 1. Purpose

M001–M005 are strictly closed and their evidence remains accepted. This addendum does not reopen their network-control contracts.

The implementation accumulated normal post-foundation debt while moving quickly from a planning-only repository to a working kernel/network substrate. Before durable persistence and the HTTP management service add more consumers, perform one bounded reconciliation/refactor pass that:

- removes stale milestone-era documentation and CLI descriptions;
- splits the largest network-control modules into clearer ownership units;
- preserves public/internal typed contracts unless a purely mechanical visibility move is required;
- preserves the exact privileged protocol, network reconciliation, firewall ownership, and rootful test behavior;
- leaves Phase 6 and Phase 7 semantics unchanged.

## 2. Findings motivating the pass

Current head after M005 closure contains several stale statements:

- `src/main.rs` still describes netd as an M002 read-only service;
- `architecture/privilege-boundary.md` says M004–M005 “will extend” a protocol that already exposes those operations;
- `plans/registry.md` refers to ordinary M004 work even though M004 is closed.

The production implementation is still coherent, but several files are now large enough that persistence/UI work would increase coupling:

- `src/reconcile.rs` — roughly one thousand lines;
- `src/firewall.rs` — roughly one thousand lines;
- `src/protocol/server.rs` — several hundred lines and owns socket lifecycle, authorization, dispatch, and error projection.

This is maintainability debt, not evidence that M001–M005 closure was incorrect.

## 3. Invariants

C001 MUST preserve:

1. M001–M005 closure evidence and historical records.
2. Rust 1.89 MSRV.
3. `unsafe_code = "deny"`.
4. One executable with separable `serve` and `netd` roles.
5. The current bounded/versioned Unix-domain privileged protocol.
6. Kernel peer-credential authorization.
7. No production `wg`, `wg-quick`, or `ip` control path.
8. Current `nl-wireguard` and `rtnetlink` semantics.
9. Dedicated `inet wg_basic` firewall ownership.
10. Bounded direct `nft` invocation only; no shell/raw caller-authored rules.
11. Existing no-op/idempotence, partial-failure/retry, and preservation behavior.
12. Existing rootful WireGuard, reconcile, and forwarding/NAT qualification.

## 4. Non-goals

C001 MUST NOT:

- add SQLite or durable state;
- change ownership from request-scoped to durable;
- change the privileged protocol schema/major version;
- add HTTP/EggServe;
- add authentication/UI;
- add IPv6;
- change nftables policy semantics;
- replace the nft backend;
- change install/update behavior;
- add a new network capability.

## 5. Target module decomposition

Exact filenames may vary, but the implementation should converge toward ownership boundaries approximately like:

```text
reconcile/
  mod.rs            public/domain-facing exports
  model.rs          desired/observed/receipt/action types
  planner.rs        pure desired-vs-observed planning
  service.rs        serialization/apply/re-observe/verify
  linux.rs          RTNETLINK backend

firewall/
  mod.rs            public exports
  policy.rs         typed policy + validation
  planner.rs        observation -> typed action plan
  nft.rs            bounded nft process backend + observation/rendering
  service.rs        lock/apply/re-observe/receipt

protocol/
  framing.rs
  wire.rs
  auth.rs           peer credentials + authorization policy
  socket.rs         bind/stale-socket/lifecycle
  dispatch.rs       operation dispatch + domain error mapping
  client.rs         request helper
```

Do not split files mechanically if a proposed file would contain only trivial forwarding. The goal is ownership clarity and test locality, not maximizing file count.

## 6. Dependency graph

```text
M001–M005 strict closure
          |
          v
C001 post-foundation reconciliation/refactor
          |
          +--> Phase 6 implementation may begin after C001 closure
          `--> Phase 7 implementation may begin after C001 closure
```

Phase 6 research/planning may proceed while C001 is implemented, because C001 is contract-preserving.

## 7. Milestone C001 — Documentation reconciliation and module decomposition

Status: ready.

Implementation plan:

- `plans/implementation/network-control/c001-post-foundation-reconciliation-and-module-decomposition.md`

Primary class: corrective / polish / invariant preservation.

Exit conditions:

- stale M002/M004/M005 future-tense text is removed;
- production modules are decomposed along coherent authority boundaries;
- no protocol/network/firewall behavior changes;
- routine and all three rootful integration jobs pass at the final head;
- closure record explicitly compares C001 behavior against the accepted M005 baseline.

## 8. Closure policy

The existing M001–M005 closure records are not edited to imply this cleanup existed earlier.

C001 receives its own closure record under:

- `plans/closure/network-control-post-foundation-reconciliation/c001-status.md`

Any discovered behavioral defect must either be fixed with explicit regression evidence inside C001 if it is tightly related and does not broaden scope, or receive a separate corrective plan.