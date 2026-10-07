# Network Control C001 Closure

Status: closed

Repository baseline: `1b17d49` (post-closure planning head)
Final implementation head: `0e74a40`
Qualification run: GitHub Actions CI run [`37617879237`](https://github.com/dbowm91/wg-basic/actions/runs/37617879237), commit `0e74a40`

## Outcome

C001 is strictly closed. Stale milestone-era wording has been reconciled across the CLI, architecture docs, and registry, and the three largest network-control modules are split along ownership boundaries without any wire-format, protocol-version, network-policy, nftables, or reconciliation-ordering change.

## Requirement-to-evidence matrix

| Requirement | Evidence |
|---|---|
| Documentation and operator-text reconciliation (work package A) | `src/main.rs` no longer describes netd as an M002 read-only service; it now states the service exposes typed WireGuard, network, and firewall operations. `architecture/privilege-boundary.md` no longer says M004–M005 "will extend" a protocol that already exposes those operations. The registry finding was already remediated at the planning baseline; section 5 and the durable-state tables were verified to contain no ordinary M004 work row. Historical closure records were not edited. |
| Reconciliation decomposition (work package B) | `src/reconcile.rs` (1,059 lines) became `reconcile/{mod,model,planner,service,linux}.rs`. `model` holds the serialized desired/observed vocabulary; `planner` holds pure planning; `service` holds the installation-wide lock, apply, re-observe, and verify; `linux` remains the isolated RTNETLINK backend. `plan_managed_interface` remains pure, mutation ordering is unchanged, and `src/reconcile/linux.rs` was not modified. |
| Firewall decomposition (work package C) | `src/firewall.rs` (991 lines) became `firewall/{mod,policy,planner,nft,service}.rs`. Ownership markers (`wg-basic:m005:v1`, `wg_basic`, `forward`, `postrouting`) and `MAX_PREFIXES` live with the policy that defines them; all rendering, observation, and process execution stay in `nft`. |
| Protocol decomposition (work package D) | `src/protocol/server.rs` (660 lines) became `protocol/{auth,socket,dispatch,client}.rs` alongside the existing `framing`/`wire`/`capability`. Peer-credential policy, socket bind/stale-path/shutdown lifecycle, operation routing with domain-error projection, and the one-shot client are separate units. No async or concurrent request handling was introduced. |
| Static guards (work package E) | `tests/architecture_guards.rs` adds 7 tests: no production module invokes `wg`, `wg-quick`, or `ip`; process execution is isolated to exactly `src/firewall/nft.rs`; no module spawns a shell; the nft backend spawns `nft` and nothing else; the protocol wire vocabulary contains no exec/shell/raw-netlink/raw-nft/file-write/sysctl escape hatch; the protocol version and operation tags are pinned; and secret wrappers redact `Debug`/`Display` including inside a derived-`Debug` aggregate. |
| No wire-format or protocol-version change | `PROTOCOL_VERSION` remains 1; every `RequestOperation` and `ProtocolError` variant is byte-identical; the four-byte big-endian length frame, 64 KiB bound, JSON envelope, request correlation, one-request-per-connection, sequential handling, two-second I/O timeout, 16-connection backlog, and early unauthorized-peer rejection are unchanged. The version pin is now test-enforced. |
| No network or firewall semantic change | nftables input rendering, expression-level drift detection, whole-table atomic replacement, the `inet wg_basic` ownership marker, the 64-prefix / 32 KiB input / 256 KiB per-stream output / five-second timeout bounds, the nft >= 0.9.0 floor, and the forwarding teardown behavior are all byte-identical moves. Verified by the rootful E2E suite. |
| Move fidelity | A normalized code-line diff of each original file against its split modules reported only import-line reshuffling and `pub(crate)` visibility changes required by the new module edges. No statement, branch, literal, or constant value was added, removed, or altered. |
| No dependency change | `git show 0e74a40 -- Cargo.toml Cargo.lock` is empty. C001 added no runtime dependency. |
| Routine and MSRV gates | On Rust 1.89: `cargo fmt --all -- --check`, `cargo check --all-targets --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`, and `cargo +1.89.0 check --all-targets --locked` all passed locally. |
| Rootful qualification | Locally, all three rootful suites passed: `wireguard_kernel` **2 passed**, `network_reconcile` **2 passed**, `network_control_e2e` **2 passed** (nftables v1.0.9). In hosted CI run `37617879237` all four jobs succeeded: `rust`, `wireguard-kernel`, `network-reconcile-kernel`, and `network-control-e2e`. |
| Public/wire API compatibility | `crate::reconcile::*`, `crate::firewall::*`, and `crate::protocol::*` re-export exactly the same public items as before the split. Existing callers (`src/protocol/wire.rs`, `src/protocol/server.rs`→`socket.rs`, `tests/network_reconcile.rs`, `tests/network_control_e2e.rs`) were not modified. Cross-module plumbing uses `pub(crate)`, not public API expansion. |

## Before/after module inventory

Before:

| File | Lines |
|---|---|
| `src/reconcile.rs` | 1,059 |
| `src/firewall.rs` | 991 |
| `src/protocol/server.rs` | 660 |

After:

| File | Lines | Ownership |
|---|---|---|
| `src/reconcile/mod.rs` | 26 | public/domain-facing exports |
| `src/reconcile/model.rs` | 290 | desired/observed/receipt/action types |
| `src/reconcile/planner.rs` | 580 | pure desired-versus-observed planning |
| `src/reconcile/service.rs` | 258 | serialization, apply, re-observe, verify |
| `src/reconcile/linux.rs` | 384 | RTNETLINK backend (unmodified) |
| `src/firewall/mod.rs` | 22 | public exports |
| `src/firewall/policy.rs` | 192 | typed policy, validation, ownership markers |
| `src/firewall/planner.rs` | 391 | observation → typed action plan |
| `src/firewall/nft.rs` | 349 | bounded nft process backend, rendering, observation |
| `src/firewall/service.rs` | 126 | lock, apply, re-observe, receipt |
| `src/protocol/mod.rs` | 32 | public exports |
| `src/protocol/auth.rs` | 32 | peer credentials + authorization policy |
| `src/protocol/socket.rs` | 476 | bind, stale-socket handling, lifecycle |
| `src/protocol/dispatch.rs` | 120 | operation dispatch + domain error mapping |
| `src/protocol/client.rs` | 84 | request helper |

Tests were moved next to the code they exercise: planning tests live with `planner`, the partial-apply/retry test with `service`, policy validation with `policy`, and nft quoting/version/bounding tests with `nft`.

## Public/wire API compatibility statement

No public item was renamed, removed, or re-signatured. No serialized field name or enum variant changed. `PROTOCOL_VERSION` is unchanged at 1. The only visibility changes are `pub(crate)` on items that previously relied on module-level privacy: `reconcile::Mutation`, `reconcile::ExecutionPlan` fields, `reconcile::ReconcileBackend`, `reconcile::plan_execution`, the firewall planner/observation/nft helpers and their fields, the firewall policy marker constants and helper methods, and the `SocketServer` fields plus `SocketIdentity` and `AuthorizationPolicy::permits` needed by the `dispatch` module. None of these were public before C001.

## Test count reconciliation

The accepted M005 baseline had 41 library tests. C001 ends with 40 library tests plus 7 new architecture-guard tests. The one-test reduction is the removal of the single `shipped_backend_uses_no_ip_subprocess` unit test from `src/reconcile.rs`; its assertion is subsumed and strictly widened by `process_execution_is_isolated_to_the_nft_backend` and `production_control_paths_do_not_invoke_wg_wg_quick_or_ip` in `tests/architecture_guards.rs`, which cover every production source file rather than one.

## Unresolved findings

No unresolved high- or medium-severity finding remains.

- Two observations were recorded during implementation and resolved without scope change: firewall ownership constants were initially placed with the planner and were moved to `policy` so that the marker vocabulary sits with the policy that defines it; and `request()`/`AuthorizationPolicy` were regenerated verbatim from the pre-split source after an initial hand-written draft was found to have altered `HashSet` semantics and the client's return type. Both were caught by the compiler and the normalized move-fidelity diff.
- The plan's stop conditions were not triggered. No behavioral defect, protocol schema change, forced public API expansion, dependency inversion, or nftables/reconciliation ordering change was required.

Disposition: `closed`.

## Successor readiness and plan queue

C001 was the sole hard blocker for Phase 6. With C001 strictly closed, the durable-state roadmap's `M001 blocked on network-control C001 closure` condition is satisfied, so `plans/implementation/durable-state/001-sqlite-state-store-and-generations.md` is promoted to ready/active. M002–M004 remain blocked in order behind M001, M002, and M003 respectively.

Phase 7 remains unblocked for planning and may proceed against the stable typed privileged protocol. Phase 8 remains blocked until Phases 6 and 7 close.