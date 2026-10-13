# macOS Native Server M004 — Darwin Interface, Address, Route, and Reconciliation Ownership

Disposition: **blocked** (modeling scope implemented; privileged native convergence unqualified).

Date: 2026-10-13

## Implementation revision

- Repository baseline: `7f0b072` (M003 blocked closure).
- Qualified implementation head: `42fa94ce390e5061b4fac85c1b23aedb0f509086`.
- Source plan: `plans/implementation/macos-native-server/004-darwin-interface-address-route-reconciliation.md` (modeling-ready → blocked by this record).

## Requirement-to-evidence matrix

| Requirement (plan) | Evidence | Result |
|---|---|---|
| Research Darwin routing APIs; typed socket/native ops; isolated audited unsafe | Darwin surface researched from upstream `tun_darwin` + `PF_ROUTE`/`ifscope` semantics and recorded in `src/reconcile/darwin.rs` module docs; modeling scope performs no I/O so no unsafe was introduced (`forbid(unsafe_code)` intact) | Passed (modeling scope) |
| Platform-neutral OS locator + Darwin-owned address/route observation; family/gateway/flags/ifscope/identity | `DarwinAddress` (tunnel/link-local/foreign scopes + owned bit), `DarwinRoute` (destination/gateway/ifscope/owned), `DarwinObservation` (ephemeral `utunN` + lists), `DarwinDesired` — 6 pure unit tests | Passed |
| Action mapping for bound utun; no independent utun create/delete; address-before-route / route-before-teardown ordering intent | `plan_darwin` is side-effect free and utun-bound (absent `utun` with non-empty desired → `InterfaceAbsent`, never cross-interface mutation); ordering documented for the backend that consumes these actions | Passed (planning; apply ordering belongs to the blocked backend) |
| Deterministic planner cases: duplicates, conflicts, renumbering, adapter changes; unsupported combinations distinguished | Unit matrix: converged→no-op, missing→add, owned-extras→remove, foreign→preserved, unowned-conflict→`Conflict`, absent/global/duplicate→refused, renumber (`utun4`→`utun7`)→re-apply without numeric deletion | Passed |
| Native Darwin IPv4/IPv6 convergence, idempotency, retry/rollback after privilege errors and crash | NOT qualified: needs the M003 live helper + privileged route socket on a disposable opted-in host | **Blocked** |
| Security: netd-only mutation, typed bounded identifiers, foreign/default-route protection, no PID-file authority, no DB in netd | Proven at model level (no deletion without exact owned identity; global `0.0.0.0/0`/`::/0` refused; `utunN` never authoritative — `LogicalTunnel`/UUIDs are). Live proof needs the backend | Partially passed (model), blocked (live) |
| Regression: Linux `network_control_e2e`, `network_reconcile`, `wireguard_kernel` unchanged | Untouched; full `cargo test` green | Passed |
| Stop: unattributable deletion, default-route surgery, stale-name confusion | Honored by construction (refusals above); no narrowing revision needed yet — the backend must still prove attribution live before claiming convergence | Passed (modeling scope) |

## Verification

Local commands on native Darwin arm64 (macOS 26.6.2, rustc 1.89.0):

- `cargo fmt --all -- --check`, `cargo check --locked --all-targets`, `cargo clippy --all-targets --locked -- -D warnings` (plus both Darwin target triples) — passed.
- `cargo test --locked` — green (lib 366 incl. 6 new `reconcile::darwin`; 55/55 guards incl. new purity guard; full integration green; one transient parallel HTTP port race observed, passes alone and on retry — pre-existing flake, also noted in M003).
- `cargo +1.89.0 check` — passed.

Privileged evidence NOT collected (same blocker as M003): real `utun` address/route add/observe/no-op/remove with IPv4+IPv6, before/after full route inventories, helper/netd kill + renumber with unrelated VPN present, Wi-Fi→Ethernet/sleep-wake handling, gateway-scoped traffic + receipts.

## Security and ownership evidence

- New `src/reconcile/darwin.rs` is pure (guard-pinned: no process/shell/netlink/nft/pfctl/`ifconfig`/`route`); the M001→M003 process-site guard updated deliberately to keep pinning exactly `[nft.rs, wireguard/darwin.rs]`.
- No schema/protocol change; `OsLocator`/`LogicalTunnel` separation from M001 preserved; dynamic `utun` identifiers never enter authoritative identity.
- Linux RTNETLINK path untouched.

## Documentation, limitations, and findings

- No current-behavior docs changed (nothing shipped). Research notes live in the module docs per the plan's verification section.
- Hard blocker (shared with M003): disposable privileged Mac host + non-interactive root + explicit host-mutation opt-in. No `utun` address/route was created here and no convergence claimed.
- Findings: no high/medium/low open items in the modeling scope.

M004 is **blocked** on privileged-host qualification. M005 modeling/policy scope may proceed; its native gateway traffic carries the same blocker.
