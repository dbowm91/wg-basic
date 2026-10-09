# IPv6 M001 — Dual-Stack Product/Domain Persistence and Tunnel Reconciliation

Disposition: **closed**.

Date: 2026-10-09

## Implementation revision

- Repository baseline: `c7de919c0b9d8f3326c50c799779ee5dc3734dca` (Phase 10 technical closure).
- Qualified final head: `fa25918b824641e00944e3edf335f7055cb11dcc`.
- Production implementation: `f673bf4` (dual-stack product, state, and kernel reconciliation), `db8c7f1` (managed IPv6 pool route for server return traffic).
- Native fixture corrections/evidence: `1fbb1d0`, `46f826d`, `008925b`, `e5e86c3`, `6a11025`, `e3197c8`, `ca5fba3`, and `fa25918`.

## Requirement-to-evidence matrix

| Requirement | Evidence | Result |
|---|---|---|
| Deterministic bounded allocation of one IPv6 server/client address with reservation and conflict handling | IPv6 allocator unit cases cover bounded gap search, `/64`, reserved/server/client addresses, invalid prefix shapes, and duplicate requests. Product tests exercise automatic assignment and address reassignment. | Passed. |
| Persist IPv6 address and peer host prefix through migration, backup/restore, and reopen | Additive schema-v6 migration and interface-local uniqueness; migration/rollback tests and backup/restore tests include IPv6 state. Old schema readers remain compatible with v1-v5. | Passed. |
| Apply the server/client addresses and peer `AllowedIPs` through typed Linux control | Product setup creates the server IPv6 `/128`, a managed IPv6 pool route, and per-peer IPv6 host prefixes through the existing typed state projection, RTNETLINK, and WireGuard backends. Hosted product job observes the recovered peer prefixes and route. | Passed. |
| Carry native IPv6 tunnel traffic, including after server disable/restart/re-enable and client reconnect | Hosted rootful product test uses real WireGuard devices in isolated Linux namespaces, consumes an exported client configuration, verifies IPv6 echo traffic, disables the network, restarts netd and the management worker, re-enables it, recreates the simulated client peer to force a fresh handshake, and verifies IPv6 traffic again. | Passed; 6 product tests passed. |
| Disable/delete affect only owned resources and preserve IPv4 compatibility | Rootful product lifecycle tests cover disable/re-enable and client deletion. Full CI passes the existing IPv4/kernel/product suites and current Rust suite. | Passed. |
| No IPv6 forwarding, nftables, or sysctl mutation is introduced | Source review confirms M001 only adds a typed route to the managed WireGuard interface; it does not change forwarding, firewall, or sysctl behavior. | Passed. |

## Verification

Local commands actually run:

- `cargo fmt --all -- --check` — passed.
- `cargo check --all-targets --locked` — passed.
- `cargo clippy --all-targets --locked -- -D warnings` — passed.
- `cargo test --locked` — 569 passed, 3 ignored.
- `cargo test --locked --features linux-integration --test product_management_rootful --no-run` — passed; the rootful binary was not run locally.

Hosted final-head evidence:

- [Full CI run 37945376954](https://github.com/dbowm91/wg-basic/actions/runs/37945376954): all 15 jobs passed on `fa25918`.
- [Rootful product job 113870168633](https://github.com/dbowm91/wg-basic/actions/runs/37945376954/job/113870168633): 6 passed, including exported-client IPv6 traffic and post-restart recovery.
- The same full run passed Rust 1.89, dependency audit, upgrade rehearsal, updater transaction rollback/recovery, WireGuard kernel control, network reconciliation, management, maintenance, backup, and systemd lanes.

## Security and ownership evidence

Codex Security diff scan `47a0ee0b-5007-41ec-aa16-f81e1aee118a` completed with zero findings on the initial M001 source change. The later production-code correction is limited to persisting and reconciling the configured IPv6 pool route through the existing typed route model and backend; the remaining later changes are rootful test evidence. Manual review found no new privilege operation, arbitrary sysctl access, firewall mutation, or untyped kernel request.

## Documentation, limitations, and findings

Current behavior is recorded in `architecture/domain-model.md`,
`architecture/state-store.md`, `architecture/reconciliation.md`,
`architecture/product-management.md`, `architecture/testing-qualification.md`,
and `docs/development.md`.

M001 delivers IPv6 tunnel addressing and tunnel-local traffic. It does not
enable forwarded IPv6 egress, NAT66, client `::/0`, or IPv6 split-route policy;
those remain successor scope. No unresolved M001 high/medium findings or
corrective requirements remain.

M001 is strictly closed. M002 is unblocked by this closure and becomes ready
only with accepted ADR-007's bounded forwarding ownership decision and its
implementation handoff.
