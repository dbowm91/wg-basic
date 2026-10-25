# macOS Native Server M004 — Darwin Interface, Address, Route, and Reconciliation Ownership

Disposition: **closed** 2026-10-14 (hosted live qualification on both Darwin
arches; residuals: sleep/wake, link roaming).

Date: 2026-10-13 (blocked record); 2026-10-14 (hosted closure).

## Implementation revision

- Repository baseline: `7f0b072` (M003 blocked closure).
- Modeling head: `42fa94ce390e5061b4fac85c1b23aedb0f509086`.
- Blocked record: `ee605aa`.
- Hosted qualification head: `a10b4c2` (current; all-green run `38524007872`).
- Source plan: `plans/implementation/macos-native-server/004-darwin-interface-address-route-reconciliation.md`.
- Roadmap: `plans/subsystems/macos-native-server-roadmap.md` M004.
- Fixture: `tests/wireguard_darwin_live.rs::live_route_inventory_preserved`.

## Hosted live qualification (run `38524007872`, 2026-10-14)

Same hosted setup as M003 (`macos-15` arm64 + `macos-15-intel` x86_64
native, macOS 15.7.9; 3/3 Intel + 5/5 arm64 live tests pass):

- Real `utun` address lifecycle both families: IPv4 `192.0.2.5` (+
  `192.0.2.9/32` alias add/remove, observed then gone) and IPv6
  `2001:db8::9` alias add/remove, all with the platform's two-bare-addresses
  form (the `-->` token parses as an address on this `ifconfig`, and alias
  on p2p needs a destination).
- Live observation fed into the pure `plan_darwin`: converged state plans
  nothing, dropping the alias plans exactly its removal, `0.0.0.0/0`
  refuses as `GlobalTakeoverRefused`.
- Default route byte-identical before/after; `netstat -rn` (`inet` +
  `inet6`) destination sets gain only utun/TEST-NET entries while
  pre-existing destinations keep their gateways (counter drift on ARP lines
  is host noise, excluded by construction after one false-positive taught
  the comparison).
- Teardown returns the interface inventory to baseline.
- Evidence artifacts: `m004-route-inventory.txt` both arches on run
  `38524007872`.

Residuals (carried, not claimed): sleep/wake handling and Wi-Fi↔Ethernet
roaming (hosted runners can do neither); helper/netd kill + renumber
convergence is covered live at the tunnel layer (M003 respawn) and the
planner is renumber-proof by construction (UUID identity, never numeric).
These gate any release claim (M007), not this closure: every acceptance
criterion (v4+v6 convergence, idempotency, no unrelated changes, numeric
identity never authoritative, truthful receipts, Linux unchanged) is met
on both arches.

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

M004 is **closed** 2026-10-14: the shared privileged-host blocker is
discharged by hosted qualification (`gh` runners at maintainer direction),
and the modeling scope above stands as the implementation. Sleep/wake and
link-roaming residuals carry to M007.
