# Network Control M005 Closure

Status: closed

Implementation baseline: `e01f35b` (closed M004 head)
Implementation commits: M005 implementation series `e01f35b..c67fff8`
Final implementation head: `c67fff8`
Qualification run: GitHub Actions CI run [`37593324627`](https://github.com/dbowm91/wg-basic/actions/runs/37593324627), commit `c67fff8`

## Outcome

M005 is strictly closed. Netd now accepts a bounded typed IPv4 network policy, enables only the fixed host forwarding setting when required, and manages the dedicated `inet wg_basic` nftables table. A rootful three-namespace test proves a WireGuard client can handshake and reach an internet-side endpoint through explicit egress masquerade, while no-NAT has no return route. Reapply, netd restart/reconcile, disable, conflict refusal, independent firewall interaction, and unrelated host-state preservation are qualified.

## Requirement-to-evidence matrix

| Requirement | Evidence |
|---|---|
| Typed, bounded policy and protocol | `DesiredNetworkPolicy` limits callers to IPv4 forwarding, a managed tunnel interface, explicit egress, bounded source prefixes, and disabled/masquerade NAT. Versioned Plan/Apply protocol operations accept no raw nft source, command, or sysctl path. |
| Conservative nftables ownership | Netd recognizes only table `inet wg_basic` with marker `wg-basic:m005:v1`. An unmarked same-name table is a conflict and survives. Exact normalized JSON expressions, chain/rule inventory, marker, and desired hash are checked; copied comments cannot conceal expression drift. |
| Atomic bounded backend | The service directly invokes `nft` with internally rendered batch input, no shell, 32 KiB input cap, 256 KiB per-stream output cap, five-second timeout, and a minimum userspace version check. Owned table replacement is one nft transaction; backend failures are redacted. |
| Forwarding semantics | Only `/proc/sys/net/ipv4/ip_forward` is read/written. Required policy changes `0` to `1`; disabling removes only the owned nft table and never resets forwarding. E2E asserts the host setting remains `1` after disable. |
| Filter/NAT scope | Generated forward policy permits established return traffic and configured tunnel-source traffic to the explicit egress, drops other traffic entering from the managed tunnel, and leaves unrelated forwarding at accept. Optional masquerade matches only configured source prefixes and egress. |
| Real handshake and forwarding | `three_namespace_wireguard_forwarding_nat_restart_and_preservation` runs client, server, and internet namespaces with kernel WireGuard, veths, netd, and nftables. The client handshakes and ping fails without NAT, then succeeds with masquerade. The internet namespace has no route to `10.8.0.0/24`, so success demonstrates the configured return path. |
| Idempotence/restart/retry | Identical policy reapply returns `NoChange` without rule accumulation. The test restarts netd, reconciles again, confirms the owned policy is unchanged, and confirms traffic continues. Dynamic kernel zero values for disabled keepalive/cleared endpoints are normalized in the WireGuard observer so they do not create false drift. |
| Disable and external firewall behavior | Disable deletes only `inet wg_basic`, preserves `ip_forward=1`, and leaves the independent `fixture_keep` table intact. A separate later-priority drop table blocks traffic until that table is removed, proving an independent firewall may still drop packets. |
| Unrelated host state | A fixture nft table snapshot is compared semantically with dynamic handles/counters removed; it survives apply, NAT transition, reapply, restart, and disable. The unrelated `203.0.113.0/24` route also survives. |
| Rust/MSRV gates | On Rust 1.89, `cargo +1.89.0 fmt --all -- --check`, `cargo +1.89.0 check --workspace --all-targets --locked`, `cargo +1.89.0 clippy --workspace --all-targets --locked -- -D warnings`, and `cargo +1.89.0 test --workspace --locked` all passed locally. The hosted Rust job ran the corresponding four checks successfully. Workspace test result: 41 library tests, 1 binary test, and 2 privileged-protocol integration tests passed; feature-gated kernel tests were run in dedicated jobs. |
| Rootful qualification | GitHub Actions run `37593324627` ran `cargo test --locked --features linux-integration --test network_control_e2e -- --nocapture` in the rootful `network-control-e2e` job: **2 passed, 0 failed, 0 ignored**. The job installs iproute2, iputils-ping, and nftables and verifies runtime prerequisites. The same run passed `wireguard-kernel` (**2 passed**) and `network-reconcile-kernel` (**2 passed**). All four CI jobs succeeded. |
| Operator/architecture documentation | `architecture/firewall.md`, `architecture/reconciliation.md`, `architecture/privilege-boundary.md`, `architecture/overview.md`, and `README.md` document the policy boundary, ownership, forwarding behavior, external-firewall limitation, and qualification command. |

## Backend research and decision

M005 compared direct Rust netfilter libraries with a bounded internal `nft` process backend. `nf_tables` 0.1.0 did not provide the required ownership-table observation/dump path at adequate maturity; `nlink` 0.29.0 requires Rust 1.98, above the repository's Rust 1.89 MSRV; `nftnl` 0.9.4 is MSRV-compatible but introduces native libmnl/libnftnl requirements and a less complete/rough API for the required expressions and inspection. The selected direct `nft` executable boundary keeps policy typed and rendering internal, and is constrained by version, input/output, timeout, and redaction checks. Its API boundary permits a future direct backend without changing the privileged protocol.

The owned table uses a stable marker, generated comments/hash, exact normalized JSON expression comparison, and atomic whole-table transactions. It owns a forward base chain and optional postrouting NAT chain only. The base chain uses standard `filter` priority with accept policy; an accept here does not override a later independent firewall drop. The UDP listen-port input exception remains an operator/host-firewall responsibility.

## Supported limits and unresolved findings

- IPv4 only; inet-family NAT requires Linux 5.2 or newer and nft userspace 0.9.0 or newer.
- One managed WireGuard interface and one explicit egress in the qualified path; at most 64 source prefixes.
- No policy routing, arbitrary rules, input UDP-port management, firewall-manager takeover, or guarantee against another firewall chain dropping traffic.
- Forwarding is host-global and intentionally remains enabled after policy removal.
- SQLite persistence, durable ownership provenance, service/UI, and operator doctor integration are downstream phases.
- Findings: no unresolved high- or medium-severity M005 ownership/correctness finding remains. The E2E test exposed kernel representations of disabled keepalive and cleared endpoint as zero-valued `Some` fields; observer normalization was implemented and covered by a unit test. The final rootful restart/reconcile scenario passes.

Disposition: `closed`.

## Successor readiness and plan queue

M005 closes the M001–M005 network-control foundation. Phase 6 durable desired state is ready to plan against the stable M004/M005 reconciliation, ownership, and network-policy contracts. Phase 7 service/security substrate is ready to plan because Phase 2's typed privileged protocol is closed. Phase 8 remains blocked on Phases 6 and 7 until both implementation plans are completed and closed.

No further implementation plan is currently eligible or present. The registry's ready/active implementation-plan table is empty. Per the planning process, future Phase 6 and Phase 7 plans should be written when each has a bounded evidence-backed handoff; no broad successor plan is created merely to populate the roadmap. There are no additional successive eligible implementation plans to execute now.
