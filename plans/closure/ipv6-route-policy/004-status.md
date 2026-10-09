# IPv6 M004 — Dual-Stack E2E and Phase 11 Closure

Disposition: **closed**. Phase 11 is technically closed.

Date: 2026-10-09

## Implementation revision

- M003 strict-closure baseline: `7bfa28f0b3acca0de04d28988daae80826d2b554`.
- M004 implementation commits: `d73f83e` and `f72ac4d`.
- Final implementation head: `f72ac4db3bc6b3eb1ecdf523e656a164703770e9`.
- Full hosted CI: [run 37959251834](https://github.com/dbowm91/wg-basic/actions/runs/37959251834), all 15 jobs passed.
- Hosted real product/API/client fixture:
  [product-management-rootful job 113917592634](https://github.com/dbowm91/wg-basic/actions/runs/37959251834/job/113917592634), 6 passed.
- Hosted full/split IPv4/IPv6 dataplane fixture:
  [network-control-e2e job 113917592920](https://github.com/dbowm91/wg-basic/actions/runs/37959251834/job/113917592920), 2 passed.
- Hosted systemd install/ownership fixture:
  [system-install-systemd job 113917592267](https://github.com/dbowm91/wg-basic/actions/runs/37959251834/job/113917592267), passed.
- Hosted supported-schema update rollback/retry and rootful upgrade rehearsal:
  jobs `113917592380` and `113917592905`, both passed.
- Hosted backup/restore, restart/recovery, maintenance, doctor, kernel WireGuard,
  network reconciliation, dependency audit, and standard upgrade rehearsal jobs
  all passed in the same full run.

## Requirement-to-evidence matrix

| Requirement | Evidence | Result |
|---|---|---|
| Real client handshake and IPv4/IPv6 traffic using an API-exported full-tunnel config | `exported_client_config_establishes_a_real_kernel_handshake` configures the client from authenticated API export with `0.0.0.0/0` and `::/0`, proves the peer handshake/counters, and carries IPv6 tunnel traffic. The three-namespace fixture proves IPv4 NAT and routed IPv6 egress/return traffic without NAT66. | Passed. |
| Full-tunnel and split-tunnel route behavior for both families | The three-namespace fixture begins with explicit family default routes and proves selected IPv4 and IPv6 destinations pass. It applies independent split prefixes, proves traffic to selected egress destinations passes, and proves IPv4/IPv6 targets outside those prefixes do not use the tunnel. The API export fixture verifies selected `AllowedIPs` exactly. | Passed. |
| Client disable/re-enable and server restart/reapply restore the same traffic and peer state | The product fixture disables the client, confirms the server peer disappears and IPv6 traffic stops, then re-enables the same peer, refreshes its session, and confirms IPv6 traffic resumes. The network-control fixture applies split routes, restarts server netd, reapplies policy, and verifies both family paths still pass. | Passed. |
| Preserve unrelated host state, keep forwarding sticky, and avoid NAT66 | The namespace test compares a foreign nftables table, retains an unrelated route and IPv4/IPv6 egress addresses through policy removal and interface teardown, proves an independent drop still blocks both families, confirms global IPv6 forwarding remains `1`, and inspects the owned rules for absence of NAT66. | Passed. |
| Backup/restore, migration, and IPv4-only compatibility | The M003 backup/restore fixture stores `::/0` and an IPv6 split route and compares the restored typed state. Full CI passes durable backup and old-schema update/restore rehearsals. Existing exact IPv4 config rendering and migration tests pass unchanged. No M004 schema migration was required. | Passed. |
| Service-manager/runtime and footprint qualification | Hosted systemd installation/ownership qualification passed. The local release footprint test passed and measured combined serve/netd RSS of 15.30 MiB, below its 30 MiB engineering signal, with a 33,579-byte embedded shell under its 36 KiB bound. The five-sample medians were 107.96 ms cold readiness, 1.12 ms `/healthz`, 33.93 ms login including Argon2id, and 20.25 ms authenticated health. | Passed. |
| Current behavior docs match tested limits and make no release claim | Updated firewall, product management, testing qualification, development, operations runbook, and client enrollment docs describe full/split route behavior, explicit upstream return routing, the lack of NAT66, and the limits of operator-provided egress. Production signing/publication remains explicitly external. | Passed. |

## Verification

Successful local commands and results:

- `cargo fmt --all -- --check` — passed.
- `cargo check --all-targets --locked` — passed.
- `cargo clippy --all-targets --locked -- -D warnings` — passed.
- `cargo test --locked` — 580 passed, 3 ignored, 36 suites.
- `cargo +1.89.0 check --all-targets --locked` — passed.
- `cargo test --locked --features linux-integration --test product_management_rootful --no-run` — passed; rootful tests were not run locally.
- `cargo test --locked --features linux-integration --test network_control_e2e --no-run` — passed; rootful tests were not run locally.
- `cargo test --release --locked --test service_footprint -- --nocapture` — 2 passed; measured figures are recorded above.
- `git diff --check` — passed.

The full hosted CI run passed all 15 jobs. The product fixture reported 6
passed, 0 failed, including the exported full-tunnel client lifecycle. The
three-namespace IPv4/IPv6 control fixture reported 2 passed, 0 failed. No
rootful suite was run locally.

## Security, ownership, and compatibility

M004 adds qualification coverage and test-only fixture logic; it does not add a
production privileged operation, raw route/firewall text, arbitrary sysctl
path, process execution path, runtime dependency, or schema migration. The
client route contract stays in the authenticated desired-state path. IPv6 is
routed through explicit tunnel and upstream return routes, not NAT66. Firewall
and unrelated egress state remain outside wg-basic's ownership. The systemd
capability allowlist and fixed global forwarding ownership contract remain
unchanged.

No unresolved high- or medium-severity M004 finding remains.

## Phase 11 disposition

All Phase 11 milestones M001–M004 are strictly closed. The subsystem roadmap,
macro roadmap, implementation plan, and registry record Phase 11 as technically
closed. Phase 12 advanced capabilities remains deferred pending a product
decision. Distribution production signing/publication remains blocked on
maintainer-provisioned production trust material and explicit release action;
it is independent of Phase 11 engineering closure.
