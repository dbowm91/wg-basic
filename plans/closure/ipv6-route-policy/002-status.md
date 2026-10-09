# IPv6 M002 — Forwarding, Firewall, and Host Ownership

Disposition: **closed**.

Date: 2026-10-09

## Implementation revision

- M001 strict-closure baseline: `fa25918b824641e00944e3edf335f7055cb11dcc`.
- Final implementation head: `306ec64` (including `6ff15d5` and `c93f715`).
- Full hosted CI: [run 37952330395](https://github.com/dbowm91/wg-basic/actions/runs/37952330395), all 15 jobs passed.
- Hosted rootful IPv6 forwarding/firewall fixture: [network-control-e2e job 113894015843](https://github.com/dbowm91/wg-basic/actions/runs/37952330395/job/113894015843), 2 passed.
- Hosted systemd qualification: [system-install-systemd job 113894015844](https://github.com/dbowm91/wg-basic/actions/runs/37952330395/job/113894015844), passed.

## Requirement-to-evidence matrix

| Requirement | Evidence | Result |
|---|---|---|
| Preserve IPv4-only defaults, APIs, firewall expressions, and forwarding behavior | IPv4 policies default IPv6 forwarding off; schema migration defaults existing state to false; existing Rust, network, product, and updater qualification all passed in the final CI run. | Passed. |
| Persist and validate explicit IPv6 forwarding policy through the typed boundary | Schema v7 stores an explicit default-false field; migration, rollback, product setup, projection, state reopen, and backup/restore tests cover opt-in and old rows. Protocol values contain no sysctl paths or caller-authored commands. | Passed. |
| Enable only fixed global IPv6 forwarding to `1`; never reset it | Netd observes strict boolean values and writes only `/proc/sys/net/ipv6/conf/all/forwarding` with `1`. The hosted namespace fixture starts with forwarding disabled, observes the per-interface forwarding effect, injects firewall failure after the sysctl write, then proves retry, policy disable, and interface teardown leave forwarding enabled. | Passed. |
| Carry routed IPv6 traffic and established return traffic without NAT66 | The three-namespace hosted fixture sends native WireGuard client traffic to a routed IPv6 egress peer with an explicit upstream return route. The generated IPv6 source rule passes traffic; inspection confirms masquerade rules remain IPv4-only. | Passed. |
| Preserve foreign firewall state and independent denial | The fixture snapshots a foreign nftables table before policy operations and compares it afterward. A later independent drop blocks both IPv4 and IPv6 traffic until that table is removed. | Passed. |
| Cover failure, retry, disable, restart, migration, backup/restore, and doctor behavior | Rootful netd test verifies a partial receipt after injected nft failure and successful retry, disable, restart/reapply, teardown, and sticky forwarding. Default state tests cover migration and backup/restore of opt-in state. Doctor remains read-only and reports the explicit requirement. | Passed. |
| Keep systemd privileges bounded to the selected fixed sysctl paths | `wg-basic-netd.service` grants writable access only to runtime state and the fixed IPv4 and IPv6 forwarding controls. Hosted native systemd install/ownership qualification passed. | Passed. |

## Verification

Local commands actually run:

- `cargo fmt --all -- --check` — passed.
- `cargo check --all-targets --locked` — passed.
- `cargo clippy --all-targets --locked -- -D warnings` — passed.
- `cargo test --locked` — 573 passed, 3 ignored.
- `cargo +1.89.0 check --all-targets --locked` — passed.
- `cargo test --locked --features linux-integration --test network_control_e2e --no-run` — passed; the rootful suite was not run locally.

The final hosted CI run passed all 15 jobs, including Rust, dependency audit,
systemd installation, all rootful network/product/maintenance/backup jobs, and
the signed updater transaction and migration rehearsal suites. The dedicated
network-control fixture reported 2 passed, 0 failed, 0 ignored.

## Security and ownership evidence

The only new privileged write is the fixed global IPv6 forwarding control,
enabled only to `1`. Its host-wide Host/Router and Router Advertisement effects
are documented; disable and teardown never restore it. The nftables mutation
remains an atomic operation scoped to the installation-owned `inet wg_basic`
table. IPv6 is routed using explicit source prefixes and egress; NAT66 and
arbitrary routes, rules, sysctl paths, and nftables text are not supported.
Systemd writable paths and doctor read-only behavior match these boundaries.

No unresolved high- or medium-severity M002 finding remains.

## Documentation and limitations

Current behavior is recorded in `architecture/firewall.md`,
`architecture/privilege-boundary.md`, `architecture/service-hardening.md`,
`architecture/state-store.md`, `architecture/diagnostics-maintenance.md`,
`architecture/product-management.md`, `architecture/testing-qualification.md`,
`docs/operations-runbook.md`, and `docs/development.md`.

IPv6 forwarding is explicit and host-global, remains enabled after wg-basic
disables policy or tears down the interface, requires the operator to install
an upstream route, and does not use NAT66. M003 client route policy and product
surface remain successor scope; M004 end-to-end dual-family qualification
remains blocked until M003 strictly closes.

M002 is strictly closed. M003 is unblocked and active under its bounded
implementation handoff; M004 remains blocked on M003.
