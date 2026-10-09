# IPv6 M003 — Client Route Policy and Product Surface

Disposition: **closed**.

Date: 2026-10-09

## Implementation revision

- M002 strict-closure baseline: `306ec649911e49cf5ee92e7289b1e3dc918abd03`.
- M003 implementation commit and final implementation head:
  `7bfa28f0b3acca0de04d28988daae80826d2b554`.
- Full hosted CI: [run 37955744248](https://github.com/dbowm91/wg-basic/actions/runs/37955744248), all 15 jobs passed.
- Hosted product and authenticated API qualification:
  [product-management-rootful job 113905694296](https://github.com/dbowm91/wg-basic/actions/runs/37955744248/job/113905694296), passed.
- Hosted IPv6 forwarding/firewall qualification:
  [network-control-e2e job 113905694350](https://github.com/dbowm91/wg-basic/actions/runs/37955744248/job/113905694350), passed.
- Hosted systemd install/ownership qualification:
  [system-install-systemd job 113905694275](https://github.com/dbowm91/wg-basic/actions/runs/37955744248/job/113905694275), passed.

## Requirement-to-evidence matrix

| Requirement | Evidence | Result |
|---|---|---|
| Explicit IPv4 and IPv6 route choices, including full and split routes | Route-policy domain tests accept `0.0.0.0/0`, `::/0`, and split prefixes; the embedded setup and client editor offer separate no-route/full/split controls for both families. Product tests accept IPv6 full tunnel only after managed IPv6 pool and client assignment exist. | Passed. |
| Bounded, unique, normalized unicast route prefixes | `ClientRoutePolicy::validate` enforces a 64-prefix maximum, duplicate detection after truncating serde input, and rejects unspecified/multicast prefixes other than the explicit family defaults. Unit tests cover each case. | Passed. |
| IPv6 routes require a managed server pool and an address assigned to that client | Desired-state tests reject IPv6 global routes without a server pool. Product tests reject an IPv6 client route on an IPv4-only client without advancing generation, and accept `::/0` for an allocated dual-stack client. | Passed. |
| Address assignment does not infer route intent; client policy remains separate from peer AllowedIPs | New address allocation leaves the policy empty unless explicitly configured. Existing `server_allowed_ips_and_client_route_policy_remain_separate` state-store test and hosted rootful product qualification preserve the distinction. | Passed. |
| Invalid HTTP mutations fail before commit and retain generation semantics | `management_http` submits an invalid IPv6 policy for an IPv4-only client, receives 422, and verifies generation and route policy remain unchanged. Existing session, CSRF, Origin, and generation checks remain in place. | Passed. |
| Selected routes, IPv6 endpoint literals, and DNS render correctly | Export unit/API tests assert stable `AllowedIPs`, IPv6 tunnel address, IPv6 DNS, and exactly one bracket pair around an IPv6 endpoint. The existing IPv4 config exact-output test remains unchanged and passes. | Passed. |
| Policies persist across reopen, backup, and restore without a migration | Product test reopens the store after saving `::/0`; backup/restore fixtures include `::/0` plus an IPv6 split prefix and compare the restored typed desired state. No schema migration was required. | Passed. |
| Operator controls preserve independent family choices and do not turn routes on implicitly | Embedded forms use separate family selectors. Default setup preserves the IPv4 split default and starts IPv6 at no route; assigning a client IPv6 address does not modify policy. Documentation describes egress requirements and the distinction from traffic qualification. | Passed. |

## Verification

Successful local commands and results:

- `cargo fmt --all -- --check` — passed.
- `cargo check --all-targets --locked` — passed.
- `cargo clippy --all-targets --locked -- -D warnings` — passed.
- `cargo test --locked` — 580 passed, 3 ignored, 36 suites.
- `cargo +1.89.0 check --all-targets --locked` — passed.
- `cargo test --locked --features linux-integration --test product_management_rootful --no-run` — passed; no rootful suite was run locally.
- `git diff --check` — passed.

The complete hosted run passed all 15 jobs, including the Rust suite, all
rootful network/product/state/maintenance suites, systemd install qualification,
dependency audit, and both updater rehearsal workflows. The product-management
rootful fixture exercised dual-stack allocation, API route policy, export, and
client lifecycle. The network-control fixture qualified the routed IPv6 server
path; selected client IPv6 traffic is intentionally reserved for M004.

## Security, compatibility, and documentation

Route policy remains a typed client-config value behind the existing
authenticated generation-checked worker path. It adds no privileged operation,
filesystem access, command text, server route, firewall mutation, or schema
migration. The HTTP service remains unprivileged. IPv4-only setup defaults and
representative exported configuration remain unchanged. The embedded asset
total ceiling was raised from 32 KiB to 36 KiB to accommodate the separate
family controls; each individual asset remains bounded at 24 KiB.

Current behavior is documented in `architecture/domain-model.md`,
`architecture/product-management.md`, `architecture/state-store.md`,
`architecture/testing-qualification.md`, `docs/client-enrollment.md`, and
`docs/development.md`.

No unresolved high- or medium-severity M003 finding remains. End-to-end
client-routed IPv6 traffic, full/split tunnel dataplane behavior, restart
reapply, and unrelated host-state preservation have not yet been claimed; they
are M004 acceptance evidence.

## Successor disposition

M003 is strictly closed. Its hard dependency is satisfied, and M004 is
unblocked under
`plans/implementation/ipv6-route-policy/004-dual-stack-e2e-and-phase-11-closure.md`.
Phase 11 remains active until M004 strictly closes.
