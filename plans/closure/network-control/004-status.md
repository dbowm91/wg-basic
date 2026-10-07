# Network Control M004 Closure

Status: closed

Implementation baseline: `a134b39` (closed M003 head)
Final implementation head: `e01f35b` (M004 implementation and focused verification)
Qualification run: GitHub Actions CI run `37589313193`, commit `e01f35b`

## Outcome

M004 is strictly closed. The service now reconciles typed WireGuard link lifecycle, WireGuard device/peer state, exact interface addresses, and supported main-table unicast routes through a deterministic desired/observed planner. RTNETLINK handles link, address, and route operations; M003 continues to handle WireGuard configuration and telemetry. Apply serializes mutation, re-observes after each full attempt, verifies convergence, and reports partial progress without claiming rollback.

## Requirement-to-evidence matrix

| Requirement | Evidence |
|---|---|
| Link lifecycle uses native APIs and wrong-kind links fail closed | `LinuxNetworkBackend` uses `rtnetlink` for link-kind observation, WireGuard creation, state change, and deletion. The rootful namespace fixture creates a managed WireGuard link through netd and verifies a same-name dummy link returns a conflict and survives. |
| Addresses/routes use RTNETLINK and preserve unrelated state | The fixture adds `10.77.0.1/24` and `203.0.113.0/24` through the production backend, then removes the owned link. Its unrelated `fixture0`, `192.0.2.9/24`, and `198.51.100.0/24` route survive. Address-derived connected routes and local-table routes are excluded from independently managed routes. |
| Pure, stable, typed planning | Unit tests cover deterministic create/address/link-up/route order, conflicting destination, invalid deletion ownership, unlisted addresses/routes, and no production `ip` subprocess. Plan actions have stable operation kind and target summaries. |
| Apply re-observes and verifies; reapply is a no-op | `kernel_reconciliation_manages_link_address_and_route_and_preserves_other_link` passed on a rootful Ubuntu 24.04 runner. First apply returned `Applied`; identical second apply returned `NoChange`; explicit deletion returned `Applied`. |
| Telemetry changes do not create config mutations | `telemetry_only_wireguard_changes_do_not_create_mutations` changes handshake/RX/TX while desired configuration remains equal and produces an empty plan. |
| Partial failure is truthful and retry converges | `partial_apply_is_observed_and_retry_converges` injects a failure after one successful address mutation. The first receipt is `PartialFailure` with one completed action and fresh observation; retry performs only the link-state action and converges; third apply is `NoChange`. |
| Mutation is serialized | `ReconciliationService` holds one installation-wide mutex for observe/plan/apply/re-observe; `SocketServer` dispatch remains sequential and bounded. No detached apply task is spawned. |
| Routine/MSRV checks | Hosted CI passed format, locked all-target check, clippy with warnings denied, and default tests on Rust 1.89. Local `cargo +1.89.0 check --all-targets --locked`, clippy, tests, and feature-enabled all-target check passed during implementation. |
| Rootful kernel evidence | `sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test network_reconcile -- --nocapture`: **2 passed, 0 failed, 0 ignored**, including actual kernel link/address/route apply, no-op reapply, wrong-kind refusal, deletion, and preservation. CI run `37588887521` supplied this evidence; the final head adds a telemetry-only pure-planner test and CI run `37589313193` was also green. |

## Dependency research and supported shape

M004 selected `rtnetlink` 0.23.0 (MIT, published MSRV 1.75) for typed WireGuard link creation, link observation/state, address observation/add/delete, and route observation/add/delete. Its `netlink-packet-core` 0.9 and `netlink-proto` 0.13 dependencies are shared with M003's `nl-wireguard`; the locked Rust 1.89 check confirms compatibility. `netlink-packet-route` 0.33 is MIT. `nlink` 0.29.0 was rejected because it requires Rust 1.98 and introduces a separate transport stack.

Managed routes are limited to main-table unicast routes with destination prefix, managed output interface, and optional same-family gateway. Policy routing, multipath, route metrics, local-table routes, and kernel-derived connected routes are out of scope. Installing a route through a down link requires a temporary link-up before the route operation; final desired state is applied afterward.

## Limitations and unresolved findings

- `Managed` is a request-scoped ownership declaration, not durable adoption provenance. Restart ownership persistence remains future work. Deleting a pre-existing link requires explicit managed/absent disposition and explicit enumeration of all observed addresses and supported routes; unlisted/unsupported resources refuse deletion.
- The backend intentionally supports only the documented simple route shape. It does not own arbitrary routing rules, firewall state, NAT, or forwarding.
- This milestone qualifies kernel object management and route installation, not end-to-end forwarded tunnel traffic. M005 owns the three-node WireGuard/forwarding/NAT fixture.
- No unresolved M004 correctness or ownership finding remains.

## Follow-on readiness

M005's hard dependency is satisfied and its plan is promoted to `ready` against `e01f35b`. Phase 6 durable-state planning is also unblocked by the stable M004 ownership boundary and is marked `ready to plan`; implementation sequencing may overlap late M005 work. No Phase 6 implementation plan exists yet, and the repository planning process says not to create one merely to fill the roadmap.
