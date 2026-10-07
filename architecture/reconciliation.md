# Network reconciliation and ownership

## Scope

The Linux reconciliation service accepts one typed desired interface and observes its named link, kind, administrative state, addresses, supported routes, and M003 WireGuard state. Planning is pure and deterministic. Applying is serialized within the netd process, executes typed operations, re-observes the managed scope, and returns a receipt with planned/completed actions and any safe failure category.

M004 uses `rtnetlink` 0.23.0 for link, address, and route operations. It is MIT licensed and its published changelog declares an MSRV of Rust 1.75. The selected APIs support WireGuard link creation, link enumeration/state, address enumeration/add/delete, and route enumeration/add/delete. Its `netlink-packet-core` 0.9 / `netlink-proto` 0.13 stack is shared with M003's `nl-wireguard`; the locked Rust 1.89 build passes. `netlink-packet-route` is MIT licensed and supplies the packet types. `nlink` was not selected because its current MSRV exceeds this project's Rust 1.89 baseline and it would introduce a separate transport stack.

## Ownership policy

`Managed` authorizes mutations for the exact resources represented in the request. `ObserveOnly` can inspect an already-converged state and fails if a mutation would be needed. Creating a missing interface requires `Managed`. An existing same-name non-WireGuard link is a conflict. Deleting a WireGuard link requires explicit `Managed` lifecycle `Absent`, and the desired removal list must enumerate every address and supported route observed on that interface. Unsupported route shapes also block deletion. This is a request-level assertion, not durable proof across process restarts; durable adoption/ownership records remain future work.

Addresses are additive/exact-match resources. Unlisted secondary addresses survive normal reconciliation; deletion fails closed if any address is unlisted. Routes are limited to main-table unicast routes with an explicit destination, the managed output interface, and an optional same-family gateway. A same-destination route elsewhere is a conflict. Routes and addresses not listed for removal are preserved. Policy routing, multipath, route metrics, rules, firewall, NAT, and forwarding are outside this phase.

## Ordering and retry

An enable plan orders link creation, WireGuard device/peer configuration, address additions/removals, route additions/removals, then final link state. Link deletion removes explicitly listed routes, then addresses, lowers the link, and deletes it. Stable ordering is independent of hash iteration.

Each successful mutation is followed by re-observation. The receipt distinguishes `NoChange`, `Applied`, `AlreadyConverged`, `FailedBeforeMutation`, `PartialFailure`, and `VerificationFailed`. The service does not claim rollback. A partial receipt includes a fresh observation when available; a new apply derives only the remaining operations. An installation-wide in-process mutex prevents concurrent apply sequences from interleaving. Netd also accepts one request at a time.

Example from the kernel fixture: first apply creates the WireGuard link, configures its key/listen port, adds one address and one route, and brings the link up; it reports `Applied`. Repeating the same desired state reports `NoChange` with zero mutations. Unit fault injection allows the address add and then fails the link-state operation; the first result is `PartialFailure` with one completed action, the retry completes the one remaining operation, and a third apply is `NoChange`.

Production reconciliation calls Rust netlink APIs and contains no `ip` subprocess. The Linux integration fixture uses `ip netns`/`ip` only to set up and inspect the disposable namespace. M005 still needs firewall, forwarding, and NAT ownership.
