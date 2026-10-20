# Network reconciliation and ownership

## Scope

The Linux reconciliation service accepts one typed desired interface and observes its named link, kind, administrative state, addresses, supported routes, and M003 WireGuard state. Planning is pure and deterministic. Applying is serialized within the netd process, executes typed operations, re-observes the managed scope, and returns a receipt with planned/completed actions and any safe failure category.

M004 uses `rtnetlink` 0.23.0 for link, address, and route operations. It is MIT licensed and its published changelog declares an MSRV of Rust 1.75. The selected APIs support WireGuard link creation, link enumeration/state, address enumeration/add/delete, and route enumeration/add/delete. Its `netlink-packet-core` 0.9 / `netlink-proto` 0.13 stack is shared with M003's `nl-wireguard`; the locked Rust 1.89 build passes. `netlink-packet-route` is MIT licensed and supplies the packet types. `nlink` was not selected because its current MSRV exceeds this project's Rust 1.89 baseline and it would introduce a separate transport stack.

## Ownership policy

`Managed` authorizes mutations for the exact resources represented in the request. `ObserveOnly` can inspect an already-converged state and fails if a mutation would be needed. Creating a missing interface requires `Managed`. An existing same-name non-WireGuard link is a conflict. Deleting a WireGuard link requires explicit `Managed` lifecycle `Absent`, and the desired removal list must enumerate every address and supported route observed on that interface. Unsupported route shapes also block deletion. A created link also receives a durable owner tag as its kernel interface alias, and an existing link is eligible for authoritative mutation or destruction only when that tag matches exactly. A missing, foreign, or duplicated tag is a conflict. See [ownership](ownership.md).

Addresses are additive/exact-match IPv4 or IPv6 resources. Unlisted secondary addresses survive normal reconciliation; deletion fails closed if any address is unlisted. Routes are limited to main-table unicast routes with an explicit destination, the managed output interface, and an optional same-family gateway. A same-destination route elsewhere is a conflict. Routes and addresses not listed for removal are preserved. Policy routing, multipath, route metrics, and rules remain outside the managed route shape. M005 adds a separate typed forwarding/firewall policy service; see [firewall ownership](firewall.md).

## Ordering and retry

An enable plan orders link creation, WireGuard device/peer configuration, address changes, and route changes. Installing a route through a down link first raises that link because the kernel rejects the route with `ENETUNREACH`; the requested final link state is applied after routes. Link deletion removes explicitly listed routes, then addresses, lowers the link, and deletes it. Stable ordering is independent of hash iteration. Routes in the kernel's local table and connected main-table routes derived from interface addresses are excluded from the managed route set; removing the address removes its connected route.

Each successful mutation is followed by re-observation. The receipt distinguishes `NoChange`, `Applied`, `AlreadyConverged`, `FailedBeforeMutation`, `PartialFailure`, and `VerificationFailed`. The service does not claim rollback. A partial receipt includes a fresh observation when available; a new apply derives only the remaining operations. An installation-wide in-process mutex prevents concurrent apply sequences from interleaving. Netd also accepts one request at a time.

Example from the kernel fixture: first apply creates the WireGuard link, configures its key/listen port, adds one address and one route, and brings the link up; it reports `Applied`. Repeating the same desired state reports `NoChange` with zero mutations. Unit fault injection allows the address add and then fails the link-state operation; the first result is `PartialFailure` with one completed action, the retry completes the one remaining operation, and a third apply is `NoChange`.

Production link, address, route, and WireGuard reconciliation calls Rust netlink APIs and contains no `ip` subprocess. The M005 firewall backend invokes `nft` directly as a bounded transition path; it does not use a shell or accept caller-authored nftables text. Linux integration fixtures use `ip netns`/`ip` only to set up and inspect disposable namespaces.

## Darwin reconciliation (C001)

The Darwin service executes the *same* portable plan through the *same*
observe/apply/verify sequence as Linux. `src/reconcile/apply.rs` owns that
sequence and is portable; only the backend differs.

The Darwin backend (`src/reconcile/backend_darwin.rs`) observes through
`getifaddrs` and the routing-table dump, and mutates through typed address,
route, and link operations. It classifies the routes it finds: the kernel's
own address-derived and broadcast routes are not managed routes, a route the
planner cannot express is counted as unsupported so a delete refuses rather
than orphaning it, and the connected network the kernel derives from the
managed address is not a managed route.

Creating a managed tunnel spawns the pinned helper, adopts exactly one new
`utunN`, and records the durable receipt. Deleting one stops the helper,
waits for the kernel device to disappear, and only then drops the receipt. A
device that does not disappear fails the delete instead of leaving a claim
that no longer describes anything.
