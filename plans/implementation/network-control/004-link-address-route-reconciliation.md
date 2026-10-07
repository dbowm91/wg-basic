# Network Control M004 — Link, Address, Route, and Reconciliation Engine

Status: closed

Repository planning baseline: `a134b39` (M003 strict implementation head)

Implementation/final head: `5c06062` (M004 accepted after hosted rootful qualification)
Closure evidence: `plans/closure/network-control/004-status.md`

Source roadmap:

- `plans/subsystems/network-control-roadmap.md#10-milestone-m004--link-address-route-and-reconciliation-engine`
- `plans/002-long-term-roadmap.md#6-phase-4--link-address-route-and-reconciliation-engine`

Canonical requirements:

- `plans/000-long-term-specification.md#9-host-networking-ownership`
- `plans/000-long-term-specification.md#11-reconciliation-model`
- `plans/001-terminology-and-domain-model.md#15-desired-state`
- `plans/001-terminology-and-domain-model.md#16-observed-state`
- `plans/001-terminology-and-domain-model.md#17-reconciliation-plan`
- `plans/adr/001-linux-native-control-plane.md`

Primary class: infrastructure / invariant

Hard dependency:

- M003 strictly closed.

## 1. Objective

Extend the network service from WireGuard-device configuration to complete typed ownership of:

- WireGuard link lifecycle;
- tunnel interface addresses;
- managed routes;

and introduce the first production reconciliation engine:

```text
desired -> observe -> validate -> plan -> apply -> re-observe -> verify
```

M004 MUST preserve M003's WireGuard control as one layer rather than absorbing all network state into one opaque “apply config” call.

Firewall, NAT, and host forwarding are M005.

## 2. Entry research

Before implementation:

1. inspect the M003 backend and closure;
2. evaluate current `rtnetlink`, `netlink-packet-route`, consolidated alternatives such as `nlink`, and any already-transitive netlink stack;
3. prefer one coherent netlink stack where practical, but do not rewrite a working M003 backend solely to make dependency names uniform;
4. verify current APIs for:
   - link enumerate/get;
   - WireGuard link-kind creation;
   - link up/down;
   - address enumerate/add/delete;
   - route enumerate/add/delete;
   - network namespace test operation if used directly;
5. record MSRV/license/dependency effects.

Do not use `ip` in shipped M004 production mutation.

## 3. Production ownership boundaries

M004 owns only resources represented in the desired-state input and validated within the accepted ownership policy.

### Link

A desired managed interface names the expected kernel interface.

Rules:

- missing link may be created as kind WireGuard;
- existing link of another kind is a conflict;
- existing WireGuard link is not automatically safe to delete merely because its name matches;
- removal requires an explicit managed/owned disposition supplied by the higher-level desired-state contract or a creation receipt within the current lifecycle;
- later durable-state work will strengthen restart ownership.

Do not delete an uncertain pre-existing interface.

### Addresses

wg-basic may add/delete only exact interface addresses belonging to the desired managed interface and known managed set.

Unrelated secondary addresses on the same interface MUST survive unless the future product explicitly owns the complete address set and that ownership is documented.

The first implementation SHOULD prefer additive/exact-managed address ownership rather than “replace all addresses.”

### Routes

The first implementation owns a deliberately small route shape.

Prefer:

- unicast routes;
- explicit destination prefix;
- explicit output interface;
- main table unless a later plan expands policy routing;
- no arbitrary rule/policy-routing mutation.

An existing conflicting route must produce a conflict rather than silent replacement.

Removal is exact-match and ownership-aware.

## 4. Desired state completion

Extend M001/M003 types into a complete network-control desired state for this phase.

Conceptually:

```text
DesiredManagedInterface {
    interface_id,
    interface_name,
    lifecycle,
    wireguard,
    addresses,
    routes,
}
```

Do not add M005 firewall/forwarding fields beyond typed placeholders.

The desired state must validate before any mutation:

- unique interface name;
- unique peer keys;
- unique client/tunnel addresses;
- valid address family/prefix relationships;
- route destinations parse and are bounded;
- route output refers to the managed interface;
- no contradictory lifecycle request.

## 5. Observed state

Create one point-in-time observed representation containing enough kernel facts to plan safely:

- link present/missing;
- ifindex;
- link kind;
- admin/up state;
- MTU if owned in desired state;
- M003 WireGuard observed state;
- addresses on the interface;
- relevant routes;
- kernel identifiers required for exact mutation.

Observation errors MUST abort planning; do not plan from partial host state unless the error is explicitly classified as irrelevant to a resource outside the managed scope.

## 6. Reconciliation planner

The planner MUST be a pure/deterministic function where practical:

```text
(desired, observed, ownership context) -> ReconcilePlan | Conflict
```

It MUST NOT mutate the kernel.

A plan contains typed mutations, not shell commands or raw netlink bytes.

Potential mutations:

- create WireGuard link;
- apply M003 WireGuard device patch;
- add/delete exact managed address;
- add/delete exact managed route;
- set link up/down;
- delete owned link when explicitly authorized.

The planner should produce a stable human/machine summary suitable for future `dry-run`.

## 7. Mutation ordering

Define and test ordering rather than relying on HashMap/set iteration.

A normal create/enable flow should follow a dependency-safe order such as:

1. create missing WireGuard link;
2. configure M003 WireGuard device/peers;
3. add intended addresses;
4. add intended routes;
5. set final link state/up.

Exact order may change if kernel evidence requires it.

A disable/remove flow must reverse dependencies safely:

1. remove owned routes that require the link;
2. remove owned addresses when desired;
3. set down if required;
4. delete link only when explicit ownership proof permits.

Do not remove firewall/NAT here.

## 8. Plan identity and verification

Every mutation SHOULD have a stable operation category/target description.

An apply result must distinguish:

- not attempted;
- applied;
- already converged/raced-to-desired;
- failed before mutation;
- failed with state uncertain after kernel response where applicable.

After applying the full plan, re-observe the managed scope and verify against desired state.

A successful system call sequence without post-observation is not convergence evidence.

## 9. Idempotence

Required property:

```text
apply(plan(desired, observe()))
observe()
plan(desired, observe()) == empty
```

for a successful supported desired state.

Test:

- first apply mutates;
- second plan is empty;
- second apply is a no-op;
- telemetry-only changes do not create configuration mutations.

## 10. Partial failure and retry

Create deterministic injection seams around backend mutations.

Required fixture:

- a multi-step plan is produced;
- an injected failure occurs after at least one successful mutation;
- apply returns a partial receipt, not “success”;
- re-observation reflects actual state;
- a fresh planner derives only remaining/corrective operations;
- retry converges.

Do not promise transactional kernel rollback where the kernel APIs do not provide it.

If safe compensation is implemented for an immediately created resource, record it as compensation, not an ACID transaction.

## 11. Concurrency

Use one mutation lock per installation/managed interface scope initially.

Requirements:

- two concurrent reconciliations cannot interleave mutations for the same managed interface;
- read-only telemetry may remain concurrent if M003 backend safety permits;
- lock cancellation/shutdown cannot leave a detached apply;
- no unbounded mutation queue.

The management process may later coalesce desired-state changes; M004 need not implement a scheduler.

## 12. Privileged protocol

Prefer exposing reconciliation as high-level operations rather than one IPC round-trip per netlink syscall.

Candidate shape:

- `ObserveManagedInterface`;
- `PlanManagedInterface`;
- `ApplyManagedInterface`.

Alternatively, management service may send validated desired state and netd may always observe/plan/apply internally.

Security preference: netd SHOULD own final observation, ownership validation, and plan derivation so a compromised management process cannot instruct lower-level arbitrary mutation sequences.

A `Plan` request may expose the resulting typed plan for dry-run display.

## 13. Network namespace integration

M004 should reduce fixture dependence on `ip` for production-owned operations.

The test harness MAY still use `ip netns`/veth setup to create disposable namespace topology if direct namespace plumbing is not a product requirement.

Within the managed namespace, production M004 code MUST perform:

- WireGuard link create;
- link state;
- tunnel address assignment;
- managed route mutation.

M003 production code continues to own WireGuard device configuration.

## 14. Preservation fixtures

Required cases:

- unrelated link survives;
- unrelated address on another link survives;
- unrelated route survives;
- wrong-kind same-name link yields conflict and survives;
- conflicting existing route is not silently replaced;
- uncertain pre-existing same-name WireGuard link is not deleted without explicit ownership.

Where exact route enumeration order varies, compare semantic sets rather than byte dumps.

## 15. Focused tests

Unit:

- desired-state validation;
- pure planner from synthetic observed fixtures;
- deterministic mutation ordering;
- conflict classification;
- exact address/route diff;
- deletion ownership policy;
- telemetry ignored by config planner;
- empty second plan/idempotence.

Linux integration:

- create link via production backend;
- apply M003 config;
- add/remove address;
- add/remove route;
- up/down;
- observe round-trip;
- preservation fixtures;
- partial-failure retry;
- delete only explicitly owned fixture link.

## 16. CLI/operator projection

If useful, add a development/admin command that prints a reconcile plan without applying it.

Do not expose a broad production `--force` that bypasses ownership checks.

Any future adoption of an existing interface must be explicit and separately planned if it weakens default fail-closed behavior.

## 17. Verification

Routine:

```text
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
```

Rootful Linux integration:

```text
sudo -E cargo test --locked --features linux-integration --test network_reconcile -- --nocapture
```

Exact test names are implementation-defined.

Add a source/runtime guard that production link/address/route mutation does not invoke `ip`.

## 18. Documentation

Update:

- `architecture/overview.md`;
- add `architecture/reconciliation.md`;
- update `architecture/wireguard-control.md` with ownership layering;
- document current supported route shape;
- document partial-failure/retry semantics;
- document the existing-interface deletion/adoption rule.

Current docs must state that NAT/firewall/forwarding is still absent.

## 19. Acceptance criteria

M004 closes only when:

1. production code creates/observes/manages WireGuard links through Rust kernel APIs;
2. addresses and managed routes are observed/mutated through RTNETLINK;
3. desired/observed planning is deterministic and non-mutating;
4. apply re-observes and verifies;
5. successful reapply is a no-op;
6. partial failure returns truthful receipt and fresh retry converges;
7. same-scope mutation is serialized;
8. unrelated host network fixtures survive;
9. uncertain/wrong-kind resources fail closed;
10. production mutation does not invoke `ip`;
11. routine/MSRV and rootful integration evidence pass.

## 20. Stop conditions

Stop and research/revise if:

- the chosen route/link library cannot represent exact required semantics;
- safe existing-interface ownership cannot be expressed without durable state and the proposed code would delete uncertain resources;
- implementation requires policy-routing/general router scope;
- M003 backend cannot coexist safely with selected RTNETLINK stack;
- a “force” bypass is proposed to satisfy tests;
- namespace fixture limitations prevent real-kernel evidence.

## 21. Closure evidence

Record:

- selected RTNETLINK dependencies and rationale;
- supported link/address/route shapes;
- reconciliation plan example;
- first/second apply mutation counts;
- partial-failure/retry trace;
- preservation fixture results;
- exact rootful integration commands/results;
- production `ip` invocation guard result;
- known limitations and persistence assumptions;
- recommendation on M005 readiness.

M005 becomes `ready` only after strict M004 closure.
