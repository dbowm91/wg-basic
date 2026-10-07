# Network Control M005 — Firewall, Forwarding, NAT, and End-to-End Qualification

Status: blocked on M004 closure

Repository planning baseline: `188f6d341758d7c2276dbf7908353ae884d6aeec`

Source roadmap:

- `plans/subsystems/network-control-roadmap.md#11-milestone-m005--nftables-forwarding-nat-and-end-to-end-qualification`
- `plans/002-long-term-roadmap.md#7-phase-5--firewall-forwarding-nat-and-network-namespace-qualification`

Canonical requirements:

- `plans/000-long-term-specification.md#9-host-networking-ownership`
- `plans/000-long-term-specification.md#10-forwardingsysctl-semantics`
- `plans/000-long-term-specification.md#20-security-model`
- `plans/001-terminology-and-domain-model.md#23-firewall-policy`
- `plans/001-terminology-and-domain-model.md#24-firewall-namespace`
- `plans/001-terminology-and-domain-model.md#25-forwarding-policy`
- `plans/adr/001-linux-native-control-plane.md`

Primary class: capability / invariant

Hard dependency:

- M004 strictly closed.

## 1. Objective

Close the Linux network-control foundation by adding the minimum safe host forwarding and nftables/NAT behavior required for an ordinary IPv4 road-warrior WireGuard server.

M005 must prove, end to end, that wg-basic can:

- configure kernel WireGuard;
- own its link/address/routes;
- enable required forwarding without unsafe teardown;
- install only its own nftables objects;
- NAT managed tunnel traffic to an explicit egress;
- pass real traffic;
- reapply/restart without rule accumulation;
- remove/disable only owned state;
- preserve unrelated host firewall/network state.

## 2. Scope constraints

M005 is deliberately narrow.

Supported initial policy:

- IPv4;
- one managed WireGuard interface in the qualification fixture;
- one explicit egress interface;
- optional masquerade/NAT mode;
- forwarding only for managed tunnel traffic;
- dedicated wg-basic nftables table/namespace;
- no policy-routing rules;
- no arbitrary per-client firewall scripts;
- no transparent takeover of firewalld/ufw rules;
- no promise to defeat an unrelated host firewall that independently drops the traffic.

IPv6 is structurally anticipated but remains Phase 11 production qualification.

## 3. Firewall backend research

Before implementation compare current maintained approaches:

1. direct NETLINK_NETFILTER/nftables Rust libraries;
2. consolidated netlink libraries already adopted by M003/M004 if they support the required nf_tables transaction semantics;
3. a bounded internal invocation of the host `nft` binary as a transitional backend.

Evaluate:

- license/MSRV;
- active maintenance;
- table/chain/rule/set observation;
- atomic batch/transaction support;
- comments/userdata/ownership marker support;
- rule expression support for interface match, source prefix, conntrack state, masquerade;
- error fidelity;
- deletion/replacement behavior;
- dependency footprint;
- testability.

Decision preference:

- direct typed kernel API when mature enough;
- bounded `nft` process backend is acceptable only under ADR-001 constraints and when direct libraries would materially increase correctness risk.

If using `nft`:

- invoke directly, never via shell;
- accept typed `FirewallPolicy` from callers, never raw nft source;
- render input internally;
- validate interface names/prefixes before rendering;
- use atomic whole-owned-table replacement where practical;
- bound stdin/stdout/stderr and timeout;
- never interpolate peer labels or arbitrary UI text;
- isolate the exception so a future direct backend can replace it.

## 4. Firewall ownership namespace

Canonical initial table name should be stable and dedicated, for example:

```text
inet wg_basic
```

The exact legal name is an implementation decision.

Requirements:

- wg-basic owns only this table and its objects;
- existing same-name table with unrecognized ownership is a conflict, not something to flush;
- ownership marker strategy must be explicit;
- replacement operates on the owned table as one declarative unit where possible;
- unrelated tables/chains/rules are never enumerated-and-rewritten as a side effect.

Because durable installation receipts arrive later, M005 must be conservative about adopting a pre-existing same-name table after process start. Qualification can operate in a clean namespace and test collision refusal explicitly.

## 5. Initial filter policy

The wg-basic table must not establish a default-drop policy for unrelated host forwarding.

A safe initial forward-hook shape is:

- base chain policy accepts unrelated traffic;
- accept managed tunnel traffic only to explicitly allowed egress;
- allow required return/established traffic;
- optionally drop packets entering from the managed WireGuard interface that do not match the allowed wg-basic forwarding policy;
- do not drop traffic unrelated to the managed WireGuard interface.

The exact nftables priority must be selected/documented so wg-basic does not pretend it supersedes other host firewall managers.

Important semantic limitation:

An `accept` in wg-basic's nftables chain does not guarantee another independent base chain will not later drop the packet. wg-basic MUST document external firewall interaction rather than claiming authoritative ownership of the entire host forward path.

M005 need not add an input-chain rule for the WireGuard UDP listen port. A host firewall may still require the operator/distribution integration to open it. The later doctor/UI should diagnose this. If implementation proposes owning an input exception, treat that as scope requiring explicit review.

## 6. NAT policy

Initial NAT policy:

```text
managed IPv4 tunnel source prefix
    + explicit egress interface
    -> masquerade in wg-basic-owned postrouting chain
```

Requirements:

- NAT is optional;
- only managed source prefixes are matched;
- egress interface is validated;
- NAT does not affect non-wg-basic traffic;
- deleting/disabling NAT removes only the wg-basic-owned rule/table state.

Do not infer “all private subnets” or masquerade all forwarding traffic.

## 7. Forwarding backend

The initial IPv4 forwarding requirement is the fixed semantic:

```text
net.ipv4.ip_forward = 1
```

The privileged protocol MUST NOT accept arbitrary sysctl paths.

A `ForwardingBackend` may read and enable this exact setting through a narrowly coded implementation.

Ownership rule:

- if already enabled, record `already enabled`;
- if disabled and desired policy requires it, wg-basic may enable it;
- M005 MUST NOT automatically write it back to `0` during disable/uninstall merely because wg-basic once enabled it.

Reason: forwarding is host-global and another service may begin depending on it.

Later install/state work may record provenance and manage a sysctl.d file, but even then teardown must remain conservative.

The reconcile plan/doctor output should report that forwarding remains enabled when wg-basic cannot prove exclusive ownership.

## 8. Desired policy types

Complete M001 placeholders into explicit bounded types.

Conceptually:

```text
DesiredNetworkPolicy {
    ipv4_forwarding: Required | NotRequired,
    forwarding: {
        ingress_interface,
        allowed_egress_interfaces,
    },
    nat: Disabled | Masquerade {
        source_prefixes,
        egress_interface,
    },
}
```

Do not add arbitrary expressions or raw rules.

The first product path may permit exactly one egress interface while types avoid making multi-egress impossible later.

## 9. Observed firewall/forwarding state

The network service must be able to observe enough to determine:

- whether the wg-basic table exists;
- whether it has recognized ownership/current desired content;
- whether unexpected owned-namespace drift exists;
- current IPv4 forwarding value.

Do not parse the entire host ruleset into wg-basic domain objects when only the owned table is required.

If using the `nft` CLI backend, prefer JSON/list output with bounded parsing over scraping human-formatted text.

## 10. Reconciliation integration

M005 extends M004's plan.

Create/enable ordering should be dependency-safe:

1. M004 link/WireGuard/address/route convergence;
2. ensure required forwarding enabled;
3. apply/replace wg-basic firewall/NAT table;
4. re-observe;
5. verify.

Disable/removal:

1. remove/replace wg-basic firewall/NAT state;
2. remove M004 owned routes/addresses/link according to desired lifecycle;
3. do not blindly disable host-wide forwarding.

A firewall application failure after forwarding was enabled is a partial failure and must be reported truthfully. Fresh reconcile can retry firewall state.

## 11. Firewall atomicity

Prefer constructing one complete intended wg-basic table and applying it atomically.

A user must never see a long sequence of individually appended rules as the steady mutation model if nftables transaction semantics can avoid it.

On failure:

- old valid owned rules should remain if the backend supports transactional replacement;
- otherwise report exact partial state and re-observe.

Never flush the global ruleset as a rollback mechanism.

## 12. Privileged protocol

The management-facing privileged operation remains desired-state/reconcile oriented.

Do not add:

- `ApplyNftSource(String)`;
- `SetSysctlPath(String, String)`.

The management process supplies typed desired network policy. netd validates and generates the privileged mutations.

Plan/dry-run projection may describe:

- “enable IPv4 forwarding”;
- “replace wg-basic nftables table”;
- “enable masquerade for 10.8.0.0/24 via eth0”;

without exposing arbitrary executable source.

## 13. End-to-end namespace fixture

M005 closure requires at least a three-node topology:

```text
client namespace
    wg-client 10.8.0.2
        |
        | WireGuard over underlay
        v
server namespace
    wg-server 10.8.0.1
    egress 192.0.2.1
        |
        v
internet namespace
    peer 192.0.2.2
```

The internet namespace MUST NOT have a route to `10.8.0.0/24`.

Therefore successful client traffic to `192.0.2.2` with a valid return path demonstrates that masquerade/NAT occurred.

Fixture construction may use `ip netns`/veth tooling.

Production wg-basic code must own:

- WireGuard control;
- managed link/address/route state;
- forwarding enablement;
- nftables/NAT policy.

Test traffic may use `ping` or a similarly ubiquitous bounded tool. Do not require a complex external test service unless needed to prove source address.

## 14. Required end-to-end cases

### A. No-NAT negative

With no return route and NAT disabled, traffic should fail or return-path verification should demonstrate no connectivity.

### B. NAT positive

Enable desired NAT policy. Client reaches internet namespace.

### C. Reapply

Reapply identical desired state:

- zero/near-zero config mutations as appropriate;
- no duplicate nft rules;
- connectivity remains.

### D. netd restart/reconcile

Restart network service while kernel state remains.

Resend same desired state.

It must recognize/reconcile owned state without accumulating rules or destroying links.

Strict durable restart ownership after host reboot remains Phase 6 because persistence is not yet present.

### E. Disable

Remove NAT/firewall owned state and managed interface state according to policy.

Unrelated firewall/network fixtures remain.

IPv4 forwarding may remain enabled and must be reported as intentionally preserved.

## 15. Preservation fixture

Before wg-basic apply, create:

- an unrelated nftables table with distinctive rules/counters/comments;
- unrelated link/route from M004 fixture;
- optionally an external forward-hook chain.

After create/reconcile/reapply/disable, assert the unrelated objects still exist with semantically equivalent configuration.

A same-name `wg_basic` table with no recognized ownership marker must trigger conflict rather than deletion.

## 16. External firewall behavior

Add a test/documentation case showing an independent host firewall drop can still block traffic despite wg-basic's allow path.

wg-basic should report the limitation diagnostically; it must not escalate into flushing/reordering another manager's table.

This is important to avoid falsely advertising wg-basic as the sole firewall authority.

## 17. Focused tests

Unit:

- typed firewall-policy validation;
- source prefix and egress validation;
- deterministic ruleset/model generation;
- ownership-marker recognition;
- same-table collision;
- forwarding transition decisions;
- no transition from `1 -> 0` under ordinary disable;
- reconcile ordering;
- firewall error redaction/bounds.

Integration:

- owned table create/observe/replace/delete;
- atomic failure behavior where testable;
- unrelated table preservation;
- same-name collision refusal;
- forwarding read/enable;
- NAT E2E topology;
- reapply/no duplicates;
- netd restart/reconcile;
- disable/preservation.

## 18. Performance/resource behavior

Firewall reconciliation is event-driven, not a frequent polling loop.

Do not add a high-frequency “repair every N seconds” task.

M005 may measure:

- initial reconcile latency;
- no-op reconcile latency;
- netd idle wakeups/CPU qualitatively.

No strict microbenchmark is required unless implementation reveals a regression.

## 19. Verification

Routine Rust gates:

```text
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
```

Rootful Linux network-control suite:

```text
sudo -E cargo test --locked --features linux-integration --test network_control_e2e -- --nocapture
```

Exact target names are implementation-defined.

If a transitional `nft` backend is selected, qualification must record the minimum supported nftables/userspace version and validate absence/failure diagnostics.

## 20. Documentation

Update/add:

- `architecture/reconciliation.md`;
- `architecture/firewall.md`;
- `architecture/privilege-boundary.md`;
- operator/developer namespace test instructions;
- external-firewall interaction;
- forwarding preservation behavior;
- exact current IPv4/NAT scope.

At M005 closure, README may claim a Linux kernel-level functional VPN foundation exists, but it must still distinguish this from the later persistence/UI product.

## 21. Acceptance criteria

M005 closes only when:

1. wg-basic owns a dedicated nftables namespace and never flushes unrelated state;
2. same-name unowned table collision fails closed;
3. typed policy can configure forwarding + optional masquerade;
4. host-wide forwarding is enabled only through a fixed allowed semantic and is not blindly reverted;
5. production firewall code uses direct netfilter or the narrowly bounded ADR-compliant `nft` backend;
6. client/server real WireGuard handshake occurs in namespace fixture;
7. NAT-positive traffic succeeds without a return route to the client tunnel subnet;
8. no-NAT negative fixture demonstrates the topology is meaningful;
9. identical reapply does not accumulate rules;
10. netd restart + fresh desired-state reconcile converges;
11. disable removes only wg-basic-owned network/firewall state;
12. unrelated nftables/link/route fixtures survive;
13. external firewall conflicts are diagnosed rather than overridden;
14. routine/MSRV/rootful integration evidence passes;
15. no unresolved high/medium network ownership or privilege finding remains.

## 22. Stop conditions

Stop and create a corrective/ADR rather than weakening safety if:

- current Rust netfilter libraries cannot safely express transactional ownership and a bounded `nft` backend also cannot be made injection-safe;
- implementation would require flushing/replacing unrelated host firewall state;
- the only way to “restore” forwarding is guessing whether other services need it;
- full-tunnel/NAT requires broad policy routing outside current scope;
- production code needs shell execution;
- the namespace test cannot produce real kernel WireGuard + NAT evidence;
- M004 ownership defects are discovered.

## 23. Closure evidence

The closure record must include:

- firewall backend research/selection;
- exact owned nftables object model;
- forwarding policy/teardown evidence;
- representative rendered/observed owned ruleset without secrets;
- no-NAT and NAT E2E results;
- proof the internet namespace lacks a client-subnet return route;
- reapply/no-duplicate result;
- netd restart result;
- same-name collision result;
- unrelated firewall/network preservation result;
- external-firewall interaction result;
- routine/MSRV/rootful verification outputs;
- unresolved findings;
- recommendation that the network-control foundation is closed and Phase 6/7 planning may proceed.

M005 strict closure is the prerequisite for claiming the foundational network substrate is implementation-complete.
