# Durable State M002 — Durable Ownership and Generation-Aware Aggregate Reconciliation

Status: blocked on Durable State M001 closure

Source roadmap:

- `plans/subsystems/durable-state-restart-reconciliation-roadmap.md#7-milestone-m002--durable-ownership-and-aggregate-netd-reconciliation`

Canonical requirements:

- `plans/adr/002-durable-state-generations-and-ownership.md`
- `plans/000-long-term-specification.md#45-explicit-host-ownership`
- `plans/000-long-term-specification.md#11-reconciliation-model`

Primary class: invariant / capability

Hard dependency:

- Durable State M001 strictly closed.

## 1. Objective

Turn request-scoped network ownership into restart-stable ownership and make one desired generation the unit of privileged reconciliation.

M002 extends the closed M004/M005 networking substrate with:

- installation/interface owner tags on kernel resources;
- installation-specific nftables ownership;
- one aggregate generation-aware privileged request;
- one outer mutation serialization boundary across interface and firewall layers;
- stale-generation protection within one netd lifetime.

## 2. Non-goals

M002 MUST NOT:

- open SQLite from netd;
- implement startup automatic reconciliation;
- implement backup/restore;
- add HTTP;
- add periodic drift monitoring;
- add IPv6;
- add multi-host coordination;
- weaken the current M004/M005 preservation rules.

## 3. OwnerTag domain

Introduce a bounded, validated `OwnerTag` derived from:

- owner-tag format version;
- `InstallationId`;
- `InterfaceId`.

Requirements:

- deterministic;
- comfortably below Linux IFALIAS maximum;
- ASCII-safe;
- no user-supplied label/name component;
- parseable back into installation/interface identity;
- invalid/foreign version rejected.

Example shape:

```text
wg-basic:v1:<installation-uuid>:<interface-uuid>
```

If a more compact encoding is selected, document it and preserve round-trip tests.

OwnerTag is not a secret.

## 4. RTNETLINK interface alias support

Extend M004 observation to capture the WireGuard link's interface alias.

Extend creation to set the expected owner tag.

For an existing link, classify:

- missing link;
- same-name WireGuard + matching owner tag;
- same-name WireGuard + absent alias;
- same-name WireGuard + foreign wg-basic owner tag;
- same-name WireGuard + unrelated alias;
- wrong-kind link.

Default behavior:

- missing: create and tag;
- matching tag: eligible for full owned reconciliation;
- all non-matching existing cases: conflict for authoritative mutation/destruction.

Do not infer ownership from public key alone.

If the interface is present with the correct owner tag but external drift changed WireGuard config, addresses, routes, or admin state, reconcile it back to desired state because ownership is proven.

## 5. Duplicate owner-tag detection

Observation SHOULD detect whether the same owner tag appears on another link.

A duplicate owner tag is a conflict requiring operator intervention; do not guess which interface is canonical.

If efficient global link enumeration is needed to prove uniqueness, bound it appropriately and keep the operation local to one apply/plan observation.

## 6. Firewall owner marker evolution

Replace the fixed product-only table marker with an installation-specific marker.

Requirements:

- table name may remain `inet wg_basic`;
- table comment binds to `InstallationId`;
- chain/rule desired-policy markers continue to bind to exact desired policy;
- table with another installation marker is a conflict;
- table with the historical M005-only marker is NOT silently adopted.

Because there is no released persistent state before Phase 6, no automatic legacy ownership migration is required by default. If repository evidence shows a practical development upgrade path is required, make it explicit and one-time rather than broadening recognition.

## 7. Aggregate intent type

Add a typed application-to-netd payload, conceptually:

```text
InstallationNetworkIntent {
    installation_id,
    generation,
    interface_id,
    desired_interface,
    network_policy,
}
```

For the Phase 6 baseline, one intent may contain one managed interface + its network policy.

The persistent schema should not preclude multiple interfaces later, but M002 need not make netd aggregate several interfaces in one request unless M001's canonical application model already requires it.

The intent MUST validate:

- generation bounds;
- owner-tag derivation;
- interface ID/name relationship;
- desired interface state;
- network policy relationship to the same interface;
- no raw nft/sysctl/netlink data.

## 8. Privileged protocol extension

Add:

- `PlanInstallationNetworkIntent`;
- `ApplyInstallationNetworkIntent`.

Response bodies:

- generation-tagged aggregate plan;
- generation-tagged aggregate apply receipt.

Do not remove the lower-level M003–M005 protocol operations yet unless repository evidence proves they are entirely internal/test-only and removing them is an explicit compatibility decision.

The aggregate path becomes canonical for Phase 6 management orchestration.

## 9. Aggregate plan

The plan contains ordered layer summaries:

- interface/WireGuard/address/route;
- forwarding/firewall.

Enable path:

1. interface layer plan;
2. firewall layer plan.

Disable/absent path:

1. firewall removal plan;
2. interface teardown plan.

The plan must expose enough information for future dry-run/status presentation without serializing raw nft source or private keys.

## 10. Aggregate apply ordering

### Present/enable

1. validate owner identity and generation;
2. reconcile interface/WireGuard/address/routes;
3. if that layer fails or does not verify, stop;
4. reconcile forwarding/firewall;
5. re-observe relevant owned state;
6. return aggregate receipt.

### Absent/disable

1. validate owner identity and generation;
2. remove/disable owned firewall policy first;
3. if that layer fails, do not delete the interface;
4. reconcile explicit interface teardown;
5. verify;
6. return aggregate receipt.

This ordering prevents a partial disable from deleting the interface while leaving a wg-basic firewall table whose semantic target no longer exists.

## 11. One outer mutation lock

Introduce one netd aggregate mutation coordinator lock that spans both current reconciliation services.

Do not rely solely on SocketServer's current sequential request dispatch because Phase 7 may change caller/concurrency behavior.

Lower-level service locks may remain defensively, but lock ordering must be fixed and deadlock-free.

Tests must prove two aggregate applies cannot interleave.

## 12. In-process generation monotonicity

netd stores ephemeral process state:

- active installation ID once first aggregate apply is accepted;
- highest accepted apply generation.

Rules:

- first valid aggregate apply establishes installation ID for the process;
- different installation ID while process is alive -> conflict;
- generation < highest accepted -> stale-generation conflict;
- generation == highest -> allowed idempotent reapply;
- generation > highest -> eligible.

Update the highest generation only at a precisely documented point.

Recommended semantics:

- once a generation begins privileged mutation, record it as highest accepted before first mutation so a delayed older request cannot follow it;
- failure/partial failure does not reduce the number;
- equal-generation retry remains allowed.

This state is deliberately lost on netd restart; persistent state + owner tags reestablish truth.

## 13. Receipt semantics

Aggregate receipt contains:

- installation ID;
- generation;
- overall status;
- interface layer receipt/plan status;
- firewall layer receipt/plan status;
- which layer failed;
- whether fresh post-observation succeeded.

Do not claim rollback.

Map overall status truthfully:

- NoChange only if both layers require no mutation;
- Applied only if requested layers verify;
- PartialFailure if an earlier layer changed state and later layer failed;
- FailedBeforeMutation if nothing changed;
- VerificationFailed where appropriate.

## 14. Management projector integration

M001's projector should now produce the full `InstallationNetworkIntent` including owner identity and generation.

Do not duplicate owner-tag construction in the HTTP/CLI layer.

## 15. Existing lower-level ownership semantics

Preserve:

- wrong-kind link conflict;
- exact managed address semantics;
- route conflict/preservation;
- unsupported-route deletion refusal;
- peer preservation semantics;
- independent firewall warning;
- no automatic ip_forward disable.

Durable owner tags strengthen interface/table proof; they do not authorize broader resource deletion.

## 16. Real-kernel tests

Extend rootful namespace fixtures.

Required cases:

1. created WireGuard link receives expected IFALIAS;
2. matching alias survives netd restart and is reconciled;
3. same-name untagged WireGuard link -> conflict;
4. same-name foreign-tag WireGuard link -> conflict and survives;
5. duplicate owner tag on another link -> conflict;
6. nft table marker includes installation ID;
7. foreign-installation table marker -> conflict;
8. equal-generation aggregate reapply -> no duplicate/no-op;
9. lower generation after higher generation -> rejected without mutation;
10. present aggregate path succeeds;
11. disable aggregate path removes firewall before interface;
12. injected firewall failure during disable leaves interface intact;
13. injected firewall failure during enable after interface change returns partial receipt and equal-generation retry converges.

## 17. Protocol tests

- stable operation names;
- owner/generation fields bounded and round-trip;
- private keys remain redacted in Debug;
- malformed owner tag rejected;
- stale-generation maps to stable conflict category or a dedicated additive protocol error if justified;
- no generic privileged operation added.

Avoid protocol-major bump unless wire compatibility truly cannot be additive.

## 18. Verification

Routine/MSRV checks.

Rootful suites must include all historical network tests plus new durable-owner aggregate tests.

The existing M003/M004/M005 qualification must remain green.

## 19. Documentation

Update/add:

- `architecture/ownership.md`;
- `architecture/reconciliation.md`;
- `architecture/firewall.md`;
- privileged protocol docs;
- state-store projection docs.

Explicitly state that M002 has durable owner identity but automatic startup application arrives in M003.

## 20. Acceptance criteria

M002 closes only when:

1. new links are tagged with installation/interface identity;
2. matching tags permit restart-safe ownership;
3. absent/foreign/duplicate tags fail closed;
4. nft table ownership is installation-specific;
5. one aggregate protocol operation carries one desired generation;
6. interface and firewall layers cannot interleave across aggregate applies;
7. stale lower generation is rejected within one netd lifetime;
8. equal-generation retry remains idempotent;
9. partial failure receipts remain truthful;
10. all historical and new rootful tests pass;
11. netd remains database-free.

## 21. Stop conditions

Stop/research if:

- current rtnetlink stack cannot safely read/write IFALIAS on Rust 1.89;
- owner-tagging would require shelling to `ip`;
- aggregate locking requires broad async/runtime redesign;
- owner marker changes would require silently adopting unknown existing host state;
- protocol changes cannot remain bounded/typed.

## 22. Closure evidence

Record:

- owner-tag format and length;
- IFALIAS kernel round-trip;
- foreign/missing/duplicate tag results;
- nft marker migration/result;
- aggregate protocol schema;
- lock/concurrency tests;
- generation stale/equal behavior;
- partial failure/retry evidence;
- rootful CI;
- recommendation on M003 readiness.