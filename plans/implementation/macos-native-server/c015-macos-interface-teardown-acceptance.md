# C015 — The macOS managed interface's teardown is refused

Status: **ready** (2026-10-23). Raised by the **F10** finding that C004's
closure record made when its gateway leg ran the product's own teardown on the
controlled host. The implementation and the evidence will be recorded in
`plans/closure/macos-native-server-corrective/c015-status.md`.

Repository baseline: `5e35a4a` (`plans/macos-native-support`).

Source: `plans/subsystems/macos-native-server-corrective-roadmap.md`, the
corrective line of the macOS native-server milestone. This is a corrective of
the **interface layer's delete path**, not of the firewall layer: C004's
anchor and its scoped teardown are closed and are not reopened here.

Canonical requirements and ADRs: `plans/000-long-term-specification.md`; ADR-008
(macOS headless platform backends); ADR-009 (Apple silicon is the only Darwin
target); `plans/003-planning-process.md` §13 (a material post-implementation
defect receives a new corrective plan, and a historical closure record stays
period-accurate).

Primary work class: **corrective / invariant** — the product refuses to remove
an interface it owns, so the operator cannot turn the managed network off
through the product on the platform the whole milestone exists for.

## Objective

Make `wg-basic network disable` remove the managed macOS interface, and make
the refusal mean what it says: a resource the product cannot prove it owns, or
one that is not the product's to remove.

Concretely: the delete path compares the **observed** interface against the
**desired** state, and on macOS the two can never be equal, so the comparison
always refuses. The observed and the desired have to be brought onto the same
terms, and the refusal has to be reserved for the case it was written for.

## Explicit non-goals

No change to the firewall layer, to the anchor's scoped install or its scoped
teardown, or to C004's gateway policy. No change to the routed-LAN mode, which
stays operator-managed. No change to the ownership rules themselves: the
product still refuses to remove an interface it cannot prove it owns, and it
still refuses to remove a foreign alias. No new capability, no new privileged
path, and no change to what the product writes to the host's network
configuration. No reopening of C003's or C004's closed scope, and no claim
about the Linux path beyond keeping it green.

## Current repository evidence

The refusal is measured, and the measurement is in C004's closure record.

**What the operator sees.** On the controlled host, `wg-basic network disable`
answers:

```
network disable committed at generation 4 but not yet enforced
(Degraded(BackendRefused)); check netd and rerun `wg-basic reconcile`
```

The generation is committed, the firewall layer's teardown **runs and
completes** — the managed anchor's two rule classes are emptied and the
anchor's file is reduced to its marker line — and the **interface** layer's
delete path refuses before it removes the device. The doctor reports it as
"network plan found an ownership conflict" / "netd returned a typed ownership
conflict", and the convergence check reads "desired 4; attempted
Some(DesiredGeneration(4)); converged Some(DesiredGeneration(3)); outcome
state_conflict".

**Why it refuses.** `src/reconcile/planner.rs` refuses to delete a managed
interface when an observed address is not in the desired list:

```rust
let listed_addresses = desired.addresses.iter().map(|entry| entry.address)...;
if observed.addresses.iter().any(|address| !listed_addresses.contains(address)) {
    return Err(ReconcileError::UnlistedResourceOnDelete);
}
```

On the controlled host's `utun0` the observed and the desired are:

| Resource | Desired | Observed |
|---|---|---|
| The IPv4 address | `10.77.0.1/24` | `10.77.0.1/32` — the device is point-to-point and the kernel holds a `/32` netmask (`inet 10.77.0.1 --> 10.77.0.1 netmask 0xffffffff`) |
| The IPv6 address | `2001:db8:77::1/64` | `2001:db8:77::1/128` (`inet6 2001:db8:77::1 --> 2001:db8:77::1 prefixlen 128`) |
| The link-local address | *not listed* | `fe80::3c84:7232:cc4e:2dc0%utun0` (`prefixlen 64`) |

The observation in `crates/darwin-sys/src/ffi.rs` collects **every** address
`getifaddrs` reports for the interface, the link-local included, and it
reports the prefix the kernel holds. The Linux observation reports the prefix
the product configured and no link-local, so the Linux delete path never sees
this shape.

The refusal travels `ReconcileError::UnlistedResourceOnDelete` →
`ProtocolError::Conflict` → `ManagementError::Conflict` →
`AttemptDisposition::StateConflict` → `DegradedCategory::BackendRefused`.

**Why previous evidence missed it.** Every macOS qualification so far ended
either with the service stopped by the fixture or with the network left
enabled. C001, C002 and C013 exercised the product's *own* lifecycle, and
C003's routed-LAN leg and C004's gateway leg both drove the product through
the **enable** path. The `network disable` path on macOS — the path that
removes the managed interface — had never been run against a real macOS host.
The defect is in the *delete* path's comparison, and no qualification had
reached it.

## Invariants this change must not break

- The product removes an interface only when it can prove the interface is
  its own: the durable owner tag, the recorded receipt and the helper's
  identity all have to agree, exactly as they do today.
- A **foreign** resource on the managed interface — an address or a route the
  product did not install and cannot account for — is still refused, and the
  refusal still says so.
- The product never removes a resource it did not install, and never restores
  one it did not remove.
- The Linux path's behaviour is unchanged; its delete path keeps refusing an
  unlisted resource.
- The firewall layer's teardown behaviour is unchanged, including C004's
  scoped empty-and-rewrite.

## Expected production changes

- The delete path's comparison, in `src/reconcile/planner.rs` and, if needed,
  in the Darwin observation in `src/reconcile/backend_darwin.rs`: the observed
  and the desired must be compared on the same terms. Two shapes are in
  play, and the plan does not pre-decide between them:
  1. **the observation normalises** — the Darwin observation reports the
     address the way the desired state names it (the product's own prefix,
     not the kernel's), and reports the kernel's own link-local address
     separately so the planner can tell an address the product installed
     from an address the kernel derived; or
  2. **the product installs the address in the form it will later compare**
     — the Darwin address setter asks for the desired prefix, and the
     kernel-derived link-local is recognised as the kernel's.
  Either is acceptable; what is not acceptable is a comparison that cannot
  succeed on a platform where it is always run.
- The Darwin address setter, if shape 2 is chosen, and the Darwin
  observation, if shape 1 is chosen: the change must not make the product
  write an address in a form the kernel will refuse.
- `src/reconcile/planner.rs`: the refusal's *wording* must keep naming the
  resource that is unlisted, so a genuine conflict is still diagnosable.

## Ordered work packages

1. **Characterise the delete path's comparison on both platforms.** Read
   `src/reconcile/planner.rs`'s `LinkLifecycle::Absent` branch and the Darwin
   and Linux observations side by side, and write down exactly which resources
   can make the comparison refuse. The list is the acceptance criteria for
   the fix: every entry must be either *removed* by the fix or *kept* as a
   genuine conflict with a named reason.
2. **Make the comparison succeed on macOS for the product's own resources.**
   The managed interface's own IPv4 address, its own IPv6 address and the
   kernel's derived link-local must not be unlisted resources. The
   implementation shape is the implementer's choice between the two above.
3. **Keep the refusal for everything else.** A foreign address, a foreign
   route, a duplicate owner tag and a missing receipt keep their own
   refusals, and the refusals keep naming what is wrong.
4. **Make the operator's path work end to end.** `wg-basic network disable`
   on macOS must remove the managed interface and report that it was
   enforced.
5. **Prove it on the controlled host.** The C004 gateway leg is re-run
   against the corrected head, and the disable must now be enforced — the
   known degradation the leg pins today must be gone, and the leg's pin
   updated with it.

## Privilege and security effects

None. The change is a comparison and, possibly, the prefix the product asks
the kernel for when it sets an address. The product's privilege, its
capabilities and the files it owns are unchanged, and the product still
removes an interface only when it proves the interface is its own.

The one security-relevant point is the *narrowing* of a refusal: the refusal
exists so that the product never removes a resource it did not install. The
fix must therefore be justified by the resource's **provenance** — an address
the product itself installed, or one the kernel derived from it — and never
by resemblance.

## Persistence, protocol, and configuration compatibility effects

None expected. The desired state keeps naming the address the way it does
today; if shape 2 is chosen, the *installed* form changes and the desired
state does not, so an installation created by an older build would compare
its own address against a differently-formed desired address — that case has
to be considered and either handled or explicitly excluded with a reason.

## Failure, cancellation, restart, and contention semantics

A teardown that is cancelled mid-way must leave the same facts it leaves
today: the interface present, with the addresses and routes the product
installed, and the firewall layer's teardown either done or not. A refusal
must leave everything untouched.

## Focused tests

- A host-free unit test for the planner's `LinkLifecycle::Absent` branch with
  a **macOS-shaped** observation: the product's own `/32` point-to-point
  address against a `/24` desired address, the `/128` IPv6 address against a
  `/64` desired address, and a link-local address that the desired state
  does not list. The plan must be accepted.
- A host-free unit test with a **foreign** address and a **foreign** route:
  the plan must still be refused, with the refusal naming the resource.
- A host-free unit test with the **Linux-shaped** observation: unchanged
  behaviour.
- A test that the refusal's wording still names the unlisted resource.

## Linux and network-namespace integration evidence

Not applicable to the macOS defect itself, but the Linux path is affected by
the shared planner, so the ordinary gate order and the rootful suites on the
controlled Linux host must stay green.

## Broad verification commands

The repository's standard gate order on the Darwin host, the Linux
feature-bearing cross-clippy, and the controlled Linux host's gate order with
all eleven rootful suites — exactly as C004 ran them. The hosted CI's
`dependency-audit` job is red for an upstream reason and stays red.

## Documentation updates

`architecture/ownership.md` (what the product removes and what it refuses to
remove), `architecture/state-store.md` if the desired address's form changes,
and `docs/operations-runbook.md` (the operator's disable path on macOS).

## Acceptance criteria

1. `wg-basic network disable` on macOS removes the managed interface and
   reports that the teardown was **enforced**.
2. The product still refuses to remove an interface whose ownership it cannot
   prove, and still refuses to remove a foreign address or route on an
   interface it does own, each with its own named reason.
3. The Linux path's behaviour is unchanged and its suites are green.
4. The C004 gateway leg is re-run against the corrected head and is green
   **without** the known-degradation pin the leg carries today.

## Stop conditions

Stop and record the discrepancy rather than working around it if:

- the comparison cannot be made to succeed without weakening the ownership
  proof — that is, if the only way to let the delete proceed is to stop
  proving that the interface is the product's own;
- the fix would require the product to remove a resource it cannot show it
  installed;
- making the comparison succeed would require the product to change what it
  writes to the host's network configuration in a way the operator would not
  expect;
- the Linux path's behaviour would have to change.

## Closure evidence requirements

`plans/closure/macos-native-server-corrective/c015-status.md` only after the
controlled-host evidence: the disable's own answer, the interface's absence
after it, the ownership refusal's survival, and the C004 gateway leg re-run
without its degradation pin. A unit test alone is not closure for a
milestone whose defect is observed on a host.
