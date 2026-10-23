# ADR-010 — The privileged authority supervises the helper it spawned

Status: accepted (maintainer decision, 2026-10-22)

Date: 2026-10-22

Amends: the recovery mechanism described in
`architecture/startup-recovery.md` ("There is deliberately no permanent
high-frequency reconciliation loop… that is the recovery mechanism, and it
must not be built here"). That sentence stays a historical record; the rule it
states still holds for the management role, and this ADR adds the narrower
exception it does not cover.

Context: `plans/closure/macos-native-server-corrective/c003-status.md`, finding
F2.

## 1. Context and decision scope

On macOS the managed tunnel is carried by a `wireguard-go` helper that `netd`
spawns as a supervised foreground child. Two facts make the helper's death a
distinct event rather than an ordinary drift:

1. **The helper's death takes the tunnel with it.** The kernel releases the
   `utunN` device when the helper's descriptor closes, and the pool route, the
   filter rules that name the device, and the tunnel itself go with it.
2. **The receipt outlives it.** The durable ownership receipt names the
   helper's pid. It is not removed when the helper dies, so the receipt
   survives as a claim about something that is gone.

That second fact was worse than it first looked. The create path treated the
*existence* of a receipt as an ownership claim, so a receipt whose helper was
dead refused every attempt to recreate the tunnel:

```
WARN netd netd.apply_action_failed operation=apply outcome=conflict
     resource_kind=create_wireguard_link
```

The tunnel could not be brought back by a re-apply, by a service restart, or
by anything short of an operator deleting the receipt by hand — a remedy that
was documented nowhere. C003 recorded the *symptom* (F2: "a killed WireGuard
helper isn't recovered automatically") and routed the recovery half to C001's
helper-crash matrix; the *wedge* behind it was not recorded at all.

Meanwhile the management role's recovery mechanism was fixed by policy:
`architecture/startup-recovery.md` states that there is deliberately no
permanent high-frequency reconciliation loop, and that "a future service
manager may restart the process; that is the recovery mechanism".

This ADR decides **who recovers a helper that dies, and with what authority**.
It does not touch the Linux line, the desired-state store, the management HTTP
surface, the client enrollment format, the typed IPC vocabulary, or the
release authority.

## 2. Options and evidence

- **A periodic reconciliation loop in the management role.** Rejected, and
  excluded by the standing rule: the management role would decide whether the
  desired state changed, which is the job the durable store and the aggregate
  coordinator already do, once, deliberately. A loop would also give the
  unprivileged role a standing reason to touch the kernel.
- **No automatic recovery at all; the operator re-applies.** Rejected as the
  whole answer: it leaves a tunnel down until somebody notices, and it is the
  shape C003's leg already exercised as a negative. It is kept as the
  *fallback*, not as the mechanism.
- **The privileged authority supervises the helper it spawned.** Chosen.
  `netd` already owns the helper's lifecycle: it spawns it, proves it, stops
  it, and re-adopts its device. A child that dies is the authority's own
  business, and the state it restores is state it already applied.
- **Make `netd` exit when its helper dies, and let launchd restart it.**
  Rejected: launchd would restart `netd`, but nothing asks the management role
  to re-apply, and the management role has no standing reason to. The tunnel
  would still be down.

## 3. Decision

1. **A receipt's existence is not a claim.** Before a create refuses because a
   receipt claims the owner tag, the receipt is re-proved against the live
   host. A receipt that cannot be re-proven is dropped and the tunnel is
   recreated over it. A receipt that *does* re-prove is a live tunnel, and a
   second tunnel over it is refused.
2. **`netd` supervises the helpers it spawned.** A monitor thread notices that
   a supervised helper is no longer running and re-applies the desired
   interface that was applied for it, which recreates the helper, re-adopts
   exactly one new device, and restores the configuration, addresses, and
   routes that belonged to the tunnel.
3. **The recovery restores; it never decides.** The re-apply uses the desired
   state `netd` already applied for that interface. The monitor never
   consults the durable store, never compares generations, and never changes
   what the desired state is.
4. **The management role's rule is unchanged.** There is still no
   reconciliation loop in the management role. The monitor is not one: it runs
   at a fixed, slow interval, only does work when a supervised child died,
   and does not observe the host for drift.
5. **The recovery is bounded and reported.** The re-apply is attempted a
   small number of times, and its outcome is an operational event
   (`netd.helper_recovery_started`, `netd.helper_recovery_completed`,
   `netd.helper_recovery_failed`).

## 4. Normative invariants

- A receipt is a claim about a helper that is expected to exist. It never
  authorizes anything on its own: the live host re-proves it first, in both
  directions. A stale receipt is dropped; a live one is refused over.
- Two devices never carry the same durable owner tag. The refusal for a live
  claim is not negotiable, and the re-apply path must not weaken it.
- The privileged authority may restore only state it applied itself, for a
  helper it owns. It never adopts a device it cannot prove, and it never
  decides that the desired state changed.
- The management role remains unprivileged and remains the only holder of the
  durable desired state. `netd` holds no authority to change it.
- A device that is not proven is not touched. A recovery that cannot prove its
  claim fails; it does not force a result.
- Linux is unchanged. The receipt, the helper, and the `utun` device are
  Darwin's, and so is this recovery.

## 5. Contract/migration/distribution consequences

- **No protocol, schema, wire, or CLI change.** The recovery is internal to
  the privileged authority. The typed IPC vocabulary, the store schema, and the
  HTTP surface are untouched.
- **No migration.** A stale receipt left by an earlier build is dropped by the
  first create that meets it, which is the path the fix repairs. Nothing has to
  be rewritten by hand.
- **A secret-handling consequence, stated plainly.** The privileged authority
  now retains the desired interface it applied, for the lifetime of the
  managed tunnel, and that desired interface carries the device's private key
  and its peers' keys. `netd` already handled those keys transiently, on the
  apply path; the change extends the window from "during the apply" to "for
  the tunnel's lifetime".
  - The retained state uses the existing `PrivateKey` and `PresharedKey`
    types, which redact `Debug` and `Display` and zeroize on drop.
  - It is dropped when the tunnel is removed, when the tunnel is replaced, and
    when the authority exits.
  - It is never logged, never rendered, and never written to the receipt.
  - The alternative — an authority that could not restore the tunnel it owns —
    was judged worse than a longer in-memory window for a key that was already
    in that process's hands.
- The Darwin launchd job carries an exit timeout, so an operator's
  `launchctl bootout` escalates to a kill if the service wedges. This is a
  hardening of the same class and is recorded here because it changes the
  operator-visible contract of the job.

## 6. Integration and closure consequences

- C011 is the corrective milestone for C003's findings F1, F2, and F3. It
  implements this ADR, the bounded shutdown, and the route-shape verification.
- C003's closure record stays a period-accurate historical record. Its F2 row
  is corrected by a dated amendment in C011's closure record, not by rewriting
  what the earlier run observed.
- C001's helper-crash matrix, which C003's record routed the recovery half to,
  is now closed by C011's controlled-host evidence.
- **M007's MUST-NOT-release standing is unchanged.** This ADR closes no
  release question.

## 7. Source references

- `plans/closure/macos-native-server-corrective/c003-status.md` (findings F1,
  F2, F3, and the disposition they carried).
- `plans/implementation/macos-native-server/c003-routed-lan-no-nat.md` (the
  milestone this corrects).
- `architecture/startup-recovery.md` (the standing no-loop rule this amends,
  and the recovery contract it now describes).
- `architecture/ownership.md` and `architecture/wireguard-control.md` (the
  receipt-as-claim contract and the helper's supervised lifecycle).
- `plans/adr/003-management-http-auth-and-worker-boundary.md` (the bounded
  worker the shutdown change stays inside).
