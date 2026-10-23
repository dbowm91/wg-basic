# C014 — The routed-LAN leg restores the filter it loaded

Status: **ready** (2026-10-23). Raised by the **F8** finding that C013's closure
record made when it re-ran C003's routed-LAN leg against C013's final head.
The implementation and the evidence will be recorded in
`plans/closure/macos-native-server-corrective/c014-status.md`.

Repository baseline: `d26c886` (`plans/macos-native-support`).

Source: `plans/subsystems/macos-native-server-corrective-roadmap.md`, the
corrective line of the macOS native-server milestone. This is a corrective of
**C003's qualification fixture**, not of the product and not of C004's subject
matter.

Canonical requirements and ADRs: `plans/000-long-term-specification.md`; ADR-008
(macOS headless platform backends); ADR-009 (Apple silicon is the only Darwin
target); `plans/003-planning-process.md` §13 (a material post-implementation
defect receives a new corrective plan, and a historical closure record stays
period-accurate).

Primary work class: **corrective / invariant** — a qualification that leaves the
host's packet filter loaded and the host's filter state changed, so the leg's
own hygiene claim is false and the residue can match a later tunnel's device.

## Objective

Make the C003 routed-LAN leg leave the disposable host's packet filter exactly
as it found it, and make the leg **prove** that.

Concretely, four pieces of residue have to go, and one of them is the reason
this is a defect rather than a tidiness item:

1. **The managed anchor's loaded rules.** macOS keeps an anchor's rules loaded
   across `pfctl -f` and `pfctl -F all`. Reloading the main ruleset without the
   anchor's `load anchor` line removes the *reference*; it does not empty the
   anchor's own ruleset. The leg must empty it: `pfctl -a <anchor> -F rules`
   for the filter class and `pfctl -a <anchor> -F nat` for the NAT class.
2. **PF's own enable state.** The leg runs `pfctl -e` to make the filter
   effective, and it never puts the host back the way it was. On a host whose
   PF was disabled, the leg leaves it **enabled**, which changes the host's
   filtering behaviour for everything on the machine.
3. **The anchor's files.** The leg writes `/etc/pf.anchors/<anchor>` and, for
   the drift control, `/etc/pf.anchors/<anchor>.drift`. The teardown removes
   the first and leaves the second.
4. **The evidence.** The leg's claim that it "left the host's routing and filter
   as it found them" has to be checked rather than asserted, or it is the same
   unchecked claim that made the defect invisible in the first place.

The hazard that makes (1) more than hygiene: two of the eight rules the leg
leaves loaded match on `utun0`. macOS recycles `utun` indices. A later tunnel
that is handed index 0 inherits the previous leg's rules, on a device the
previous leg never saw. The leg's own drift control had already established
that a stale rule can match the wrong device; this is the same hazard, left
behind by the leg itself.

## Explicit non-goals

- **The product is not changed.** This defect is in the fixture, not in the
  product. The product writes no PF state, no forwarding sysctl, and no route
  in the routed-LAN mode, and that stays true.
- **C003's routed-LAN contract is not reopened.** Its traffic evidence is real
  and unaffected; the residue is the leg's hygiene, not the product's
  behaviour. C003's closure record keeps its history and carries the dated
  §12 amendment that recorded this finding.
- **C004's PF/NAT gateway work is untouched.** C004 gains a *product-side* PF
  write path with its own scoped ownership; this corrective is about a
  *test-side* teardown. The two must not be confused, and C014 does not
  pre-empt any of C004's design decisions.
- **No new PF capability is invented for the fixture.** The restoration uses
  the same fixed `pfctl` verbs the leg already uses, with the anchor scoped by
  `-a`.
- **The hosted macOS runner is not used for this.** The leg needs a disposable
  macOS host with a real PF and a second kernel; a hosted runner cannot
  produce the leg.
- **The guest's own PF policy is not rewritten.** The restoration restores the
  *state* the leg found; it does not install a policy of its own.

## Current repository evidence

| Fact | Source |
|---|---|
| The leg's teardown removes the anchor from `/etc/pf.conf`, reloads `/etc/pf.conf`, and deletes the anchor file — and nothing else | `tests/wireguard_darwin_routed.rs:631` (`remove_operator_filter`) |
| The leg enables PF and never disables it | `tests/wireguard_darwin_routed.rs:620` (`pfctl -e`), and no `pfctl -d` anywhere in the file |
| The leg writes a `.drift` sibling next to the anchor file and never removes it | `tests/wireguard_darwin_routed.rs:1210` (`let drift_path = format!("{rules_path}.drift");`) |
| The leg's drift control loads the drifting file into the anchor with `pfctl -a <anchor> -f <file>` | `tests/wireguard_darwin_routed.rs:1222` |
| After the leg, PF was still **Enabled** and the anchor still held **eight** loaded rules, two of them matching on `utun0` | measured on the disposable guest immediately after the leg was re-run against `d26c886`; recorded in `plans/closure/macos-native-server-corrective/c003-status.md` §12.1 |
| The anchor's `.drift` file was still in `/etc/pf.anchors/` after the leg | the same measurement; the listing shows `wg-basic-v1-0349b3e7-3a2e-4a9b-a901-c521c4e31163.drift` |
| macOS keeps a loaded anchor's **rules** across `pfctl -f` and `pfctl -F all`; `pfctl -F all` without `-a` flushes the **main** ruleset, not every anchor | the same measurement: the leg's own `pfctl -a <anchor> -F all` (line 1240) did not stop the anchor's rules from being loaded again afterwards, and the eight rules survived the final `pfctl -f /etc/pf.conf` |
| The leg's "left the host as it found it" claim is a **documented** claim | `plans/closure/macos-native-server-corrective/c003-status.md` §2, the row that §12 amends |
| The guest must have PF **Disabled** for the hosted live fixture's own PF probe | `tests/wireguard_darwin_live.rs` (`live_pf_inventory_and_anchor_probe`); the leg leaving PF enabled is exactly the condition that breaks it |

## Invariants this change must not break

- **The leg must not weaken any traffic assertion.** The negatives, the
  forwarded traffic, the spoofed-source rejection, the unapproved-destination
  rejection, and the helper-recovery leg all stay as they are.
- **The restoration must be scoped.** It may touch **only** the anchors the leg
  itself created (named `wg-basic-v1-*`), and only their own rulesets. It must
  never flush the main ruleset, never flush a foreign anchor, and never touch
  Apple's own `com.apple/*` anchors.
- **The restoration must restore, not impose.** PF's enable state goes back to
  what the leg found, not to a state the leg prefers.
- **A fixture may not claim what it has not measured.** The leg's restoration
  claim becomes a measured assertion with the evidence recorded, in the same
  way C013 made the hosted live fixture's claims measured.
- **The fixture's evidence is written even when the leg fails.** The
  restoration state has to be in the evidence file whatever the outcome.

## Expected production changes

**None.** The product is not touched. The change is confined to
`tests/wireguard_darwin_routed.rs` and, if the helpers belong there, to
`tests/darwin_live_common/mod.rs`.

The fixture grows:

1. A **baseline capture** of the host's filter state before the leg installs
   anything: PF's enable state (`pfctl -s info`), the main filter and NAT
   rulesets, and the set of anchors present in `/etc/pf.anchors/`.
2. A **pure restoration planner**: a function that turns the baseline and the
   leg's own anchor name into the exact list of commands the teardown runs.
   Pure, so it can be asserted on without a host.
3. A **pure residue check**: a function that takes a captured post-teardown
   inventory and reports whether anything of the leg's is left. Pure, so it can
   be asserted on without a host.
4. A **measured teardown**: the restoration runs, the post-teardown inventory is
   captured, the residue check runs, and the leg asserts the residue is empty
   and PF's enable state matches the baseline.

## Ordered work packages

- **WP1 — capture the baseline.** Before the leg installs the operator filter,
  record PF's enable state, the main rulesets, and the anchors directory
  listing. Log all of it.
- **WP2 — the restoration planner (pure).** A function
  `restoration_commands(anchor, anchor_path, pf_was_enabled) -> Vec<Vec<String>>`
  that produces the teardown's exact argv vectors. It MUST:
  - flush the managed anchor's **filter** rules and its **NAT** rules
    separately (`pfctl -a <anchor> -F rules`, `pfctl -a <anchor> -F nat`), and
    never a bare `-F all` (that is the main ruleset);
  - remove the anchor's lines from `/etc/pf.conf` and reload it;
  - remove the anchor's file **and** its `.drift` sibling;
  - run `pfctl -d` **only** when PF was disabled at the baseline;
  - name no path outside `/etc/pf.anchors/<anchor>` and `/etc/pf.conf`;
  - contain no root-ruleset flush, no table flush, and no foreign anchor.
- **WP3 — the residue check (pure).** A function over a captured inventory
  that reports: an anchor of the leg's that still holds loaded rules; a
  leftover anchor file or `.drift` file; PF's enable state differing from the
  baseline; a main ruleset that differs from the baseline. It returns the
  residue it found, by name, so the failure message says what was left.
- **WP4 — the measured teardown.** Run the planner's commands, capture the
  post-teardown inventory, run the residue check, assert it is empty, and log
  both inventories. The teardown runs even when the leg has already failed
  part-way, so a failed leg does not leave residue either.
- **WP5 — regression evidence.** The deterministic tests below.
- **WP6 — qualification.** Re-run the routed-LAN leg on the disposable guest at
  the final head and measure the guest's filter state before and after the
  leg: PF's enable state unchanged, no `wg-basic-v1-*` anchor holding loaded
  rules, no `wg-basic-v1-*` file left in `/etc/pf.anchors/`, and the main
  rulesets as they were.
- **WP7 — records.** This plan, the closure record, the registry, the roadmap,
  and the documentation below.

## Privilege and security effects

None to the product. The fixture already runs as root on a disposable host; it
runs `sudo pfctl` today and will run a bounded set of `sudo pfctl` verbs
tomorrow. The privilege the fixture uses does not change; the set of things it
touches shrinks.

The important security property is that the fixture's footprint on the host
**decreases**: after this change, a leg that has run leaves behind no loaded
rules, no enabled PF it did not find, and no files. The residue the leg used to
leave was a loaded rule set that could match a later tunnel's device.

## Persistence, protocol, and configuration compatibility

None. The product's state schema, the UAPI encoding, the netd/serve protocol,
and the configuration surface are untouched. This is a test-only change.

## Failure, cancellation, restart, and contention semantics

- **A failed leg.** The restoration still runs. A leg that panics half-way
  through must not leave residue either, so the restoration is invoked from a
  path that also runs on failure.
- **A cancelled leg.** The same: the restoration is not conditional on the
  leg having reached its end.
- **A restart of the leg.** A second run on the same host must not inherit the
  first run's residue. This is exactly the case the defect breaks, and it is
  the case the qualification proves: the leg is run twice on the same guest,
  and the second run's baseline must show no residue from the first.
- **Contention.** The restoration is scoped to the leg's own anchors by name,
  so a concurrent anchor of another installation is never flushed. Where two
  installations share a host, the restoration names its own anchor only.

## Focused tests

Deterministic, host-free, and each fails without the corresponding fix:

| Test | Proves |
|---|---|
| the restoration planner flushes the managed anchor's filter rules and its NAT rules, and never emits a bare `-F all` | the anchor's loaded rules are actually emptied — the core of the defect |
| the restoration planner removes the anchor file and its `.drift` sibling | the leftover file is gone |
| the restoration planner disables PF only when the baseline had it disabled | the host's own state is restored, not overwritten |
| the restoration planner names only the leg's own anchor and never a foreign anchor | the restoration is scoped |
| the residue check reports an anchor that still holds loaded rules | the residue check is not vacuous |
| the residue check reports a leftover anchor file, a leftover `.drift` file, and a changed PF enable state | each residue is detected by name |
| the residue check reports nothing for a clean inventory | the check does not fire on a clean host |
| the residue check reports a main ruleset that differs from the baseline | the leg's own ruleset change is caught |

These run in the ordinary gate order on the Darwin host and in the hosted macOS
`gates-arm64` job; they need no PF and no root.

## Linux and network-namespace integration evidence

Not applicable to the defect: it is a macOS-host qualification-hygiene defect,
and the product is unchanged. The Linux evidence is the **non-regression**
evidence — the whole gate order, including the feature-bearing Linux
cross-clippy — because the changed test target is compiled by it. The Linux
rootful suites are unaffected, and the closure record says so rather than
implying they were re-qualified for this milestone.

## Broad verification commands

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
CC_x86_64_unknown_linux_gnu=$HOME/wg-toolchain/zigcc \
  AR_x86_64_unknown_linux_gnu="zig ar" \
  cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets \
    --features linux-integration -- -D warnings
```

plus the routed-LAN leg on the disposable macOS guest (WP6), run **twice on
the same guest** so the second run's baseline is the proof that the first run
left nothing.

## Documentation updates

- `architecture/testing-qualification.md` — the suite catalog: what the
  routed-LAN leg now proves about the host it ran on, and that the leg
  restores the filter it loaded.
- `docs/development.md` — the routed leg's host requirements: the guest's PF
  must be **Disabled** before the leg runs (the leg restores it either way),
  and the leg must be run on a disposable guest whose filter may be inspected
  afterwards.
- `plans/closure/macos-native-server-corrective/c003-status.md` — **no edit**.
  The finding is already recorded there by the dated §12 amendment, and
  §13 of the planning process requires the historical record to stay
  period-accurate.

## Acceptance criteria

1. After the routed-LAN leg, the disposable guest's PF enable state is what it
   was before the leg.
2. After the leg, no `wg-basic-v1-*` anchor holds loaded rules, in the filter
   class or the NAT class.
3. After the leg, `/etc/pf.anchors/` holds no file belonging to the leg,
   including no `.drift` sibling.
4. After the leg, the main filter and NAT rulesets are what they were.
5. The deterministic tests above exist and fail without the fix.
6. The leg passes at the final head on the disposable guest, twice on the same
   guest, and the second run's baseline shows no residue from the first.
7. The Linux gate order, including the feature-bearing cross-clippy, is green
   on the final head, and the ordinary suite is green.
8. The dependency audit's status is unchanged and is not claimed as green.

## Stop conditions

- If the anchor's loaded rules cannot be emptied without flushing a table the
  leg does not own, or without touching the main ruleset, **stop** and record
  the discrepancy. A restoration that has to flush the main ruleset is a
  different and more dangerous operation, and it is not this plan.
- If restoring PF's enable state would require a privileged capability the leg
  does not already have, **stop**.
- If the residue check cannot be made to distinguish the leg's own residue
  from a concurrent installation's, **stop**: a restoration that could flush
  another installation's anchor is not acceptable.
- If the leg's traffic assertions have to be weakened for the restoration to
  pass, **stop**.
- If the guest cannot be run twice on the same host for the qualification,
  **stop** and report; the second run is the proof that the residue is gone.

## Closure evidence requirements

Per `plans/003-planning-process.md` §6: implementation commits; repository
baseline and final head; a requirement-to-evidence matrix; the exact
verification commands and their results; the disposable-host evidence (the
guest's filter inventory before and after the leg, and the second run's
baseline); the documentation evidence; the known limitations; the unresolved
findings by severity; and a disposition.

The closure record states plainly that the residue was found by C013's
re-run of C003's leg, that the finding was made in C013's record and corrected
in C003's record by a dated amendment, and that this corrective is where the
defect itself is closed.
