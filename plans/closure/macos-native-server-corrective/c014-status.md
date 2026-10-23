# macOS Native Server C014 — The routed-LAN leg restores the filter it loaded

Disposition: **closed** (2026-10-23) — C003's routed-LAN qualification leg did
not restore the host's packet filter. On macOS a loaded anchor's **rules**
survive `pfctl -f` and `pfctl -F all`, so removing the anchor's `load anchor`
line from `/etc/pf.conf` and deleting its file left the anchor's rules loaded
and being evaluated; the leg ran `pfctl -e` and never put PF's enable state
back, and the disposable guest had PF **disabled** at the start; and the leg
left the `.drift` file it wrote for the drift control in `/etc/pf.anchors/`.
Two of the eight leftover rules match on `utun0`, and macOS recycles `utun`
indices, so a later tunnel handed that index would have inherited the previous
leg's rules. The defect was in C003's **fixture**, not in the product: the
product writes no PF state, no forwarding sysctl, and no route in the routed-LAN
mode, and C003's traffic evidence is unaffected. The leg now captures the
host's filter inventory before it installs anything, restores the managed
anchor's filter and NAT rulesets per class, removes the anchor's file and its
`.drift` sibling, puts PF's enable state back the way it found it, and
**measures** that it did instead of asserting it. The leg was run twice on the
same guest with no PF reset in between: both runs passed, and after each run
the main filter and NAT rulesets were byte-identical to the baseline, PF's
enable state was unchanged (disabled), `/etc/pf.anchors` still held only
`com.apple`, and there was no anchor file and no `.drift` sibling.

Date: 2026-10-23.

Source plan: `plans/implementation/macos-native-server/c014-routed-leg-filter-restoration.md`
(committed `d4ae75b`).
Corrective roadmap: `plans/subsystems/macos-native-server-corrective-roadmap.md`
(C014).
Baseline: `plans/macos-native-support@d26c886`.
Implementation head: `7855533` — *test(macos): restore the filter the routed-LAN
leg loaded*, on top of `d26c886`; `tests/wireguard_darwin_routed.rs` only,
935 lines changed.
Docs head, and branch head at the time of writing: `5e35a4a`.

## 1. What was wrong

One defect, in C003's qualification fixture. The leg's teardown restored the
host's **ruleset** and the host's **routes**, and asserted that it left the
host's routing and filter as it found them. It did not restore the host's
**filter**.

Three pieces of residue were left, and one of them is the reason this is a
defect rather than a tidiness item:

1. **The managed anchor's loaded rules.** macOS keeps a loaded anchor's rules
   across `pfctl -f` and across a bare `pfctl -F all`. Reloading the main
   ruleset without the anchor's `load anchor` line removes the *reference*; it
   does not empty the anchor's own ruleset. The teardown removed the reference
   and deleted the anchor file, and the anchor's rules stayed loaded.
2. **PF's own enable state.** The leg runs `pfctl -e` to make the operator's
   rules effective and never put the host back the way it was. The disposable
   guest had PF **disabled** at the start, so the leg left it **enabled**,
   which changes the host's filtering behaviour for everything on the machine.
3. **The anchor's files.** The leg writes `/etc/pf.anchors/<anchor>` and, for
   the drift control, `/etc/pf.anchors/<anchor>.drift`. The teardown removed
   the first and left the second.

The measurement that exposed all three is in C003's closure record §12.1 and
in C013's closure record as **F8**, where the observation was made — measured
on the disposable guest immediately after C013 re-ran C003's leg against
C013's final head:

```
$ pfctl -s info | head -2
Status: Enabled for 0 days 00:33:11           Debug: Urgent

$ pfctl -a wg-basic-v1-0349b3e7-3a2e-4a9b-a901-c521c4e31163 -s rules
pass out on en0 inet from 10.77.0.0/24 to 10.20.20.0/24 flags S/SA keep state
pass out on en0 inet6 from 2001:db8:77::/64 to 2001:db8:20::/64 flags S/SA keep state
pass in on en0 inet from 10.20.20.0/24 to 10.77.0.0/24 flags S/SA keep state
pass in on en0 inet6 from 2001:db8:20::/64 to 2001:db8:77::/64 flags S/SA keep state
pass in on utun0 inet from 10.77.0.0/24 to 10.20.20.0/24 flags S/SA keep state
pass in on utun0 inet6 from 2001:db8:77::/64 to 2001:db8:20::/64 flags S/SA keep state
pass out on utun0 inet from 10.20.20.0/24 to 10.77.0.0/24 flags S/SA keep state
pass out on utun0 inet6 from 2001:db8:20::/64 to 2001:db8:77::/64 flags S/SA keep state

$ ls -la /etc/pf.anchors/
-rw-r--r-- 1 root wheel 44 Oct 22 14:47 wg-basic-v1-0349b3e7-3a2e-4a9b-a901-c521c4e31163.drift
```

**Two of the eight leftover rules match on `utun0`**, and macOS recycles `utun`
indices: a later tunnel that was handed index 0 would inherit the previous
leg's rules, on a device the previous leg never saw. The leg's own drift
control had already established that a stale rule can match the wrong device —
this is that same hazard, left behind by the leg itself.

**The defect is in the fixture, not in the product.** The product writes no PF
state, no forwarding sysctl, and no route in the routed-LAN mode; the filter
is the operator's, installed from the rules the product reports. C003's
traffic evidence is real and unaffected. What was false was the leg's own
hygiene claim, and the claim was checked by nobody.

## 2. Why the previous evidence missed it

Because it was an assertion, not a measurement.

C003's closure record §2 carried the row:

> | Stop if the only workable strategy needs uncontrolled PF edits, unbounded
> sysctl writes, default-route takeover, unqualified filtering, or foreign
> resource deletion | None was needed. The product writes no PF state, no
> sysctl, and no route; the operator installed the filter, the forwarding
> switches, and the upstream routes, and the run's teardown left the host's
> routing and filter as it found them |

The last clause is the one that was inaccurate. The run's own inventory
covered the host's routes and the **main** filter ruleset — `routes before`,
`routes after`, `routes IPv6 before`, `routes IPv6 after`, `packet filter
before`, `packet filter after`, and `forwarding after` — and **not** the
anchor's own two rulesets, **not** PF's enable state, and **not** the anchors
directory. Those three omissions are exactly the three things the teardown did
not restore, so an inventory that omitted them could not have found the
residue. What the teardown *did* restore, C003's §12.1 records exactly:
`/etc/pf.conf` and the main ruleset back to the stock macOS ruleset, the
host's routes as they were, no product process, no control socket, and no
state directory remaining. The anchor's rules were still being evaluated by
the kernel, on a device index the host recycles.

The residue was found by **C013**, which re-ran C003's routed-LAN leg on the
disposable guest against C013's final head so that C003's controlled-host
evidence would remain true of the code C013 landed, and then measured what the
leg left behind. C013 recorded the finding as **F8**; C003's closure record
carries the same observation as its dated §12 amendment. Per §13 of the
planning process the defect needed its own corrective, with its own plan and
its own closure record — this one — and the historical record was left as it
was written.

## 3. The implementation

| Commit | What it changed |
|---|---|
| `d4ae75b` | the plan, the registry entry, and the corrective roadmap entry |
| `7855533` | the fixture: `tests/wireguard_darwin_routed.rs` only, 935 lines changed. The product (`src/`) is untouched |
| `5e35a4a` | the documentation: what the routed-LAN leg now proves about the host it ran on, and the leg's host requirements |

The fixture grows four things, exactly as the plan's "expected production
changes" asked:

1. **A baseline capture** of the host's filter state, taken *before* the leg
   installs anything (`capture_filter_inventory`): PF's enable state, the main
   filter ruleset, the main NAT ruleset, **every anchor's own two rulesets**,
   and the anchors-directory listing. The managed anchor is read whether or
   not the main ruleset still refers to it, because an anchor whose rules are
   still loaded no longer has to be referred to.
2. **A pure restoration planner**,
   `restoration_commands(anchor, anchor_path, pf_was_enabled) -> Vec<Vec<String>>`,
   with no host access, so it can be asserted on without a PF and without
   root. It produces the teardown's exact argv, in the order the operations
   depend on: the anchor's filter class (`-a <anchor> -F rules`) and then its
   NAT class (`-a <anchor> -F nat`) — **one flush per class**, because
   `-F rules` alone leaves the NAT rules loaded, and a bare `-F all` flushes
   the **main** ruleset, which the leg does not own and never flushes; then
   the anchor's lines out of `/etc/pf.conf` and a reload; then the anchor's
   file **and** its `.drift` sibling; and last the filter's enable state
   (`pfctl -d` only when the baseline had PF disabled).
3. **A pure residue check**, `residue_found(baseline, after, anchor) -> Vec<String>`,
   also with no host access. It reports, by name: an anchor of the leg's that
   still holds loaded filter rules or loaded NAT rules, a leftover anchor
   file, a leftover `.drift` file, a changed PF enable state, and a main
   filter or NAT ruleset that differs from the baseline.
4. **A measured teardown** (`restore_the_filter`). It runs the planner's
   commands **unchecked on purpose** — a restoration that stops at the first
   failure leaves more behind, and the residue check is what reports what is
   left — then captures the inventory again, runs the residue check, logs both
   inventories and the residue, and the leg asserts that the residue is empty.
   The leg's body is a function of its own, and the caller catches a panic,
   runs the restoration, and only then re-raises the failure, so **a leg that
   panics or is cancelled is restored too**. The filter context is recorded
   before the filter is installed, so a leg that fails between the install and
   the end is restored as well.

**Eight host-free regressions** cover the planner and the residue check, and
each one was **mutation-tested**: each was changed to remove its fix, and
confirmed to fail without it. They run in the ordinary gate order on the
Darwin host and in the hosted macOS `gates-arm64` job, and they need no PF and
no root.

The plan carries every element that `plans/003-planning-process.md` §5
requires of an implementation plan — repository baseline, source roadmap and
milestone, canonical requirements and ADRs, primary work class, objective,
explicit non-goals, current repository evidence, invariants, expected
production changes, ordered work packages, privilege and security effects,
persistence/protocol/configuration compatibility effects, failure, cancellation,
restart and contention semantics, focused tests, Linux/network-namespace
integration evidence, broad verification commands, documentation updates,
acceptance criteria, stop conditions, and closure evidence requirements — and
each is discharged below.

## 4. Requirement-to-evidence matrix

Every row is a requirement of
`c014-routed-leg-filter-restoration.md`, named by the element it comes from.

| Requirement | Evidence |
|---|---|
| **Objective 1** — the managed anchor's loaded rules are emptied, in the filter class and the NAT class separately, and never with a bare `-F all` | `restoration_commands` emits `sudo /sbin/pfctl -a <anchor> -F rules` and then `sudo /sbin/pfctl -a <anchor> -F nat`; the regression `the_restoration_flushes_the_managed_anchor_and_never_the_main_ruleset` asserts both and asserts that no `-F all` and no unscoped flush is ever emitted; the guest measurement: the managed anchor holds **no** filter rules and **no** NAT rules after each run |
| **Objective 2** — PF's enable state is put back the way the leg found it | `restoration_commands` emits `pfctl -d` when the baseline had PF disabled and `pfctl -e` when the baseline had it enabled; the regression `the_restoration_restores_the_filters_enable_state`; the guest measurement: `Status: Disabled` before run 1, after run 1, and after run 2 |
| **Objective 3** — the anchor's file and its `.drift` sibling are removed | `restoration_commands` emits `rm -f <anchor_path>` and `rm -f <anchor_path>.drift`; the regression `the_restoration_removes_the_anchor_file_and_its_drift_sibling`; the guest measurement: `/etc/pf.anchors` held only `com.apple` after each run, and the inventory's "any wg-basic anchor file or drift sibling" section reads `(none)` |
| **Objective 4** — the leg's "left the host's routing and filter as it found them" claim is checked, not asserted | `capture_filter_inventory` before the leg, `capture_filter_inventory` again after the teardown, `residue_found` over the two, and the leg's assertion that the residue is empty; the leg's own evidence line `the residue the leg left on the host's packet filter: []` |
| **WP1 / expected change 1** — the baseline is captured before the leg installs anything, and it is the host's own state | the capture is taken before the filter is installed, and the filter context carrying it is recorded before the install as well; the log's baseline inventory, and the run's "FILTER INVENTORY: BEFORE RUN 1" |
| **WP2 / expected change 2** — a pure restoration planner that produces the teardown's exact argv | `restoration_commands(anchor, anchor_path, pf_was_enabled) -> Vec<Vec<String>>`; no host access, no `Command`; four regressions over it |
| **WP3 / expected change 3** — a pure residue check that reports the residue it found, by name | `residue_found(baseline, after, anchor) -> Vec<String>`; no host access; four regressions over it |
| **WP4 / expected change 4** — a measured teardown that runs even when the leg has failed part-way | `restore_the_filter` runs the planner's commands unchecked, captures the inventory again, and returns the residue; the leg's body is `run_routed_lan_leg`, the caller catches the panic with `catch_unwind`, restores, and re-raises with `resume_unwind` |
| **Invariant** — the leg must not weaken any traffic assertion | the traffic assertions are untouched by `7855533`: the forwarded traffic, the spoofed-source rejection, the unapproved-destination rejection, and the helper-recovery leg all stay as they are; both runs carried the real IPv4 and IPv6 downstream and return traffic (see §5.5) |
| **Invariant** — the restoration must be scoped to the anchors the leg itself created, and only their own rulesets | the regression `the_restoration_names_only_the_legs_own_anchor`: the only anchor the argv names is the leg's own, no argument mentions `com.apple`, and the only paths named are the leg's anchor file, its `.drift` sibling, and `/etc/pf.conf`; there is no table flush and no root-ruleset flush anywhere in the planner |
| **Invariant** — the restoration must restore, not impose | the enable state goes back to the baseline's, not to a state the leg prefers (`pfctl -d` only when the baseline had PF disabled); the regression `the_restoration_restores_the_filters_enable_state`; the guest's main rulesets are the stock macOS ruleset before and after |
| **Invariant** — a fixture may not claim what it has not measured | the residue check compares the post-teardown inventory against the baseline; the measured inventories are in §5.5 and in the leg's own evidence file |
| **Invariant** — the fixture's evidence is written even when the leg fails | `Evidence`'s `Drop` implementation writes the file, so the transcript that carries the restoration's verdict is written whatever the outcome (`tests/darwin_live_common/mod.rs`) |
| **Failure semantics** — a failed leg still restores the filter | the leg's own failure is logged first, then the restoration runs, then the failure is re-raised; the filter context exists before the install |
| **Cancellation semantics** — a cancelled leg still restores the filter | the restoration is not conditional on the leg having reached its end; it runs from the caller, outside the leg's body |
| **Restart semantics** — a second run on the same host inherits no residue from the first | the qualification runs the leg **twice on the same guest with no PF reset in between**; run 2's baseline is the proof, and it shows no loaded rules, no file of the leg's, the original enable state, and the original main rulesets |
| **Contention semantics** — a concurrent installation's anchor is never flushed | the residue check and the planner are both scoped to the leg's own anchor name and its own two files; the regression `the_restoration_names_only_the_legs_own_anchor` |
| **Focused test 1** — the planner flushes the managed anchor's filter rules and its NAT rules, and never emits a bare `-F all` | `the_restoration_flushes_the_managed_anchor_and_never_the_main_ruleset`; mutation-tested |
| **Focused test 2** — the planner removes the anchor file and its `.drift` sibling | `the_restoration_removes_the_anchor_file_and_its_drift_sibling`; mutation-tested |
| **Focused test 3** — the planner disables PF only when the baseline had it disabled | `the_restoration_restores_the_filters_enable_state`; mutation-tested |
| **Focused test 4** — the planner names only the leg's own anchor and never a foreign anchor | `the_restoration_names_only_the_legs_own_anchor`; mutation-tested |
| **Focused test 5** — the residue check reports an anchor that still holds loaded rules | `the_residue_check_reports_an_anchor_that_still_holds_loaded_rules`; mutation-tested |
| **Focused test 6** — the residue check reports a leftover anchor file, a leftover `.drift` file, and a changed PF enable state | `the_residue_check_reports_a_leftover_file_and_a_changed_enable_state`; mutation-tested |
| **Focused test 7** — the residue check reports nothing for a clean inventory | `the_residue_check_reports_nothing_for_a_clean_inventory`; mutation-tested |
| **Focused test 8** — the residue check reports a main ruleset that differs from the baseline | `the_residue_check_reports_a_main_ruleset_that_differs_from_the_baseline`; mutation-tested |
| **Acceptance 1–4** — after the leg, PF's enable state is what it was, no `wg-basic-v1-*` anchor holds loaded rules in either class, `/etc/pf.anchors/` holds no file of the leg's, and the main filter and NAT rulesets are what they were | the three measured inventories in §5.5, and the leg's own post-teardown inventory with the residue `[]` |
| **Acceptance 5** — the deterministic tests exist and fail without the fix | eight regressions, each mutation-tested; §3 |
| **Acceptance 6** — the leg passes at the final head on the disposable guest, twice on the same guest, and the second run's baseline shows no residue from the first | `RUN1_EXIT=0` and `RUN2_EXIT=0`, `test result: ok. 1 passed; 0 failed` on each; §5.5 |
| **Acceptance 7** — the Linux gate order, including the feature-bearing cross-clippy, is green, and the ordinary suite is green | §5.1, §5.2, §5.3 |
| **Acceptance 8** — the dependency audit's status is unchanged and is not claimed as green | §5.4: the hosted `dependency-audit` job is red for the upstream reason already recorded, and is routed to C005/M007 |
| **Non-goal** — the product is not changed | `7855533` touches `tests/wireguard_darwin_routed.rs` only; `src/` is untouched by C014; the product still writes no PF state, no forwarding sysctl, and no route in the routed-LAN mode |
| **Non-goal** — C003's routed-LAN contract is not reopened, and its closure record keeps its history | C003's record is not rewritten; it carries its dated §12 amendment recording the finding; the leg's traffic evidence was re-run here and is unaffected |
| **Non-goal** — C004's product-side PF/NAT work is untouched | C014 changes no `src/firewall/*` file and makes no decision about the product's own anchor ownership; C004's implementation is a separate commit (`7c7da7b`) on the same branch |
| **Non-goal** — the guest's own PF policy is not rewritten | the restoration removes only the leg's own lines from `/etc/pf.conf` and reloads; the guest's main rulesets are the stock macOS ruleset before and after, and `com.apple`'s two rules are untouched |
| **Stop conditions** — none was triggered | the anchor's rules could be emptied without touching the main ruleset or a table; the restoration needed no privilege the leg did not already have; the leg's own residue was distinguishable from a concurrent installation's; no traffic assertion was weakened; and the guest could be run twice on the same host, which is the proof the residue is gone |
| **Documentation updates** | §7 |

## 5. Commands and results

### 5.1 On the Darwin host

```
cargo fmt --all -- --check                           GATE_EXIT 0
cargo check --all-targets --locked                   GATE_EXIT 0
cargo clippy --all-targets --locked -- -D warnings   GATE_EXIT 0
cargo test --locked                                  GATE_EXIT 0
cargo +1.89.0 check --all-targets --locked           GATE_EXIT 0
```

The ordinary suite: **43 binaries, 732 passed, 0 failed, 15 ignored**. The
fifteen ignored are the `#[ignore]`d tests the ordinary suite may not run: the
Darwin live fixtures, the Darwin controlled-host legs, the Darwin routed-LAN
leg, the upgrade-rehearsal fixtures, the canonical-path systemd installation
fixture, and the unrelated-uid IPC privilege check.

At the **final head** (`bc70125`) — the tree that adds C004's gateway evidence
leg and both closure records — the same gate order was re-run: **44 binaries,
750 passed, 0 failed, 16 ignored**, with `fmt`, `check`, `clippy` and the MSRV
check green. The sixteenth ignored test is C004's own live gateway leg, which
the ordinary suite may not run and which the controlled host ran instead. The
controlled Linux host's gate order and all eleven rootful suites were re-run
at the same head and are green (44 binaries, 672 passed, 0 failed, 3 ignored),
and the hosted `macOS qualification` and `Distribution foundation` workflows
both succeed.

### 5.2 On the controlled Linux host (`sugarwookie@192.168.182.143`)

The canonical platform's own gate order and every rootful suite, at the head
that carries this change:

```
cargo fmt --all -- --check                                           GATE_EXIT 0
cargo check --all-targets --locked                                   GATE_EXIT 0
cargo clippy --all-targets --locked -- -D warnings                   GATE_EXIT 0
cargo clippy --all-targets --locked --features linux-integration -- -D warnings   GATE_EXIT 0
cargo test --locked                                                  GATE_EXIT 0
cargo +1.89.0 check --all-targets --locked                           GATE_EXIT 0
```

The ordinary suite on that host: **43 binaries, 672 passed, 0 failed, 3
ignored** — the three ignored are the Linux-only canonical installation and
update-transaction fixtures.

All **eleven** rootful suites green:

| Target | Result |
|---|---|
| `wireguard_kernel` | green |
| `network_reconcile` | green |
| `network_control_e2e` | green |
| `durable_owner` | green |
| `durable_restart` | green |
| `durable_backup` | green |
| `product_management_rootful` | green |
| `maintenance_rootful` | green |
| `doctor_readonly` | green |
| `service_rootful_e2e` | green |
| `upgrade_rehearsal_rootful` | green |

The host's unrelated state was inventoried before and after: the network
namespace list, the links, the IPv4 and IPv6 route tables, the nftables ruleset
and table list, the systemd units matching `wg-basic*`, the canonical
installation paths, and `wg show`. Namespaces, links, the nftables table list,
the units, and the canonical paths are **unchanged**; the route tables differ
only in the host's own router-advertisement expiry timers counting down, and
the ruleset only in the host's own packet counters moving. No route, rule,
unit, or path was added or removed.

This is the **non-regression** evidence the plan asked for, not new Linux
qualification: the defect is a macOS-host fixture hygiene defect and the
product is unchanged by C014.

### 5.3 The Linux cross-clippy, on the Darwin host

A feature-bearing Linux cross-clippy with the zig toolchain, so that a Darwin
host type-checks the Linux-gated code:

```
CC_x86_64_unknown_linux_gnu=$HOME/wg-toolchain/zigcc \
  AR_x86_64_unknown_linux_gnu="zig ar" \
  CARGO_TARGET_DIR=/private/tmp/wg-c004-cross-target \
  cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets \
    --features linux-integration -- -D warnings       CROSS_CLIPPY_EXIT 0
```

### 5.4 In hosted CI

Every hosted job is green **except** the `dependency-audit` job, which is red
for the upstream reason already recorded — upstream `eggup-archive` pins
`zip ^6.0.0` — and is routed to C005/M007. **The dependency audit is not
claimed as green.**

The head the gates above ran at is the branch head `5e35a4a`, which carries
C014's fixture change (`7855533`), C004's product-side implementation
(`7c7da7b`), and the documentation (`5e35a4a`). C014's own implementation
commit touches `tests/wireguard_darwin_routed.rs` only.

### 5.5 On the disposable macOS guest — the controlled-host qualification

**The host.** A disposable macOS guest (macOS 26.6.2 build 25G83, arm64) in a
UTM Apple-silicon virtual machine, with a Linux peer host on the second
segment and this Mac as the upstream router. The guest was re-created for
this run; the earlier one had been destroyed.

**The binaries under test**, staged on the guest and compared on both sides
before the run:

```
fcc81252994e9f37b1ac2c5ebacef422baa3b58b73506e65c0c025f018296bc4  /tmp/final/wg-basic
cd5aa53120c8548010b4fd5b1f8a509d8dcc69f6a4ddfb974cb4a5b376f0e77c  /tmp/final/wireguard_darwin_routed
ccc10eaf95306a80eb1fe91fee2d9c9d5f8585be43b44384cb2a28fa1093e705  /tmp/wireguard-go (the pinned helper, unchanged)
```

**The method.** The C003 routed-LAN leg was run **twice on the same guest with
no PF reset between the runs**, and the filter inventory was captured
**before run 1**, **after run 1**, and **after run 2**.

**The result.** Both runs passed:

```
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out; finished in 190.41s
RUN1_EXIT=0
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out; finished in 194.97s
RUN2_EXIT=0
```

**The measured inventories.** Before run 1:

```
--- pfctl -s info ---
Status: Disabled for 0 days 00:00:00          Debug: Urgent

--- main filter ruleset ---
scrub-anchor "com.apple/*" all fragment reassemble
anchor "com.apple/*" all
--- main nat ruleset ---
nat-anchor "com.apple/*" all
rdr-anchor "com.apple/*" all
--- anchors directory ---
-rw-r--r--  1 root  wheel  329 Aug 12 18:51 com.apple
--- every anchor's own two rulesets ---
  com.apple: 2 filter rules, 0 nat rules
--- anchors that hold nothing ---
--- any wg-basic anchor file or drift sibling ---
  (none)
```

After run 1, before run 2:

```
--- pfctl -s info ---
Status: Disabled for 0 days 00:00:00          Debug: Urgent

--- main filter ruleset ---
scrub-anchor "com.apple/*" all fragment reassemble
anchor "com.apple/*" all
--- main nat ruleset ---
nat-anchor "com.apple/*" all
rdr-anchor "com.apple/*" all
--- anchors directory ---
-rw-r--r--  1 root  wheel  329 Aug 12 18:51 com.apple
--- every anchor's own two rulesets ---
  com.apple: 2 filter rules, 0 nat rules
--- anchors that hold nothing ---
  wg-basic-v1-7e6f5106-354f-4da1-9089-1f607a4e369c: empty
--- any wg-basic anchor file or drift sibling ---
  (none)
```

After run 2:

```
--- pfctl -s info ---
Status: Disabled for 0 days 00:00:00          Debug: Urgent

--- main filter ruleset ---
scrub-anchor "com.apple/*" all fragment reassemble
anchor "com.apple/*" all
--- main nat ruleset ---
nat-anchor "com.apple/*" all
rdr-anchor "com.apple/*" all
--- anchors directory ---
-rw-r--r--  1 root  wheel  329 Aug 12 18:51 com.apple
--- every anchor's own two rulesets ---
  com.apple: 2 filter rules, 0 nat rules
--- anchors that hold nothing ---
  wg-basic-v1-1658d35c-d96b-4371-a7de-7665e27b87fd: empty
  wg-basic-v1-7e6f5106-354f-4da1-9089-1f607a4e369c: empty
--- any wg-basic anchor file or drift sibling ---
  (none)
```

Read against the baseline: the main filter ruleset and the main NAT ruleset
are **byte-identical** to the baseline in all three inventories; PF's enable
state is **unchanged (disabled)**; `/etc/pf.anchors` holds **only**
`com.apple`; there is **no** wg-basic anchor file and **no** `.drift` sibling;
and the only non-empty anchor is `com.apple`, with 2 filter rules and 0 NAT
rules, exactly as at the baseline.

The leg's **own** post-teardown measurement agrees, inside its evidence file:

```
the packet filter inventory:
the packet filter is disabled
the main filter ruleset:
scrub-anchor "com.apple/*" all fragment reassemble
anchor "com.apple/*" all
the main NAT ruleset:
nat-anchor "com.apple/*" all
rdr-anchor "com.apple/*" all
the anchor wg-basic-v1-7e6f5106-354f-4da1-9089-1f607a4e369c holds these filter rules:
the anchor wg-basic-v1-7e6f5106-354f-4da1-9089-1f607a4e369c holds these NAT rules:
the anchor com.apple holds these filter rules:
anchor "200.AirDrop/*" all
anchor "250.ApplicationFirewall/*" all
the anchors directory holds: ["/etc/pf.anchors/com.apple"]

the residue the leg left on the host's packet filter: []
```

The traffic evidence is unaffected and was re-run in both passes: the IPv4 and
IPv6 downstream probes to the approved prefix and the IPv4 and IPv6 return
probes all answered in each run.

**The only difference between the three inventories is the kernel's own anchor
objects**: one empty wg-basic anchor object after run 1, two after run 2.
**PF never destroys an anchor object** — it is a kernel object, not a loaded
ruleset — so the residue is empty objects, never rules. The hazard the
finding was about, a stale rule matching a later tunnel's recycled `utun`
index, does not recur.

**The evidence files** are kept locally at `~/wg-qual/c014-evidence/`:

| File | What it holds |
|---|---|
| `c014-run.log` | the whole session: the guest's restore and reset, the digests of the three binaries under test, the three externally captured filter inventories (before run 1, after run 1 before run 2, after run 2), both runs' full transcripts with `RUN1_EXIT=0` and `RUN2_EXIT=0`, and the listing of the evidence files the runs wrote |
| `run1.txt` | run 1's own evidence file, `c003-routed-lan-approved-prefix.txt`: the leg's transcript with the baseline inventory, the traffic probes, the restoration commands and their results, the post-teardown inventory, and the residue `[]` |
| `run2.txt` | run 2's own evidence file, the same, with run 2's own anchor (`wg-basic-v1-1658d35c-…`) and the same empty residue |

## 6. Security and ownership evidence

- **The fixture's footprint on the host decreases.** After this change a leg
  that has run leaves behind no loaded rules, no enabled PF it did not find,
  and no files. The residue it used to leave was a loaded rule set that could
  match a later tunnel's device.
- **The restoration is scoped.** It may touch only the anchor the leg itself
  created and only that anchor's own two rulesets. It never flushes the main
  ruleset, never flushes a table, never flushes a foreign anchor, and never
  touches Apple's own `com.apple/*` anchors — asserted by the planner's
  regressions and confirmed by the measurement, in which `com.apple` held the
  same two rules before and after.
- **The restoration restores, not imposes.** PF's enable state goes back to
  what the leg found: `pfctl -d` when the baseline had PF disabled, `pfctl -e`
  when it had PF enabled. The guest, which had PF disabled, was left disabled.
- **The claim is measured.** The residue check compares two inventories, and
  the leg fails on any difference. Nothing in this change relaxes a check to
  make a test pass; the fixture's claim was narrowed to what it can prove.
- **No new privilege.** The fixture already ran as root on a disposable host
  and already ran `sudo pfctl`; the set of things it touches shrinks. The
  product's privileged trust boundary, the helper's identity pinning and
  supervision (ADR-010), the persisted state, the UAPI encoding, the
  netd/serve protocol, and the configuration surface are all unchanged.
- **The product writes no PF state, no forwarding sysctl, and no route** in
  the routed-LAN mode, and that is still true.

## 7. Documentation evidence

- `architecture/testing-qualification.md` — what the routed-LAN leg now proves
  about the host it ran on: that it restores the filter it loaded, what it
  measures before and after, why the `-F rules` / `-F nat` split is not a
  detail, and that it is qualified by being run twice on the same guest.
- `docs/development.md` — the routed leg's host requirements: use a disposable
  macOS host whose filter may be inspected afterwards, and the guest's PF must
  be **Disabled** before the leg runs, because the hosted live fixture's own
  PF probe requires it.
- `plans/closure/macos-native-server-corrective/c003-status.md` — **not
  rewritten**. The finding is already recorded there by the dated §12
  amendment, and §13 of the planning process requires the historical record to
  stay period-accurate. This record describes that amendment from C014's side
  only.
- `plans/registry.md` and `plans/subsystems/macos-native-server-corrective-roadmap.md`
  — C014's entry (raised at `d4ae75b`).

## 8. Known limitations

- **The kernel's empty anchor objects accumulate and are never destroyed.**
  This is PF's behaviour, measured: one empty wg-basic anchor object after run
  1, two after run 2, each listed by `pfctl -s Anchors` and each holding
  nothing. PF never destroys an anchor object — it is a kernel object, not a
  loaded ruleset. The rules themselves are always restored, so the residue is
  empty objects and never rules, and the hazard the finding was about does not
  recur. Nothing in this record claims that the objects are removed.
- **The restoration is measured rather than asserted, and that has a
  consequence.** A host whose filter was changed by something else during the
  run is reported as **residue** — the leg fails and says what differs —
  rather than silently accepted as restored. That is the intended direction of
  travel, but it means a concurrent change on the same host can turn the leg
  red for a reason that is not the leg's own residue. The message names what
  differs.
- **The hosted macOS runner cannot produce this leg.** It needs a disposable
  macOS host with a real PF, a second kernel, and a peer host; the evidence
  above is controlled-host evidence, and the hosted `gates-arm64` job carries
  only the host-free regressions.
- **The M007 MUST-NOT-release standing is unchanged by this corrective.**
  Installation and transactional self-update remain unimplemented, Phase 10
  remains planned, and M001 remains ready. Nothing in this record authorizes a
  release, a tag, or an artifact.

## 9. Findings, by severity

- **F8 (low, fixed here): C003's routed-LAN leg did not restore the host's
  packet filter.** It left the managed anchor's eight rules loaded and being
  evaluated, left PF **enabled** on a host that had PF disabled, and left the
  `.drift` file it wrote for the drift control in `/etc/pf.anchors/`. Two of
  the eight rules matched on `utun0`, an index macOS recycles. The finding was
  made in C013's closure record, where the leg was re-run, and is recorded in
  C003's closure record as its dated §12 amendment. It is fixed here, in
  C003's fixture, and the fix is measured on the disposable guest twice over
  (§5.5). The product wrote none of the residue and is unaffected.
- **Open, low, and not a defect in the code: the empty anchor objects
  accumulate.** PF does not destroy an anchor object, so a host that has run
  the leg keeps one empty `wg-basic-v1-*` object per run. No rules are left in
  them, no file is left on disk, and PF's enable state is restored; the
  objects themselves are PF's behaviour and nothing in the leg's scope can
  change that (§8).
- **No new finding is raised by this corrective.** The open items other records
  carry — C013's **F6**, the product's identification of its device by diffing
  the host's inventory — are unaffected by it and are not closed here. The
  hosted `dependency-audit` job is red for the upstream reason already
  recorded and routed to C005/M007; it is not a finding of this milestone and
  it is not claimed as green.

## 10. Disposition

**Closed.** The routed-LAN leg now leaves the host's packet filter the way it
found it, and it proves that by measurement rather than by assertion. It
captures the host's filter inventory before it installs anything, empties the
managed anchor's filter and NAT rulesets one class at a time, removes the
anchor's lines from `/etc/pf.conf` and reloads, removes the anchor's file and
its `.drift` sibling, and restores PF's enable state — and it does all of that
whether the leg reached its end, failed part-way, or was cancelled.

The controlled-host evidence closes it: on a disposable macOS guest the leg
was run **twice on the same guest with no PF reset in between**, and both runs
passed. Before run 1, after run 1, and after run 2 the main filter and NAT
rulesets were byte-identical to the baseline, PF's enable state was unchanged
(disabled), `/etc/pf.anchors` held only `com.apple`, and there was no anchor
file and no `.drift` sibling. The leg's own residue check reported `[]` on
both runs. The only difference between the three inventories is the kernel's
own empty anchor objects, which PF never destroys (§8).

The eight host-free regressions that hold the planner and the residue check in
place were each mutation-tested, and the ordinary gate order is green on the
Darwin host, the controlled Linux host, and the feature-bearing Linux
cross-clippy, with all eleven rootful suites green and the controlled Linux
host's unrelated state preserved.

The defect was in C003's **fixture**, not in the product. The product writes
no PF state, no forwarding sysctl, and no route in the routed-LAN mode, and
that is unchanged; C003's routed-LAN contract, its traffic evidence, and its
closure stand, and its closure record keeps its history with the dated §12
amendment that recorded the finding. Nothing in this milestone widens what
C004 may claim, the Darwin Internet-exit gateway mode remains C004's subject,
the supported Darwin target remains Apple silicon alone under ADR-009, and
M007's MUST-NOT-release standing is unchanged. The dependency audit's status
is unchanged and is not claimed as green.
