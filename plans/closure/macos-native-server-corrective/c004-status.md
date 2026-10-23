# macOS Native Server C004 — Effective, administrator-opt-in PF/NAT gateway

Disposition: **closed** (2026-10-23) — the macOS PF observation became a
bounded, installation-scoped **write** path: the product owns exactly one
anchor and one anchor file, installs its rendered filter and translation rules
into that anchor with `pfctl -a <anchor> -f <file>`, proves that the
administrator's parent invokes the anchor in **both** the filter and the NAT
table, and refuses every incomplete attachment with its own actionable
remediation. The controlled-host run carried real traffic through it: the
IPv4 far side observed the **translated** source, the IPv6 far side observed
the **untranslated** source, the return path worked, and the teardown emptied
the anchor's two rule classes and left the administrator's parent and every
foreign rule exactly as it found them. The mechanism was measured against the
real `pfctl` before it was implemented, and the measurement changed the plan:
an absent anchor and an emptied one are different facts, and the rendered
file's rule order is part of the contract. Two product defects were found and
corrected during the qualification, one leg defect was found and corrected in
the fixture, and one **pre-existing** defect outside this milestone's scope —
the macOS managed interface's own teardown is refused — is recorded as **F10**
and routed to **C015**. The M007 MUST-NOT-release standing is unchanged.

Date: 2026-10-23.

## 1. What this milestone was

C003 made the routed-LAN mode work on macOS against an operator-managed PF
filter, and it read that filter **read-only**: the product observed what the
administrator had installed and refused when the observation did not match the
policy. C004 is the gateway half of the same line, and there the translation
has to be *effective*: the product itself has to put a masquerade rule and the
filter rules into the host's packet filter, and it has to be able to prove
afterwards that the rules it wrote are the rules the kernel is evaluating.

The plan's non-goals are the shape of the work: no editing, replacing or
reordering `/etc/pf.conf`; no `pfctl -f` of the root ruleset; no table flush;
no enabling or disabling PF globally; no taking or restoring the global
forwarding switches; no NAT66; and no change to C003's routed-LAN mode, which
stays operator-managed.

## 2. The mechanism, measured before it was implemented

Work package 1 of the plan was to establish the install mechanism against the
real `pfctl` on the disposable guest, with the contract as the constraint and
the mechanism as the question. The measurements are recorded in the plan
itself and they decided the implementation:

- **Install:** `pfctl -a <anchor> -f <file>` loads the file into the anchor's
  **filter and NAT** rulesets. The root ruleset is byte-identical before and
  after; no table is flushed; PF is not toggled.
- **Remove:** `pfctl -a <anchor> -F rules` then `pfctl -a <anchor> -F nat`.
  `-F rules` alone leaves the NAT rules loaded, so **both** classes are
  required.
- **Order:** PF evaluates *options, normalization, queueing, translation,
  filtering*. A `nat` rule must precede any `pass`/`block` rule in the same
  file, and a file in the wrong order is refused. The product's rendered file
  therefore puts the NAT rules first.
- **`load anchor "<id>" from "<file>"`** populates both classes, so an
  administrator's own reload of `/etc/pf.conf` restores both.
- **A failed load** exits 1, prints `pf rules not loaded`, and leaves the
  anchor's existing content intact: the apply path is fail-closed.
- **An absent anchor** is reported by `pfctl -a <name> -s rules` as exit **0**
  with `pfctl: DIOCGETRULES: Invalid argument` on stderr. The exit code does
  not distinguish an absent anchor; the message does. This was the plan's
  first correction: the pre-existing observation classified a missing anchor
  from a non-zero exit, so on macOS an anchor the administrator had never
  installed was reported as an **emptied** one — two different facts, and the
  difference is the difference between "not installed yet" and "the installed
  rules were removed".
- **The `pfctl -f` warning** (`Use of -f option, could result in flushing of
  rules present in the main ruleset added by the system at startup.`) is
  printed on stderr for **every** load, anchor-scoped ones included. It is not
  an error; the exit code is 0 and the root ruleset is provably preserved. The
  product must not read it as a failure.
- **Anchor objects accumulate:** `pfctl -s Anchors` enumerates every anchor
  object in the kernel, 62 on the guest, attached or not, and PF never
  destroys one. "Removal" can therefore only ever mean emptying the anchor's
  **rules**.

Two further measured facts shaped the administrator's procedure and the
teardown:

- **The anchor's file must exist before the parent's `load anchor` line is
  loaded.** With the attachment in place and the file absent, `pfctl -f
  /etc/pf.conf` **fails** (`No such file or directory`, `cannot open the main
  config file!`, `pf rules not loaded`) and the kernel keeps the previous
  ruleset — the host's *entire* packet-filter configuration breaks, not just
  this installation's anchor. An empty file is enough.
- **Appending all three parent lines to the end of `/etc/pf.conf` makes the
  main ruleset fail to load.** The `nat-anchor` line must precede the stock
  `anchor "com.apple/*"` line. The plan's own operator snippet had the
  ordering wrong; it was corrected against the measurement before the
  implementation started.

## 3. The implementation

Commits: the product and the corrected plan at **`7c7da7b`**, the
documentation at **`5e35a4a`**. Repository baseline for this work: `d26c886`;
branch head at the time of writing: `5e35a4a`.

- **`src/firewall/pfctl.rs`** — the write path. The module's contract changed
  from read-only to scoped: `observe()` now returns the anchor's filter and
  NAT rulesets and tells an **absent** anchor from an **emptied** one;
  `install_anchor(anchor, content)` validates the anchor's name, writes
  `<dir>/.<anchor>.tmp`, renames it over the destination, reads the file back
  and compares its sha256 with what was written, then loads the file into the
  anchor with the fixed vector `["-a", anchor, "-f", path]`; `clear_anchor(anchor,
  content)` flushes both classes and rewrites the file, and never removes it;
  `read_anchor_file(anchor)` reads it. One `Command::new(PFCTL)`, no shell, no
  caller-supplied path or text, bounded output and runtime, and an anchor-name
  validation (`[A-Za-z0-9._-]`, at most 200 bytes, never `.` or `..`).
- **`src/firewall/pf.rs`** — the anchor file's renderer and the comparators.
  `anchor_file_content` emits the marker line and then the **NAT rules
  first**, because PF refuses a file whose translation rule follows its
  filtering rules. `nat_content_matches` and `parse_nat_rule` compare the
  translation rules while tolerating the `inet`/`inet6` family token and the
  `round-robin` annotation PF itself adds, and fail closed otherwise.
  `owns_anchor_file` proves ownership from the marker the product itself
  wrote, so the administrator's routed-LAN filter is never removed and a mode
  change is handled.
- **`src/firewall/service_darwin.rs`** — the gateway mode. `plan()` reports a
  `GatewayVerdict` instead of refusing outright; `observe_gateway` computes
  that verdict as a **pure function** of injected facts, so it is testable
  without a host; `install_gateway_anchor` installs and then re-observes both
  classes; `release_managed_anchor` proves ownership from the file's marker
  and, when it owns it, empties both classes and rewrites the file to its
  marker line; `release_if_owned` runs in every non-gateway mode, and an
  unreadable file or packet filter yields "nothing observed" — no residue
  claimed and nothing removed — rather than an error that would block the
  reconcile.
- **`src/firewall/policy.rs`** — `FirewallActionKind::InstallManagedPfAnchor`
  and `RemoveManagedPfAnchor`, the `ManagedAnchorResidueObserved` warning, the
  `GatewayVerdict` type, the optional `gateway` field on
  `FirewallPlanSummary` (with `#[serde(default)]`, exactly as C003 added
  `routed_lan`), and the `FirewallError` variants
  `GatewayAttachmentMissing`, `NatDrift` and `AnchorConflict`.
- **`src/doctor.rs` / `src/main.rs`** — a `Gateway` doctor check that names
  each missing prerequisite and the three attachment lines.
- **`tests/architecture_guards.rs`** — the guard that pinned `pfctl.rs`'s
  read-only contract was **rewritten**, not deleted: it now pins the scoped
  apply (the verb set, exactly one `Command::new(PFCTL)`, the anchor-scoped
  `-f`/`-F` window, the bounds), the C003 guard that required the gateway to
  stay refused was updated to C004's contract, and a new guard pins that the
  gateway owns one anchor and never the host's own configuration. All 68
  guards pass.

No ADR was required: ADR-008 §3.6 already permits a scoped macOS PF/NAT
backend with no root reload, no table flush, no global toggle and no
`/etc/pf.conf` write, and the measured mechanism stays inside that envelope.

## 4. The controlled-host qualification

**Environment.** The disposable macOS guest (macOS 26.6.2 build 25G83, arm64,
in a UTM Apple-silicon virtual machine) is the appliance; the Linux peer host
is the off-host client and the far-side egress endpoint; this Mac is a pure
forwarder. The guest's segment is `192.168.64.0/24` and the peer's is
`192.168.65.0/24`, so the Mac routes between them and its own PF anchor
decides what is forwarded. The guest had to be **re-created** for this run —
the earlier disposable guest was destroyed mid-session — which meant
re-downloading the 18.4 GB restore image (`UniversalMac_26.6.2_25G83_Restore.ipsw`,
sha256 `885503b7f4b06609e9a512f2befd40f59730640a3f1233e3892d60affdd51c95`,
verified against the recorded digest), restoring macOS, and re-staging the
binaries.

**Binaries under test.** `wg-basic` sha256
`fcc81252994e9f37b1ac2c5ebacef422baa3b58b73506e65c0c025f018296bc4`;
the leg `wireguard_darwin_gateway` sha256
`9e93838aeca05fd75dad3b66526e7604dbfa1c0fef166c420945f3c997b05467`;
the pinned helper `wireguard-go` sha256
`ccc10eaf95306a80eb1fe91fee2d9c9d5f8585be43b44384cb2a28fa1093e705`.

**Method.** The leg acts as the administrator where an administrator acts: it
creates the anchor's file, attaches the anchor in both rule classes, reloads
the host's own configuration, enables PF, and sets the host's forwarding
switches. It then drives the product through the gateway policy and measures
the far side's own observation of the traffic that arrived there.

**Result.** `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 18
filtered out; finished in 45.51s`.

The claims, and the evidence for each:

| Claim | Evidence |
|---|---|
| The IPv4 far side observes the **translated** source | "the far side observed the IPv4 source **192.168.64.4** (the gateway's egress address is 192.168.64.4, the client's tunnel address is 10.77.0.2)" — the far side saw the gateway's egress address, not the client's tunnel address. The observation is taken **in the downstream LAN namespace**, on the packet that actually arrived there, by a packet-socket capture the peer driver runs there. |
| The IPv6 far side observes the **untranslated** source | "the far side observed the IPv6 source **2001:db8:77::2** (the client's tunnel address is 2001:db8:77::2)" — no NAT66: the client's own IPv6 address is what arrived. |
| The return path works | the peer's probes to the far side answered in **both** families: "64 bytes from 10.20.20.2: icmp_seq=1 ttl=61", "3 packets transmitted, 3 received, 0% packet loss" for IPv4, and "64 bytes from 2001:db8:20::2: icmp_seq=1 ttl=61" for IPv6. |
| The root ruleset is never loaded, PF is never toggled, no table is flushed | the inventory before the run: "the packet filter is disabled"; the main filter ruleset held only `scrub-anchor "com.apple/*" all fragment reassemble` and `anchor "com.apple/*" all`; the main NAT ruleset held only `nat-anchor "com.apple/*" all` and `rdr-anchor "com.apple/*" all`; `/etc/pf.anchors` held only `com.apple`; the only non-empty anchor was `com.apple` with 2 filter rules and 0 NAT rules. The residue after the run: "the residue the leg left on the host's packet filter: **[]**". |
| The forwarding switches are untouched by the product | the leg set `net.inet.ip.forwarding` and `net.inet6.ip6.forwarding` to 0 and read them back; the product's own remediation for a disabled switch says "wg-basic never writes it". The switches are the administrator's and the product only reads them. |
| The gateway converges | the verdict: "the gateway's disposition: **pass** — the gateway prerequisites are in place — host forwarding is enabled, the administrator's parent invokes the installation anchor in both rule classes, and the anchor's rules match the rendered policy". |
| The negatives refuse, each with its own actionable error | four distinct refusals, below. |
| The teardown leaves the host's PF configuration as it found it, apart from the anchor's own removal | the anchor's filter class after the teardown: empty; the anchor's NAT class after the teardown: empty; the anchor's file after the teardown: `"# wg-basic-v1 managed anchor for installation 4bdf2d6e-d73c-45f1-99d6-10b68c3e1a5b\n"` — the marker line alone, so the administrator's `load anchor` line keeps resolving and the file is never removed. The administrator's `anchor` and `nat-anchor` parent lines were both asserted still in place. |

**The four refusals, each with its own remedy:**

1. *Forwarding off* — "host forwarding is not enabled for a family this policy
   requires"; the remedy names the host configuration to change and states
   that "wg-basic never writes it".
2. *A filter-only parent* — "the administrator's PF configuration does not
   invoke the installation anchor in both rule classes"; the remedy gives the
   whole administrator's procedure: "create /etc/pf.anchors/<anchor> first,
   then add the nat-anchor line in the translation section of /etc/pf.conf and
   the anchor and load anchor lines at the end, then run pfctl -f /etc/pf.conf".
3. *A NAT-only parent* — the same refusal for the other incomplete shape.
4. *Drift in the anchor* — "the managed anchor's NAT rules do not match the
   rendered policy — the installation anchor holds translation rules the
   product did not render"; the remedy: "remove the foreign translation rules
   from the installation anchor; an anchor that translates traffic the policy
   never approved is drift".

The evidence is kept locally at `~/wg-qual/c004-evidence/`
(`c004-gateway-ipv4-egress.txt` is the leg's own transcript, `c004-run.log` the
run's log).

## 5. Defects the qualification found

**Two in the product, corrected in this milestone.**

- The observation reported an **absent** anchor as an **emptied** one
  (section 2). The observation now tells them apart, so the doctor's verdict
  for "the administrator has not attached the anchor" is distinct from "the
  installed rules were removed".
- The rendered anchor file's **order** is part of the contract, because PF
  refuses a file whose translation rule follows its filtering rules. The
  renderer now emits the NAT rules first.

**One in the leg's fixture, corrected in the fixture.** The leg's
`root_command` helper ran `sudo` with the program's arguments but **without
the program itself**, so every privileged call it made was malformed
(`sudo -f /etc/pf.conf` instead of `sudo /sbin/pfctl -f /etc/pf.conf`). The
leg also attached the anchor in the parent's configuration **before** creating
the anchor's file, which — by the measurement in section 2 — makes the host's
entire ruleset fail to load; the file is now created before the first
attachment. And the leg's `stop_the_service` was not idempotent, so a second
call on an already-unloaded job failed the leg on launchd's "no such service".
None of these three was a product defect, and all three were found only by
running the leg against a real host.

## 6. Requirement-to-evidence matrix

| Plan requirement | Evidence |
|---|---|
| Work package 1 — establish the PF install mechanism against the real `pfctl` | The measurement table in the plan's work package 1, taken on the disposable guest on 2026-10-23; the plan's stop conditions were not triggered. |
| Work package 2 — the bounded apply backend | `src/firewall/pfctl.rs`: fixed argument vectors, the fixed system path, bounded output and runtime, no shell, no caller-supplied path or text, an exact digest comparison before writing, and a re-observation after writing; pinned by the rewritten architecture guard. |
| Work package 3 — the gateway plan | `src/firewall/service_darwin.rs`: `observe_gateway` → the pure `gateway_verdict(forwarding_ok, anchor, observation, expected)`; the verdict "pass — the gateway prerequisites are in place". |
| Work package 4 — the failure and recovery semantics | The four refusals in section 4; the teardown empties both classes and rewrites the file; a refusal leaves the anchor's content intact (the measured fail-closed load). |
| Work package 5 — the evidence leg | `tests/wireguard_darwin_gateway.rs`, green on the controlled host; the translated source, the untranslated IPv6 source, the return path, and the negatives. |
| Acceptance 1 — a gateway policy converges and the doctor reports the tunnel and the filter as in effect | the verdict "pass — the gateway prerequisites are in place". |
| Acceptance 2 — the IPv4 far side observes the translated source and the return path works | "the far side observed the IPv4 source 192.168.64.4". |
| Acceptance 3 — the IPv6 far side observes the untranslated source | "the far side observed the IPv6 source 2001:db8:77::2". |
| Acceptance 4 — the negatives refuse, each with its own actionable error | the four refusals in section 4. |
| Acceptance 5 — the root ruleset is never loaded, PF is never toggled, no table is flushed, the forwarding switches are untouched | the inventory before the run and the empty residue after it (section 4). |
| Acceptance 6 — the teardown leaves the host's PF configuration as it found it, apart from the anchor's own removal | the anchor's two classes empty, the file reduced to its marker line, the administrator's parent lines still in place. |
| Acceptance 7 — every Linux job is green, the Darwin gates are green, the ordinary suite is green | section 7. |

## 7. The gates run at this head

**On the Darwin host:** `cargo fmt --all -- --check`,
`cargo check --all-targets --locked`,
`cargo clippy --all-targets --locked -- -D warnings`,
`cargo test --locked` (43 binaries, **732 passed**, 0 failed, 15 ignored) and
`cargo +1.89.0 check --all-targets --locked` (MSRV) — all green at `5e35a4a`.
At the head that carries this milestone's evidence leg and its closure
records (`bc70125`; the commit after it changes the two closure records and
nothing else) the same gate order was re-run: **44 binaries, 750
passed, 0 failed, 16 ignored**, with `fmt`, `check`, `clippy` and the MSRV
check green. The Linux
feature-bearing cross-clippy with the zig toolchain
(`CC_x86_64_unknown_linux_gnu=$HOME/wg-toolchain/zigcc`,
`AR_x86_64_unknown_linux_gnu="zig ar"`,
`cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets
--features linux-integration -- -D warnings`) exits 0.

**On a controlled Linux host** (`sugarwookie@192.168.182.143`): the same gate
order green — `fmt`, `check`, `clippy`, `clippy` with the Linux feature,
`test` (43 binaries, **672 passed**, 0 failed, 3 ignored at `5e35a4a`; **44
binaries, 672 passed**, 0 failed, 3 ignored at the final head) and MSRV — and
all **eleven** rootful suites green: `wireguard_kernel`, `network_reconcile`,
`network_control_e2e`, `durable_owner`, `durable_restart`, `durable_backup`,
`product_management_rootful`, `maintenance_rootful`, `doctor_readonly`,
`service_rootful_e2e`, `upgrade_rehearsal_rootful`. The host's namespaces,
links, nftables tables, units and canonical installation paths were unchanged
before and after; only the route expiry timers and the nftables counters moved.

**Hosted CI at the final head** (`bc70125`): the `CI` workflow's **only**
failing job is `dependency-audit`, which is **red** and must never be claimed
green — upstream `eggup-archive` pins `zip ^6.0.0`. It is routed to
C005/M007. The `macOS qualification` workflow and the `Distribution
foundation` workflow both **succeed**.

## 8. Documentation

`architecture/firewall.md` (the gateway's PF ownership and the scoped apply),
`architecture/ownership.md` (what the product owns and what the administrator
owns), `architecture/testing-qualification.md`,
`docs/operations-runbook.md` (the administrator's procedure, the forwarding
switches, PF enable, the doctor table, the egress and no-NAT66 facts, and the
teardown), and `docs/development.md` were updated in `5e35a4a`. Six stale
claims were corrected in place. **No document claims that the gateway carries
traffic**: the gateway's traffic claim is the controlled-host evidence in
section 4 and nothing else.

## 9. Known limitations and unresolved findings

**F10 — the macOS managed interface's own teardown is refused (material,
corrective required).** The `network disable` command commits its generation
but reports "not yet enforced (Degraded(BackendRefused))", because the
**interface** layer's delete path refuses before it removes the device. The
measured cause: `src/reconcile/planner.rs` refuses to delete a managed
interface when an observed address is not in the desired list, and on macOS
the observed forms never are:

- the desired address is `10.77.0.1/24` and the observed one is
  `10.77.0.1/32` — the utun device is point-to-point and the kernel holds a
  `/32` netmask (`inet 10.77.0.1 --> 10.77.0.1 netmask 0xffffffff`);
- the desired IPv6 address is `2001:db8:77::1/64` and the observed one is
  `2001:db8:77::1/128`;
- the kernel also gives the device a link-local address
  (`inet6 fe80::3c84:7232:cc4e:2dc0%utun0 prefixlen 64`), which the desired
  state never lists, and the `getifaddrs` observation in
  `crates/darwin-sys` collects every address the kernel reports.

The refusal is `ReconcileError::UnlistedResourceOnDelete` →
`ProtocolError::Conflict` → `ManagementError::Conflict` →
`AttemptDisposition::StateConflict` → `DegradedCategory::BackendRefused`. The
doctor reports it as "network plan found an ownership conflict / netd
returned a typed ownership conflict".

This defect is **outside this milestone**: C004's scope is the PF/NAT anchor,
and the anchor's own teardown **did** run and **did** complete — the two rule
classes were emptied and the anchor's file was reduced to its marker line.
The managed *tunnel device* is not removed, and the operator cannot turn the
managed network off through the product on macOS. Per §13 it receives its own
corrective plan, **C015**
(`plans/implementation/macos-native-server/c015-macos-interface-teardown-acceptance.md`),
and the leg pins the refusal's shape so that a degradation with any other
cause still fails the leg.

**Other limitations, stated plainly.**

- The kernel accumulates **anchor objects** and never destroys them (62 on the
  guest). The product's own anchor is scoped by its installation-scoped name,
  and it never enumerates or touches a foreign anchor; "removal" can only ever
  mean emptying the rules.
- The gateway's **IPv6** path is routed, not translated, and the product does
  not translate IPv6 at all. There is no NAT66.
- The gateway's traffic claim is the controlled-host evidence in section 4. No
  consumer macOS gateway claim is made, and none is implied.
- The product never writes the forwarding switches, never toggles PF, never
  flushes a table and never edits `/etc/pf.conf`. Those remain the
  administrator's.
- The M007 MUST-NOT-release standing is unchanged by this milestone; the
  gateway mode's release gate is discharged, and C005's release half and the
  maintainer's authority are not.

## 10. Amendments to earlier records

None. C003's closure record and its traffic evidence are unaffected: C004
changes the product's macOS firewall backend and adds the gateway mode, and
C003's routed-LAN mode stays operator-managed and unchanged.
