# macOS Native Server C007 — Effective PF Attachment Verification

Disposition: **closed** (2026-10-21) — the PF attachment verifier's two
fail-open defects are corrected, the verifier is exact and per rule class, and
the correction is evidenced by unit tests, by the real macOS `pfctl` output of
a live host, and by the hosted arm64 and Intel live fixtures. C004's own
disposition is unchanged: its *live* half — the bounded `pfctl` backend, the
ordering analysis, and the effective-traffic evidence — remains open and
blocked on C003 and on an administrator-integrated controlled host.

Date: 2026-10-21.

Source plan: `plans/implementation/macos-native-server/c007-effective-pf-attachment-verification.md`.
Baseline: `plans/macos-native-support@e0a81b0`.
Implementation head: `1bf4bb3` (the verifier), `2b672da` (the Intel job runs
the PF anchor cycle too).

## Implementation revision

- Repository baseline: `e0a81b0` (C006 closed, the armed working Mac
  refreshed).
- Implementation commit: `1bf4bb3` — *macos(c007): make the PF attachment
  verifier exact and per class*.
- Qualification commit: `2b672da` — the Intel live job now runs the PF
  anchor cycle, so both architectures qualify the same verifier.
- The defect was raised by the corrective roadmap's evidence-triggered gap
  list (`plans/subsystems/macos-native-server-corrective-roadmap.md:18`) and
  is C004's subject. C004 is blocked behind C003, which is blocked behind
  C001's closure, so the defect could not be reached in the dependency order.
  Per `plans/003-planning-process.md` §13 it was corrected under its own
  plan, with its own closure record and its own evidence. C004's record and
  disposition are not rewritten.

## The defect, as it was

`src/firewall/pf.rs::attachment_verified` was:

```rust
parent_filter_output.contains(anchor) || parent_nat_output.contains(anchor)
```

Two independent fail-open paths:

1. **Substring membership.** `contains(anchor)` matched the managed name
   inside any other token — a longer anchor name, a comment, a label.
2. **A filter-OR-NAT predicate.** The two rule classes were one boolean, so
   a parent that referenced only the NAT anchor satisfied a check that
   required the filter anchor, and the other way round.

The unit test encoded the wrong contract: it asserted that a NAT-only parent
reference verifies.

## What the real host prints

Read-only observation on the maintainer's macOS 26.6.2 host, plus a scoped
fixture anchor that was loaded and flushed:

```
$ pfctl -s rules
scrub-anchor "com.apple/*" all fragment reassemble
scrub-anchor "com.apple.internet-sharing" all fragment reassemble
anchor "com.apple/*" all
anchor "com.apple.internet-sharing" all

$ pfctl -s nat
nat-anchor "com.apple/*" all
nat-anchor "com.apple.internet-sharing" all
rdr-anchor "com.apple/*" all
rdr-anchor "com.apple.internet-sharing" all

$ pfctl -a wg-basic-fmt-probe-parent -s rules
anchor "wg-basic-fmt-probe-child" all
```

An invocation names the anchor in double quotes as the rule's second token,
under the keyword of its own table; the same name can exist independently in
both tables; and the host's own rulesets are full of near-miss tokens
(wildcard anchors, `scrub-anchor`, `rdr-anchor`).

The hosted arm64 runner printed the same shapes during the qualification
(§ *Live qualification* below).

## The correction

`src/firewall/pf.rs` now models:

- `RequiredAttachments { filter, nat }` with `FILTER_ONLY` and
  `FILTER_AND_NAT`;
- `Attachment { Invoked, Missing }`;
- `AttachmentObservation { filter, nat }` with
  `verified(required) -> bool`;
- `observe_attachments(parent_filter_output, parent_nat_output, anchor)`;
- `attachment_verified(parent_filter_output, parent_nat_output, anchor,
  required)` — the only place a boolean is produced, and it is a
  **conjunction** over the required classes.

A rule invokes the managed anchor only when the rule's **first token** is
that table's keyword (`anchor` in the filter table, `nat-anchor` in the NAT
table) **and** the rule's **second token** is the managed name as a **whole
token** (quoted or bare). Everything else is not an invocation, and the
observation is fail-closed: an ambiguous observation is `Missing`, never
`Invoked`.

| Shape | Real example | Before | After |
|---|---|---|---|
| A longer name that contains the managed name | `anchor "wg-basic-v1-<uuid>-backup" all` | attached | **missing** |
| A comment naming the anchor | `# anchor "wg-basic-v1-<uuid>" all` | attached | **missing** |
| Another table's keyword | `scrub-anchor "com.apple/*" all` | attached | **missing** |
| The other class only | parent has `nat-anchor`, not `anchor` | attached | **missing** for the filter class |
| The anchor defined but never invoked | the anchor exists in the table | — | **missing** |

## Requirement-to-evidence matrix

| Requirement (plan §11) | Evidence | Result |
|---|---|---|
| §11.1 The filter class is verified only by a filter-table `anchor` rule naming the managed anchor as a whole token | `src/firewall/pf.rs`: `invokes_anchor(output, "anchor", anchor)` requires the first token to be `anchor` and the second to be the whole name. The unit test `an_invocation_in_the_filter_table_verifies_the_filter_class` shows `filter == Invoked` for `anchor "wg-basic-v1-test" all` and `nat == Missing`. The live control C verifies it against real `pfctl` output | Passed (code + unit + live) |
| §11.2 The NAT class is verified only by a NAT-table `nat-anchor` rule naming the managed anchor as a whole token | The unit test `an_invocation_in_the_nat_table_verifies_the_nat_class` shows `nat == Invoked` for `nat-anchor "wg-basic-v1-test" all` and `filter == Missing`; `another_tables_keyword_is_not_an_invocation` shows a filter-table `anchor` rule is not a NAT invocation. The live control B recognizes the host's own real `nat-anchor "com.apple/*" all` | Passed (code + unit + live) |
| §11.3 A parent that references the managed name in any other way verifies nothing | `a_longer_name_that_contains_the_managed_name_is_not_an_invocation`, `a_comment_naming_the_managed_anchor_is_not_an_invocation`, `another_tables_keyword_is_not_an_invocation`, `the_anchor_must_be_named_as_a_whole_token`; the live control D against a real `pfctl` listing of `anchor "wg-basic-live-2593-collision" all` | Passed (code + unit + live) |
| §11.4 A required class that is not invoked makes the verdict false even when the other class is invoked | `the_two_rule_classes_are_verified_independently` asserts a filter-only parent and an NAT-only parent each fail `FILTER_AND_NAT`; `AttachmentObservation::verified` is a conjunction. The live control C asserts that a real parent invocation verifies `FILTER_ONLY` and **not** `FILTER_AND_NAT` | Passed (code + unit + live) |
| §11.5 The live fixture's unattached-anchor assertion still holds, and the fixture proves the positive and collision cases against real `pfctl` output | `tests/wireguard_darwin_live.rs::live_pf_inventory_and_anchor_cycle` now runs controls A (negative), B (the host's own invocations), C (a scoped parent that invokes the managed anchor) and D (a colliding name), asserts the per-class observation, and asserts the main ruleset is byte-identical before and after. The hosted arm64 evidence reproduces all four; the Intel job runs the same test from `2b672da` | Passed (live, arm64 and Intel) |
| §11.6 Every gate is green and the Linux native CI shows no regression | See *Verification*. The local gates are green; the Linux native CI at this head was red for three jobs **because of C006's cross-platform startup wait**, which this corrective neither caused nor fixed — it is corrected under C009, and the three jobs are green there | Passed here; the Linux residual is C009's |
| §3.3 The live `pfctl` backend, the ordering analysis, the effective-traffic evidence, the administrator distribution gate, and the NAT66/routed-IPv6 semantics stay with C004 | Nothing in this record implements them. C004's plan and its blocked disposition are unchanged; only its step 2's *model* half is closed | Passed (scope held) |

## Live qualification

Hosted macOS runners, the arm64 job of run **39557082295**
(`macos(c007): make the PF attachment verifier exact and per class`, all
four jobs green). Reproduced from the run's
`macos-live-evidence-arm64` artifact, `m005-pf-anchor-cycle.txt`:

```
$ pfctl -s rules
scrub-anchor "com.apple/*" all fragment reassemble
anchor "com.apple/*" all

$ pfctl -s nat
nat-anchor "com.apple/*" all
rdr-anchor "com.apple/*" all

control A (negative): the managed anchor is invoked by neither class
control B (positive): the host's own filter invocation of com.apple/* is recognized
control B (positive): the host's own NAT invocation of com.apple/* is recognized
$ pfctl -a wg-basic-live-2593-parent -s rules
anchor "wg-basic-live-2593" all

control C (positive): a real parent invocation verifies the filter class, and the NAT class stays independently missing
$ pfctl -a wg-basic-live-2593-collision-parent -s rules
anchor "wg-basic-live-2593-collision" all

control D (collision): a longer anchor name does not verify the managed anchor
$ pfctl -s rules
scrub-anchor "com.apple/*" all fragment reassemble
anchor "com.apple/*" all

anchor cycle complete: loaded, verified, flushed; nothing attached
```

The last `pfctl -s rules` is the **after** observation: it is identical to
the first one, which is the fixture's proof that it left the main ruleset
exactly as it found it.

The Intel job of the same run exercised the per-class negative assertion
through `live_forwarding_and_unattached_anchor_probe`:

```
anchor loaded, PF enabled, attachment absent: inert by construction
```

From `2b672da` the Intel job also runs the full anchor cycle, so both
architectures qualify the same controls. Run **39558364317**
(`macos(c007): run the PF anchor cycle on the Intel runner too`, all four
jobs green) carries that evidence: the Intel runner's
`m005-pf-anchor-cycle.txt` records the same four controls against its own
`pfctl` output —

```
control A (negative): the managed anchor is invoked by neither class
control B (positive): the host's own filter invocation of com.apple/* is recognized
control B (positive): the host's own NAT invocation of com.apple/* is recognized
control C (positive): a real parent invocation verifies the filter class, and the NAT class stays independently missing
control D (collision): a longer anchor name does not verify the managed anchor
anchor cycle complete: loaded, verified, flushed; nothing attached
```

— and the Intel runner's own main ruleset has the same shape as the arm64
runner's:

```
$ pfctl -s rules
scrub-anchor "com.apple/*" all fragment reassemble
anchor "com.apple/*" all
```

## Verification

Local, on the implementation head:

```text
$ cargo fmt --all -- --check
(no output — clean)

$ cargo clippy --all-targets --locked -- -D warnings
(no output — clean)

$ cargo test --locked
664 passed; 0 failed

$ cargo +1.89.0 check --all-targets --locked
Finished `dev` profile

$ cargo check --locked --target x86_64-apple-darwin --all-targets
Finished `dev` profile

$ CC_x86_64_unknown_linux_gnu="$HOME/wg-toolchain/zigcc" \
  AR_x86_64_unknown_linux_gnu="zig ar" \
  cargo check --locked --target x86_64-unknown-linux-gnu --all-targets
Finished `dev` profile
```

(The Linux cross target needs a cross C compiler for `libsqlite3-sys`'s build
script; the `zig cc` wrapper is the recipe `docs/development.md` already
documents, and the wrapper on this host has been restored.)

Hosted:

- macOS qualification run **39557082295**: `gates-arm64`, `gates-intel`,
  `live-arm64`, `live-intel-tunnel` — all four green.
- **The Linux native CI at this head was red, and not only for the
  pre-existing `dependency-audit` upstream `zip 6.0.0` advisory.** Three
  further jobs failed — `rust`, `upgrade-rehearsal`, and
  `upgrade-rehearsal-rootful` — for a reason that belongs to C006, not to
  this corrective: C006's backend startup wait was applied on every
  platform and delayed the Linux management daemon's listener. The
  pre-existing advisory hid those three failures in the same red runs. The
  Linux path is restored, and the three jobs are green again, under
  **C009** (`plans/closure/macos-native-server-corrective/c009-status.md`);
  this corrective neither caused nor fixed it.
- The Linux cross-clippy gate, which cannot run on this host without a cross
  C toolchain, runs again now that the documented `zig cc` wrapper is
  restored on the host:

  ```text
  $ CC_x86_64_unknown_linux_gnu="$HOME/wg-toolchain/zigcc" \
    AR_x86_64_unknown_linux_gnu="zig ar" \
    cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets \
      --features linux-integration -- -D warnings
  Finished `dev` profile
  ```

## Security and ownership evidence

- The corrected module remains **pure**: no I/O, no process execution, no
  host state. The architecture guard
  `the_darwin_pf_model_renders_without_executing` still forbids
  `std::process::Command`, `Command::new`, `process::Stdio`, a shell,
  `pfctl -f`, and `/etc/pf.conf` in `src/firewall/pf.rs`, and still requires
  the module to model `ANCHOR_PREFIX`, `attachment_verified`,
  `rules_digest`, `teardown_order`, and `is_ipv4`.
- A new guard, `the_darwin_pf_attachment_verifier_is_per_class_and_token_exact`,
  pins the correction itself: the substring forms (`.contains(anchor)`,
  `parent_filter_output.contains`, `parent_nat_output.contains`) are
  forbidden in the module, and it must model `invokes_anchor`, the `anchor`
  and `nat-anchor` keywords, and the token comparison.
- The live fixture stays inside the binding scope of the macOS workflow: no
  `pfctl -e` in this test, no main-ruleset edit, no `/etc/pf.conf` write, no
  NAT traffic claim. The parent anchor that invokes the managed anchor is
  itself never invoked by the main ruleset, so the chain is inert; the
  fixture proves the *verifier*, not a gateway.
- The Darwin firewall service is unchanged and still **refuses** every
  non-host-only policy with `FirewallError::Unsupported`. The corrected
  verifier therefore has no production call site yet, by design: C004 wires
  the live backend to it. Nothing in this corrective can make a host report
  a convergence it did not achieve.
- No privileged boundary was widened: no new socket, no new identity, no
  new file ownership, no protocol operation.

## Docs and operations evidence

- `architecture/firewall.md` — the Darwin PF model's verification contract is
  now the current behavior it describes.
- `plans/implementation/macos-native-server/c007-effective-pf-attachment-verification.md`
  — this corrective's plan.
- `plans/subsystems/macos-native-server-corrective-roadmap.md` and
  `plans/registry.md` — C007's status and its effect on C004.
- `architecture/testing-qualification.md` — the live fixture's new controls
  are part of the suite's description.
- `docs/development.md` — unchanged: the macOS gate list it records was
  already accurate.

## Known limitations

1. **The correction is the verifier, not the backend.** Nothing yet reads a
   real `pfctl` ruleset in the product: the live `pfctl` backend, the
   bounded invocation, the ordering analysis against a real parent ruleset,
   and the effective-traffic evidence are C004's, and C004 is blocked on
   C003 and on an administrator-integrated controlled host.
2. **The verdict is per class, not per rule.** The model proves that the
   parent *invokes* the anchor. It does not evaluate PF's last-match-wins
   ordering, so a parent whose later rules would drop the traffic is still
   reported as attached. That analysis needs a real ruleset and stays with
   C004.
3. **The real-host observation is read-only plus one scoped fixture
   anchor.** The captured `pfctl` output is a snapshot of one macOS
   26.6.2 host and of the hosted runners' rulesets; a host with a different
   ruleset shape would need its own capture, and the matcher fails closed
   on anything it does not recognize.
4. **The probe left two empty anchor-table entries on the maintainer's Mac.**
   The format probe loaded two fixture-named anchors and flushed their
   rules; PF has no supported "delete anchor" operation, so the empty
   entries remain in the anchor table. They carry no rules and are invoked
   by nothing, and the main ruleset was never touched.
5. **No release claim exists.** ADR-008/M007 still withholds every macOS
   release; this record changes nothing about that.

## Unresolved findings by severity

- **High (pre-existing, fixed here):** the attachment verifier could report
  an anchor as attached when a *different* anchor's name merely contained the
  managed name, and could report it as attached when only one of the two
  rule classes was invoked. Both are fail-open paths in the direction of
  claiming effective policy that was never established. The verifier is now
  exact and per class, and the live fixture proves both exclusions against
  real `pfctl` output.
- **Medium (pre-existing, fixed here):** the unit test encoded the wrong
  contract — it asserted that an NAT-only parent reference verifies. A test
  that asserted a wrong contract is why the defect survived; the test now
  asserts the conjunction, and a second test asserts that an NAT-only
  parent satisfies neither requirement.
- **Medium (pre-existing, out of scope):** the `dependency-audit` CI job
  fails on three upstream `zip 6.0.0` advisories reached through
  `eggup-archive = "=0.1.3"`. Not resolvable in this repository without an
  upstream release; unrelated to this corrective.
- **Low (pre-existing, environmental, now runnable again):** the Linux
  cross-clippy gate could not run on this host because no cross C toolchain
  was present. The recipe was already documented in `docs/development.md`;
  the host-side `zig cc` wrapper has been restored and the gate, including
  the `linux-integration` variant, is green again. `cargo zigbuild` covers
  the same target.
- **Informational:** the read-only format probe used two fixture-named PF
  anchors on the maintainer's Mac, loaded and flushed in the same run. The
  two empty anchor-table entries are the residue; no rule and no main-ruleset
  line was left behind.

## Disposition

**Closed.** The two fail-open defects in the PF attachment verifier are
corrected: the verifier is now token-exact and per rule class, its verdict is
a conjunction over the required classes, and the exclusion of every
near-miss shape is covered by unit tests, by the real `pfctl` output of a
live macOS host, and by the hosted arm64 and Intel live fixtures. The
qualification of the *live* half — the bounded `pfctl` backend, the ordering
analysis, and effective traffic with an administrator-attached anchor — is
**not** claimed here: it remains C004's, blocked on C003 and on an
administrator-integrated controlled host, and C004's own disposition is
unchanged. No macOS release, tag, or asset is claimed, and M007's
MUST-NOT-release standing is unchanged.
