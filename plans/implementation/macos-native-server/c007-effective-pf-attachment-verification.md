# macOS Native Server C007 — Effective PF Attachment Verification

Status: **active**; the implementation is in this branch and the closure
evidence is in `plans/closure/macos-native-server-corrective/c007-status.md`.
Baseline: `plans/macos-native-support@e0a81b0`.
Source: corrective roadmap C004 step 2
(`plans/implementation/macos-native-server/c004-pf-nat-effective-gateway.md`);
the gap list in `plans/subsystems/macos-native-server-corrective-roadmap.md` §1;
M005 (`plans/closure/macos-native-server/005-status.md`).
Authority: ADR-007 and ADR-008; `plans/003-planning-process.md` §13
(corrective passes), §11 (network-control evidence rule), §12 (security rule).
Primary class: corrective / invariant.

## 1. The defect, as observed

The corrective roadmap's evidence-triggered gap list records, at
`plans/subsystems/macos-native-server-corrective-roadmap.md:18`:

> `src/firewall/pf.rs::attachment_verified` uses substring membership and a
> filter-OR-NAT predicate; neither proves effective policy attachment for both
> required rule classes.

The code is exactly that, at `src/firewall/pf.rs:90`:

```rust
pub fn attachment_verified(
    parent_filter_output: &str,
    parent_nat_output: &str,
    anchor: &str,
) -> bool {
    parent_filter_output.contains(anchor) || parent_nat_output.contains(anchor)
}
```

Two independent ways to be wrong, both in the *fail-open* direction:

1. **Substring membership.** `contains(anchor)` matches the managed name
   inside any *other* token. An anchor named `wg-basic-v1-<uuid>` is reported
   as attached when the parent's ruleset invokes `wg-basic-v1-<uuid>-backup`,
   and also when the managed name appears inside a comment, a label, or an
   unrelated rule's text.
2. **A filter-OR-NAT predicate.** The two rule classes are one boolean. A
   parent that invokes **only** the NAT anchor satisfies a check that requires
   the filter anchor, and vice versa. C004 requires the two classes to be
   verified *independently*: "NAT-only or filter-only parent references are
   not proof" (`c004-pf-nat-effective-gateway.md`, step 2).

The current unit test even encodes the wrong contract: it asserts that a
NAT-only parent reference verifies (`src/firewall/pf.rs:186`).

### 1.1 What the real host actually prints

Read-only observation on macOS 26.6.2 (`pfctl -s rules`, `pfctl -s nat`), and
a scoped fixture anchor loaded and flushed on the same host:

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

Three facts follow, and the fix depends on all three:

- an invocation names the anchor in **double quotes** as the rule's second
  token, and the rule's **first token is the table's keyword** — `anchor` in
  the filter table, `nat-anchor` in the NAT table;
- the same anchor name can exist **independently in both tables** and is
  attached **independently** in each, which is exactly why one boolean over
  two tables is wrong;
- the host's own rulesets are full of *other* anchors, including wildcard
  anchors and `scrub-anchor`/`rdr-anchor` rules, so a name-substring test
  runs against real text that contains many near-miss tokens.

## 2. Why the earlier evidence missed it

- The M005 closure recorded attachment verification as "modeled purely
  (`attachment_verified` requires parent invocation, not mere existence) with
  fixture tests" (`plans/closure/macos-native-server/005-status.md:45`). The
  model it recorded was the *intent*; the implementation tested **existence
  of a substring** and had **no notion of rule class at all**.
- The hosted macOS live fixture only ever observes the **unattached** case
  (`tests/wireguard_darwin_live.rs:637`), which the loose predicate also
  answers correctly. A verifier that is too loose and a verifier that is
  right both return `false` there, so the loose one passed.
- C004 is blocked behind C003, and C003 is blocked behind C001's closure, so
  the subject of the defect could not be reached in the dependency order. The
  defect is in the **verifier**, not in the routed-LAN capability, and does
  not depend on either.

## 3. The fix

### 3.1 Per-class, exact, invocation-shaped observation

`src/firewall/pf.rs` gains a typed observation model:

- `RequiredAttachments { filter: bool, nat: bool }` — the rule classes the
  administrator's parent configuration must attach, with `FILTER_ONLY` (a
  host-only or non-masquerading policy) and `FILTER_AND_NAT` (a masquerading
  policy) as the two named cases;
- `Attachment { Invoked, Missing }` — the state of one class;
- `AttachmentObservation { filter: Attachment, nat: Attachment }` — the
  per-class observation, so a caller can say *which* class is missing
  instead of only that "something" is;
- `observe_attachments(parent_filter_output, parent_nat_output, anchor)` —
  the observation;
- `attachment_verified(parent_filter_output, parent_nat_output, anchor,
  required)` — the verdict, and the **only** place a boolean is produced: it
  is the conjunction over the *required* classes, never a disjunction over
  the tables.

### 3.2 What counts as an invocation

A rule in a given table invokes the managed anchor only when **both** hold:

- the rule's **first token** is that table's keyword — `anchor` for the
  filter table, `nat-anchor` for the NAT table; and
- the rule's **second token** is the managed anchor's name as a **whole
  token**, quoted (`"name"`) or bare.

Everything else is not an invocation, and each exclusion is a real shape the
host produces:

| Shape | Real example | Old verdict | New verdict |
|---|---|---|---|
| A different anchor whose name *contains* ours | `anchor "wg-basic-v1-<uuid>-backup" all` | attached | **missing** |
| A comment naming the anchor | `# anchor "wg-basic-v1-<uuid>" all` | attached | **missing** |
| Another table's keyword | `scrub-anchor "com.apple/*" all` | attached (substring) | **missing** |
| The NAT class only | parent has `nat-anchor` but no `anchor` | attached (OR) | **missing** for the filter class |
| The anchor merely defined, never invoked | the anchor exists in the table | — | **missing** |

The matcher is **token-exact**, so it is immune to the substring class of
false positives by construction, and the per-class split removes the
disjunction by construction. Both are fail-closed: an ambiguous observation
is reported as *missing*, never as *attached*.

### 3.3 What this corrective does not do

This is the **verifier** half of C004 step 2 only. It does not implement the
live `pfctl` backend, the bounded `pfctl` invocation, the effective-traffic
evidence, the ordering analysis against a real parent ruleset, the
administrator distribution gate, or the NAT66 / routed-IPv6 semantics. Those
remain C004's, and C004 remains blocked on C003 and on an
administrator-integrated controlled host.

## 4. Ordered work packages

1. `src/firewall/pf.rs` — the typed observation model, the exact invocation
   matcher, and the conjunction verdict.
2. `src/firewall/mod.rs` — re-export the new items.
3. `src/firewall/pf.rs` unit tests — the exclusion table above, one test per
   shape, plus the real captured macOS `pfctl` output as a regression
   fixture.
4. `tests/wireguard_darwin_live.rs` — the live fixture gains the three
   controls it never had: a **positive** control (a parent anchor that
   invokes the managed anchor, observed through real `pfctl` output), a
   **collision** control (a parent that invokes a *longer* name), and the
   existing negative control, now asserted per class.
5. `tests/architecture_guards.rs` — pin the new API in the PF guard.

## 5. Privilege and security effects

None. The module stays pure: no I/O, no process execution, no host state, no
network. The guard that pins `src/firewall/pf.rs` free of `Command::new`,
shell, `pfctl -f`, and `/etc/pf.conf` continues to hold, and the new code
adds no forbidden token.

The **live fixture** does execute `pfctl` as root, as it already does. The
new controls load two additional **fixture-named** anchors, never edit the
main ruleset, never write `/etc/pf.conf`, never call `pfctl -e`, and are
flushed before the test ends. The parent anchor that invokes the managed
anchor is itself never invoked by the main ruleset, so the chain is inert:
it proves the *verifier* against real output without affecting traffic.

## 6. Compatibility effects

None. No wire format, no schema, no protocol message, no CLI surface, no
Linux path, and no installed state changes. The Darwin firewall service
still refuses every non-host-only policy, so the corrected verifier has no
production call site yet — by design: C004 wires the live backend to it.
The Linux nft path is untouched.

## 7. Failure, cancellation, and contention semantics

The verifier has no state and cannot fail partially: an observation is
computed from text and is either `Invoked` or `Missing`. A caller that
requires both classes and gets one `Missing` gets a **false** verdict and
must report degraded, never converged. There is nothing to cancel, retry, or
contend: the same input always yields the same observation.

## 8. Focused tests

- Unit (in-module): the exclusion table — substring collision, comment,
  foreign keyword, cross-class reference, bare versus quoted name, the
  real captured macOS rulesets, and the conjunction over required classes.
- Live (hosted macOS runners, as root, disposable): the positive, collision,
  and negative controls against real `pfctl` output.
- Guard: the PF module stays free of process execution and keeps modeling
  the required API.

## 9. Broad verification commands

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
cargo check --target x86_64-apple-darwin --all-targets --locked
```

Plus the hosted macOS qualification workflow (arm64 and Intel runners) for
the live controls, and the Linux native CI for the no-regression claim.

## 10. Documentation updates

- `architecture/firewall.md` — the Darwin PF model's verification contract,
  as current behavior.
- `plans/closure/macos-native-server-corrective/c007-status.md` — the
  closure record.
- `plans/registry.md` and
  `plans/subsystems/macos-native-server-corrective-roadmap.md` — the
  corrective's status and its effect on C004.

## 11. Acceptance criteria

1. The filter class is verified only by a filter-table `anchor` rule that
   names the managed anchor as a whole token.
2. The NAT class is verified only by a NAT-table `nat-anchor` rule that
   names the managed anchor as a whole token.
3. A parent that references the managed name in any other way — inside a
   longer name, in a comment, under another table's keyword — verifies
   **nothing**.
4. A required class that is not invoked makes the verdict **false**, even
   when the other class is invoked.
5. The existing live fixture's unattached-anchor assertion still holds, and
   the live fixture now also proves the positive and collision cases against
   real `pfctl` output.
6. Every gate in §9 is green, and the Linux native CI shows no regression.

## 12. Stop conditions

Stop and record the discrepancy rather than working around it if:

- proving effective attachment turns out to require editing the main
  ruleset, `/etc/pf.conf`, or calling `pfctl -e` — none of which this
  product may do (Apple TN3165, advanced-administrator opt-in only);
- the real host's invocation format cannot be recognized by the token-exact
  matcher, because a matcher that has to guess is a matcher that can
  produce a false "attached";
- the fix would require a live `pfctl` backend in the product — that is
  C004's scope, and this corrective stays a pure model.

## 13. Closure evidence requirements

`plans/closure/macos-native-server-corrective/c007-status.md` must record:
the implementation head and baseline, the requirement-to-evidence matrix
against §11, the exact commands and their output, the real captured macOS
`pfctl` output used as the regression fixture, the hosted live run's
evidence, the security and ownership evidence, the documentation evidence,
the known limitations, the unresolved findings by severity, and an explicit
disposition. C004's own evidence and disposition are not changed by this
record, except that its step 2's *model* half is no longer open.
