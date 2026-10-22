# macOS Native Server C004 — Effective, Administrator-Opt-In PF/NAT Gateway

Status: **ready** (2026-10-22). The hard dependency C003 is closed, C007 closed
the verifier, M005's closure decided the distribution model, and the
qualification environment is settled on the existing two-guest controlled host.
Implementation and evidence are recorded in
`plans/closure/macos-native-server-corrective/c004-status.md`.

Baseline: `plans/macos-native-support@4388dce`.

Source: corrective roadmap C004; `plans/implementation/macos-native-server/005-forwarding-pf-nat-and-platform-policy.md`
and `plans/closure/macos-native-server/005-status.md`; ADR-008; ADR-007.

Canonical requirements and decisions: ADR-008 §3.6 (a macOS PF/NAT backend is
allowed only on M005's demonstrated conditions, with no global flush/reload,
no `/etc/pf.conf` replacement, no global PF toggles, and no silent
modifications), ADR-007 (bounded host ownership for IPv6 forwarding), and M005's
closure decision — advanced-administrator opt-in only, general consumer macOS
gateway support not claimed and not advertised.

Primary class: **capability** (an operator-visible IPv4 Internet-egress
gateway) with an **invariant** core (the product's PF ownership stays scoped,
reversible, and never touches the root ruleset).

## Objective

Turn the read-only PF observation into a verified, administrator-opt-in
IPv4-egress gateway: the product owns exactly one installation-scoped anchor,
installs and removes it reversibly, proves the parent actually invokes it in
both the filter and the NAT table, and carries real traffic through it — an
IPv4 peer whose source is translated and whose return path works, and IPv6
that is routed and never NAT66.

## Non-goals

No general consumer macOS gateway claim or advertisement. No editing,
replacing, or reordering `/etc/pf.conf`. No `pfctl -f` of the root ruleset, no
table flush, no enabling or disabling PF globally, no taking or restoring the
global forwarding switches. No NAT66. No arbitrary PF source, script, path, or
sysctl through the management path. No macOS bypass of the Linux nft contract.
No unconditional host-only-to-gateway upgrade. No change to C003's routed-LAN
mode, which stays operator-managed.

## Current repository evidence

- **The Darwin firewall refuses the gateway mode.** `src/firewall/service_darwin.rs`
  maps `NetworkPolicyMode::Gateway` to `FirewallError::Unsupported`, with the
  comment that the internet-exit gateway "is a different contract with a
  different filter and NAT surface. It is refused rather than half-applied."
- **The PF module observes and renders; it does not write.** `src/firewall/pf.rs`
  provides `render_policy` (which already emits `nat on {egress} from {prefix}
  to any -> ({egress})` for IPv4 only, with "IPv6 is routed, never translated"),
  `render_routed_policy`, `anchor_content_matches`, `observe_attachments`,
  `attachment_verified`, `rules_digest`, and `teardown_order`.
- **The pfctl module is strictly read-only, by contract.**
  `src/firewall/pfctl.rs` states that it "never loads a ruleset, never flushes
  an anchor, never edits `/etc/pf.conf`, and never enables or disables PF",
  with a fixed argument vector, no shell, a bounded output (256 KiB) and a
  bounded runtime (10 s) per invocation. Its observation carries
  `parent_filter`, `parent_nat`, and `anchor_filter` — **there is no
  `anchor_nat`**, so the NAT anchor's own content is not observed today.
- **The verifier is already exact.** C007 replaced the substring/disjunction
  test with `observe_attachments` / `RequiredAttachments`, where a masquerading
  policy requires `FILTER_AND_NAT`: the filter table's parent must invoke the
  managed anchor and the NAT table's parent must invoke it, independently, as
  whole tokens.
- **The routed-LAN mode works on the controlled host.** The C003/C011 leg
  proved IPv4 and IPv6 traffic through a managed `utun` to an approved
  downstream prefix and back, with the negatives still refusing.

## Invariants

1. The product owns **one** installation-scoped anchor and **one** anchor
   file. It writes neither `/etc/pf.conf` nor any foreign anchor, and it never
   loads the root ruleset.
2. The administrator attaches the parent. `anchor "wg-basic-v1-<id>"` and
   `nat-anchor "wg-basic-v1-<id>"` are the operator's lines in the operator's
   `/etc/pf.conf`; without both, the backend reports degraded and applies
   nothing.
3. PF is never enabled or disabled by the product, and no table is ever
   flushed by the product.
4. The global forwarding switches are read-only to the product, sticky, and
   left as the administrator set them (ADR-007).
5. IPv4 masquerade is IPv4 only. IPv6 is routed and **never** translated.
6. Every PF invocation is a fixed argument vector to the fixed system path
   `/sbin/pfctl`, with no shell, a bounded output, and a bounded runtime.
7. The rendered rules are a canonical AST with a deterministic renderer; the
   product compares the installed content by exact digest and repairs nothing
   by guessing.
8. Foreign PF state, foreign anchors, the default route, and the shared
   forwarding switches are never destroyed or restored by the product.

## The qualification environment (settled)

The environment requirement is met by the **existing** controlled host, and
disposability is inherited rather than re-proved: the C003/C011 leg already
reset the disposable macOS guest to pristine between runs — the product
uninstalled, the state directory moved aside, the management identity removed,
the job overrides enabled, and no plist or process left behind.

| Role | Machine | What it provides |
|---|---|---|
| Appliance (the NAT gateway) | disposable macOS guest | administrator-attached PF, real default route via the host, disposable |
| Off-host client and far-side egress endpoint | Linux guest, namespaces `wgbpeer` and `wgblan` | a real Linux-kernel WireGuard peer, and a far side at 10.20.20.2 / 2001:db8:20::2 |
| Forwarder between the segments | this Mac | **a pure forwarder**: its qualification anchor already carries `no nat` for both lab prefixes, so the host does not translate |

Two consequences the evidence must respect:

- **The egress evidence is lab-internal.** The product's translation is
  observable at the far side (`wgblan`), because the host does not translate on
  the way. At the real Internet the home router translates again and the
  product's translation would be masked. C004's evidence is a LAN far side,
  which the plan's "observable LAN/Internet egress endpoints" allows, and the
  closure record states it plainly.
- **The operator step grows a NAT class.** The guest's `/etc/pf.conf` must
  carry, for the managed anchor:

  ```
  anchor "wg-basic-v1-<id>" all
  nat-anchor "wg-basic-v1-<id>" all
  load anchor "wg-basic-v1-<id>" from "/etc/pf.anchors/wg-basic-v1-<id>"
  ```

  A filter-only parent does not satisfy a masquerading policy, and C007's
  verifier says so exactly.

The guest currently carries three accumulated `wg-basic-v1-<uuid>` anchors from
the C003/C011 legs, and the restore script does not remove them. The leg must
install and remove its own anchor, and the restore script must learn to clear
them, so a later run does not inherit a stale anchor the product will never
match.

## Expected production changes

- `src/firewall/pfctl.rs`: a bounded, scoped **apply** path alongside the
  read-only observation, with the module's contract updated to state exactly
  what it may and may not do. The observation grows an `anchor_nat` field so
  the installed NAT rules can be verified, not assumed.
- `src/firewall/pf.rs`: the gateway plan's rule set (already rendered by
  `render_policy`) becomes installable, with the canonical AST, the digest
  comparison, and the reversible removal order (already modelled by
  `teardown_order`).
- `src/firewall/service_darwin.rs`: `NetworkPolicyMode::Gateway` becomes a
  plan instead of `Unsupported`, and it fails closed when the attachment, the
  egress, or the forwarding prerequisites are not proven.
- `src/reconcile/`: the gateway's desired state is applied and observed like
  any other managed resource, with its receipt.

## Ordered work packages

1. **Establish the PF install mechanism against the real `pfctl`.** Determine,
   on the disposable guest, the exact invocation that installs the managed
   anchor's content and loads it into the filter and NAT tables **without
   replacing the root ruleset**, and the exact invocation that removes it.
   The constraint is the contract, not the mechanism: the root ruleset is
   never loaded, no table is flushed, PF is never toggled. If no such
   invocation exists that preserves foreign state, **stop** (§Stop conditions).
2. **The bounded apply backend.** Fixed argument vectors, the fixed system
   path, bounded output and runtime, no shell, no caller-supplied path or
   text, an exact digest comparison before writing, and a re-observation after
   writing. A refusal preserves foreign rules and skips the rest of the
   teardown until the firewall cleanup is safe.
3. **The gateway plan.** Render the policy with `render_policy`, install it
   into the managed anchor, observe both the filter and the NAT anchor's
   content, and report convergence only when the observed content matches the
   rendered digest **and** both parent classes invoke the anchor.
4. **The failure and recovery semantics.** A collision, a stale receipt, drift
   in the anchor file, a user-changed parent, PF disabled, a renumbered
   `utun`, a netd restart, and a disable/re-enable cycle each produce their own
   visible outcome, and nothing foreign is destroyed or restored.
5. **The evidence leg.** The two-guest topology above, with the NAT-class
   operator attachment, the IPv4 translated-source observation, the IPv4
   return path, the IPv6 no-NAT66 observation, and the negatives: a filter-only
   parent, a NAT-only parent, a parent whose anchor name merely collides, and a
   drifted anchor file.

## Privilege and security effects

The privileged daemon gains a bounded PF write path it does not have today.
It writes one file under `/etc/pf.anchors/`, named for the installation, and
loads it into the anchor the administrator attached. It cannot write the root
ruleset, cannot flush a table, cannot toggle PF, and cannot touch the
forwarding switches. The unprivileged management side never reaches
`pfctl`; the split is unchanged.

The anchor's rules widen the host's filter and NAT surface exactly as the
policy states, and only for the declared tunnel prefixes. The absence of the
operator's attachment is a degraded state with an actionable error, never a
silent partial install.

## Persistence, protocol, and configuration compatibility

The desired-state model already carries `mode` and `destination_prefixes`, and
the schema is at version 8; no migration is required and no stored state
changes shape. The management API's setup body already carries `mode` and
`destination_prefixes`. The wire protocol and the client configuration format
are unchanged. Linux behaviour is unchanged: the gateway mode remains
macOS-only, and the Linux nftables contract is not touched.

## Failure, cancellation, restart, and contention semantics

- A failed observation or installation is a **degraded** result with a
  category, never a silent success and never a partially-installed "converged"
  state.
- The installation is atomic from the product's point of view: the anchor
  file is written whole, the content is verified by digest, and a mismatch is
  reported rather than repaired by guessing.
- A concurrent manager that changes the parent or the anchor file between the
  observation and the write is detected by the post-write re-observation, and
  the product reports the conflict instead of overwriting it.
- A restart re-observes before it applies. A receipt that cannot be re-proven
  is not a claim (the rule C011 established), and the gateway follows it.
- Disabling the managed network removes the anchor's rules and leaves the
  administrator's parent and every foreign rule untouched.

## Focused tests

- The rendered gateway rules are exact and deterministic: IPv4 masquerade
  present, IPv6 absent, the egress interface named, the tunnel prefixes
  exact.
- The install invocation's argument vector is fixed, contains no shell
  metacharacter, names only the managed anchor and its own file, and carries
  the root-ruleset-loading verb **not at all**.
- The remove invocation is the exact inverse and leaves the parent's rules
  untouched.
- The observation distinguishes an anchor that is attached, attached by a
  colliding name, NAT-only, filter-only, and absent.
- The digest comparison rejects a drifted anchor file and accepts an exact
  match.
- The plan refuses to converge when forwarding is off, when the egress
  interface is absent, or when the parent's classes are incomplete.
- Every refusal preserves foreign rules and skips the remaining teardown.

## Integration evidence

On the disposable macOS guest, with the Linux guest providing the off-host
client and the far-side endpoint:

- The IPv4 peer reaches the far side and **the far side observes the
  translated source** — the tunnel pool address is not what arrives — and the
  return path works.
- The IPv6 peer reaches the far side and **the far side observes the
  untranslated source**, with no NAT66 anywhere in the path.
- The negatives refuse: a filter-only parent, a NAT-only parent, a colliding
  anchor name, a drifted anchor file, and an unapproved destination.
- The PF inventory before and after is captured, so the evidence shows what
  the product changed and what it left alone.
- A helper renumber and a netd restart are survived, and the anchor's rules
  are re-proven against the observed content.
- The teardown leaves the administrator's parent and every foreign rule
  exactly as it found them.

## Broad verification commands

```
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo test --locked -p wg-basic-darwin-sys
cargo +1.89.0 check --all-targets --locked
cargo check --locked --target aarch64-apple-darwin --all-targets
cargo zigbuild --locked --target x86_64-unknown-linux-gnu --all-targets
CC_x86_64_unknown_linux_gnu=$HOME/wg-toolchain/zigcc AR_x86_64_unknown_linux_gnu="zig ar" \
  cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets -- -D warnings
CC_x86_64_unknown_linux_gnu=$HOME/wg-toolchain/zigcc AR_x86_64_unknown_linux_gnu="zig ar" \
  cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets \
  --features linux-integration -- -D warnings
```

The last one is part of the gate order since C012 and is mandatory here: the
Linux-gated code is compiled by neither of the two commands above it.

## Documentation updates

- `docs/operations-runbook.md`: the administrator's attachment, including the
  `nat-anchor` class; the operator's forwarding step; what the doctor reports
  for a gateway policy; and the egress and no-NAT66 expectations.
- `architecture/firewall.md` (or the equivalent): the product's PF ownership,
  what it may write, and what it must never touch.
- `architecture/ownership.md`: the anchor file as a managed resource with a
  receipt, and the administrator's parent as foreign state.
- The operator-facing setup prompt: the advanced-administrator framing, stated
  as a precondition rather than a warning.

## Acceptance criteria

1. A gateway policy on macOS converges, and the doctor reports the tunnel and
   the filter as in effect.
2. The IPv4 far side observes the translated source and the return path works.
3. The IPv6 far side observes the untranslated source.
4. The negatives refuse, each with its own actionable error.
5. The root ruleset is never loaded, PF is never toggled, no table is flushed,
   and the forwarding switches are untouched — each provable from the PF
   inventory and the sysctl values before and after.
6. The teardown leaves the host's PF configuration as it found it, apart from
   the managed anchor's own removal.
7. Every Linux job is green, the Darwin gates are green, and the ordinary
   suite is green.

## Stop conditions

Stop and record the discrepancy rather than working around it if:

- the install mechanism cannot avoid replacing the root ruleset, or cannot
  avoid flushing a table;
- preserving third-party PF state proves impossible;
- the mechanism would require the product to edit `/etc/pf.conf`, to enable or
  disable PF, or to own the forwarding switches;
- NAT66 proves unavoidable for the IPv6 path;
- the effective attachment cannot be proven for the NAT class, so the product
  would have to claim a convergence it cannot observe;
- the implementation needs a privileged capability that ADR-008 §3.6 and
  M005's closure did not already decide. That is an ADR question, not an
  implementation detail: it stops the milestone and returns to ADR-008.

M007's MUST-NOT-release gate is held pending C005 throughout.

## Closure evidence requirements

`plans/closure/macos-native-server-corrective/c004-status.md` only after real
effective packet evidence: the PF inventory before and after, the translated
and untranslated source observations, the negatives, the recovery cases, and
the exact commands and their results. A rule string is not evidence of a
packet.
