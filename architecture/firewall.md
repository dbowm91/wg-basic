# Firewall, forwarding, and NAT ownership

## Supported policy

The network policy names one managed WireGuard interface, one explicit egress interface, and one or more unique source prefixes (bounded to 64). IPv4 forwarding remains independently selectable. IPv6 forwarding is an explicit opt-in and its source prefixes must be covered by configured managed IPv6 tunnel state. NAT is IPv4 masquerade only; IPv6 traffic is routed without NAT66. The protocol accepts typed values only; it does not accept rule text, command arguments, or sysctl paths.

When IPv4 forwarding is required, netd reads and may set only `/proc/sys/net/ipv4/ip_forward` to `1`. When IPv6 forwarding is explicitly required, it reads and may set only `/proc/sys/net/ipv6/conf/all/forwarding` to `1`. Neither setting is reset during policy removal or interface teardown. The IPv6 global control also changes Linux per-interface Host/Router and Router Advertisement behavior; disabling the policy leaves it enabled. Operators must arrange an upstream route for the selected IPv6 tunnel prefix.

## Typed routing modes

The routing mode is part of the desired state, not something the apply infers.
`NetworkPolicyMode` (`src/domain/state.rs`) has three variants: `HostOnly`
(the default), `RoutedLan`, and `Gateway`. The mode is persisted with the
policy (schema version 8, see [the state store](state-store.md)), and the
projection carries it — together with the approved downstream prefixes — into
the firewall policy (`src/firewall/policy.rs`), which carries the same `mode`
and `destination_prefixes`.

A mode's own rules are checked together in `validate_policy_mode`, because a
policy that contradicts itself is refused rather than resolved:

- a **host-only** policy carries no forwarding obligation, no masquerade, and
  no destination allowlist;
- a **gateway** policy carries no destination allowlist;
- a **routed-LAN** policy carries one bounded allowlist — at most
  `MAX_ROUTED_LAN_DESTINATIONS` (16) prefixes, each a valid unicast prefix
  that is neither the default route nor an overlap with a source prefix —
  never masquerades, requires the forwarding of every family it names, and
  keeps every source prefix inside the managed tunnel pool.

The product's setup path derives the mode when the caller does not state one
(no forwarding and no masquerade is host-only; anything else is a gateway) and
refuses an explicit mode that contradicts the forwarding and masquerade
settings. A routed LAN is implemented on macOS only and is refused on every
other platform.

The Linux nftables backend forwards to any destination, so it **refuses** a
routed-LAN policy with `FirewallError::Unsupported` instead of applying a
bounded policy as an unbounded one. The Darwin service implements the
host-only and the routed-LAN contracts, and the gateway mode is a third
contract of its own, with a different filter and NAT surface.

## nftables boundary

The service owns the dedicated `inet wg_basic` table. A table-level marker binds ownership to the installation identity (`wg-basic:v1:<installation-uuid>`); a same-name table carrying another installation's marker is a conflict and is never flushed or deleted. The historical M005 product-only marker `wg-basic:m005:v1` is recognized specifically and reported as a distinct legacy-ownership conflict; it is never silently adopted, because no durable state shipped before Phase 6. The generated table has an accepting forward base chain, an established/related return rule to the managed tunnel, source-family-prefix and explicit-egress allow rules from the tunnel, and a drop for other traffic entering that managed tunnel. IPv4 masquerade rules match only configured IPv4 source prefixes and egress; no IPv6 masquerade rule is generated. Table and chain/rule comments include a deterministic desired-policy hash. Reconciliation compares the normalized JSON for each owned chain and rule with the expected expression model, in addition to checking ownership and object inventory; kernel handles are ignored. Changed expressions with copied comments are detected as drift and replaced.

Mutations are sent as one internally rendered `nft -f -` batch, so replacement is a single nftables transaction. The process is invoked directly, never through a shell. Input is capped at 32 KiB, each output stream at 256 KiB, and execution at five seconds. The binary absence maps to `Unsupported`; permission failures are distinguished; malformed JSON, timeout, and command failures return a redacted backend failure. No nftables command output or generated source is returned in protocol errors.

The `nft` executable is a runtime requirement for firewall policy operations. The minimum supported userspace is nftables 0.9.0; netd checks `nft --version` and reports older/missing/unparseable versions as unsupported. The inet-family NAT path requires Linux 5.2 or newer. The repository's rootful qualification uses the Ubuntu runner's packaged nftables and checks `nft --version` before creating namespaces. Runtime compatibility is also validated by JSON table listing and the actual atomic batch; unsupported kernel combinations fail without claiming convergence. The minimum kernel/userspace pair is documented from nftables' [NAT compatibility guidance](https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_%28NAT%29). This is a transitional backend. A direct netfilter backend can replace it without changing the protocol policy types.

## Interaction with other firewall managers

The wg-basic forward chain uses the standard `filter` priority and an `accept` base policy so it does not establish a default drop for unrelated host forwarding. An accept verdict in this chain does not override a later independent base chain: another firewall manager can still drop the packet. Plan and apply responses carry an `independent_firewall_may_still_block_forwarded_traffic` warning. The namespace qualification installs such a later drop and verifies traffic is blocked until that separate table is removed. wg-basic does not flush, reorder, or edit that table. The WireGuard UDP listen port also remains the responsibility of the host firewall/operator.

## Disable and preservation

Removing the network policy deletes only `inet wg_basic`; it does not change either forwarding sysctl. In the aggregate disable path the firewall removal is the first step, and the interface teardown runs only after it succeeds — so a firewall that refuses to remove its table leaves the managed link intact rather than deleting the link and orphaning a policy whose target no longer exists. Link/address/route removal is driven by the same desired-state request, and is applied by the reconciliation engine after the firewall layer has cleared. Namespace qualification verifies unrelated nftables objects and routes survive policy apply, no-NAT/NAT transition, reapply, netd restart, and disable; a rootful fixture injects a firewall backend failure on the disable path and verifies the blocked teardown and its recovery. The firewall service does not enumerate or rewrite the rest of the host ruleset.

## Qualification

Run the three-namespace kernel test on a rootful Linux host with kernel WireGuard, `iproute2`, `iputils-ping`, and `nftables` installed:

```text
sudo -E cargo test --locked --features linux-integration --test network_control_e2e -- --nocapture
```

The IPv4 no-NAT case must fail until masquerade is enabled. The IPv6 fixture installs an upstream route to the tunnel prefix and proves routed traffic plus established return traffic without NAT66. Its client starts with explicit IPv4 and IPv6 full-tunnel routes, then changes to independent split prefixes; selected destinations pass and destinations outside those prefixes do not. Traffic under the split policy resumes after server netd restart/reapply, while unrelated firewall, route, and egress-address state remains intact.

## Darwin host-only contract (C001)

The Darwin C001 deployment is **host-only**: the managed tunnel carries the
host's own traffic, and the machine's own services reach the tunnel's peers.
There is no forwarding, no NAT, no routed LAN, and no PF anchor.

The host-only contract therefore does exactly two things, and both are
honest:

1. it **refuses** any policy that requires forwarding or NAT, with
   `FirewallError::Unsupported`, instead of silently ignoring the request and
   reporting a success that did nothing; and
2. it **reports** the host's global forwarding state, which is host-global
   state this product does not own and never changes.

Nothing in the **host-only** path writes PF state, forwarding sysctls, or host
routes. The read-only `pfctl` observation backend landed with the routed-LAN
corrective, and the host-only contract still never writes PF state. The
service's second contract — the routed LAN — is described below, and it is
free of PF writes as well, because its filter is operator-managed. The third
contract — the administrator-attached gateway — is the one mode in which the
product writes PF state, and its scope is stated below.

## Darwin routed-LAN contract (C003)

The Darwin service implements two contracts, and they are deliberately
different. The host-only contract above refuses forwarding and NAT. The
**routed-LAN** contract forwards authorized client traffic to an explicit
allowlist of downstream LAN prefixes, and it is **proved, never assumed**.

Nothing in the Darwin path writes PF state, forwarding sysctls, or host
routes. The Darwin product owns no filter, no forwarding switch, and no
route. What it does is observe the host and refuse to claim convergence when
the host is not actually ready:

1. **Forwarding.** The host's global IPv4/IPv6 forwarding must already be
   enabled for every family the policy requires. The state is read through
   `net.inet.ip.forwarding` and `net.inet6.ip6.forwarding` and is never
   written: it is host-global, shared with whatever else on the machine routes
   packets. An unreadable switch is refused the same way as an off one,
   because an unknown prerequisite is not a proven one.
2. **The operator-managed filter.** The filter is operator-managed under Apple
   TN3165: the administrator installs the rules and attaches the installation
   anchor from their own PF configuration. The product observes what is in
   effect — attachment is verified per rule class and token-exactly, as
   described under *Darwin PF attachment verification (C007)* below — and the
   anchor's content must be **exactly** the rendered policy.
3. **The routes.** Every approved destination must be reached by a specific
   route through the declared egress interface, never by the default route
   alone, and no foreign route may compete with it. The route that carries
   traffic back to the tunnel pool must exist and must be scoped to the
   managed `utun` device.

Each failure has its own refusal, because "routed LAN is not available here"
and "the upstream route back to the pool is missing" call for different
operator actions. The verdict vocabulary is `RoutedLanVerdict` (`Ready`,
`ForwardingDisabled`, `FilterMissing`, `FilterDrift`, `MissingReturnRoute`,
`RouteConflict`, `UnsupportedTopology`, `TunnelUnavailable`), and six firewall
errors carry the same names, so a refusal names the prerequisite that is
missing rather than a generic failure.

The **plan reports what it observed; the apply is what refuses.** A plan
carries the verdict and the exact rules the operator has to install
(`FirewallPlanSummary::required_filter_rules`), so the diagnostics can name
the missing prerequisite and the missing rules; the apply returns the
refusal. Nothing is repaired by guessing, and a drifted filter is never
rewritten.

The rules reach the operator as **structured data**, not as prose: the
doctor's `routed_lan` check carries them in `required_filter_rules`, because
the doctor's bounded evidence string cannot hold a routed LAN's rule set and
a truncated rule is not a rule an operator can install. The bounded evidence
reports the rule count instead.

The rendered rules (`render_routed_policy` in `src/firewall/pf.rs`) are one
filter rule per source and destination pair, in **both** directions: an `in` rule
bound to the managed tunnel device and an `out` rule bound to the egress
interface carry the pool's traffic to the approved destination, and the mirror
pair — `in` on the egress interface, `out` on the managed tunnel device — carries
the approved destination's own traffic back to the pool. All of them are `keep
state`. There is deliberately no `to any` rule and no NAT rule, because a
routed LAN is a routing decision and not a masquerade. The ingress rule names
the dynamic `utun` the helper currently holds, which is what rejects a
spoofed source arriving on another interface — and why the rules have to be
re-installed when the helper is renumbered.

The return leg is not optional. A routed LAN that only renders the forward
direction leaves the approved host unable to reach the pool at all, and leaves
the reply to a forwarded packet resting on a state entry the operator's own
filter never created. The return rules are bounded exactly like the forward
ones — only the approved destination may originate towards the pool, and only
towards the pool — so they widen nothing: a destination outside the approved
prefix is still refused in both directions.

A pair is rendered only when the source and the destination are of the same
address family. PF matches one family per rule and refuses to load a rule
that mixes them ("rule expands to no valid combination"), and carrying
traffic between the families would need a translation that a routed LAN never
performs. The policy's own validation refuses an approved destination whose
family the tunnel pool does not carry, so a destination that could never be
delivered is refused rather than approved and then silently unreachable.

`anchor_content_matches` compares the observed anchor content against the
rendered policy after normalizing both into a small rule grammar, so an extra,
missing, renamed, or non-stateful rule is drift. The normalization has to
survive PF's own canonical rendering: PF resolves the address family it
matched and the state flags it applied, and prints them (`pass in on utun0
inet from 10.77.0.0/24 to 10.20.20.0/24 flags S/SA keep state`). An operator
who installed exactly the reported rules must not be told the filter drifted.

### The `pfctl` boundary

`src/firewall/pfctl.rs` is the only place the Darwin product touches the
host's packet filter. Its observation half is bounded and read-only:

- it runs `/sbin/pfctl` with fixed argument vectors only — `-s rules`, `-s
  nat`, and `-a <anchor> -s rules`;
- it never loads a ruleset, never flushes, never edits `/etc/pf.conf`, and
  never enables or disables PF;
- each invocation is time-bounded and each output stream is capped.

The observation answers two different questions: the parent rulesets say
whether the managed anchor is attached at all, and the anchor's own content
says whether the attached rules are the ones this policy needs.

The same module carries the gateway mode's bounded apply path. It is scoped
to the installation's own anchor and the installation's own file, and it is
described under *Darwin gateway contract (C004)* below. It never loads the
root ruleset, never flushes a table, never edits `/etc/pf.conf`, and never
enables or disables PF.

## Darwin PF attachment verification (C007)

The PF model in `src/firewall/pf.rs` is a **pure** module: it renders the
installation-scoped anchor's rules, digests them for drift detection, and
verifies that an administrator's parent configuration actually attaches the
anchor. It performs no I/O, spawns nothing, and mutates no host state; the
live `pfctl` observation lives in `src/firewall/pfctl.rs`, whose observation
half is strictly read-only.

Attachment verification is **per rule class and token-exact**:

- the filter table and the NAT table hold independent anchors that may share
  a name, and each is attached by its own parent rule, so the two classes are
  observed separately (`observe_attachments` → `AttachmentObservation`);
- a rule invokes the managed anchor only when the rule's **first token** is
  that table's keyword (`anchor` in the filter table, `nat-anchor` in the
  NAT table) **and** the rule's **second token** is the managed anchor's
  name as a whole token, quoted or bare;
- the verdict (`attachment_verified`) is a **conjunction** over the required
  classes, so a parent that references one class never satisfies a
  requirement for both.

Everything else is not an invocation, and the observation fails closed: a
name that merely *contains* the managed name, a comment naming it, another
table's keyword (`scrub-anchor`, `rdr-anchor`), and the anchor's own
definition all report **missing**. The hosted macOS live fixture proves
each of those exclusions against real `pfctl` output — a scoped parent
anchor that invokes the managed anchor (the positive case), a parent that
invokes a longer name (the collision case), the host's own invocations, and
the uninvoiced main ruleset — and asserts that the fixture leaves the main
ruleset exactly as it found it.

## Darwin gateway contract (C004)

The gateway mode is the one mode in which the product writes to the host's
packet filter, and the write is deliberately narrow: the product owns **one**
installation-scoped anchor and **one** anchor file, and nothing else. It is an
advanced-administrator opt-in under Apple TN3165 — general consumer macOS
gateway support is not claimed and not advertised.

The PF behaviour stated here was **measured on a disposable macOS guest on
2026-10-23**. The packet-level qualification — an IPv4 peer whose source is
translated at the far side, and an IPv6 peer whose source is not — is C004's
own evidence work and is **not closed** at the time of writing. What follows
is the contract, the ownership, the mechanism, and the operator procedure;
it claims no packet evidence.

### What the product owns

- **One anchor**, named `wg-basic-v1-<installation-id>`. The name is derived
  from the installation identity and is never chosen by a caller.
- **One anchor file**, `/etc/pf.anchors/<anchor>`. The path is derived from
  the anchor's own name and is never caller-supplied.
- **Nothing else.** The product writes neither `/etc/pf.conf` nor any foreign
  anchor, and it never loads the root ruleset.

The administrator's parent invokes the anchor in **both** rule classes: the
filter table's parent and the NAT table's parent, each by its own rule. A
filter-only parent does not satisfy a masquerading policy, and the
verification described under *Darwin PF attachment verification (C007)* above
says so exactly. The parent's `load anchor` line populates **both** of the
anchor's rulesets, so the administrator's own reload of `/etc/pf.conf`
restores both classes without the product re-loading them.

### The install and the removal

The install is one invocation:

```text
pfctl -a <anchor> -f /etc/pf.anchors/<anchor>
```

It loads the file into the anchor's **filter and NAT** rulesets. The **root
ruleset is byte-identical before and after** — `pfctl -s rules` and `pfctl -s
nat` are unchanged — no table is flushed, and PF is not toggled.

The removal is two invocations, and **both** are required:

```text
pfctl -a <anchor> -F rules
pfctl -a <anchor> -F nat
```

`-F rules` alone leaves the **NAT** rules loaded. PF keeps a loaded anchor's
rules across `pfctl -f` and `pfctl -F all`, so emptying the anchor's own
rules is the only way to remove them; a removal that empties only the filter
class leaves a translation rule in effect on the host.

A **failed load is fail-closed**: `pfctl` exits non-zero, prints `pf rules not
loaded`, and the anchor's existing filter and NAT content is left intact.
`pfctl` also prints `Use of -f option, could result in flushing of rules
present in the main ruleset added by the system at startup.` on stderr for
**every** load, including an anchor-scoped one. It is not an error — the exit
status is 0 and the root ruleset is provably preserved — so it is never
reported as a refusal.

### Rule order inside the anchor file

PF requires the rules of one ruleset to appear in the order *options,
normalization, queueing, translation, filtering*. A `nat` rule must precede
any `pass`/`block` rule in the same file; a file in the wrong order is refused
with `Rules must be in order: options, normalization, queueing, translation,
filtering` and exit 1. The product's anchor file therefore carries its
**translation rules first**, because a renderer that emitted the filtering
rules first would produce a rule set that cannot be installed at all.

### An absent anchor is not an emptied one

macOS signals an anchor that does not exist with **exit 0** and
`pfctl: DIOCGETRULES: Invalid argument` on stderr, so the exit status alone
cannot tell an absent anchor from an emptied one — the message is the only
signal. The two are different facts: an absent anchor means the
administrator has not installed the managed anchor, and an emptied one means
the installed rules were removed.

### Ownership is provable from the host's state

The anchor file the product writes carries a marker comment that the product
writes and recognises:

```text
# wg-basic-v1 managed anchor for installation <installation-id>
```

It is a comment, so it changes no rule and no rule digest, and it is what
makes the file's ownership provable from the host's state alone. The
routed-LAN mode's filter belongs to the administrator and carries no marker,
so the product never removes it — it reports the residue instead.

### The teardown keeps the administrator's attachment resolvable

The teardown empties the anchor's rules in **both** classes and **rewrites the
anchor file to its marker line alone** rather than removing it. The
administrator's `load anchor` line names that file, and a missing file makes
the next `pfctl -f /etc/pf.conf` fail outright — which would break the host's
whole packet-filter configuration, not just this installation's anchor. PF
never destroys an anchor object: `pfctl -s Anchors` enumerates every anchor
object in the kernel — 62 on the disposable guest, including ones that are
not attached to the main ruleset — and an anchor object is only ever emptied,
never removed. "The managed anchor's removal" can therefore only ever mean
the anchor's **rules**, and the file has to survive as a valid, empty rules
file for the administrator's `load anchor` line to keep resolving.

### What the product never does

The gateway mode does not widen the product's PF ownership beyond the anchor
it owns. It never:

- loads the root ruleset;
- flushes a table;
- enables or disables PF, or toggles it globally;
- takes or restores the global forwarding switches — they are host-global and
  shared with everything else on the machine, so the product reads and reports
  them and never writes them (ADR-007);
- writes `/etc/pf.conf`, or any foreign anchor.

Every `pfctl` invocation is a fixed argument vector to the fixed system path
`/sbin/pfctl`, with no shell, a bounded output, and a bounded runtime.
