# Firewall, forwarding, and NAT ownership

## Supported policy

The network policy names one managed WireGuard interface, one explicit egress interface, and one or more unique source prefixes (bounded to 64). IPv4 forwarding remains independently selectable. IPv6 forwarding is an explicit opt-in and its source prefixes must be covered by configured managed IPv6 tunnel state. NAT is IPv4 masquerade only; IPv6 traffic is routed without NAT66. The protocol accepts typed values only; it does not accept rule text, command arguments, or sysctl paths.

When IPv4 forwarding is required, netd reads and may set only `/proc/sys/net/ipv4/ip_forward` to `1`. When IPv6 forwarding is explicitly required, it reads and may set only `/proc/sys/net/ipv6/conf/all/forwarding` to `1`. Neither setting is reset during policy removal or interface teardown. The IPv6 global control also changes Linux per-interface Host/Router and Router Advertisement behavior; disabling the policy leaves it enabled. Operators must arrange an upstream route for the selected IPv6 tunnel prefix.

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

The Darwin firewall service therefore does exactly two things, and both are
honest:

1. it **refuses** any policy that requires forwarding or NAT, with
   `FirewallError::Unsupported`, instead of silently ignoring the request and
   reporting a success that did nothing; and
2. it **reports** the host's global forwarding state, which is host-global
   state this product does not own and never changes.

Nothing in the Darwin path writes PF state, forwarding sysctls, or host
routes. The PF backend lands with the routed-LAN corrective and stays behind
an explicit distribution decision.

## Darwin PF attachment verification (C007)

The PF model in `src/firewall/pf.rs` is a **pure** module: it renders the
installation-scoped anchor's rules, digests them for drift detection, and
verifies that an administrator's parent configuration actually attaches the
anchor. It performs no I/O, spawns nothing, and mutates no host state; the
live `pfctl` backend lands with the routed-LAN corrective (C004).

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
