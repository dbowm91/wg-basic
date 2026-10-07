# Firewall, forwarding, and NAT ownership

## Supported policy

The initial network policy is IPv4-only and names one managed WireGuard interface, one explicit egress interface, and one or more source prefixes (bounded to 64). NAT is either disabled or masquerade. Prefixes must be unique, IPv4, and non-unspecified. The protocol accepts these typed values only; it does not accept rule text, command arguments, or sysctl paths.

When forwarding is required, netd reads and may set only `/proc/sys/net/ipv4/ip_forward` to `1`. It never writes `0` during policy removal or interface teardown. The setting is host-global and may be required by other services, so a disable receipt does not claim it was restored to a prior value.

## nftables boundary

The service owns the dedicated `inet wg_basic` table. A table-level `wg-basic:m005:v1` marker establishes ownership; an existing same-name table without it is a conflict and is never flushed or deleted. The generated table has an accepting forward base chain, an established/related return rule to the managed tunnel, source-prefix and explicit-egress allow rules from the tunnel, and a drop for other traffic entering that managed tunnel. Masquerade rules match only the configured source prefixes and egress. Table and chain/rule comments include a deterministic desired-policy hash. Reconciliation checks ownership, marker inventory, and expected chain/rule counts before reporting convergence.

Mutations are sent as one internally rendered `nft -f -` batch, so replacement is a single nftables transaction. The process is invoked directly, never through a shell. Input is capped at 32 KiB, each output stream at 256 KiB, and execution at five seconds. The binary absence maps to `Unsupported`; permission failures are distinguished; malformed JSON, timeout, and command failures return a redacted backend failure. No nftables command output or generated source is returned in protocol errors.

The `nft` executable is a runtime requirement for firewall policy operations. The minimum supported userspace is nftables 0.9.0; netd checks `nft --version` and reports older/missing/unparseable versions as unsupported. The inet-family NAT path requires Linux 5.2 or newer. The repository's rootful qualification uses the Ubuntu runner's packaged nftables and checks `nft --version` before creating namespaces. Runtime compatibility is also validated by JSON table listing and the actual atomic batch; unsupported kernel combinations fail without claiming convergence. The minimum kernel/userspace pair is documented from nftables' [NAT compatibility guidance](https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_%28NAT%29). This is a transitional backend. A direct netfilter backend can replace it without changing the protocol policy types.

## Interaction with other firewall managers

The wg-basic forward chain uses the standard `filter` priority and an `accept` base policy so it does not establish a default drop for unrelated host forwarding. An accept verdict in this chain does not override a later independent base chain: another firewall manager can still drop the packet. Plan and apply responses carry an `independent_firewall_may_still_block_forwarded_traffic` warning. The namespace qualification installs such a later drop and verifies traffic is blocked until that separate table is removed. wg-basic does not flush, reorder, or edit that table. The WireGuard UDP listen port also remains the responsibility of the host firewall/operator.

## Disable and preservation

Removing the network policy deletes only `inet wg_basic`; it does not change `ip_forward`. M004 link/address/route removal remains an explicit separate typed desired-state request. Namespace qualification verifies unrelated nftables objects and routes survive policy apply, no-NAT/NAT transition, reapply, netd restart, and disable. The firewall service does not enumerate or rewrite the rest of the host ruleset.

## Qualification

Run the three-namespace kernel test on a rootful Linux host with kernel WireGuard, `iproute2`, `iputils-ping`, and `nftables` installed:

```text
sudo -E cargo test --locked --features linux-integration --test network_control_e2e -- --nocapture
```

The client namespace has no route from the internet namespace to its tunnel prefix. The no-NAT case must fail; enabling the typed masquerade policy must make ping succeed. This demonstrates a working return path through NAT rather than a preconfigured route.
