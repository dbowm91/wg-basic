# macOS Native Server M005 — Forwarding, PF/NAT Policy, and Gateway Feasibility Decision

Status: planned; blocked on M004 resource ownership closure AND explicit PF/product-distribution gate review
Primary class: invariant / capability / architectural decision
Roadmap: plans/subsystems/macos-native-server-roadmap.md M005
Baseline: main 47c72b0e81d569d48396c615120453bf0cf1d46e; reconcile with actual implementation head.
Authority: plans/000-long-term-specification.md; plans/002-long-term-roadmap.md; plans/003-planning-process.md; plans/adr/008-macos-headless-platform-backends.md; existing Linux ADRs remain in force.

## Objective

Establish and qualify a legitimate, bounded macOS gateway model with IPv4 forwarding/NAT and routed IPv6. Decide whether advanced-administrator PF anchors are an acceptable supported deployment mode under Apple TN3165; if not, document alternate Apple-supported strategy or formally narrow support rather than claiming full gateway functionality.

## Non-goals

No systemwide PF editor, global rules flush, stealth /etc/pf.conf overwrite, unbounded PF text passthrough, disabling PF globally, NAT66 by default, or claiming an Apple-supported PF product API without evidence.

## Current repository evidence

src/firewall/nft.rs reads /proc/sys/net/ipv4/ip_forward, /proc/sys/net/ipv6/conf/all/forwarding and executes bounded nft; src/firewall/service.rs applies dedicated nft table. architecture/firewall.md records foreign-table preservation and sticky forwarding. Darwin has PF anchors but Apple TN3165 https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api warns PF is not a general product API. PF anchor rules require deliberate parent filter/NAT attachment; mere anchor existence is not effective packet policy.

## Mandatory invariants

- Apple supported/distribution posture must be recorded before shipping; a user opting in as advanced administrator is not blanket product API authorization.
- Network policy remains typed (v4 forwarding, v6 forwarding, source prefixes, explicit egress and NAT flag); no remote raw PF.
- PF rules must actually match packets through reachable filter/NAT anchors; verify on host, not via syntax or dry-run alone.
- No foreign PF table, anchor, global enabled state, forwarding sysctl, Internet Sharing/third-party service overwritten.
- Host global forwarding is shared/sticky: never silently reset to previous value on disable.
- Fail closed on missing or altered anchor inclusion; never modify /etc/pf.conf automatically to force acceptance.

## Ordered implementation work

1. Research macOS version-target PF/forwarding behavior and exact platform guidelines with primary sources. Write an addendum/ADR gate defining *advanced-admin PF mode*, requisite explicit host administrator setup and whether it is compatible with intended distribution. If not, evaluate Network Extension or re-scope gateway capability before coding.
2. Build read-only PF inventory and anchor attachment verification, including both nat-anchor and filter anchor invocation order. Identify conflicts with existing PF state, third-party managers, Internet Sharing and SIP-protected settings.
3. If PF acceptable, define a bounded dedicated installation-specific anchor and predictable rules plus administrative configuration instructions; default to no implicit parent-file mutation. Establish exact owner marker, anchor matching/digest and fail-closed drift behavior. Native netd only invokes bounded internally rendered pfctl operations; never shell or arbitrary user text.
4. Define controlled forwarding sysctl observations/enable for IPv4/IPv6; enforce explicit policy, strict paths, no unrequested family toggles; report persistence/reboot/operator steps. Preserve foreign state.
5. Implement observe/plan/apply/verify and teardown ordering; demonstrate IPv4 no-NAT vs masquerade, IPv6 routed return without NAT66, host firewall interactions; expose degraded reasons and no false convergence.
6. Document supported/unsupported configurations and the exact admin opt-in contract; decision must be explicit before progressing M006.

## Security, persistence, protocol, failures and compatibility

PF anchor injection is a privileged host-global concern. Requires exact anchor name, ownership evidence, parent attach proof, no unrestricted firewall modification. A separate netd process enforces validation independent of API. Use fixed argv, output/input/time caps, redacted errors and no shell. Traffic cannot leak during partial policy apply: follow conservative firewall-before-teardown ordering and prove drop/allow semantics. Migration of persisted policy must not change Linux semantics.

## Native and regression tests

On isolated real macOS host with explicit admin-approved PF setup: test effective forwarded IPv4 to client and egress, NAT return, no-NAT failure where applicable, routed IPv6 both directions, foreign anchors and rules before/after, nonexistent/inert anchor, drift, conflicting rule priorities, PF disabled/enabled, wrong owner, internet sharing coexistence or documented incompatibility. Inject pfctl timeout/apply failure; compare all foreign config. Perform Linux rootful nft and IPv4/IPv6 E2E regression.

## Verification and documentation

Capture primary Apple TN3165 review, chosen distribution classification, exact PF and sysctl observations and packet proof. Native macOS real traffic with ingress/egress counters, not rules-only mock. Run standard all-platform cargo/test and Linux CI. Update architecture/firewall.md/docs/operations-runbook.md only after implementation; write operator-facing PF prerequisites.

## Explicit acceptance criteria

Clear approved deployment mode and constraints; owned effective PF NAT/filter packets actually traverse tunnel and egress, including IPv6 routing and disable/retry. No foreign PF/global forwarding mutation. All failures report actionable degraded status. No release or full macOS gateway claim if TN3165 distribution concern unresolved.

## Stop conditions

STOP if PF attachment requires silently rewriting unrelated config, API compatibility/distribution posture is unacceptable, foreign state cannot be preserved, NAT behavior fails real traffic verification, or global PF state must be seized. Revise ADR and gate dependent milestones.

Only after implementation write plans/closure/macos-native-server/005-status.md with exact head, commands/results, native host evidence, preservation and privilege matrix, unresolved severity-graded findings, docs, and a justified closure disposition. Do not edit historical Linux closure evidence.
