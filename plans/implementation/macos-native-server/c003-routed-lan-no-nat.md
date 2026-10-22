# macOS Native Server C003 — Explicit Routed-LAN Mode Without NAT

Status: **implemented and qualified; conditionally closed 2026-10-22**. The hard dependency on C001 was discharged 2026-10-21; the native controlled-host proof this plan required was produced on 2026-10-22 and is recorded in `plans/closure/macos-native-server-corrective/c003-status.md`. The two findings that remain are recorded there and are routed to C001/C002's service-lifecycle matrix.
Baseline: `plans/macos-native-support@fc51146e811cabebd042d852449c6e7f4f854265`.
Source: corrective roadmap C003; M004/M005 (`plans/closure/macos-native-server/{004,005}-status.md`), ADR-008 and ADR-007.
Primary class: corrective / capability / invariant.

## Objective

Add an intentionally bounded routing capability that lets VPN clients reach administrator-approved downstream LAN subnets without requiring PF NAT or changing the host default route. A WireGuard endpoint with only host-local traffic (C001) is not a routed gateway. Avoid treating routed-LAN support as implicitly equivalent to Internet exit gateway support.

## Non-goals

No IPv4 masquerade, NAT66, automatic `/etc/pf.conf` edits, indiscriminate global forwarding enable/disable, forwarding over an uncontrolled interface, general destination allow-all, Wi-Fi/Internet Sharing manipulation, arbitrary sysctl/route IPC or automatic publicly supported macOS release.

## Implementation work

1. **Typed mode contract:** distinguish `host_only` from explicit `routed_lan` intent at the policy/validation layer (versioned schema/API migration only if needed, with Linux-compatible defaults). Select an allowlist of destination prefixes and a specific observed egress interface. Reject default routes, overlapping/conflicting foreign routes, spoofed peer sources, unsupported interfaces and ambiguous L2/L3 topology.
2. **Forwarding prerequisites:** read and surface `net.inet.ip.forwarding` and `net.inet6.ip6.forwarding`; require explicit administrator-controlled system enablement/prerequisite for enabled address families. Global settings are shared: do not adopt as app-owned state or revert settings that another service may rely on. Refuse ready/converged when kernel prerequisites are missing; no silent fallback.
3. **Return-path proof:** require administrator-installed, observed upstream IPv4/IPv6 routes back to the VPN pools; do not assume replies route through the Mac or silently seize upstream gateway settings. Keep all managed prefix/interface routes scoped to the correct dynamic `utun` with re-observed identity from C001.
4. **Security policy:** forwarding must be bounded to authorized sources/destinations, with an actual operator-managed packet-filter policy that can be observed and proven effective on the chosen host. Do not make the C001 "host-only no firewall needed" branch apply here. If there is no safely verifiable filter/forwarding setup, refuse rather than advertise routed support. PF rules and any privileged integration remain opt-in per TN3165; implementation must not sneak in general PF automation.
5. **State/recovery:** on peer/prefix removal, netd outage, helper renumbering, uplink change or routing conflict, refuse stale convergence; preserve foreign routes and shared forwarding state. Doctor/health should distinguish "missing return route", "forwarding disabled", "filter missing", "route conflict", and "not supported".

## Qualification and security evidence

On a disposable administrator-controlled Mac, use a separate LAN host and real WireGuard peer on Linux. Prove IPv4 and IPv6 packets: tunnel peer → utun → approved LAN host → return route → tunnel; verify wrong destination and spoofed source are rejected and counters confirm the intended path. Record upstream route tables, host routing + PF inventory before/after, and negative tests for no return route, forwarding off, disabled filter, foreign route collision, helper restart, physical link failover, reapply and teardown. No mock-only routed claim.

Require native arm64 for the targeted published scope, routine/MSRV + all Linux rootful suites. Stop if the only workable strategy needs uncontrolled PF main-ruleset edits, unbounded sysctl write, broad default-route takeover, unqualified policy filtering, or foreign resource deletion. Document operator prerequisites and known unsupported topologies. Close only in `plans/closure/macos-native-server-corrective/c003-status.md` with real traffic and preservation evidence.

## Amendment (2026-10-21)

ADR-009 makes Apple silicon (`aarch64-apple-darwin`) the only supported Darwin
target for the macOS native-server line, so the architecture gate above is
amended from native arm64 and Intel to native arm64 alone. The retired Intel
capability is retired by scope, not by new measurement: the macOS
controlled-host evidence exists for Apple silicon only, and no hosted macOS
runner can reboot or reach the private-LAN peer, so the Intel legs were
structurally unreachable rather than merely unattempted.

Nothing else in this plan changes. The disposable administrator-controlled Mac,
the separate LAN host, the real Linux peer, the real-traffic proof,
**no mock-only routed claim**, and the stop conditions remain exactly as
written. C003 remains unimplemented and unqualified on its own implementation
and qualification, the published scope still means a qualified and
demonstrated configuration, and the macOS support floor stays macOS 13.0.

## Implementation and qualification (2026-10-22)

The plan is implemented and qualified, and its closure record is
`plans/closure/macos-native-server-corrective/c003-status.md`. This section
records what the implementation became; it does not replace the requirements
above, and the closure record carries the requirement-to-evidence matrix.

- **Typed mode contract.** `host_only`, `routed_lan`, and `gateway` are three
  variants of one typed contract, persisted in the desired state with a
  schema-8 migration. `routed_lan` carries the approved destination prefixes
  and the observed egress interface; `gateway` is refused on Darwin (C004's
  subject) and `routed_lan` is refused on Linux.
- **Forwarding prerequisites.** The product reads both forwarding sysctls and
  writes neither. A missing family is a refusal, not a fallback.
- **Return-path proof.** The approved destinations need a specific route
  through the declared egress interface — never the default route — and the
  tunnel pool needs an observed route scoped to the managed device.
- **Operator-managed filter.** The product observes a bounded read-only view
  of the operator's PF anchor, renders the rules the operator has to install
  (both directions, both address families, no `to any`, no NAT), reports them
  on the doctor check as structured data, and refuses on absence or drift.
- **Qualification.** A disposable macOS guest ran the product's own managed
  deployment as the server, a real WireGuard peer in a Linux namespace on a
  second guest was the peer, and the LAN host lived in its own namespace
  behind the upstream router. Real IPv4 and IPv6 traffic traversed the tunnel
  to an approved prefix and back; a destination outside the approved prefix
  and a spoofed source were refused; every missing prerequisite produced its
  own named refusal.
- **Defects.** The qualification exposed twelve defects, all corrected, each
  covered by a test that fails without the fix. Two of them — the routed-LAN
  filter carrying only its forward leg, and the traffic probes' assertions
  being satisfied by `100% packet loss` — would have let a leg that carried
  no traffic at all report a pass.
- **Findings that remain.** The management service does not terminate within
  the qualification's bound after `SIGTERM`, and a killed WireGuard helper is
  not recovered automatically. Both are classified, with evidence, in the
  closure record, and both belong to C001/C002's service-lifecycle matrix
  rather than to this contract.

## Amendment (2026-10-22): the two findings are corrected under C011

The two findings above are corrected under **C011**
(`plans/implementation/macos-native-server/c011-service-lifecycle-and-helper-recovery.md`),
with the recovery decision recorded in **ADR-010**
(`plans/adr/010-privileged-helper-supervision.md`). Re-reading them against
the code and against a fresh reproduction changed what they are:

- The `SIGTERM` finding was a **misreading**. The service does act on the term
  and exits in under a second; what the run observed afterwards was launchd's
  `KeepAlive` successor, not a hung process. The run's own evidence shows three
  different process identifiers after three successive stops. The code-level
  claim underneath the finding was true, though — the stop request could be
  refused by a saturated queue, and the join that followed was unbounded — and
  both are fixed.
- The helper finding was **worse than recorded**: the recovery path was broken
  as well as absent, because a receipt naming a dead helper refused every
  attempt to recreate the tunnel. It is fixed by re-proving the receipt before
  it can refuse, and by the privileged authority replacing the helper it lost.

This amendment does not reopen this plan's scope and does not change what this
milestone proved. The closure record stays a period-accurate historical
record; the findings are corrected there, by C011's closure record.

The Darwin Internet-exit gateway mode remains refused, the supported Darwin
target remains Apple silicon alone under ADR-009, and installation and
transactional self-update remain unimplemented.
