# macOS Native Server C003 — Explicit Routed-LAN Mode Without NAT

Status: **blocked, hard dependency C001**. Interface exploration can proceed; no networking claim before native controlled-host proof.
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

Require native arm64 and Intel for the targeted published scope, routine/MSRV + all Linux rootful suites. Stop if the only workable strategy needs uncontrolled PF main-ruleset edits, unbounded sysctl write, broad default-route takeover, unqualified policy filtering, or foreign resource deletion. Document operator prerequisites and known unsupported topologies. Close only in `plans/closure/macos-native-server-corrective/c003-status.md` with real traffic and preservation evidence.
