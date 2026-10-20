# macOS Native Server C004 — Effective, Administrator-Opt-In PF/NAT Gateway

Status: **blocked** (hard C003; operationally requires an administrator-integrated, disposable host capable of effective PF attachments and real Internet/LAN egress).
Baseline: `plans/macos-native-support@fc51146e811cabebd042d852449c6e7f4f854265`.
Source: corrective roadmap C004, M005 plan and `plans/closure/macos-native-server/005-status.md`; ADR-008/ADR-007.
Primary class: corrective / invariant / capability.

## Objective and defect

Convert the isolated PF rule renderer/anchor fixture into a verified optional IPv4 Internet-egress gateway, while retaining Apple TN3165's **advanced-administrator-only** deployment decision. Earlier macOS CI showed anchors could be loaded *without* attachment and did not prove forwarding/NAT traffic. `src/firewall/pf.rs::attachment_verified` currently uses substring matching and logical OR across filter and NAT parents, insufficient to prove effective placement or policy.

## Non-goals

No general consumer macOS gateway claim, replacing `/etc/pf.conf`, global `pfctl -f` of the root ruleset, enabling/disabling PF globally on the user's behalf, hidden policy edits, NAT66, arbitrary PF source/scripts through UDS, macOS bypass of the Linux nft contract, or unconditional host-only-to-gateway upgrade.

## Ordered work

1. **Distribution gate:** restate Apple TN3165 in operator docs and installation prompts. Admin must explicitly configure and authorize the parent anchor calls outside wg-basic. Never claim compatibility with every host version/Internet Sharing/third-party firewall; refuse unsupported host PF topology.
2. **Effective attachments:** replace `attachment_verified` with semantic observations of independently required filter and IPv4 NAT attachment and ordering; mere anchor presence, substring/name collision, NAT-only or filter-only parent references are not proof. Verify parent rules actually invoke the managed child anchor, that current rules load without alternate precedence dropping traffic, and that the expected egress interface and route match observed network state.
3. **Safe control:** implement bounded typed PF observation/apply/remove for *only* installation-scoped anchors. Canonical rule AST/internal deterministic renderer, strict size/time/output bounds, exact content/digest drift comparison and control over accepted paths. Never execute shell or accept caller-provided PF text/path/sysctl; host state is re-observed before and after application. Rejection preserves foreign rules and skips helper teardown until firewall cleanup is safe. Explicitly handle collision, stale receipts, drift, user-changed parent, PF disabled, and simultaneous managers.
4. **IPv4 NAT / IPv6 routed:** require specific allowed VPN sources/destinations and known egress. Prove IPv4 egress with translated source and successful return; route IPv6 using explicit upstream return policy and prove **no NAT66**. Keep global forwarding admin-owned/sticky and make failure visible, not "converged".
5. **Dynamic recovery:** revalidate upstream interface/address, PF attachments, link transitions, netd restart, helper renumbering, sleep/wake, double instance, disable/re-enable and uninstall. No foreign anchors, root PF configuration, default route or shared forwarding toggles are destroyed/restored incorrectly.

## Native evidence and regressions

On a consented administrator-managed test Mac whose PF parent has been explicitly attached by the operator, use an off-host WireGuard Linux client plus observable LAN/Internet egress endpoints. Capture PF parser/inventory, effective packets and NAT translations (not just rule strings), IPv6 return traffic, drop/denial negative controls, per-anchor drift, before/after rule snapshots and startup/shutdown/reboot behavior. Include independent filter-only and NAT-only false-convergence regressions and parent anchor substring spoofing. Reboot and foreign firewall manager interference tests must fail safely.

Normal Rust/MSRV/architecture guards, Darwin native CI and all Linux nft/rootful and distribution suites remain mandatory. Stop immediately if policy attachment requires unbounded root-ruleset takeover, cannot preserve third-party PF state, conflicts with Apple-supported deployment policy, or makes NAT66 unavoidable. Hold the M007 MUST-NOT-release gate pending C005. Closure: `plans/closure/macos-native-server-corrective/c004-status.md` only after real effective packet evidence.
