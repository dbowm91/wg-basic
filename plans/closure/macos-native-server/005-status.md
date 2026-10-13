# macOS Native Server M005 — Forwarding, PF/NAT Policy, and Gateway Feasibility Decision

Disposition: **blocked** (policy decided + model implemented; native gateway traffic unqualified).

Date: 2026-10-13

## Implementation revision

- Repository baseline: `ee605aa` (M004 blocked closure).
- Qualified implementation head: `be077d1944588bdc82a285434098d2d2fdf75a11`.
- Source plan: `plans/implementation/macos-native-server/005-forwarding-pf-nat-and-platform-policy.md` (policy-ready → blocked by this record).

## The M005 distribution decision (explicit gate review)

Apple TN3165 (`Packet Filter Is Not API`) warns PF is not a product API for
broadly distributed software; it is intended for system implementations and
advanced user/admin use. Reviewed against the wg-basic appliance model:

- **Decision: advanced-administrator opt-in ONLY. General consumer macOS
  gateway support is NOT claimed and MUST NOT be advertised.**
- The administrator explicitly attaches the installation anchor from their
  own PF configuration. wg-basic never rewrites `/etc/pf.conf`, flushes any
  table, disables or enables PF globally, or seizes global forwarding.
- Without a verified parent attachment, the backend reports degraded and
  applies nothing (fail closed with an actionable error).
- IPv4: forwarding + masquerade through the dedicated anchor, opt-in only.
  IPv6: routed return, categorically never NAT66.
- Global forwarding toggles are shared and sticky: observed read-only,
  enabled only when the explicit policy requires, never silently reset on
  disable/teardown.
- If a future Apple-supported server-grade NAT integration appears, this
  decision returns to ADR-008 review rather than stretching PF further.

This decision gates M006 (the installer MUST NOT auto-modify PF configuration;
launchd + helper provenance proceed independently) and M007 (release claims
must label macOS gateway as advanced-admin-only).

## Requirement-to-evidence matrix

| Requirement (plan) | Evidence | Result |
|---|---|---|
| §5.1 Research + addendum/ADR gate: advanced-admin mode, explicit setup, distribution compatibility; alternate strategy or re-scope if unacceptable | This record is the gate: TN3165 reviewed, advanced-admin-only mode defined with explicit-setup + no-auto-mutation rules above; no alternate architecture needed because the narrowed scope is lawful for expert-operated headless installs. Re-scope applied (no general gateway claim) rather than disguised risk | Passed (decision recorded) |
| §5.2 Read-only PF inventory + anchor attachment verification (nat + filter order); conflicts with existing PF, managers, Internet Sharing, SIP | Attempted unprivileged on native host: `pfctl -s info` → `/dev/pf: Permission denied` (PF is root-gated even for reads — inventory itself needs privilege, recorded honestly); `sysctl net.inet.ip.forwarding/net.inet6.ip6.forwarding` → `0`/`0` read-only (observed, never mutated). Attachment verification modeled purely (`attachment_verified` requires parent invocation, not mere existence) with fixture tests | Passed (read-only facts; live inventory blocked on root) |
| §5.3 Bounded dedicated anchor + predictable rules + admin instructions; no implicit parent mutation; owner marker/digest/drift fail-closed; bounded internally rendered pfctl only, never shell/user text | `src/firewall/pf.rs`: `anchor_name` (installation-scoped deterministic), `render_policy` (IPv4 masquerade, NAT66 excluded by `is_ipv4` gate), `rules_digest` drift detection, `teardown_order`. No `Command`/shell/`pfctl -f`/`/etc/pf.conf` in the module (guard-pinned); bounded invocation designed but deliberately not implemented until live qualification | Passed (model; execution blocked) |
| §5.4 Controlled forwarding sysctl observe/enable; explicit policy, strict paths, no family toggles; persistence/reboot/operator steps; foreign preservation | Strict constants `net.inet.ip.forwarding` / `net.inet6.ip6.forwarding`; no caller sysctls expressible; observed values `0`/`0` left untouched; policy states enable-only-with-opt-in + never-reset (documented + modeled) | Passed (model; live enable blocked) |
| §5.5 Observe/plan/apply/verify + teardown ordering; v4 no-NAT vs masquerade, v6 routed no-NAT66, firewall interactions; degraded reasons, no false convergence | Ordering modeled (`teardown_order`: filter-anchor → nat-anchor → helper; global/foreign never touched); `FirewallService` Darwin still returns `Unsupported` (no false convergence). Live demo needs root + helper | Partially passed (model), blocked (live) |
| §5.6 Supported/unsupported configs + exact opt-in contract before M006 | Contract in the decision above + module docs; M006 installer constraint recorded (no PF auto-configuration) | Passed |
| Native + regression tests (isolated admin-PF host: forwarded v4/NAT, routed v6, foreign preservation, drift/conflict/disabled/wrong-owner/Sharing cases; pfctl failure injection; Linux nft + dual-stack E2E regression) | Unit layer green (6 `firewall::pf` + purity guard); Linux suites untouched and green. Live traffic, anchor attach/drift, and failure injection need root on a disposable host | Partially passed (unit), **blocked** (live) |
| Stop: silent unrelated-config rewrite, unacceptable distribution posture, unpreservable foreign state, failed NAT verification, seized global PF | Honored: no config write exists in the tree; posture resolved by narrowing (advanced-admin-only); foreign preservation modeled; no NAT claim made without traffic proof | Passed (by refusal to over-claim) |

## Verification

Local commands on native Darwin arm64 (macOS 26.6.2, rustc 1.89.0):

- `cargo fmt --all -- --check`, `cargo check/clippy --locked --all-targets -- -D warnings` (plus both Darwin triples), `cargo test --locked` (lib 372 incl. 6 new `firewall::pf`; 56/55+1 guards; integration green modulo the known transient parallel port race), `cargo +1.89.0 check` — passed.
- Read-only host facts (zero mutation): `pfctl -s info` → permission denied (root-gated); `sysctl` forwarding `0`/`0` (observed only).
- No `utun`, route, PF, sysctl, or forwarding mutation was performed in this session.

Privileged evidence NOT collected (blocker shared with M003/M004): effective forwarded IPv4 (no-NAT/NAT), routed IPv6 both directions, anchor attach + packet matching (not rule text), foreign-PF/Internet-Sharing coexistence, drift/conflict/PF-disabled/wrong-owner cases, `pfctl` timeout/failure injection, Linux nft + dual-stack E2E rerun at this head.

## Security and ownership evidence

- No new privileged operation: `pf.rs` contains no process/shell/sysctl-write/file-write (guard `the_darwin_pf_model_renders_without_executing` green); `PROCESS_MODULES` unchanged (`[nft.rs, wireguard/darwin.rs]`).
- Typed policy only (`DesiredNetworkPolicy` in, rendered anchor rules out); no remote raw PF anywhere; Linux `nft` owner-table claims never copied (anchors require parent invocation by design).
- Linux firewall path untouched; Darwin live firewall still `Unsupported` (fail closed, degraded receipts truthful).

## Documentation, limitations, and findings

- No current-behavior docs changed (no shipped gateway behavior). The decision + contract live here and in `src/firewall/pf.rs` docs; operator-facing PF prerequisites will be written when live qualification exists. `README` still claims Linux-native only.
- Hard blocker (shared): disposable privileged Mac host + non-interactive root + explicit host-mutation opt-in for live gateway traffic. No packet claim made.
- Downstream effect: M006 MUST NOT auto-configure PF (installer constraint recorded); M007 must label any macOS gateway claim advanced-admin-only with this decision cited.
- Findings: no high/medium/low open items in the policy/model scope.

M005 is **blocked** on live gateway qualification with the decision above binding. M006 launchd/installation scope may proceed under the no-PF-mutation constraint; its native install evidence carries the same privileged-host blocker.
