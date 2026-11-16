# ADR-014 — Maintainer authorization for Apple silicon macOS server release

Status: accepted (maintainer decision, 2026-11-16)

Date: 2026-11-16

Supersedes: the binding **MUST-NOT-release** verdict in
`plans/closure/macos-native-server/007-status.md` for Apple silicon only.
Does not rewrite that historical record; this ADR is the release-authority
amendment C005 and M007 required. Amended by ADR-009's Apple-silicon-only
target set. Does not amend ADR-006's Linux Phase 10 claims or the R004b
checksums-only waiver.

## 1. Context and decision scope

M007 recorded **MUST-NOT-release** for the headless macOS server (2026-10-14),
later narrowed to Apple silicon by ADR-009 (2026-10-21) without lifting the
ban. The corrective line then closed production integration on Apple silicon:

| Capability | Closure | Evidence class |
|---|---|---|
| Host-only product path + off-host Linux peer | C001 closed 2026-10-21 | controlled-host arm64 |
| launchd least-privilege install + cold reboot | C002 / C006 closed 2026-10-21 | controlled-host arm64 |
| Routed LAN (operator-managed PF) | C003 closed 2026-10-22 | controlled-host arm64 |
| Gateway PF/NAT (installation-scoped anchor) | C004 closed 2026-10-23 | controlled-host arm64; TN3165 |
| Declared helper provenance | C008 closed 2026-10-21 | repository + qualification |
| Apple-silicon-only refuse | C010 closed 2026-10-21 | installer + CI |
| Eggpack `aarch64-apple-darwin` target | landed 2026-11-16 | producer contract + `macos-15` runner |

Remaining operational gates named by C005 before operator documentation may
claim a published macOS release:

1. **C015** — managed-interface teardown on `network disable` (code landed;
   controlled-host disable evidence still required for closure).
2. **C005 packaging/docs** — Darwin binary (+ companion helper install path),
   exact support matrix in operator docs, checksums-only honesty, no Darwin
   self-update fiction.

This ADR is the **maintainer re-authorization** that amends M007. It does not
by itself publish a tag, ship assets, or rewrite Linux release policy.

## 2. Options and evidence

- **Keep MUST-NOT-release indefinitely.** Rejected: corrective closures already
  prove host-only, routed, gateway, install, and reboot on Apple silicon; the
  remaining work is teardown evidence, packaging honesty, and docs.
- **Authorize a consumer “macOS supported” claim including unsigned self-update
  and notarization.** Rejected: contradicts R004b checksums-only, TN3165, and
  C005's no-signing-fiction rule.
- **Authorize Apple silicon headless server publication under an exact matrix,
  checksums-only, advanced-admin gateway, no self-update.** Chosen.

## 3. Decision

1. **M007 MUST-NOT-release is amended for Apple silicon.** The maintainer
   authorizes publication of headless macOS server artifacts for
   `aarch64-apple-darwin` only, under the support matrix in §4, once the
   publication gates in §5 are closed. Intel remains refused (ADR-009).
2. **Checksums-only stands** (R004b). No Minisign trust root, no notarization
   claim, and no Darwin `update check` / `update run` path until a separate
   trust-policy ADR is accepted. Update commands remain fail-closed.
3. **Gateway mode is advanced-administrator-only** (Apple TN3165). The product
   owns one installation-scoped PF anchor; parent `anchor` / `nat-anchor` /
   `load anchor` lines and host forwarding remain the administrator's. Never
   market as a general consumer VPN gateway.
4. **Routed LAN** remains operator-managed PF + forwarding + upstream return
   routes; the product refuses when prerequisites are missing.
5. **Host-only** requires no PF mutation and no forwarding writes.
6. **Linux is unchanged.** Linux remains the canonical appliance; this ADR
   adds a second published platform, it does not demote Linux.
7. Historical M007 and corrective closures stay period-accurate. New closure
   evidence is recorded under `plans/closure/macos-native-server-corrective/`.

## 4. Authorized support matrix

| Mode | Arch | Floor | Claim | Operator prerequisites |
|---|---|---|---|---|
| Host-only | `aarch64-apple-darwin` | macOS 13.0+ aspirational; qualified on macOS 15.x hosted and macOS 26.6.2 controlled-host arm64 | Authorized | None beyond install + pinned helper |
| Routed LAN | same | same | Authorized | Admin enables forwarding; installs matching PF filter; upstream return routes |
| Gateway (IPv4 NAT, IPv6 routed no NAT66) | same | same | Authorized as **advanced-administrator-only** | Admin attaches parent PF lines; product owns scoped anchor only |
| Darwin self-update | — | — | **Not authorized** | Fresh install per release |
| Intel Mac | — | — | **Refused** | — |

Client configs exported for standard WireGuard clients (including macOS
clients of a Linux or Darwin server) remain ordinary WireGuard interop and
are not this ADR's subject.

## 5. Publication gates (still required)

Before README / installation / runbook may say a macOS release **is
supported** (rather than authorized-pending):

1. Close **C015** with controlled-host evidence that `network disable` removes
   the managed `utun` and reports enforced convergence.
2. Close **C005** with: Eggpack Darwin binary in the release workflow (already
   contracted), documented companion helper build/install (`--helper` +
   provenance), exact matrix above in operator docs, release-mode smoke, and
   an explicit C005 closure verdict that cites this ADR.
3. Produce the first Darwin assets only through the existing checksums-only
   Eggpack draft/staging path; no signing ceremony.

Until those gates close, operator docs MUST state that Apple silicon is
**maintainer-authorized under ADR-014** and **not yet a published supported
release**.

## 6. Normative consequences

- `plans/registry.md` records this amendment and the remaining C015/C005 gates.
- ADR-008's status line points here for release authority; its PF research
  body stays historical. TN3165 consumer prohibition is reaffirmed.
- M007's historical MUST-NOT-release text remains; a dated amendment section
  points here.
- Unsupported OS/arch/mode continues to refuse at install time.
- No Windows claim is implied.

## 7. Source references

- `plans/closure/macos-native-server/007-status.md`
- `plans/closure/macos-native-server-corrective/c001-status.md` through
  `c004-status.md`, `c008-status.md`, `c010-status.md`
- `plans/implementation/macos-native-server/c005-release-qualification-and-reconciliation.md`
- `plans/implementation/macos-native-server/c015-macos-interface-teardown-acceptance.md`
- ADR-008, ADR-009, ADR-006, R004b waiver
