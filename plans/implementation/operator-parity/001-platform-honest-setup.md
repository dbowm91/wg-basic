# Operator parity M001 — Platform-honest setup

Status: **closed** (2026-11-10). Closure: `plans/closure/operator-parity/001-status.md`.

Repository baseline: `a9b0c06af205b20923f7db350a65379cb176e56e`

Source roadmap: `plans/subsystems/operator-parity-roadmap.md`

Canonical requirements and ADRs:

- `plans/000-long-term-specification.md` §§2 and §4.7 (easy defaults, the product does not flush unrelated host state)
- `plans/adr/004-product-management-enrollment-and-api-semantics.md`
- `plans/adr/007-ipv6-forwarding-ownership.md`
- `plans/adr/008-macos-headless-platform-backends.md` (PF is an admin opt-in; no foreign PF edit)
- `plans/adr/009-apple-silicon-only-darwin-target.md`

Primary work class: capability

Hard dependencies: Phase 8 product API closed; Darwin gateway and routed-LAN observations closed (C003, C004, C007). C015 is not a dependency.

## Objective

Make the first server save on each target system ask for a network mode that host can actually enforce, and show the operator the prerequisites the product already knows how to name.

On Linux the pre-filled form stays an IPv4 NAT gateway. On Apple silicon the pre-filled form is host-only: forwarding off, masquerade off, so `resolve_policy_mode` derives `HostOnly` and the Darwin service has nothing to refuse. An operator who then opts into a gateway or a routed LAN sees the existing verdict and the exact lines they have to install. The product still does not install those lines.

## Explicit non-goals

- No write to a Darwin forwarding sysctl, to `/etc/pf.conf`, to a foreign anchor, or to PF's enable flag.
- No new UDS opcode and no new `nft` or `pfctl` argument.
- No change to Linux nftables generation, to the routed-LAN refusal on Linux, or to C004's anchor apply.
- No C015 teardown work.
- No claim that a Mac gateway carries traffic beyond the evidence C004 already recorded.
- No macOS release, and no Intel target.
- No client expiry, preshared-key control, or MTU. Those are M002–M004.
- No automatic detection of the egress interface. A guessed `en0` is the same class of bug as the current `eth0`.

## Current repository evidence

The setup form in `src/http/assets/index.html` checks IPv4 forwarding and masquerade and fills egress with `eth0`. `submitSetup` in `src/http/assets/app.js` omits `mode` unless the operator selected routed LAN. `resolve_policy_mode` derives `Gateway` when either forwarding or masquerade is set.

That derivation is the Linux product. The Darwin `FirewallService::plan` returns `gateway: Some(verdict)` or `routed_lan: Some(verdict)` and does not write while planning. `operator_attachment` renders the three parent lines, and the doctor text in `src/main.rs` already tells the operator which section of `/etc/pf.conf` each line belongs in. The HTTP API does not return any of that. `GET /api/v1/health` is available after login and before setup.

A missing or unread forwarding switch is already distinct from "forwarding is off" in the Darwin service. The projection must keep that distinction.

## Invariants

- Desired state remains the only authority. This milestone adds a read model.
- The historical setup JSON — IPv4 forwarding required, masquerade true, `mode` omitted — still persists a gateway on every platform. The UI default changes on Darwin. The API default does not.
- Host-only still rejects forwarding, masquerade, and destination prefixes. Gateway still rejects destination prefixes. Routed LAN still rejects masquerade and is still Linux-unsupported.
- Planning a policy does not apply it.
- Unrelated host firewall, route, and sysctl state is not modified by the new route.

## Expected production changes

1. An authenticated `GET /api/v1/network-prerequisites` (exact path, session required, no CSRF because it is safe). It returns:
   - `host_platform`: `linux` or `macos`, from the binary's target, not from a client hint;
   - `forwarding`: per family, one of `enabled`, `disabled`, or `not_observed`;
   - `attachment`: on macOS, the three `operator_attachment` lines and the anchor file path for this installation, plus the section each line belongs in (translation, filtering, load);
   - `attachment` absent on Linux;
   - when a server is already configured, the current `GatewayVerdict` or `RoutedLanVerdict` and, for routed LAN, the existing `required_filter_rules`.
2. The setup page, after login, reads that route before showing the form.
   - Linux: keep today's checked forwarding, checked masquerade, egress value `eth0`, and the help text that Linux forwarding is global and is not turned off later.
   - macOS: forwarding unchecked, masquerade unchecked, egress empty with placeholder `en0`, interface name still the logical `wg0`, and a note that the kernel device is a `utun`. Mode stays "automatic", which now derives host-only.
   - Unknown platform: check nothing, fill no egress, and show a banner. Do not fall through to the Linux checks.
3. Choosing gateway or routed LAN on macOS reveals the attachment lines or the required filter rules from this route, including the section order. The page says the product will not write them. Choosing them on Linux does not show PF lines. Routed LAN on Linux stays a setup error from the existing API refusal.
4. A saved gateway or routed LAN that is not yet enforceable still returns the existing `202` with the pending/degraded wording. The prerequisite block stays visible. Do not describe that save as a working internet VPN.

## Ordered work packages

1. Add the read-only projection in the management worker, built from the installation id, `operator_attachment`, and one firewall `plan` call. Do not call `apply`.
2. Publish it on the authenticated GET route with the same Host and response-header policy as the other product reads. Bound the JSON. Cap rule lists at the existing routed-LAN maximum.
3. Teach the setup script the platform defaults and the disclosure. Keep artifact and client flows untouched.
4. Add the regression coverage in the tests below.
5. Update current-behavior docs only after the code lands: `architecture/product-management.md` and the operator setup section of `docs/client-enrollment.md` or `docs/operations-runbook.md`, wherever server setup is actually described. Planned wording does not go into those files first.

## Privilege and security effects

The route is a session read. It reveals that the host is Linux or macOS, whether forwarding is on, and the installation's anchor name. That name is already derived from the installation id and is not a credential. It must not include pfctl transcripts, nft source, sysctl paths, or peer keys.

No privilege boundary moves. `netd` is contacted only if the worker already contacts it for a firewall plan. A refused or absent backend yields `not_observed` and an empty verdict, not a fabricated ready state.

## Persistence, protocol, and configuration compatibility

No schema migration. No DesiredGeneration change. Existing setup clients that send the historical body keep their meaning. The new route is additive. Older pages simply never call it; the static assets ship inside the binary, so the matching page arrives with the route.

## Failure, cancellation, restart, and contention

- `netd` down: `200` with `forwarding: not_observed` and no verdict. Setup of a host-only server still proceeds.
- `netd` returns a conflict or unsupported policy: the route returns that as a named prerequisite, not as a 500 with a backend string.
- Operator saves gateway while the parent is missing: the existing apply refusal stands. The page keeps the three lines.
- Two browsers: the route is stateless. Setup itself keeps `expected_generation` and `409`.
- Restart: nothing in this milestone is armed in the background.

## Focused tests

- Host-free: historical setup body resolves to gateway; macOS-shaped unchecked body resolves to host-only; an explicit gateway with masquerade is accepted by `resolve_policy_mode` and still does not imply a sysctl write.
- HTTP: the new route requires a session; its JSON on a Linux test build has `host_platform: linux` and no attachment lines; a fixture Darwin plan projection maps `ForwardingDisabled`, `AttachmentMissing`, and `Ready` without calling apply.
- UI contract test, at the script or fixture level the repo already uses for the shell: the macOS branch does not submit `ipv4_forwarding_required: true` or `masquerade: true` for an untouched form.
- A test that a Linux untouched-form body still contains those two flags. This is the regression that protects the closed gateway.

## Linux and network-namespace integration evidence

No new topology. Run the existing rootful firewall suite that already proves masquerade (`network_control_e2e` or the suite `docs/development.md` names for the nftables gateway) and confirm it was not retargeted. The historical body is the one that suite's product setup uses; if a test posts the form defaults, keep the Linux defaults in that test.

Darwin packet evidence is not required. M001 does not change the apply path C004 measured.

## Broad verification commands

The ordinary gate order in `docs/development.md` for a Rust change, including the Linux cross-clippy when the edit touches `cfg(target_os)` code. Do not start a rootful suite beyond the one regression suite above unless that gate list already includes it. Do not run a controlled-host macOS qualification for this milestone.

## Documentation updates

After the code lands, document the two defaults and the fact that a Mac gateway still needs the administrator's parent lines. State the section order. Do not document Darwin forwarding as something the product turns on.

## Acceptance criteria

1. An untouched setup on Linux still requests an IPv4 NAT gateway, and that request still maps to the closed nftables behavior.
2. An untouched setup on macOS requests host-only and can converge without a PF write.
3. Opting into gateway or routed LAN on macOS shows the existing verdict and the exact operator lines, and the process writes neither forwarding nor `/etc/pf.conf`.
4. A missing backend is `not_observed`, never a silent ready.
5. No new privileged opcode, and `tests/architecture_guards.rs` still passes.

## Stop conditions

Stop and return to planning if the only way to satisfy a test is to set a sysctl, edit `/etc/pf.conf`, enable PF, add a UDS opcode, or accept caller-supplied rule text. That work is an ADR, not this milestone.

Stop if the Linux historical body stops deriving a gateway.

## Closure evidence requirements

A closure record under `plans/closure/operator-parity/001-status.md` after implementation. It needs the commands actually run, the historical-body regression result, the projection tests, confirmation that no Darwin write path was added, and the doc updates. Do not write that record in advance.
