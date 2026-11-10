# Windows Native Server M007 — Product-Path Qualification and the Support Claim

Status: **implemented; closure blocked** on `windows-2025` evidence. The support sentence stays unpublished until that job shows translated traffic.
Primary class: qualification
Source: `plans/subsystems/windows-native-server-roadmap.md` M007
Baseline: `554de7a3b5ae83700222a290664fbbbeb3cd521a`. Rebase onto the closed M006 head.
Canonical: `plans/adr/011-windows-server-wireguard-nt.md` §4; `plans/000-long-term-specification.md` §6.3; `plans/003-planning-process.md` §11.
Dependencies: M006 **hard**. Publishing a release artifact is an operational dependency on the maintainer and is not granted by closing this milestone.

## 1. Objective

Run the operator path on `windows-2025` through the installed services: sign in, create the gateway, enroll a client, export the config, apply that config to a second local adapter, and observe translated IPv4. Write the support sentence so it names Windows Server 2025 x64 and the limits this CI cannot cross. Leave the Phase 10 Linux release pipeline unchanged.

## 2. Non-goals

No claim of Windows 11, Server 2022, arm64, reboot survival, a client reaching the server from the public internet, IPv6 egress, or coexistence with WireGuard for Windows, WSL, or Docker. No Authenticode. No Windows target added to the eggpack release workflow. A two-runner UDP hole punch may be attached as an optional spike transcript; a spike failure does not fail the milestone and a spike success does not widen the claim.

## 3. Repository evidence

M003 proved a handshake outside the product API. M005 proved translation outside the installed services. M006 proved the services start. The product API, enrollment, and export already exist and are what this milestone must drive. Operator-parity M001 made untouched Linux setup a gateway and untouched macOS setup host-only. ADR-011 makes untouched Windows setup a gateway request that refuses when a foreign NetNAT is present.

## 4. Invariants

- The support sentence is one SKU and one qualification host. Broader wording is a failed milestone even if the tests passed.
- The test uses the exported config as the second adapter's configuration. A hand-built peer that skips export does not satisfy the product path.
- Linux and macOS docs do not start describing Windows behavior as if it were theirs.
- The Windows distribution states that `wireguard.dll` is covered by the prebuilt-binary license and that the rest of the binary is MIT.
- No new privileged opcode appears in this milestone.

## 5. Expected production changes

Production changes are limited to defects this qualification exposes in M001–M006, each fixed inside its owning contract, plus the documentation of the support sentence. A defect that needs a new ownership rule returns to ADR-011 instead of being patched around inside the test.

The sentence, once the evidence exists:

> wg-basic runs as a headless WireGuard server with an IPv4 NAT gateway on Windows Server 2025 x64. That behavior is qualified on the GitHub-hosted `windows-2025` runner. Reboot survival, inbound reachability from the public internet, IPv6 egress, and every other Windows edition are not part of this claim.

## 6. Ordered work packages

1. Install via M006 on a fresh `windows-2025` job. Record `Get-NetNat` first. If a foreign NAT is present, the job's expected result is the product's refusal, and this milestone stays blocked under M005's rule rather than being declared closed on a refusal alone.
2. Through the HTTP API: create the administrator, sign in, submit gateway setup, enroll one client, download the config.
3. Apply that config to a second `wireguard-nt` adapter in the job. Handshake. Send to the external echo. Record the observed source address.
4. Uninstall. Record services, pipe, NAT, and the state directory (state kept). Confirm a planted foreign file remains.
5. Update README, the operations runbook, and `architecture/overview.md` to the sentence in §5, with pointers to the firewall and privilege docs updated in earlier closures. State the DLL license next to the install section.
6. Run the Linux gate order and the macOS workflow at the same head. Attach optional hole-punch output if it was attempted, labeled as a spike.

## 7. Privilege, secrets, and host ownership

The API token and the client private key follow the existing redaction rules. The second adapter is test harness, not a second product service, and it is closed before uninstall. The harness must not weaken the pipe ACL to reach `netd`.

## 8. Persistence, protocol, compatibility, failure

The enrolled client and the database survive uninstall, matching the Linux state-preserving uninstall. A failed echo is a failed milestone, not a documentation waiver. A Linux database restored onto the Windows install still reconciles; include one such open-and-reconcile if M006 has not already recorded it.

## 9. Tests and integration evidence

This milestone's evidence is the `windows-2025` product-path job, the echo transcript, the uninstall transcript, and green Linux and macOS CI. Unit tests added here cover only the support-sentence and license text being present in the docs, so a later edit cannot generalize "Windows Server 2025 x64" into "Windows".

## 10. Verification

The product-path job, `docs/development.md` Linux gates, and the macOS qualification workflow. Record the runner image version beside the support sentence's qualification note in the closure record, not as a floating "latest".

## 11. Documentation

README summary, `docs/operations-runbook.md`, `architecture/overview.md`, `architecture/firewall.md`, `architecture/privilege-boundary.md`, and `architecture/wireguard-control.md` agree with §5. `plans/000` is not edited to say the platform has shipped; it already authorizes the line. Closure updates the registry status.

## 12. Acceptance criteria

- API-enrolled client, exported config, handshake, translated public source.
- Uninstall preserves state and foreign files and removes the owned NAT.
- Docs use the bounded sentence.
- Phase 10 workflows have no Windows target.
- Linux and macOS CI are green.

## 13. Stop conditions

Stop if the test configures the second peer without the exported config, if the docs claim a SKU the job did not run, if a foreign NAT was removed to obtain the echo, or if the Linux release workflow was edited to upload a Windows binary. Publishing remains a separate maintainer decision after closure.

## 14. Closure

`plans/closure/windows-native-server/007-status.md` with the API transcript, the echo result, the doc diff, and the explicit list of unmeasured items from §2. Disposition `closed` only when the echo evidence and the bounded sentence are both present. Otherwise `blocked`.
