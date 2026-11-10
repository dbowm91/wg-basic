# Windows Native Server M005 — Forwarding and an Owned WinNAT Gateway

Status: **implemented; closure blocked** on `windows-2025` evidence
Primary class: invariant / capability
Source: `plans/subsystems/windows-native-server-roadmap.md` M005
Baseline: `554de7a3b5ae83700222a290664fbbbeb3cd521a`. Rebase onto the closed M004 head.
Canonical: `plans/adr/011-windows-server-wireguard-nt.md` decisions 6, 7, and 8; `plans/003-planning-process.md` §11 and §12.
Dependencies: M004 **hard**. The M001 `Get-NetNat` inventory is an input, not a substitute for this milestone's own before-snapshot.

## 1. Objective

Make gateway mode on Windows Server 2025 do three owned things: enable IPv4 forwarding under the global-toggle rule, create one WinNAT whose internal prefix is this installation's tunnel prefix, and install installation-scoped user-mode firewall filters that permit the forwarded tunnel. Prove it with translated IPv4 traffic on `windows-2025`. Refuse when a NetNAT this installation does not own is already present.

## 2. Non-goals

No IPv6 NAT. No second kernel callout driver. No deletion of a foreign NAT, including a WSL or Docker NAT, even when that deletion would make the test pass. No ICS. No `netsh` script from the protocol. No claim of a remote client on the public internet. No reboot test. Routed-LAN mode is not a qualified Windows claim; this runner has no second network to prove it. Host-only mode remains the mode that applies M003 and M004 and does not touch forwarding or NAT.

## 3. Repository evidence

Linux gateway mode writes the owned nftables table and IPv4 forwarding. macOS gateway mode writes one PF anchor after the administrator attaches it. Windows has the mode enum in desired state from the macOS work. ADR-011 requires the Windows default of an untouched setup to request gateway mode, matching Linux, and to refuse rather than silently downgrade when the host cannot own the NAT. M001's inventory is the first measurement of whether `windows-2025` already has a NetNAT. This plan does not assume the answer.

Microsoft documents a single WinNAT internal prefix per host. A second `New-NetNat` leaves the system in an unknown state.

## 4. Invariants

- The product creates a NetNAT only when `Get-NetNat` is empty, or when the single existing object is the one this installation recorded. Any other observation is a named refusal and a no-op.
- The internal prefix equals the tunnel prefix in desired state. The caller does not supply a NAT name or a prefix through the protocol; both are derived.
- `IPEnableRouter` and per-interface forwarding are observed first. The previous value is stored with the installation's runtime evidence. Teardown restores the previous value only when this installation changed it and the live value is still the value this installation set. An already-enabled host stays enabled.
- Firewall filters carry an installation-scoped name and are removed by that name. The host firewall policy is not reset.
- The egress interface is the one that owns the IPv4 default route, and it must not be the tunnel adapter. Zero or several such interfaces is a refusal.
- IPv6 forwarding is unchanged by gateway apply.

## 5. Expected production changes

Windows firewall apply for gateway mode performs the observation, the forwarding change, the single NetNAT, and the scoped filters, then verifies by reading them back. The existing firewall plan and receipt types gain a Windows observation that reports `enabled`, `disabled`, or `not_observed` without pretending an nftables table exists. Untouched Windows setup requests gateway mode. A refusal names the blocking object and the remediation, which is operator action, not an automatic delete.

Teardown of gateway mode removes the owned NetNAT, the owned filters, and the forwarding change under the rule in §4. It does not remove the adapter; M004's disable path does that.

## 6. Ordered work packages

1. On a fresh `windows-2025` job, record `Get-NetNat`, interface forwarding, and the default route before any product mutation. If a NetNAT exists, the positive gateway test is a stop for this milestone and the refusal test is the one that must pass. Do not clear the foreign object.
2. Implement the observation and the refusal. The refusal test plants a decoy NetNAT with a prefix that is not the tunnel prefix, runs apply, and shows the decoy still present and no second NAT created. Remove the decoy in the test's own cleanup, not in the product.
3. Implement owned create and owned delete against an empty `Get-NetNat`, plus the forwarding ownership rule and the scoped filters.
4. Translated-traffic test, only when step 1 found no foreign NAT. Two local adapters from M003: the server adapter at the tunnel gateway address, the client adapter as the enrolled peer with the server's exported config and an allowed route that covers an external echo. After handshake, the client sends to the echo. The echo observes the runner's public IPv4, not the tunnel address. Capture the echo result and `Get-NetNat` in the artifact.
5. Teardown and a second observation: owned NAT gone, decoys from other tests gone only if the test planted them, forwarding back to the recorded previous value when this installation changed it, foreign routes from M004 still present.

## 7. Privilege, secrets, and host ownership

All of this runs in `netd`. The protocol operation stays the existing firewall apply. A filter body or a NAT prefix in the request is rejected as unknown input. The before/after `Get-NetNat` transcript is the ownership evidence.

## 8. Persistence, protocol, compatibility, failure

No schema change is expected. The mode field already exists. If a Windows-only observation cannot fit the existing receipt without a protocol version bump, stop and extend the version explicitly rather than overloading a Linux field. A crash after the NAT is created and before the receipt is stored is repaired by the next apply: the NAT's recorded prefix and name match this installation, so it is adopted, not duplicated. A crash after a partial filter install is a non-converged receipt and a retry. A foreign NAT observed after adoption is a refusal that leaves both objects alone.

## 9. Tests and integration evidence

The refusal test and, when the runner allows it, the translated-echo test are the milestone's kernel evidence. Both run on `windows-2025`. Linux nftables gateway tests stay green and are not Windows evidence. IPv6 transit is reported `not_observed` on this runner unless a real IPv6 path is actually present; absence does not fail the IPv4 gate and does not count as IPv6 support.

## 10. Verification

`windows-2025` job. Linux gate order, including the rootful firewall suites. macOS workflow unchanged.

## 11. Documentation

At closure, `architecture/firewall.md` describes the one-NetNAT rule, the forwarding restore rule, and the refusal. It does not call the runner result a general Windows gateway guarantee beyond Server 2025 x64.

## 12. Acceptance criteria

- Foreign NetNAT causes a named refusal and is still there afterward.
- When the runner starts with no NetNAT, the echo sees the runner's public IPv4 as the source of the tunneled client packet.
- Teardown removes only the owned NAT and owned filters.
- Forwarding is not left enabled if this installation turned it on, and is not turned off if it was already on.
- Host-only apply changes neither forwarding nor `Get-NetNat`.

## 13. Stop conditions

Stop if a pass requires `Remove-NetNat` of an object the product did not create, if the echo sees the tunnel address, if a second kernel driver would be required, or if the only available NAT mechanism is Internet Connection Sharing. Revise ADR-011 rather than shipping a downgraded mode under the gateway name.

## 14. Closure

`plans/closure/windows-native-server/005-status.md` with the before/after `Get-NetNat` transcripts, the echo observation, and the forwarding before/after values. If step 1 found a foreign NAT and the positive test could not run, the disposition is `blocked`, not `closed`.
