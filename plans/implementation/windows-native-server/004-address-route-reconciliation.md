# Windows Native Server M004 — Address and Route Reconciliation

Status: **implemented; closure blocked** on `windows-2025` evidence
Primary class: capability / invariant
Source: `plans/subsystems/windows-native-server-roadmap.md` M004
Baseline: `554de7a3b5ae83700222a290664fbbbeb3cd521a`. Rebase onto the closed M003 head.
Canonical: `plans/adr/011-windows-server-wireguard-nt.md` decision 5; `plans/003-planning-process.md` §11.
Dependencies: M003 **hard**. The LUID comes from an adapter M003 proved this process owns.

## 1. Objective

Assign and remove the tunnel's own IPv4 and, when configured, IPv6 addresses, and install and remove only the host routes this installation owns, using IP Helper on the adapter LUID. Re-apply is a no-op when the host already matches. A route or address this installation does not own is preserved.

## 2. Non-goals

No forwarding toggle, no WinNAT, no firewall filter, no default-route hijack, and no SCM install. Cryptokey routes stay inside the driver and are not copied into the host route table. IPv6 internet egress is not a gate of this milestone.

## 3. Repository evidence

Linux reconciliation uses RTNETLINK and proves ownership with the owner tag, not with ifindex alone. macOS uses the Darwin route socket and refuses an uncertain utun. The portable planner already separates desired addresses and managed routes from observation. Windows M003 produces a LUID and a GUID and does not program addresses.

## 4. Invariants

- Desired state remains the SQLite generation. The LUID is read back from the live adapter and checked against the M003 receipt before every mutation.
- A stale LUID or a recycled interface index is a refusal.
- The planner's portable actions are the ones applied. Windows does not grow a second planner that accepts raw route commands.
- Foreign adapters and foreign routes are in the before/after snapshot and are unchanged.
- Unsafe IP Helper calls live in `crates/win32-sys`.

## 5. Expected production changes

The Windows reconciliation backend observes addresses and routes on the owned LUID, plans with the existing planner, applies with IP Helper, and verifies by observing again. Owned routes are those the desired state names and that point at this LUID. The gateway route for the tunnel subnet, when desired state contains it, is owned. A default route is not installed by this milestone.

IPv6 addresses present in desired state are applied when the stack accepts them. If the runner has no IPv6 source that can prove traffic, the milestone records the address as configured and does not claim IPv6 transit.

## 6. Ordered work packages

1. Observe addresses and routes for one LUID, including the case where the adapter is absent.
2. Apply and delete owned addresses and routes. Verify by a second observation. A partial failure returns a non-converged receipt listing the action that failed.
3. Idempotent re-apply against an already-correct adapter produces an empty mutation set.
4. Qualification on `windows-2025`: install a decoy route and a decoy address on a second, foreign adapter; run reconcile; show the decoys unchanged; delete the desired tunnel; show the owned address and route gone and the decoys still present.
5. Restart `netd` and reconcile the same generation. The result is a no-op when the host still matches, and a repair when an owned address was removed underneath.

## 7. Privilege, secrets, and host ownership

Mutation stays inside `netd`. `serve` submits the existing reconcile request. No new opcode. The before/after route and address tables are the preservation evidence. An uncertain LUID skips deletion and leaves the host as it was.

## 8. Persistence, protocol, compatibility, failure

No schema change. Existing reconcile request and receipt types are reused. A crash after a partial apply is repaired by the next reconcile of the same generation, which observes and continues. It does not start by deleting every address on every adapter. Contention with another process that owns the default route is a refusal to touch that route.

## 9. Tests and integration evidence

Planner tests stay pure and portable. Live address and route tests, including the decoy preservation, run on `windows-2025`. Linux rootful reconciliation suites run and remain the Linux evidence only.

## 10. Verification

`windows-2025` live tests. Linux gate order. macOS workflow unchanged.

## 11. Documentation

`architecture/reconciliation.md` gains the Windows LUID rule at closure. It states that forwarding and NAT are still absent.

## 12. Acceptance criteria

- Tunnel IPv4 address converges and survives a second apply as a no-op.
- Owned route converges; a foreign route and a foreign adapter's address do not change.
- A stale LUID cannot delete.
- `Get-NetNat` is unchanged by this milestone's tests.

## 13. Stop conditions

Stop if ownership is inferred from the adapter name, if the implementation installs `0.0.0.0/0` toward the tunnel, or if preservation can be shown only by skipping the decoy assertion.

## 14. Closure

`plans/closure/windows-native-server/004-status.md` with the before/after route tables and the stale-LUID refusal.
