# macOS Native Server C001 — Production Backend Wiring and Host-Only Convergence

Status: **ready** (planning only; no runtime implementation or closure).
Baseline: `plans/macos-native-support@fc51146e811cabebd042d852449c6e7f4f854265`.
Source: `plans/subsystems/macos-native-server-corrective-roadmap.md` C001; original M002–M004 plans and `plans/closure/macos-native-server/{002,003,004,007}-status.md`.
Authority: canonical spec/process, ADR-008 and ADR-001–007; Linux regressions binding.
Primary class: corrective / capability / invariant.

## Objective and root cause

Make a headless macOS host-only WireGuard **appliance**, not merely a root-run utun test: the real authenticated HTTP/management command path must create and reconcile a Mac-owned WireGuard interface, apply peers, report telemetry and survive failure. Earlier M003/M004 fixture closure directly exercised helper and platform commands, bypassing the public `WireGuardBackend` and `ReconciliationService` dispatch paths. The M007 must-not-release judgment therefore stands.

## Non-goals

No PF/NAT, IP forwarding, routed LAN, default-route modification, public release, arbitrary OS-command or privilege-boundary escape hatch. No new WireGuard protocol implementation, consumer macOS VPN client, or Linux module refactor. Keep management API/schema wire shape unless an explicit versioned migration is proved necessary.

## Required implementation slices

1. **Service-backed helper:** replace the Darwin `src/wireguard.rs` `UnsupportedBackend` facade with the already pinned `src/wireguard/darwin.rs` foreground helper supervisor/UAPI. Implement `observe_device` and `apply_patch` against a **durable per-netd managed runtime registry** keyed by InstallationId/logical InterfaceId (process-local plus protected runtime receipts, not an alternative desired store). Authorize helper path and hash before launch; fixed argv, restricted environment, bounded output/time, redacted secrets. Separate logical identity from ephemeral `utunN` and UAPI path.
2. **Ownership:** after spawn and across worker/helper/netd restart, prove process executable identity, saved protected receipt, kernel utun, UAPI socket owner and direct live observations jointly. Before stop/delete/replace re-observe; stale, missing, shared or foreign evidence is a conflict. Never terminate a PID based solely on a receipt or kill another VPN's `utun`. Apply generations idempotently; abort rather than guess on mixed state.
3. **Darwin reconciliation:** implement the actual service behind `src/reconcile/service_darwin.rs` using the existing typed planner, direct constrained Darwin network APIs (e.g. routing socket/`getifaddrs` and properly bound address control) and fresh observation. Test-only `ifconfig`/`route` probes are not a production backend. Preserve scoped IPv6/link-local behavior, all foreign routes, host defaults and their byte-level representation. Map planner contradictions to typed conflict/degraded errors, never generic false-success.
4. **Host-only firewall semantics:** `FirewallService` may return observed `NoChange` **only** for an explicitly host-only intent that has no forwarding/NAT/firewall obligations and whose absence of managed PF effects is verified. Refuse with `Unsupported`/degraded for every routed, masquerade, unsupported or ambiguous policy. A blanket no-op for all Darwin policy values is forbidden.
5. **Aggregate control and visibility:** connect real `protocol::dispatch`/`aggregate` through WireGuard + interface + verified host-only firewall ordering. Ensure applied generation is committed only when the exact generation's actual device/address/peer state is observed. Expose honest health, doctor and live counters in existing authenticated management/API/UI, retaining the narrow privileged request vocabulary.
6. **Operational contract:** managed enable, disable, peer add/update/remove, deletions, SIGTERM, helper crash, `netd` crash, repeated reconcile, concurrent attempts and replace attempts have deterministic replay, cleanup, retention or degraded results. Document the exact helper recovery and no-foreign-adoption contract.

## Security/compatibility

`serve` remains unprivileged; `netd` is the only authority to open/manipulate host networking. SQLite retains keys/generation/authorship, with existing encrypted/permission-constrained secret handling and redaction, UDS getpeereid authorization and bounded framing. Explicit typed operations only. If new persisted locator/receipt information is required, introduce versioned compatible migration and prove old Linux DB restore/rollback. Check macOS helper source MIT license/revision, no PATH executable discovery or unsafe shell. A protected receipt alone NEVER authorizes deletion.

## Focused tests and adversarial controls

Unit + integration: Linux netlink behavior unchanged; Darwin UAPI parses hex keys/errno trailer, helper restart/utun renumber, ambiguous ownership, malicious UDS frames, wrong helper digest, stale socket, double-instance lock, missing/foreign address, global route conflicts, peer update/delete, exact-generation CAS. Negative control: replaced `WireGuardBackend`/`ReconciliationService` stubs must cause end-to-end test failure, never a green mock.

Root-run disposable macOS ARM64 and native Intel: start the *real* `netd` and unprivileged `serve`, initialize SQLite/admin, configure server and enroll a real independent Linux-kernel WireGuard peer via HTTP, establish handshake, exchange IPv4 **and** IPv6 packets with local Mac-owned addresses, measure telemetry at the API, disable/delete and verify interface/route/pid/socket cleanup. Repeat netd/helper restart, idempotent replay and foreign-owner refusal. Capture before/after route and VPN inventory. The Mac need not forward any third-party traffic for this corrective.

## Verification, acceptance, stop and closure

Run fmt/check/clippy/test/MSRV, existing Linux rootful WireGuard, reconciliation, firewall, product and systemd suites, both Darwin target checks and native live CI; include exact reproducible E2E script with opt-in and cleanup. Acceptance requires real product/API → typed IPC → helper + addresses/routes → observed generation convergence, dual-stack off-host traffic, truthful failures, zero foreign mutation on both native arches. Stop on unverifiable helper/utun identity, broad netd authority, default-route takeover, false applied receipt, inability to preserve unrelated interfaces, or privilege regression. Update docs/architecture only after behavior is implemented. Write `plans/closure/macos-native-server-corrective/c001-status.md` with strict evidence and unresolved findings; do not reinterpret M003/M004 historical closures.
