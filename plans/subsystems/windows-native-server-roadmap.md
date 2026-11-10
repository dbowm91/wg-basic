# Windows Native Server Roadmap

Status: implemented 2026-11-10. M001–M007 closure blocked on `windows-2025` evidence. No Windows support claim.

Owner: headless WireGuard server on Windows Server 2025 x64, ending in an IPv4 NAT gateway. Not a Windows WireGuard client application, and not a Phase 10 update to the Linux installer.

Canonical authority: `plans/000-long-term-specification.md` §6.3; `plans/002-long-term-roadmap.md` §14B; `plans/003-planning-process.md`; `plans/adr/011-windows-server-wireguard-nt.md`. ADR-001 through ADR-010 stay binding for Linux and macOS. ADR-006's Phase 10 claim is unchanged.

Baseline: `554de7a3b5ae83700222a290664fbbbeb3cd521a` (2026-11-10).

## 1. Goal and boundaries

Run wg-basic as a native headless WireGuard server on the one Windows system GitHub-hosted CI can provide: `runs-on: windows-2025`, Windows Server 2025 x64. Reuse SQLite desired state, the management API, the embedded UI, enrollment, and typed privileged `netd`. The line ends with gateway mode proven by translated IPv4 traffic on that runner.

Linux and macOS stay fully functional. A Windows client importing a generated config does not satisfy this roadmap.

In scope: amd64 Server 2025 compile and test, named-pipe peer identity, the pinned `wireguard-nt` DLL, address and route ownership, one owned WinNAT plus installation-scoped firewall filters, SCM installation of the two roles, and a written support claim that names this SKU only.

Out of scope: Windows 11, Windows Server 2022, arm64, a reboot-and-resume qualification, a publicly reachable UDP port, IPv6 NAT, IPv6 egress as a release gate, coexistence with WireGuard for Windows or with WSL/Docker NAT, Authenticode, a Windows self-update, and any change to the Linux nftables or systemd paths.

## 2. Non-negotiable invariants

1. No arbitrary commands, DLL paths, registry paths, firewall scripts, or NAT names over privileged IPC. Authorization comes from the kernel at accept time.
2. The adapter name, LUID, and interface index are not a stable logical interface id. Uncertain ownership refuses the mutation.
3. Foreign adapters, routes, addresses, firewall rules, and NetNAT objects stay in place. A second WinNAT is never created in order to overwrite the first.
4. Desired generation and client identity do not change because the host is Windows. Schema migration only through an explicit versioned contract. This line prefers none.
5. Crash, restart, and partial apply have an explicit retry, no-op, or refusal. There is no silent convergence.
6. Linux and macOS CI stay green on every milestone, including their rootful suites where the milestone touches shared code.
7. A Windows compile, and a Windows client's ability to import a config, are not a working Windows server.
8. The support sentence names Windows Server 2025 x64 qualified on `windows-2025`. It does not say "Windows support" without that bound.

## 3. Current evidence

At the baseline the crate does not compile for `x86_64-pc-windows-msvc`:

- `nix` is an unconditional dependency. `src/protocol/socket.rs` and `src/protocol/auth.rs` use `std::os::unix` (`UnixListener`, `SO_PEERCRED` / `getpeereid`).
- State, backup, migrations, and the service lease use Unix mode bits.
- `src/distribution.rs` and `src/update.rs` are systemd.
- `src/platform/mod.rs` has `Linux`, `Darwin`, and `Unsupported`. `has_native_network_backend` is Linux-only.
- `src/wireguard.rs` and `src/firewall/mod.rs` already fail closed for a non-Linux, non-macOS target. `src/reconcile/mod.rs` exports `service_darwin::ReconciliationService` for every non-Linux target, so the Windows stub does not compile.
- No workflow uses a Windows runner. Client export already emits the standard config keys and does not need a Windows backend.

`Get-NetNat` on a fresh `windows-2025` job has not been recorded. M001 records it. M005 does not assume the result.

## 4. Dependency graph

```text
M001 portable boundary and windows-2025 build
  -> M002 named-pipe identity, doctor, fail-closed network
  -> M003 pinned wireguard-nt adapter, handshake, counters
  -> M004 address and route ownership
  -> M005 forwarding, one owned WinNAT, translated IPv4
  -> M006 SCM install and uninstall
  -> M007 product-path qualification and the support claim
```

M006's installer design may proceed against M002's written identity contract. Its closure waits on M005, because the installer must not advertise a gateway the runner has not shown. M003's zip pin is fixed by ADR-011; implementation still waits on M002 so only `netd` loads the DLL.

## 5. Milestone contracts

| Milestone | Primary class | Scope / acceptance boundary | Hard dependency | Status |
|---|---|---|---|---|
| M001 portability foundation | infrastructure / invariant | Shared modules build and their unit tests pass on `windows-2025`. Network apply fails closed. Linux and macOS unchanged. Read-only `Get-NetNat` inventory recorded. | baseline | **implemented; closure blocked** |
| M002 Windows privilege and IPC | invariant | Named pipe, kernel peer identity, serve accepted, other local users refused, doctor tells the truth, still no adapter. | M001 | **implemented; closure blocked** |
| M003 wireguard-nt lifecycle | capability / invariant | Pinned DLL, adapter create/close, configuration, same-VM handshake and counters, ownership refusal. No addresses or NAT. | M002 | **implemented; closure blocked** |
| M004 addresses and routes | capability / invariant | IP Helper apply/observe/verify on the adapter LUID. Foreign routes and adapters preserved. | M003 | **implemented; closure blocked** |
| M005 forwarding and WinNAT gateway | invariant / capability | One owned NAT, forwarding ownership, scoped filters, translated IPv4 observed, foreign NAT refused. | M004 | **implemented; closure blocked** |
| M006 SCM installation | infrastructure / capability | Two services, transactional install/uninstall, wrong SKU refused. No reboot claim. No self-update. | M005 | **implemented; closure blocked** |
| M007 qualification and support claim | qualification | Product path on `windows-2025`, support sentence bounded to this SKU, Linux and macOS still green. Publishing a Windows release stays a maintainer act. | M006 | **implemented; closure blocked** |

Plans: `plans/implementation/windows-native-server/001` through `007`.

## 6. Hard validation gates

- M001: `cargo test --locked` on `windows-2025` for the portable suites; full Linux CI; macOS workflow unchanged and green; architecture guards cover the new cfg split.
- M002: a standard user token is rejected; the serve identity is accepted; a foreign or pre-existing pipe is preserved; the job's own administrator token is not silently treated as serve.
- M003: digest-verified DLL, real adapter, real handshake and counters between two adapters on the runner, kill and recreate, foreign adapter left in place.
- M004: IPv4 tunnel address and owned routes converge, idempotent re-apply, foreign route preserved, stale LUID cannot delete.
- M005: `Get-NetNat` before mutation; refusal when a foreign NAT exists; when none exists, translated IPv4 to an external echo; teardown removes only the owned NAT and restores forwarding only if this installation enabled it.
- M006: install, failed-install rollback, uninstall leaves foreign files and a foreign NAT, serve token is not an administrator, a Client SKU and Server 2022 are refused.
- M007: API-created server and client, exported config applied to the second adapter, translated traffic, docs name the SKU and the license, no Phase 10 workflow change.

## 7. Risk and stop conditions

Stop if the pinned zip digest does not match, if `wireguard.dll` will not load on `windows-2025` without test-signing, if a gateway pass requires deleting a foreign NetNAT, if translated traffic cannot be observed, if the pipe ACL has to admit every Administrator, or if shared code changes Linux or macOS behavior. Return to ADR-011 rather than adding a shell fallback.

A same-VM handshake does not prove a remote client. M007 says so in the support sentence. Reboot is not attempted.

## 8. Handoff and closure

Each milestone gets `plans/closure/windows-native-server/00N-status.md` only after implementation evidence exists. Record the runner image version, the exact commands, the `Get-NetNat` transcript, and the Linux and macOS results. Do not edit historical Linux, macOS, or operator-parity closure records. Current-behavior docs change when the behavior exists, not in this planning pass.
