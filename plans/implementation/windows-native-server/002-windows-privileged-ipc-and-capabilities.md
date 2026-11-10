# Windows Native Server M002 — Named-Pipe Identity and Capabilities

Status: **implemented; closure blocked** on `windows-2025` evidence
Primary class: invariant
Source: `plans/subsystems/windows-native-server-roadmap.md` M002
Baseline: `554de7a3b5ae83700222a290664fbbbeb3cd521a`. Rebase onto the closed M001 head before implementation.
Canonical: `plans/adr/011-windows-server-wireguard-nt.md`; `plans/000-long-term-specification.md` §6.3; `plans/003-planning-process.md`.
Dependencies: M001 **hard**. The pipe protocol is the existing framed protocol; the wire schema does not change.

## 1. Objective

Replace the Unix-socket listener on Windows with a named pipe whose peer identity comes from the kernel. `serve` is accepted. Every other local identity is refused. Doctor reports Windows facts and still reports the network backends unsupported. No adapter is created.

## 2. Non-goals

No `wireguard.dll`, no IP Helper mutation, no firewall, no NAT, no SCM service registration, no change to the Linux `SO_PEERCRED` path or the macOS `getpeereid` path.

## 3. Repository evidence

Linux authorizes `SO_PEERCRED` and, by default, its own uid plus root. macOS authorizes `getpeereid` and its own uid only. The socket path default is `/run/wg-basic/netd.sock`. Windows has no uid. M001 leaves `netd` refusing to bind.

## 4. Invariants

- The request body never supplies the peer identity.
- Administrators are not an implicit allow. The job runs as an administrator; that token must still be refused unless it is the configured serve identity.
- A pre-existing pipe, or a pipe this process did not create, is preserved and reported as a conflict.
- Protocol operations and frame limits stay the ones Linux already enforces.
- Unsafe Win32, if any is required beyond a safe wrapper, lives in `crates/win32-sys`. The main crate keeps `forbid(unsafe_code)`.

## 5. Expected production changes

Windows `netd` listens on `\\.\pipe\wg-basic\netd` unless `--socket` names another pipe under `\\.\pipe\wg-basic\`. The DACL grants access to the serve account SID passed by `--allow-user` (a local account name resolved on the host) and to `netd`'s own SID. The integrity label is high. Medium-integrity callers fail at open. On accept, `netd` reads the client process id and that process's token user SID and integrity level, then checks the SID against the policy. Linux and macOS flags keep their current meaning. Doctor on Windows reports the OS caption, build, architecture, installation type, and pipe reachability, and reports WireGuard, routes, and firewall unsupported.

## 6. Ordered work packages

1. Add the Windows listener beside the Unix listener, selected by `cfg`. Share framing, dispatch, and the operation set.
2. Implement the DACL and the kernel peer check. Resolution of `--allow-user` happens on the host; the protocol does not carry a SID from the client.
3. Define stale-pipe replacement: only a pipe this installation's `netd` created, and only after a failed connect plus a re-check of the pipe's owner, may be removed. Anything else is a conflict.
4. Point doctor and the capability snapshot at the Windows facts. Do not invent `CAP_NET_ADMIN` or a nftables version.
5. CI on `windows-2025`: create a standard user and an administrator user that is not the serve user; prove refusal and acceptance; prove a foreign pipe is left in place.

## 7. Privilege, secrets, and host ownership

`netd` is elevated for this milestone's tests because the runner is elevated. The accept check still requires the serve SID. Secrets in the frame are unchanged. The pipe is local. No filesystem path in the request is opened.

## 8. Persistence, protocol, compatibility, failure

No schema and no protocol version change. A Linux client of the protocol is source-compatible at the frame layer; this milestone does not make a Linux `serve` talk to a Windows `netd` across machines. A refused peer closes the pipe without writing a receipt. Shutdown removes the pipe only when the owner re-check still matches. A crash that leaves the pipe is the next start's stale-pipe case, not a reason to delete a pipe owned by someone else.

## 9. Tests and integration evidence

Focused Windows tests for accept, reject, stale replacement, and foreign preservation. Linux `darwin_ipc` is untouched; Linux socket tests stay green. No network-namespace claim is made for Windows. Linux namespace suites run to prove the shared dispatch did not move.

## 10. Verification

`windows-2025` job including the new identity tests. Linux gate order from `docs/development.md`. macOS workflow unchanged.

## 11. Documentation

`architecture/privilege-boundary.md` gains the Windows pipe facts when they are true. Until closure, the architecture doc stays Unix-only. The plan is the intended behavior.

## 12. Acceptance criteria

- Serve identity accepted; standard user and a different administrator refused.
- Foreign pipe preserved.
- Doctor does not report a Windows network backend as available.
- Linux and macOS CI green.

## 13. Stop conditions

Stop if the only workable DACL admits `BUILTIN\Administrators`, if peer identity has to be read from the request, or if the milestone starts loading `wireguard.dll`.

## 14. Closure

`plans/closure/windows-native-server/002-status.md` after the identity tests have run on `windows-2025`. Record the accounts used and the refusal errors.
