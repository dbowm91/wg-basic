# Windows Native Server M006 — Service Control Manager Installation

Status: **implemented; closure blocked** on `windows-2025` evidence
Primary class: infrastructure / capability
Source: `plans/subsystems/windows-native-server-roadmap.md` M006
Baseline: `554de7a3b5ae83700222a290664fbbbeb3cd521a`. Rebase onto the closed M005 head.
Canonical: `plans/adr/011-windows-server-wireguard-nt.md` decisions 3 and 9; ADR-006 remains the Linux distribution claim and is not extended here.
Dependencies: M005 **hard** for closure. The service identity contract from M002 is the interface this installer consumes.

## 1. Objective

Install and remove two Windows services on Windows Server 2025 x64: an unprivileged `serve` and a privileged `netd` that loads `wireguard.dll`. A failed install rolls back the objects it created. Uninstall removes those objects and leaves foreign files and a foreign NetNAT in place. Any other Windows edition or architecture is refused before any service is created.

## 2. Non-goals

No self-update, no eggup or systemd change, no Authenticode, no published release artifact, no reboot qualification, and no Phase 10 workflow edit. Do not start the services on a SKU this line does not claim.

## 3. Repository evidence

Linux installation writes systemd units and `sysusers` entries under the Phase 10 layout. macOS uses launchd. Windows has neither. M002 names the pipe and the serve account. M005 has proven gateway apply inside a job, not yet as a service that outlives one process.

## 4. Invariants

- `serve` runs as a local account that is not in Administrators and whose token is medium integrity. `netd` is the only service that loads the DLL.
- The pipe DACL from M002 lists that serve account and `netd`, not `BUILTIN\Administrators`.
- The installer writes only under the installation root it creates and only the two service registrations it records. A path that already exists and is not in the install receipt is preserved.
- SKU check comes first: installation type Server, amd64, build family 10.0.26100. Windows 11 is build family 26100 with installation type Client and is refused. Server 2022 is refused. The check uses the OS facts, not the GitHub runner label.
- Rollback of a failed install removes only objects this attempt created, in reverse order.

## 5. Expected production changes

`wg-basic system install` and `system uninstall` gain a Windows implementation, cfg-gated, that does not compile into the Linux systemd path. The layout is:

- `C:\ProgramData\wg-basic\state\` for the database, owned by the serve account;
- `C:\ProgramData\wg-basic\bin\` for the executable and `wireguard.dll` plus the license file;
- `C:\ProgramData\wg-basic\netd\` for runtime receipts, not desired state.

Service names are `wg-basic` and `wg-basic-netd`. Recovery on process exit is restart. The installer does not set a dependency on a reboot. `system status` reports the two services, the pipe, the SKU check, and the last receipt without mutating.

Uninstall stops the services, removes the registrations, removes the pipe if this installation owns it, runs the M005 and M004 teardown for objects this installation owns, and removes the bin directory. The state directory is kept unless the operator asks for the existing purge flow, which keeps its current guards.

## 6. Ordered work packages

1. SKU refusal, with tests that a simulated Client installation type and a simulated build outside 10.0.26100 refuse and create no files.
2. Account creation for `serve`, service registration, file copy including the license, and pipe ACL pointed at those accounts.
3. Failure injection after each step (account created, files copied, one service registered) and proof that rollback leaves the machine without those objects.
4. Happy-path install on `windows-2025`, start both services, show `serve` is not an administrator, show a product read reaches `netd`, then uninstall and show the service list, the pipe, and the bin directory gone.
5. Plant a foreign file under `C:\ProgramData\wg-basic-foreign` and a decoy NetNAT. Uninstall leaves both.

## 7. Privilege, secrets, and host ownership

The installer itself is elevated. The services it creates are not both elevated. The database stays readable by `serve` and not by the world. `netd` remains database-free. No installer step fetches an unpinned URL; the DLL in the bin directory is the one M003 verified, copied from the build output.

## 8. Persistence, protocol, compatibility, failure

The database format does not change. A database copied from Linux opens, and reconcile then applies it through the Windows backends. A crash during install is recovered by re-running install, which treats a half-created receipt as its own rollback case rather than as a foreign installation. A half-created tree that fails the receipt check is not adopted.

## 9. Tests and integration evidence

SKU refusal can be a pure test of the classifier. Install, rollback, and uninstall run on `windows-2025` against the real SCM. Linux systemd install tests stay green and cover Linux only. No reboot is performed; the closure says boot persistence is unmeasured.

## 10. Verification

`windows-2025` install job. Linux gate order, including the systemd install suites. macOS workflow unchanged.

## 11. Documentation

`docs/operations-runbook.md` gains a Windows Server 2025 install section at closure: the SKU, the two accounts, the layout, and the statement that reboot survival has not been qualified. README stays a summary and points at that section only after closure.

## 12. Acceptance criteria

- Client SKU and a non-26100 Server build are refused with no files left behind.
- Both services run; `serve` is not an administrator; `netd` serves the pipe.
- Failed install rolls back.
- Uninstall preserves the foreign file and the decoy NetNAT.
- Linux installer behavior is unchanged.

## 13. Stop conditions

Stop if `serve` must be an administrator to open the state directory, if the pipe ACL has to include all administrators, or if rollback deletes a path the installer did not create.

## 14. Closure

`plans/closure/windows-native-server/006-status.md` with the service queries, the token groups of both processes, and the foreign-object snapshots. Disposition notes the reboot gap explicitly.
