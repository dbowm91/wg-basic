# Windows Native Server M003 — wireguard-nt Adapter Lifecycle

Status: **implemented; closure blocked** on `windows-2025` evidence
Primary class: capability / invariant
Source: `plans/subsystems/windows-native-server-roadmap.md` M003
Baseline: `554de7a3b5ae83700222a290664fbbbeb3cd521a`. Rebase onto the closed M002 head.
Canonical: `plans/adr/011-windows-server-wireguard-nt.md` decision 2 and the zip pin; `plans/003-planning-process.md` §11 and §12.
Dependencies: M002 **hard**. The DLL is loaded only inside `netd` after the pipe accepts a peer.

## 1. Objective

Load the pinned `wireguard-nt` 1.1 amd64 DLL from `netd`'s directory, create and destroy an adapter, apply and observe device configuration, and prove a handshake and counters between two adapters on `windows-2025`. Ownership is the requested GUID plus a live adapter this process created. A name match alone authorizes nothing.

## 2. Non-goals

No IP address assignment, no route changes, no forwarding change, no WinNAT, no firewall rule, no SCM install, and no download of any DLL other than the pinned zip. Do not vendor GPL driver source. Do not build the driver. Do not call `wireguard.exe`.

## 3. Repository evidence

Linux uses `nl-wireguard`. macOS supervises `wireguard-go` and records a runtime receipt. Windows has neither. ADR-011 pins:

- `https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip`
- SHA-256 `dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace`

That digest is the official client's `build.bat` pin. This plan's implementation re-hashes the download. A mismatch is a stop, not a warning.

## 4. Invariants

- The DLL path is the directory of the `netd` executable plus `wireguard.dll`. It is not a request field and not the process working directory.
- Load uses a search flag that does not consult the working directory.
- `prebuilt-binaries-license.txt` is extracted beside the DLL and shipped with the test artifact.
- The adapter GUID is derived from the installation id and the interface id. It is runtime evidence. SQLite does not gain a column for it.
- A foreign adapter, including one whose name equals the logical name, is left untouched.
- Private keys and preshared keys stay in the existing secret wrappers. Logs and receipts do not contain them.
- Unsafe FFI lives only in `crates/win32-sys`.

## 5. Expected production changes

`netd` on Windows, after M002's accept check, can observe and apply a WireGuard device patch through the existing protocol operations. The backend maps those operations onto `WireGuardCreateAdapter`, `WireGuardOpenAdapter`, `WireGuardSetConfiguration`, `WireGuardGetConfiguration`, and `WireGuardCloseAdapter`. The tunnel type string passed to the driver is the one the signed driver registers (`WireGuard`). The adapter name is the logical interface name. Creating an adapter writes a receipt containing the GUID, the LUID, and the DLL digest. The receipt is not desired state.

The CI job fetches the zip, verifies the archive digest, verifies the extracted amd64 DLL digest, and fails the job on mismatch. The recorded DLL digest is whatever the verified archive contains; it is written into the provenance file next to the archive digest.

## 6. Ordered work packages

1. Add `crates/win32-sys` and the load/create/configure/observe/close wrappers. Refuse to load if the digest file beside the DLL does not match the pin.
2. Add a provenance record, on the pattern of `helper/wireguard-go.provenance.json`, naming the URL, archive digest, DLL digest, license name, and the statement that the bytes were not built here.
3. Map the existing device patch and observation types onto the driver's configuration struct. Cryptokey routes are the peer `AllowedIPs`. Host routes are not installed.
4. Same-VM qualification: two adapters, one listen port on localhost, handshake, bidirectional tunnel packets, counters move, close, recreate with the same GUID, and a second run that finds a foreign adapter and refuses to delete it.
5. Kill the `netd` process while an adapter exists and start again. The new process adopts the adapter only when the GUID and the DLL digest match the receipt. Otherwise it refuses.

## 7. Privilege, secrets, and host ownership

Adapter creation requires the elevated `netd`. `serve` never loads the DLL. The protocol still cannot name a path. Teardown closes only an adapter whose GUID matches. An adapter left behind by a crashed process is adopted or refused as in package 5; it is not deleted because the name matched.

## 8. Persistence, protocol, compatibility, failure

No schema migration. A failed `WireGuardSetConfiguration` leaves the previous device configuration in place and returns a typed error, not a converged receipt. Retry of the same generation is safe. A newer generation invalidates an older in-flight receipt, consistent with the existing generation rule. Contention on the adapter name with a foreign owner is a conflict, not an overwrite.

## 9. Tests and integration evidence

Unit tests with a fake backend for the GUID derivation and the refusal rules. The handshake, counters, recreate, and foreign-adapter tests run on `windows-2025` against the real DLL and are the milestone's kernel evidence. Linux namespace suites stay green and are not cited as Windows evidence.

## 10. Verification

`windows-2025` job with the digest check and the live adapter tests. Linux gate order. macOS workflow unchanged.

## 11. Documentation

`architecture/wireguard-control.md` gains a Windows section only at closure, stating the DLL pin, the handle ownership, and that addresses are still absent. The license file is linked from that section.

## 12. Acceptance criteria

- Archive and DLL digests verified in the job log.
- Handshake and counters observed between two local adapters.
- Foreign adapter preserved.
- Restart adopts only a matching GUID and digest.
- No address, route, or NAT change during the job (`Get-NetNat` matches the M001 inventory shape for objects this job did not create; this job creates none).

## 13. Stop conditions

Stop if the zip digest mismatches, if the DLL will not load without test-signing or a reboot, if adoption is implemented as "delete whatever has this name", or if completing the handshake requires `wireguard.exe` or Wintun.

## 14. Closure

`plans/closure/windows-native-server/003-status.md`. Include both digests, the runner image version, the handshake transcript, and the foreign-adapter transcript.
