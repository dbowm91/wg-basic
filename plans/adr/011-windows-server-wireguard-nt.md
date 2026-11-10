# ADR-011 — Headless Windows Server support on wireguard-nt

Status: accepted for architecture and staged implementation. The only qualified target is Windows Server 2025 x64 on the GitHub-hosted `windows-2025` runner. No Windows support claim exists until M007 closes.

Date: 2026-11-10

Supersedes: nothing. Extends ADR-001's portability provision without altering the qualified Linux kernel backend. Does not amend ADR-006: Phase 10 remains a systemd, Linux-only distribution claim. Does not amend ADR-008 or ADR-009.

## 1. Context and decision scope

wg-basic ships as a Linux-native WireGuard server, with a separately gated headless macOS server. Desired state, authentication, the management worker, the HTTP API and UI, and enrollment are reusable. The network implementation assumes Generic Netlink, RTNETLINK, nftables, Unix peer credentials, and systemd.

Windows support means a headless server installed on Windows Server, including an IPv4 NAT gateway as the end state of this line. It does not mean packaging a configuration for the official WireGuard for Windows app. A Windows client that imports an exported config is already standard WireGuard interop and is outside this ADR.

The maintainer can qualify this line only on GitHub-hosted runners. There is no local Windows host. The support claim is therefore exactly the runner that can execute it.

## 2. Options and evidence

- Remain Linux and macOS only. Lowest risk. Rejects the requested platform.
- `wireguard-go` plus Wintun. Reuses the Darwin helper shape. Wintun 0.14.1 is the last signed build; the official Windows client removed that path in 2021. The helper's UAPI pipe admits Local System and Administrators. Shipping it means a Go binary plus a second proprietary DLL. Rejected.
- BoringTun, or driving `wireguard.exe /installtunnelservice`. A second dataplane, or a second product's service as a desired-state authority. ADR-001 already rejected `wg-quick` as the control plane. Rejected.
- Build `wireguard-nt` from its GPL-2.0 source and sign it here. GitHub-hosted runners load attested drivers, not test-signed ones, and test-signing requires a reboot this CI cannot survive. Upstream forbids distributing a driver built under the WireGuard name. Rejected.
- `wireguard-nt` 1.1, the in-kernel dataplane the official Windows client ships. Configuration is `WireGuardSetConfiguration` on an adapter handle held by `netd`. Addresses, routes, forwarding, and NAT stay typed host operations, as they are on Linux. Accepted.

`WireGuardSetConfiguration` installs cryptokey routes only. It does not assign addresses, install host routes, or NAT. Peer `AllowedIPs` stay inside the driver. The host route table gains the tunnel address and the routes this product owns.

The signed redistributable, as pinned by WireGuard for Windows `build.bat`:

- URL: `https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip`
- SHA-256: `dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace`

The zip contains `wireguard.dll` for amd64, arm64, and x86, `wireguard.h` (`GPL-2.0 OR MIT`), and `prebuilt-binaries-license.txt`. This planning pass did not re-download the zip. M003 verifies the bytes and stops on mismatch.

Source is GPL-2.0. The DLL is not. WireGuard LLC's prebuilt-binary license allows redistribution only beside software that calls it through `wireguard.h`, forbids modification and reverse engineering, and reserves the right to change the license, the API, or the download. The Windows distribution is MIT code plus that DLL. The license file ships beside the DLL.

GitHub-hosted images available on 2026-11-10:

| Label | OS | In this claim |
|---|---|---|
| `windows-2025` (`windows-latest` today) | Windows Server 2025 x64, build family 10.0.26100 | yes |
| `windows-2022` | Windows Server 2022 x64 | no |
| `windows-11-arm` | Windows 11 Enterprise arm64, public repositories only | no |

`windows-latest` is not the pin. It moves. A hosted job runs as an administrator with UAC disabled, cannot reboot and continue, and has no stable inbound UDP mapping. Microsoft documents one WinNAT internal prefix per host.

## 3. Decision

1. Preserve the unprivileged `serve` / privileged `netd` split, the typed authenticated local protocol, SQLite as the only desired-state authority, generation and CAS semantics, and the narrow mutation vocabulary. Linux and macOS behavior stay as they are.
2. The Windows dataplane is the pinned `wireguard-nt` 1.1 amd64 DLL, loaded by `netd` from its own directory. The DLL path is not a protocol field. No PowerShell, `netsh`, `wireguard.exe`, or caller-supplied driver path crosses the privileged protocol.
3. The qualified target is one SKU: Windows Server, amd64, build family 10.0.26100, which is Windows Server 2025 as hosted by `windows-2025`. Installation on any other Windows edition or architecture fails closed. Windows 11 shares the 26100 build family and is distinguished by installation type Client, so build number alone is not acceptance.
4. Local IPC on Windows is a named pipe with an explicit DACL. The accepted peer is the `serve` service identity, learned from the kernel at accept time. Membership in Administrators is not a bypass. The pipe name is this product's, not WireGuard's `ProtectedPrefix\Administrators\WireGuard` pipe.
5. Logical tunnel identity stays `InstallationId` + `InterfaceId` + `InterfaceName`. The NDIS adapter name, interface index, and LUID are ephemeral locators. A GUID derived from the installation and the interface id is the adapter identity requested at creation, so Windows does not mint a new network profile per recreation. The GUID is runtime evidence, not a second desired-state store.
6. The end state of this line is gateway mode: tunnel addresses, forwarding, and one WinNAT whose internal prefix is the tunnel prefix this installation owns. A pre-existing NetNAT is a refusal with a remediation. This product does not delete a NAT it did not create. IPv6 is routed and is not NAT. IPv6 egress is unqualified on the hosted runner.
7. Host-global IPv4 forwarding follows the same ownership rule as every other global toggle: record the previous value, enable it for gateway apply, and restore it on teardown only when this installation turned it on and can prove it still owns that change. An already-enabled value is left enabled.
8. Firewall changes are user-mode WFP or the Windows firewall API, scoped to this installation and removed on teardown. A second kernel callout driver is out of scope. The product never flushes the host firewall.
9. Service installation is Service Control Manager, two services, under a later milestone. It is not Phase 10, not eggup, and not a self-update path. Authenticode and a published Windows artifact wait for a separate maintainer authorization. M007 may not describe a CI build as a release.
10. Unsafe Win32 stays in one workspace crate, `crates/win32-sys`, package `wg-basic-win32-sys`. The main crate keeps `forbid(unsafe_code)`.

## 4. Normative invariants

- SQLite alone is desired state. A runtime receipt or adapter GUID is evidence.
- After a crash, `netd` re-observes the adapter and revalidates ownership before any destructive mutation. A stale LUID or a recycled interface index never authorizes deletion.
- The privileged endpoint cannot request process execution, a DLL path, a firewall rule script, a registry path, or a NAT name chosen by the caller.
- On a hash mismatch, a missing DLL, an unexpected driver version, a foreign NetNAT, an ambiguous default route, or uncertain ownership: fail closed, preserve unrelated host state, and return a named error.
- Linux kernel, nftables, netlink, systemd, and release gates remain normative on Linux. macOS gates remain normative on macOS. Windows assurance comes from `windows-2025` jobs, not from a Linux namespace test renamed as Windows.
- A green `cargo test` on Windows is not a gateway claim. Gateway closure requires observed translated traffic on that runner.
- Reboot survival, a client on the public internet, IPv6 internet egress, coexistence with the official WireGuard app, WSL, or Docker, and Windows 11 or arm64 are outside the support claim. A hole-punch between two runners may be recorded as a spike. It is not a release gate.

## 5. Contract, migration, and distribution consequences

Share portable types only. Do not serialize a LUID, interface index, or adapter GUID as desired state. Prefer no schema migration. A Linux or macOS database remains readable and its exported client configuration stays identical.

The Windows build fetches the pinned zip, checks the archive digest and the amd64 DLL digest, and refuses any other bytes. Upgrades are an explicit pin change in a later plan, reviewed like the macOS helper provenance bump. GPL driver source is not vendored.

Phase 10's Linux artifacts gain no Windows target. A Windows layout lives under the installation directory this line defines in M006 and is uninstalled by that installer only.

## 6. Integration and closure consequences

Follow `plans/subsystems/windows-native-server-roadmap.md` M001–M007. M001 is the portability boundary and is ready. M002 is pipe identity. M003 is the DLL and a real handshake. M004 is addresses and routes. M005 is forwarding and WinNAT, and it stops if the hosted runner cannot show translated traffic without deleting a foreign NAT. M006 is SCM install. M007 is the support claim.

M005's first act on a runner is to read `Get-NetNat` before creating anything. M001 records that read-only inventory so the later milestone inherits a measurement. If a NetNAT is already present, gateway apply refuses. The qualification does not remove it to force a pass.

## 7. Source references

- wireguard-nt and the prebuilt-binary license: https://git.zx2c4.com/wireguard-nt/about/
- Pinned zip: https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip
- Official client pin: WireGuard for Windows `build.bat` (`wireguard-nt-1.1.zip`, digest above)
- `wireguard.h` create-adapter and set-configuration API: https://github.com/WireGuard/wireguard-nt/blob/master/api/wireguard.h
- WinNAT one-prefix limit: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/setup-nat-network
- GitHub-hosted runner labels: https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- ADR-001, ADR-006, ADR-008, ADR-009
