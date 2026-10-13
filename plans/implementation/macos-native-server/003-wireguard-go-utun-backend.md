# macOS Native Server M003 — wireguard-go utun Dataplane, Ownership, and UAPI

Status: planned; blocked pending hard predecessor
Primary class: capability / invariant
Source: plans/subsystems/macos-native-server-roadmap.md M003
Baseline: main 47c72b0e81d569d48396c615120453bf0cf1d46e (2026-10-11); rebase/revalidate against actual implementation head before applying.
Canonical: plans/000-long-term-specification.md; plans/002-long-term-roadmap.md; plans/003-planning-process.md; plans/adr/008-macos-headless-platform-backends.md; Linux ADR-001–007 are preserved.
Dependencies: M002 strict closure; M001 stable logical-identity contract.

## 1. Objective

Establish one real headless macOS WireGuard server tunnel with the supported userspace dataplane, typed peer CRUD, handshake/endpoint/RX/TX observation, and independently verifiable ownership across tunnel/helper restarts.

## 2. Non-goals

No host forwarding/NAT, PF, route-policy gateway, consumer Network Extension app, or backend replacement on Linux; no homegrown WireGuard crypto. No production claim based on a helper started from PATH.

## 3. Repository evidence

src/wireguard/backend.rs observes/applies via nl-wireguard and Linux kernel WireGuard device. src/reconcile/planner.rs currently includes CreateWireGuardLink and ConfigureWireGuard mutations; observed owner tag lives in IFLA_IFALIAS. Upstream wireguard-go supports Darwin utun and WG_TUN_NAME_FILE, but has no sticky socket/fwmark on macOS. Thus a logical wg0 must not be conflated with utunN. Existing peer/device typed structures and telemetry live in src/wireguard.rs.

## 4. Invariants

- The exact pinned, verified helper binary is an explicit runtime dependency on macOS, managed only by netd; no request-controlled binary paths/flags.
- Run foreground; netd supervises or holds a validated process identity and bounded exit/restart contract, never orphaning silently.
- Dynamic kernel-assigned utun names cannot themselves prove ownership; require protected identity receipt plus live helper/socket and kernel-interface consistency.
- A foreign existing utun, process, UAPI socket, or mismatched owner is never adopted or killed, even if names match.
- Typed WireGuard requests only, no raw user-authored UAPI text; zeroize or minimize transient private-key buffers; redact logs.

## 5. Ordered implementation packages

1. Pin upstream wireguard-go version/commit, MIT license and source provenance; specify helper compilation and architectures without silently depending on Homebrew or runtime Go; consider official upstream UAPI design before writing parser.
2. Implement validated fixed-argv foreground helper supervisor with controlled environment, reserved root-owned runtime directory, bounded WG_TUN_NAME_FILE, process exit handling, and no global PATH lookup. Validate helper binary hash/signature relative to installation receipt.
3. Implement bounded userspace WireGuard UAPI observation and typed patch serialization: private key/listen port, peers, AllowedIPs, preshared keys where present, endpoint, keepalive, tx/rx and latest handshake. Enforce finite request/response bounds, timeouts, canonical encoding and secret scrubbing; never export raw UAPI through IPC.
4. Implement Darwin logical tunnel mapping and proof of ownership: authenticated helper/control socket, expected interface name from trusted runtime file, process identity, exact interface/device observation, installation identity, and fail-closed stale evidence handling. Explicitly prove safe after crash, PID reuse simulation, utun renumbering, and concurrent other VPNs.
5. Exercise the existing aggregate planner with one Darwin managed tunnel; translate only supported actions and distinguish unsupported route/firewall operations for M004/M005. Gather real Mac ↔ Linux standard WG interoperability and telemetry evidence.

## 6. Privilege, secrets, and host ownership

Keep executable launch and UAPI exclusively inside netd; never let authenticated API choose helper path or command flags. Identity/provenance matters because helper is root privileged. Restrict runtime socket mode, path traversal, symlinks and helper logs; protect key material on errors/restarts; no adoption of another utun/WG socket by numeric name.

## 7. Storage, protocol, compatibility and runtime failures

Linux nl-wireguard backend and existing API remain unchanged. If the current aggregate plan assumes interface_alias or ifindex it must receive an explicit Darwin observation alternative, not a fabricated alias. A helper crash means degraded service and bounded restart/reconciliation; committed desired state remains durable, incomplete apply must not claim success. A new utun number after reboot does not change logical persisted identity or client configs.

## 8. Focused and integration tests

- Native macOS real helper start, utun identity, UAPI set/get, peer add/update/delete, endpoint and keepalive changes, handshake + packet traffic with standard Linux client.
- Kill helper mid-apply; restart netd, kill/restart serve, simulate stale/malicious name file, occupied UAPI socket, foreign utun, PID reuse and duplicate installation; verify no foreign resource termination.
- Cover empty peers, 256-peer bound, malformed device/peer output, UAPI denial, oversized response, timeout, partial apply and secrets in error text.
- Linux kernel WireGuard namespace/e2e tests unchanged.

## 9. Verification, documentation, and closure

Run Darwin privileged fixture on real macOS; record exact OS version, utun names, upstream commit/hash, helper UID/PID and tunnel packet evidence, plus Linux client keys masked. Capture performance/steady-state process RSS and log-volume (compare against Linux baseline but do not enforce Linux-only 30 MiB budget on helper without new agreed threshold). Update current wireguard control and doctor docs after acceptance.

## 10. Acceptance criteria

- Native Mac hosts a WireGuard interface, client establishes handshake and passes tunnel packets, device/peer counters/endpoint correctly reported by the existing API.
- Lost helper/process, stale utunN, foreign UAPI socket and wrong binary identity fail closed without mutation of foreign state.
- Reconcile/restart yields same logical identity/peer configuration and truthful generation receipts.
- All Linux network-control and management tests remain green.

## 11. Stop conditions

If upstream helper license/provenance unsuitable, utun identity cannot be established safely, UAPI control requires global unbounded privilege, or WireGuard traffic only works by invoking wg-quick or arbitrary shell hooks.

Closure record: plans/closure/macos-native-server/003-status.md, authored only after implementation and evidence. Record commit/PR, baseline and final head, passed/failed exact commands, native host/kernel traffic, foreign-state snapshots, security findings, documentation diffs, and strict disposition.
