# macOS Native Server Support Roadmap

Status: line verdict recorded 2026-10-13 — M001–M002 closed, M003–M006 blocked on privileged-host qualification (safe/policy/installation scopes implemented; TN3165 advanced-admin-only decided), M007 blocked verdict with MUST-NOT-release decision + unblock checklist

Owner: headless Darwin WireGuard server deployment, not a macOS WireGuard client application.

Canonical authority: plans/000-long-term-specification.md (platform extension); plans/002-long-term-roadmap.md; plans/003-planning-process.md; plans/adr/008-macos-headless-platform-backends.md; prior ADR-001 through ADR-007 remain binding for Linux.

Baseline: main 47c72b0e81d569d48396c615120453bf0cf1d46e (2026-10-11). This planning branch changes no runtime code or historical closure evidence.

## 1. Goal and boundaries

Enable wg-basic to run as a native, headless macOS WireGuard *server*, using the existing local management API, embedded UI, SQLite authoritative state, explicit client enrollment/export, typed privileged netd, and safe host-network reconciliation. Linux remains fully functional without runtime/ABI regression. A macOS *client* that imports a generated config is already a standard-WireGuard interoperability question and does not satisfy this roadmap.

Scope includes Apple Silicon and Intel if native support can be qualified, durable tunnel/peer management, telemetry, IPv4 and IPv6 addressing, forwarding, validated gateway/NAT policy, local authentication, start-on-boot, crash recovery, state-preserving uninstall, and release artifacts. DNS resolution/server operation, systemwide kill switch, consumer menu-bar app, third-party VPN import, and general PF configuration editing are out of scope.

## 2. Non-negotiable invariants

1. No arbitrary commands, PF source, paths, routes, or sysctl names over privileged IPC; only closed typed operations, bounded input and output, and authorization by the OS.
2. Observable owner identity across restarts; dynamic utunN assignment is not a stable logical interface ID.
3. Preserve foreign routes, addresses, PF anchors, global firewall state, and forwarding configuration. Refuse destructive mutation when ownership is uncertain.
4. Stored desired generation and client/public key identity remain authoritative and unchanged by host choice. Migration only through versioned guarded contracts.
5. Crash, restart, sleep/wake, network switching, concurrent service attempts, and partial failure have explicit replay/no-op/repair or degraded outcomes.
6. Linux's established performance/ABI/CLI/service/network paths must remain unchanged, with full Linux CI on every platform refactor.
7. A native Darwin compile and a Linux client's ability to import configs do not constitute a working macOS server.
8. Respect Apple's TN3165: do not mistake a PF admin capability for approved broadly distributed application API. Record the final PF/NAT product policy, or block gateway release.

## 3. Current evidence / hotspots

- src/lib.rs and src/main.rs gate networking, HTTP, protocol, reconcile, release/install roles on Linux and explicitly reject non-Linux runtime.
- Cargo.toml keeps tokio, x25519-dalek, serde_json, EggServe and other shared consumers under cfg(target_os="linux"); some portable modules already reference gated modules.
- src/reconcile/model.rs and domain/interface_name.rs assume IFLA_IFALIAS and Linux names; src/reconcile/linux.rs uses RTNETLINK; src/wireguard/backend.rs uses nl-wireguard.
- src/protocol/socket.rs uses SO_PEERCRED; src/firewall/nft.rs uses nft and /proc; src/distribution.rs, src/update.rs and release/eggpack/* assume systemd and Linux targets.
- Phases 1–11 closure documents prove Linux behavior, not macOS. No Darwin native qualification currently exists.

## 4. Dependency graph

M001 portable type/runtime boundary and Darwin build
  -> M002 privileged IPC, macOS host capabilities
  -> M003 wireguard-go/utun UAPI and real handshake
  -> M004 Darwin addresses/routes/ownership and restart
  -> M005 host forwarding / PF decision and gateway qualification
  -> M006 launchd, safe installer, signed-helper identity, platform release integration
  -> M007 native cross-platform release/security closure

M002 and M003 may prototype against M001's stable written interfaces but may not claim readiness before hard closure. M006 design research may run in parallel, but install/recovery closure depends on the preceding host-network invariants. M005 PF feasibility spike may begin as research immediately; no production PF mutation before M004 proof and security review.

## 5. Milestone contracts

| Milestone | Primary class | Scope / acceptance boundary | Hard dependency | Status |
|---|---|---|---|---|
| M001 portability foundation | infrastructure / invariant | shared modules build on macOS; Linux unaffected; explicit logical vs OS interface identity | Linux main baseline | closed 2026-10-13 (`plans/closure/macos-native-server/001-status.md`) |
| M002 Darwin privilege + IPC | invariant | native getpeereid authorization, secure socket lifecycle, bounded typed protocol and doctor | M001 | closed 2026-10-13 (`plans/closure/macos-native-server/002-status.md`) |
| M003 userspace WireGuard | capability / invariant | bundled/pinned foreground helper, utun ownership, UAPI peer CRUD, real handshake/telemetry | M002 | **blocked** 2026-10-13 — safe scope implemented (`plans/closure/macos-native-server/003-status.md`); live handshake needs disposable privileged host |
| M004 Darwin resources | capability / invariant | address/route apply/observe/verify, no foreign deletion, crash/utun churn tests | M003 | **blocked** 2026-10-13 — modeling scope implemented (`plans/closure/macos-native-server/004-status.md`); native convergence needs disposable privileged host |
| M005 forwarding/PF/NAT | invariant / capability | approved strategy, opt-in PF if lawful/suitable, observed filter+NAT and real traffic | M004 + explicit PF ADR gate | **blocked** 2026-10-13 — TN3165 advanced-admin-only decision + anchor model (`plans/closure/macos-native-server/005-status.md`); live traffic needs disposable privileged host |
| M006 launchd + distribution | infrastructure / capability | native services, install/reinstall/uninstall, ABI/build/release artifacts, rollback-safe behavior | M005 | **blocked** 2026-10-13 — installation scope implemented (`plans/closure/macos-native-server/006-status.md`, no PF auto-configuration); native install/boot/reboot/recovery needs disposable privileged host |
| M007 security + platform E2E | qualification | Apple Silicon and Intel native hardware/VM real traffic, external-state preservation, release policy | M006 | **blocked** 2026-10-13 — verdict recorded (`plans/closure/macos-native-server/007-status.md`): support matrix, threat review, MUST-NOT-release decision + unblock checklist; live dual-arch traffic + release readiness need disposable privileged hosts |

Plans: plans/implementation/macos-native-server/001 through 007.

## 6. Hard validation gates

- M001: Darwin cargo check --all-targets plus Rust MSRV and complete Linux CI; no fake stub of supported runtime roles. Typed backend contracts compile and have mock tests.
- M002: real macOS unauthorized user rejected, authorized service accepted, root not default universal bypass; socket stale/foreign/symlink race tests; SIGTERM and restart.
- M003: real utun creation, pinned wireguard-go child, UAPI read/write/handshake/counters, endpoint roaming; kill/respawn, PID reuse, stale name/sock, foreign utun preservation.
- M004: real macOS IPv4/IPv6 tunnel address/route convergence, idempotency, network change and foreign state tests; no blind default route.
- M005: default deny unqualified gateway mode; real forwarded IPv4 no-NAT/NAT traffic and IPv6 routed traffic; PF anchor attach and packet matching demonstrable (not just rule text), foreign PF and Internet Sharing coexistence tested; record TN3165 distribution decision.
- M006: launchd boot/restart, separate service users, helper binary provenance, installer transactional semantics, restored state compatibility; do not re-enable unsigned self-updates.
- M007: capture exact OS build, arch, hardware, interface names, routes, PF inventory, command outputs, remote client traffic, crash windows, and reproducible evidence; no unmeasured release readiness claims.

## 7. Risk and stop conditions

Stop for an unsupported or insecure macOS helper, untrusted executable lookup, ownership inference from utunN alone, inaccessible UAPI, ambiguous route deletion, PF root anchor overwrite, unsupported release trust, or an attempt to substitute mocked tests for real packet traffic. If an Apple-supported server-grade NAT integration is not viable and PF use does not meet the distribution decision, return to ADR-008 rather than advertising full gateway support.

Do not copy Linux nftables owner-table claims into PF: anchors must actually be reachable by parent filter/NAT rules and global rules can still override them. Dynamic uplink changes must trigger observation/re-evaluation, not unbounded high-frequency scans.

## 8. Handoff and closure

Every M00N requires a corresponding plans/closure/macos-native-server/00N-status.md with exact diff/head, verification, native macOS evidence, Linux regressions, security and foreign-state preservation matrix, known limitations, and disposition. Never create closure ahead of implementation. Update current-behavior docs only when supported functionality exists. Do not edit historical Linux closure records.
