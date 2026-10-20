# macOS Native Server C005 — Native E2E, Distribution, and Release-Gate Reconciliation

Status: **blocked** (hard C001+C002 for any product qualification; C003 required for routed claims; C004 required for gateway claims; external controlled host and maintainer authorization required for release).
Baseline: `plans/macos-native-support@fc51146e811cabebd042d852449c6e7f4f854265`.
Source: corrective roadmap C005; M006/M007 plans and `plans/closure/macos-native-server/{006,007}-status.md`; ADR-008 and ADR-006.
Primary class: corrective / qualification / release invariant.

## Objective

Finish the actual product integration/security/recovery/distribution validation rather than treating low-level M003/M004 runner fixtures as a releasable VPN appliance. Produce a support matrix with **exact** capability and architecture labels, a documented honest release recommendation, and no implicit authorization to publish or relax M007.

## Non-goals

No production release or tag from this corrective, no silent alteration of the checksums-only trust policy, no blanket “macOS supported” from a compile or loopback peer, no default macOS self-update, no retroactive editing of previous M007/Phase 10 closures.

## Ordered work

1. **Select scoped claim:** inventory C001 host-only, C002 installed service identity, C003 routed LAN, C004 opt-in PF/NAT independently. For a contemplated earlier host-only/routed release, require an explicit maintainer-approved ADR-008 addendum and an explicit amendment of M007 gate scope *before* authorizing a release. Without that decision, original full-gateway NAT + IPv6 + reboot + dual-arch M007 gates remain binding for every macOS release. Do not represent intermediate modes as public support solely because their code works.
2. **Real product E2E:** fresh host user/bootstrap/SQLite, auth + CSRF, server setup, enrollment, exported Linux-kernel client configuration, peer add/delete, handshake, IPv4/IPv6 packets, telemetry, health and doctor through the real app. Confirm exact desired/applied generation across interface, helper and firewall; disabled state and foreign VPN preservation.
3. **Native lifecycle:** app/helper/netd crashes, double instance, partial install, checksum tamper, network switch, sleep/wake, cold reboot and post-reboot traffic, state-preserving uninstall and same-client-key reinstall, DB backup/restore and old-version rollback. Prove `serve` EUID is not root, `netd` is appropriately privileged, no secret leakage and no permissive IPC. Qualify Intel launchd natively, not just cross-compilation/Rosetta.
4. **Supply chain and release integration:** make pinned `wireguard-go` per-target helper a declared, immutable build input with recorded upstream commit/tag, MIT license, Go compiler/toolchain and SHA-256 evidence. Integrate `aarch64-apple-darwin` and `x86_64-apple-darwin` targets into Eggpack only after checking producer/consumer capabilities and distribution policy; produce exact-target package/binary + helper + receipts + install/uninstall; deny cross-architecture mixing and malformed installer manifest. Record binary/provenance/SBOM/advisory/license and actual release-mode RSS/CPU/latency. Preserve Linux artifacts and release behavior. **No code-signature claim without actual signing/notarization; no signed-manifest or active updater unless a separate approved trust policy is implemented.**
5. **Documentation/decision:** update README, CLI help, current architecture, docs/installation, operator runbook, security notes, target/version matrix and registry *after implementation evidence*, not in advance. Run maintainer review and record exact supported modes and floors (macOS 13+ is an unqualified aspiration until version-specific native evidence exists); an unsupported OS/arch/mode must visibly refuse. Track advisories, high/medium findings and production prerequisites.

## Required qualification evidence and stop gates

Routine Rust fmt/check/clippy/test/MSRV; native debug + release binaries; reproducible command/log/artifact digests; full existing Linux kernel/namespace, product UI, systemd and distribution/rootful CI. Repeat run on native Apple Silicon and Intel; for OS floors use actual tested versions or narrow stated support. Real off-host Linux kernel peers and effective traffic matching each claimed mode, separate administrator PF host for gateway, repeat cold reboot, crash/roaming, adverse foreign configurations and no-footprint-regression measurements. Record all native OS builds, target triples, installed SHA256s, user IDs, exact linked CI run IDs, PF/route inventories and failures (no silent test skips).

MUST-NOT-release remains until all targeted-mode security and operational gates pass and a specific maintainer authorization changes the recorded verdict under the proper ADR/release-policy authority. Gateway claims require C004 full NAT + routed v6. Any missing Intel service lifecycle, boot recovery, provenance, foreign preservation, privilege separation, or real packet evidence blocks claims for that target/mode. Write only a new `plans/closure/macos-native-server-corrective/c005-status.md` with evidence, severity-rated residuals and explicit release verdict; never overwrite M007 historical closure.
