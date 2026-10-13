# macOS Native Server M006 — launchd Installation, Artifact Provenance, and Recovery

Status: planned; blocked on M005 verified gateway strategy and host-network closure
Primary class: infrastructure / capability
Roadmap: plans/subsystems/macos-native-server-roadmap.md M006
Baseline: main 47c72b0e81d569d48396c615120453bf0cf1d46e; reconcile with actual implementation head.
Authority: plans/000-long-term-specification.md; plans/002-long-term-roadmap.md; plans/003-planning-process.md; plans/adr/008-macos-headless-platform-backends.md; existing Linux ADRs remain in force.

## Objective

Install and supervise the complete headless macOS product on native arm64 and x86_64 systems, preserve secret-bearing state through uninstall/reinstall and failure recovery, and integrate Darwin artifact/helper identities with honest current release authenticity policy.

## Non-goals

No new GUI app, mandatory Homebrew, Docker, Network Extension entitlements, automatic signed self-update while no production signing root exists, or modifying existing Linux systemd units.

## Current repository evidence

src/distribution.rs is hardcoded to systemd/sysusers (/etc/systemd, /var/lib); src/update.rs uses service_endpoint('wg-basic.service'), systemd transaction journal paths; src/release.rs LinuxTarget only; release/eggpack/pack.toml and distribution.toml list GNU targets only; release pipelines have Linux-only assumptions. README says v0.1.0 checksums-only stable and self-update permanently fail-closed by maintainer decision.

## Mandatory invariants

- Real separate privilege domains under launchd with service UID/permissions; netd not HTTP/SQLite-capable.
- Install/uninstall checks owned exact service definitions, executable and helper hash; refuse modified/foreign files and launchd labels.
- No unverified download executes with root privileges; production signing claims remain absent until deliberately changed.
- SQLite installation ID, keys, sessions and ownership survive ordinary state-preserving reinstall and reboot.
- An updater never starts a binary against incompatible migrated SQLite schema; fail-closed self-update current policy unchanged.
- Linux targets and systemd behavior unchanged.

## Ordered implementation work

1. Research minimum supported Darwin versions/architectures and signed/notarized distribution choices, Mac launchd bootstrap domains/user-group service identities, recommended canonical state/runtime paths, file ACL/ownership and secure background process behavior.
2. Define native two-label system LaunchDaemon lifecycle, keepalive/throttle, SIGTERM/drain, restart ordering and netd helper process control. Install without private-key or admin password argv/environment leakage.
3. Implement platform-specific installer and owner receipts, helper source revision+hash, exact target packaging, unprivileged state/database initialization, secure directory creation and locked root transaction.
4. Add distribution targets aarch64-apple-darwin and x86_64-apple-darwin to Eggpack after verifying supported producer/validator behavior. Do not break Linux release pipeline; guard against mixing a macOS helper binary and Linux artifact. Provide platform-specific installation instructions and upgrade constraints.
5. Implement state-preserving uninstall and guarded destructive purge; process stop/disable, firewall detach/cleanup before helper teardown under M005 contract; preserve foreign service labels and PF state.
6. Prove health, backup/restore, crash-safe restart and rollback *mechanically in fixture*; no active production self-update without approved trust root and signed distribution policy.

## Security, persistence, protocol, failures and compatibility

macOS root daemon runs only verified exact binary + pinned helper with minimal filesystem/sockets; unprivileged management account alone owns encrypted/permission-restricted SQLite secrets. No uncontrolled helper PATH search. Test symlink/TOCTOU/foreign plist/receipt and copied install spoofing. Code signing/notarization must be documented (either provided and verified or expressly absent with release limits).

## Native and regression tests

Native arm64 launchd boot/install/reboot/kill/restart, preserve DB on uninstall, reinstall recover same keys, in-use helper crash and netd loss, rollback fixture with SQLite schema compatibility, modified binary/helper/plist refusal, foreign launchd labels, PF anchor preservation, network connection after reboot. Intel native installation evidence required for full dual-arch support. Linux systemd and update_transaction_rootful suites unchanged.

## Verification and documentation

Capture launchctl print, plist ownership, service identities, installed artifact hashes and OS/hardware versions, real tunnel traffic, before/after system and PF state. Run macOS native test commands plus full Linux CI. Update docs/installation.md, docs/release-signing.md and release tooling after observing evidence.

## Explicit acceptance criteria

Both macOS targets have provenance-bound artifacts and platform-target selection, real service manager lifecycle, exact helper identity, successful reboot and same client traffic, state-preserving install/uninstall, safe recovery. Installer never claims unsupported signing or self-update assurance. Linux remains qualified.

## Stop conditions

If helper or root service can be replaced silently, privileged installer overwrites foreign destination, launchd restart cannot preserve ownership, rollback risks incompatible DB/schema, or a platform target cannot be natively qualified: stop, label target unsupported, do not ship.

Only after implementation write plans/closure/macos-native-server/006-status.md with exact head, commands/results, native host evidence, preservation and privilege matrix, unresolved severity-graded findings, docs, and a justified closure disposition. Do not edit historical Linux closure evidence.
