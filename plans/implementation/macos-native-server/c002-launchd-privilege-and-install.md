# macOS Native Server C002 — Least-Privilege LaunchDaemons and Real Installer

Status: **interface-ready in parallel; integrated closure hard-blocked on C001**.
Baseline: `plans/macos-native-support@fc51146e811cabebd042d852449c6e7f4f854265`.
Source: corrective roadmap C002, original M002/M006 and `plans/closure/macos-native-server/{002,006,007}-status.md`.
Authority: ADR-008, privilege-boundary ADR-001, distribution ADR-006; macOS release policy checksums-only.
Primary class: corrective / invariant / infrastructure.

## Objective and missed evidence

Make the existing `src/launchd.rs` prototype a secure two-service, installable macOS deployment. Its two plists omit `UserName`/`GroupName`; when bootstrapped into the system launchd domain the default is a root process. A functional privileged `netd` does NOT justify running management HTTP/SQLite as root. Prior launchd fixtures verified process supervision, not an unprivileged effective UID for the application.

## Non-goals

No GUI, NetworkExtension, Homebrew requirement, automatic PF main-ruleset modification, unsigned self-update, systemwide VPN policy, or relaxation of existing Linux systemd identity/ownership contracts. Do not create a new generic privileged install command executor.

## Ordered work

1. **Define service identity:** set restricted durable `serve` service account/group and explicit root `netd` account in rendered LaunchDaemon plists; document whether dedicated system account is created by installer or a verified preprovisioned account is required. Ensure stable UID resolution and safe refusal on renamed/reused IDs. Use `UserName`/`GroupName` in a tightly constrained plist renderer; escape XML or generate structured plists with fixed schema. Forbid arbitrary launchd label, executable, env, working directory, user/group or log path injection.
2. **Filesystem and IPC:** design root-controlled executable/helper/plist/receipt directories, management-owned `/var/db/wg-basic` (0700; no root-mode `serve`), root-controlled `/var/run/wg-basic` socket parent (non-world-writable), socket owner/group/mode granting only the intended service identity, verified `getpeereid` and denial of other local/root identities unless explicitly approved. Check no root/admin session secret leakage to logs, argv, temp files, or process env. Probe and refuse symlinks/foreign inode replacement and TOCTOU; no world-writable parent.
3. **Installer CLI:** wire Darwin `system install/status/uninstall` in `src/main.rs` to verified exact-target `src/launchd.rs` install contracts. Privileged install must validate artifact/helper hashes, source/target names and ownership receipts before writing. Install bootstrap `netd` then `serve`, verify actual EUID/EGID, effective socket permissions, health and convergence, and handle partial launchctl failures transactionally without touching foreign labels. Installer must not silently edit PF configuration or enable systemwide forwarding. Preserve SQLite/client keys and admin sessions on state-preserving uninstall/reinstall, guard purge separately.
4. **Recovery and reboot:** SIGTERM drains, KeepAlive restarts both roles with bounded backoff, stale socket and helper ownership are resolved through C001 rather than blind helper kill. Prove system-domain boot after cold reboot, service user identity, DB preservation, complete network reconvergence and uninstall with no leaked jobs. Test native ARM64 and Intel: hosted temporary bootstrap alone does not prove reboot.
5. **Packaging truth:** install both pinned `wg-basic` binary and pinned `wireguard-go` helper from immutable exact-target metadata; prohibit execution of unverified downloaded bytes as root. No production signature or automatic updater claims; keep `update run/check` fail closed under existing trust policy.

## Security, persistence and failure semantics

`netd` alone is root; `serve` is a dedicated local principal, bound by directory/socket permissions, HTTP auth/CSRF and persisted state rules. A persisted install receipt is evidence, not proof of an arbitrary foreign file's ownership. An interrupted install cannot leave a permissive socket or elevated HTTP daemon. Existing SQLite migrations, rollback checks and Linux installation contract must remain compatible.

## Tests and acceptance

Static tests: refuse missing/invalid service identity and dangerous plist characters, verify XML exact entries and trusted path/labels, require effective UIDs, deny root management service launch, refuse foreign plist/helper/receipt, symlink swap, socket unauthorized peer, wrong hash and wrong architecture. Controlled host: initial install → health → API traffic from C001 → kill both roles → supervise → reboot → same keys/traffic → uninstall preserving DB → reinstall → identical identity, with foreign launchd jobs/route state preserved. Capture launchctl print, `id`/EUID, `stat` perms, process ownership, helper hashes and pre/post host inventory. Repeat Intel natively.

Require Linux CI, Darwin native CI, fmt/clippy/MSRV and rootful integration. **Block closure if `serve` runs as root**, if privilege identity is only inferred from plist text, if helper provenance is not checked at execution time, if Linux paths change, or if reboot persistence cannot be demonstrated. M006 historical closure remains as recorded; record corrective implementation and evidence in `plans/closure/macos-native-server-corrective/c002-status.md`.
