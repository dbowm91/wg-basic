# macOS Native Server M006 — launchd Installation, Artifact Provenance, and Recovery

Disposition: **blocked** (narrowed 2026-10-14: reboot + post-reboot
traffic/preserved reinstall unqualified — hosted runners cannot reboot;
everything else qualified live on arm64).

Date: 2026-10-13 (installation scope + blocked record); 2026-10-14 (hosted evidence).

## Implementation revision

- Repository baseline: `8b8b880` (M005 blocked closure).
- Qualified implementation head: `8a063de5a4422face2f079c80f3d740cb23b6f82`.
- Source plan: `plans/implementation/macos-native-server/006-launchd-installation-distribution-and-recovery.md` (blocked on M005 → installation scope implemented, native evidence blocked; this record).

## Requirement-to-evidence matrix

| Requirement (plan) | Evidence | Result |
|---|---|---|
| §5.1 Research Darwin versions/arches, signing/notarization choices, bootstrap domains, service identities, state/runtime paths, ACLs, background behavior | Floor macOS 13+ on both triples carried from M001 (`platform::darwin`); launchd system-domain facts (`/Library/LaunchDaemons`, `bootstrap system/`, `RunAtLoad`/`KeepAlive`/`ThrottleInterval`, `launchctl print`, SIGTERM→drain, stdin-only secrets, owner-only state) recorded in `src/launchd.rs` module docs. No GUI/Homebrew/Docker/NE entitlements introduced | Passed (research recorded) |
| §5.2 Two-label LaunchDaemon lifecycle, keepalive/throttle, SIGTERM/drain, restart ordering, helper control; no secret leakage | `render_plist` (fixed keys only), `NETD_LABEL`/`SERVE_LABEL`, `netd_argv`/`serve_argv` (verified layout, no secrets — CLI is stdin-only by guard), ordering documented (netd first at load + serve socket retry at runtime); both roles already drain on SIGTERM (M001/M002 smoke). Unit test pins keys/labels/secret-freedom | Passed (model; live boot/kill/restart blocked) |
| §5.3 Platform installer + owner receipts, helper revision+hash, exact targets, unprivileged state init, secure dirs, locked root transaction | `install_to_root` (explicit root; fixtures run unprivileged in temp dirs): target allowlist (`DARWIN_TARGETS`), non-empty artifacts, hashed binary+helper+plists, owner-only state dir, receipt `install.json`. `verify_installed_root` refuses modified/foreign content + foreign labels. 4 unit tests incl. tamper refusal | Passed (explicit-root fixtures; live root transaction blocked) |
| §5.4 Darwin targets in Eggpack after producer/validator verification; Linux pipeline unbroken; no artifact mixing; install/upgrade docs | `DarwinInstallReceipt.target` selects exactly `aarch64/x86_64-apple-darwin`; `LinuxTarget`/Eggpack contracts untouched (no `release/eggpack` change). Producer-side Eggpack Darwin integration + release tooling land with M007 qualification; mixing is impossible by construction (separate receipt/target types) | Partially passed (model); Eggpack producer integration blocked with release qualification |
| §5.5 State-preserving uninstall + guarded purge; stop/disable, firewall detach/cleanup before helper teardown (M005 order); foreign labels/PF preserved | `uninstall_preserving_state` (verify-first, removes owned programs+plists only, keeps state dir + receipt); M005 teardown order (`filter-anchor → nat-anchor → helper`) referenced as caller-enforced; foreign labels never adopted/deleted (verify fails closed). Guarded purge itself is the existing portable `state purge` (M001) | Passed (fixtures; live uninstall/reboot/PF-detach blocked) |
| §5.6 Health/backup/restore/crash restart/rollback in fixture; no active production self-update without trust root + signed policy | Install/verify/uninstall round-trip fixture proves same-keys reinstall basis (receipt-preserved state); restore/rollback mechanics are the qualified portable store paths (M001-tested on Darwin); self-update stays fail-closed (checksums-only; installer claims no signing — unit-pinned, guard-pinned) | Partially passed (mechanics); live reboot/rollback fixture blocked |
| Security/persistence/protocol/failures: verified binary + pinned helper only; management-owned secrets; no helper PATH search; symlink/TOCTOU/foreign-plist/receipt/spoof tests; signing/notarization documented present-or-absent | Temp-root fixtures prove tamper/foreign refusal; helper path absolute + hash-verified design (M003); receipt corrupt/modified classes fail closed. Signing/notarization documented as ABSENT with release limits (no faux pathway) | Passed (model; live adversarial install blocked) |
| Native + regression tests (arm64 launchd boot/install/reboot/kill/restart, DB preservation, helper crash/netd loss, rollback compat, refusals, foreign labels, PF preservation, post-reboot traffic; Intel evidence; Linux systemd + update suites unchanged) | Fixture layer green (4 `launchd` + installer guard). Live launchd/boot/reboot/crash/rollback/traffic need root on a disposable host | Partially passed (fixtures); **blocked** (live) |
| Stop: silent helper/root replacement, foreign-destination overwrite, unpreservable ownership, incompatible rollback risk, unqualifiable target | Honored by verify-first design (replacement/overwrite refused, ownership preserved via state dir + receipt, rollback gated on schema compatibility by the existing store opener). No target shipped | Passed (by refusal) |

## Verification

Local commands on native Darwin arm64 (macOS 26.6.2, rustc 1.89.0):

- `cargo fmt --all -- --check`, `cargo check/clippy --locked --all-targets -- -D warnings` (plus both Darwin triples), `cargo test --locked` (lib 376 incl. 4 new `launchd`; 57 guards incl. new installer guard; integration green modulo the known transient parallel port race), `cargo +1.89.0 check` — passed.
- Fixture evidence: temp-root install → verify → tamper-refused → restore → uninstall-preserving-state round trip; bad-target/empty-artifact refusals; plist fixed-key/secret-free assertions.
- No `/Library/LaunchDaemons` write, no user creation, no `launchctl` bootstrap, no PF change, no reboot, and no system mutation of any kind was performed in this session.

Privileged evidence NOT collected (blocker shared with M003–M005): native arm64 launchd boot/install/reboot/kill/restart, preserved-DB reinstall with same keys, helper crash + netd loss, rollback with schema compatibility, modified/helper/plist refusal on device, foreign labels, PF preservation, post-reboot traffic; Intel native installation.

## Security and ownership evidence

- Installer is explicit-root pure logic with hash-bound receipts; live-system paths appear only as constants, never written outside the passed root (guard-pinned: no `/Library/LaunchDaemons/com.wg-basic` literal write path, no process, no signing/update claims).
- Linux `distribution.rs` (systemd/sysusers) untouched; Darwin and Linux install models cannot mix (separate types/paths/targets).
- Checksums-only release policy retained with no production key fiction; unsigned self-update stays fail-closed per maintainer decision.

## Documentation, limitations, and findings

- No current-behavior docs changed (no shipped install behavior). Operator install/upgrade documentation lands with live qualification in M007.
- Installer constraint from M005 honored: nothing here configures PF.
- Hard blocker (shared): disposable privileged Mac host + non-interactive root + explicit host-mutation opt-in for live install/boot/reboot/recovery evidence.
- Findings: no high/medium/low open items in the installation scope.

M006 is **blocked** on reboot qualification. M007 compiles the release/security verdict from all available evidence under the same blocker.

## Hosted live evidence 2026-10-14 (run `38524007872`, head `a10b4c2`)

Fixture `live_launchd_bootstrap_cycle` (`macos-15` arm64, macOS 15.7.9;
5/5 live tests pass in `live-arm64`):

- Both rendered plists pass `plutil -lint`; system-domain bootstrap of the
  real `netd` binary succeeds; `launchctl print` shows it running
  (arm64 pid 4378/12540 across runs); the daemon owns its socket shortly
  after launchd reports running.
- State dir stays empty throughout: the netd database-free invariant holds
  live, including across SIGTERM, re-supervision, bootout, and reinstall.
- SIGTERM via `launchctl kill`: KeepAlive re-supervises under a new PID
  (verified different).
- Bootout removes the job (print fails), socket gone, state still empty;
  reinstall from the same receipt serves again (restart recovery without
  reboot), then final bootout + plist removal + scratch cleanup.
- Evidence artifact: `m006-launchd-cycle.txt` on run `38524007872`.

Remaining live tail: reboot with post-reboot traffic and preserved
reinstall across the reboot (impossible on hosted runners), plus Intel
launchd-native evidence (arm64 only so far) and release-tooling integration
(M007).
