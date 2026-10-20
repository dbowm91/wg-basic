# macOS Native Server C002 — Least-Privilege LaunchDaemons and Real Installer

Disposition: **blocked** (narrowed 2026-10-20: the service identity, the
constrained installer, the bounded launchd control, and the hosted
bootstrap/KeepAlive/bootout/reinstall cycle are implemented and evidenced; the
**three-phase cold-reboot qualification is written and armed on a controlled
arm64 host** — it installs the deployment, enrolls a client through the real
HTTP surface, records what has to survive, and registers the boot-time job
that verifies it in the new boot — but the reboot itself has not been taken,
so the plan's acceptance still needs a **cold reboot on a rebootable host**,
which hosted macOS runners cannot prove — the same reboot gap M006 already
records).

Date: 2026-10-20.

## Implementation revision

- Repository baseline: `0887964` (the C001–C005 corrective handoff).
- Implementation head: `1806d3e` ("macos(c002): release the privileged socket when the daemon is stopped"),
  on top of `c9f8fc9` ("macos(c002): read the effective identity the way BSD ps
  reports it"), on top of `e4f47d5` ("macos(c002): own the receipt and the privileged
  socket explicitly"), `1d8ca63` ("macos(c001,c002): fix the Darwin interface
  inventory and the hosted live failures") and `e94306c` ("macos(c001,c002): wire the
  production Darwin host-only backend and installer"). The C002 live qualification
  `live_c002_management_daemon_runs_unprivileged` is in `1d8ca63` and drives the
  product's own installer from `e4f47d5`.
- Source plan: `plans/implementation/macos-native-server/c002-launchd-privilege-and-install.md`.
- Source roadmap: `plans/subsystems/macos-native-server-corrective-roadmap.md` (C002).
- Historical M006 and M007 closures are untouched and remain as recorded.

## Requirement-to-evidence matrix

| Requirement (plan) | Evidence | Result |
|---|---|---|
| §1 Service identity: restricted durable `serve` service account/group and an explicit root `netd` account in the rendered LaunchDaemon plists; document whether the installer creates the account or a verified preprovisioned account is required; stable UID resolution and safe refusal on renamed/reused IDs; `UserName`/`GroupName` in a tightly constrained plist renderer; escape XML or generate structured plists with a fixed schema; forbid arbitrary label, executable, env, working directory, user/group, or log path injection | `src/launchd.rs`: `ServiceRole` owns the label, the account, the group, and the log path; `NETD_USER = "root"`, `NETD_GROUP = "wheel"`, `SERVE_USER = "_wg-basic-serve"`, `SERVE_GROUP = "_wg-basic-serve"`. `render_service_plist(role)` takes **no** caller path at all: the executable, the socket, the state, and the log path are the deployment's own, and every interpolated value is XML-escaped with control characters refused. `resolve_service_identity` resolves the account through the directory service and refuses a missing account, an account below `MIN_SERVICE_UID` (macOS reserves UIDs below 500), and an account whose primary group is not the dedicated group. **The account is preprovisioned**: the installer never creates accounts and never adopts an unknown identity | Passed (code + unit) |
| §2 Filesystem and IPC: root-controlled executable/helper/plist/receipt directories, management-owned `/var/db/wg-basic` (0700, no root-mode `serve`), root-controlled `/var/run/wg-basic` socket parent (non-world-writable), socket owner/group/mode granting only the intended service identity, verified `getpeereid`, denial of other local/root identities unless explicitly approved; no root/admin session secret leakage to logs, argv, temp files, or process env; refuse symlinks/foreign inode replacement and TOCTOU; no world-writable parent | `src/launchd.rs`: `STATE_DIR_MODE = 0700` (management-owned), `RUNTIME_DIR_MODE = 0755` (root-controlled, never world-writable), `SOCKET_MODE = 0660`, `LOG_DIR_MODE = 0755`, `LOG_FILE_MODE = 0640`, `RECEIPT_MODE = 0600`. `secure_directory`/`secure_file` refuse a symlink in place of an owned path; `verify_installed_root` re-checks the exact modes and refuses a widened runtime directory. `authorize_socket_group` binds the socket to root and the management group. The privileged daemon admits the management UID that the **verified install receipt** records, and the UDS peer identity is the existing `getpeereid`/`SO_PEERCRED` path in `src/protocol/auth.rs`. The CLI is stdin-only, so no secret reaches argv, a log, a temp file, or the process environment | Passed (code + unit) |
| §3 Installer CLI: Darwin `system install/status/uninstall` wired to the verified exact-target install contracts; validate artifact/helper hashes, source/target names, and ownership receipts before writing; bootstrap `netd` then `serve`; verify the actual EUID/EGID, effective socket permissions, health, and convergence; handle partial `launchctl` failures transactionally without touching foreign labels; never silently edit PF or enable systemwide forwarding; preserve SQLite/client keys and admin sessions on state-preserving uninstall/reinstall, with the purge guarded separately | `src/main.rs` wires `system install --helper PATH`, `system status`, and `system uninstall` on Darwin to `src/launchd_install.rs`. The installer requires effective root, refuses a symlinked or non-regular binary or helper, pins the exact Darwin target triple, writes and verifies the owned layout, resolves and binds the management identity, applies the management ownership, bootstraps `netd` then `serve`, and **rolls back the first registration** if the second fails. It never touches PF or forwarding, and `uninstall_preserving_state` keeps the state directory and the receipt. The purge stays the separate guarded `state purge` | Passed (code + unit); live EUID proof in the hosted run |
| §4 Recovery and reboot: SIGTERM drains, KeepAlive restarts both roles with bounded backoff, stale socket and helper ownership resolved through C001 rather than a blind helper kill; prove system-domain boot after a cold reboot, service user identity, DB preservation, complete network reconvergence, and uninstall with no leaked jobs; test native ARM64 and Intel (hosted temporary bootstrap alone does not prove reboot) | `RunAtLoad` + `KeepAlive` + `ThrottleInterval` remain in the rendered plists; both roles already drain on SIGTERM. The hosted live cycle proves bootstrap, `launchctl print` with a running pid, KeepAlive re-supervision under a **new pid** after SIGTERM, bootout with the job gone from the system domain, and a reinstall cycle that serves again from the same receipt with a byte-identical helper. Stale socket and helper ownership are resolved through the C001 receipt and joint ownership proof, never a blind kill. The **cold reboot** qualification is written as three phases — `arm` installs the deployment, enrolls a client through the real HTTP surface, records the client, the peer, the interface, and the management identity, and installs the boot-time job; `reboot` takes the host down; `verify` runs in the new boot and checks that both roles came back from the system domain, that the management daemon still runs as the unprivileged identity, that the state database still authenticates the same credential and still holds the same client and peer, that the network reconverged, and that the uninstall leaves no job, plist, or binary behind. The arm phase is **observed and passing** on a controlled arm64 host (see *Verification* below); the reboot has not been taken, so the system-domain boot after a cold reboot, the database preservation across it, and the post-reboot reconvergence remain unqualified | Partially passed (hosted restart cycle; armed cold-reboot arm phase); **blocked** on the cold reboot |
| §5 Packaging truth: install both the pinned `wg-basic` binary and the pinned `wireguard-go` helper from immutable exact-target metadata; prohibit execution of unverified downloaded bytes as root; no production signature or automatic updater claims; `update run/check` stays fail closed | `install_to_root` takes the exact bytes of both artifacts, hashes them, records both digests in the owner-only receipt, and refuses an unsupported target triple or an empty artifact. The helper netd later executes is hash-verified against the receipt **at execution time** (`verify_helper_sha256` runs before every spawn), so unverified bytes are never executed as root. The module contains no signing claim and no updater enablement, and the existing guard `no_production_signing_claim_exists` still holds | Passed (code + unit) |
| Static tests: refuse a missing/invalid service identity and dangerous plist characters; verify the exact XML entries and the trusted paths/labels; require effective UIDs; deny a root management service launch; refuse a foreign plist/helper/receipt, a symlink swap, a socket unauthorized peer, a wrong hash, and a wrong architecture | `src/launchd.rs` unit tests cover the fixed keys and identity in the rendered XML, the refusal of a control character, the symlink refusal in place of an owned directory, the non-world-writable runtime directory, the wrong target triple, and the empty artifact. New architecture guards `the_darwin_launchd_control_is_a_closed_verb_and_target_set`, `the_darwin_management_daemon_is_never_root`, `the_darwin_netd_always_sets_the_privileged_socket_ownership`, and `the_management_identity_owns_the_receipt_it_reads` pin the bounded `launchctl` boundary, the non-root management account, the socket's ownership, and the receipt's owner. The native live test `live_c002_management_daemon_runs_unprivileged` runs the product's own transactional installer, reads the **real** effective UID and GID of each running daemon with `ps`, and the **real** socket owner, group, and mode with `stat` | Passed (code + unit); live runtime UID proof in the hosted run |
| Controlled host: initial install → health → API traffic from C001 → kill both roles → supervise → reboot → same keys/traffic → uninstall preserving DB → reinstall → identical identity, with foreign launchd jobs and route state preserved; capture `launchctl print`, `id`/EUID, `stat` perms, process ownership, helper hashes, and the pre/post host inventory; repeat Intel natively | The hosted ARM64 and Intel runs capture `launchctl print`, the effective UIDs, the socket permissions, and the helper digests, and prove the install → bootstrap → SIGTERM → supervise → bootout → reinstall cycle with the layout verified against its receipt. The API-traffic leg is **met on arm64** by C001's controlled-host product path (real installer, real daemons, real handshake, dual-stack traffic, API telemetry) — see `c001-status.md`. The **cold-reboot** leg is written and armed on a controlled arm64 host; the reboot itself has not been taken, and the Intel leg beyond the hosted restart cycle remains unqualified | Partially passed (hosted ARM64 + Intel; arm64 API-traffic leg; armed cold-reboot arm phase); **blocked** on the reboot |
| Blockers: never close if `serve` runs as root, if the privilege identity is only inferred from plist text, if helper provenance is not checked at execution time, if Linux paths change, or if reboot persistence cannot be demonstrated | `serve` is declared and, in the live qualification, **observed** as the dedicated unprivileged account; the identity is read from the running process, not from the plist text. The helper digest is checked before every spawn. No Linux path, unit, service, or schema changed: the Linux reconciliation service now shares the same portable apply module with byte-identical plan and failure mapping, and the Linux build and clippy are clean. Reboot persistence is **not** demonstrated | **Blocked** on the reboot condition |

## Verification

Native Darwin arm64 (macOS 26.6.2, rustc 1.89.0), run from the repository root:

- `cargo fmt --all -- --check` — passed.
- `cargo clippy --locked --all-targets -- -D warnings` — passed.
- `cargo test --locked` — passed: 641 tests, 0 failures, including the new `launchd` identity, renderer, layout, and symlink tests and the seven new architecture guards. The suite was run four times in a row after the scratch-path fix; every run was green.
- `cargo test --locked -p wg-basic-darwin-sys` — passed: 9 tests.
- `cargo check --locked --target aarch64-apple-darwin` and `--target x86_64-apple-darwin` — passed.
- `cargo zigbuild --locked --target x86_64-unknown-linux-gnu --all-targets` — passed (the Linux **test** targets compile too; several modules and fixtures exist only on Linux and a macOS build never sees them).
- `cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets -- -D warnings` — passed, with and without the `linux-integration` feature.
- The branch's Linux `cargo clippy --all-targets --locked -- -D warnings` gate was **red before this change** (a dead `getsockopt`/`PeerCredentials` import left behind in `src/protocol/socket.rs` by the M002 refactor). It is removed here and the gate is green again.
- The `dependency-audit` CI job fails on **pre-existing** upstream advisories in `zip 6.0.0` reached through `eggup-archive = "=0.1.3"`. It is unrelated to C002 and is recorded as an unresolved finding below. Every other job of Linux native CI run `39427800154` passes: `rust`, `doctor-readonly`, `system-install-systemd`, `wireguard-kernel`, `network-control-e2e`, `network-reconcile-kernel`, `product-management-rootful`, `durable-owner`, `durable-backup`, `durable-restart`, `maintenance-rootful`, `upgrade-rehearsal`, `upgrade-rehearsal-rootful`, and `update-transaction-rootful`.

Native hosted macOS qualification, run `39427791794` on `plans/macos-native-support`:
**all four jobs passed** — `gates-arm64`, `gates-intel`, `live-arm64`, and
`live-intel-tunnel`. The C002 live qualification passed on the hosted arm64
runner and wrote its evidence to the run's `macos-live-evidence-arm64`
artifact:

```
the transactional installer completed the deployment
system/com.wg-basic.netd:  state = running | last exit code = (never exited)
system/com.wg-basic.serve: state = running | last exit code = (never exited)
netd pid=4573 euid=0 egid=0; serve pid=4575 euid=8998 egid=8999
socket owner=root(0) group=_wg-basic-serve(8999) mode=660
install receipt uid=8998 (management uid=8998)
teardown complete: roles stopped, account removed
```

That is the C002 claim itself, observed rather than asserted: the privileged
daemon runs as root, the management daemon runs as the dedicated unprivileged
account, the privileged socket is root-owned and reachable only by the
management group, and the management identity owns the receipt it reads. The
M006 launchd cycle in the same run recorded `bootout complete: job gone,
socket gone, state preserved-empty` and `reinstall cycle: same receipt serves
again after bootout`.

Three earlier hosted runs of this line failed, and every failure was a real
defect in this change rather than an environment gap: run `39420943827` (the
M006 launchd cycle asserted a synchronous socket removal), run `39423536138`
and run `39425260093` (the C002 qualification left a job registered when it
failed, which broke the M006 cycle that runs after it; the privileged socket
kept an inherited group; the receipt was unreadable by the management daemon;
and the daemon did not release its socket when it was stopped during
startup). The root causes are recorded under *Unresolved findings by severity*
below.

### Arm64 controlled-host cold-reboot qualification (arm phase)

The cold-reboot leg was run as root on a disposable arm64 Mac (macOS 26.6.2,
rustc 1.89.0). The **arm phase** is observed and passing:

```
the transactional installer completed the deployment
the administrator was provisioned as the management identity
the product enrolled client 05acb66f-7658-40d7-aa39-21bcf0ad0233 with public key dJxTT6v9Dbs/WmKAhwsdZTYYV808ltE/4wEfa/NysGw=
recorded the expectations that must survive the reboot at /var/db/wg-basic-qual/reboot-expectations.json
the boot-time job is installed and will run in the next boot, not now
```

The host was left in that state: `netd` running as `root`, `serve` running as
`_wg-basic-serve`, the managed tunnel's helper running, the state database
owned by the management identity, and the boot-time job installed at
`/Library/LaunchDaemons/com.wg-basic.qual-reboot.plist`.

The **reboot has not been taken**: the maintainer deferred it, because it
takes down the machine the qualification runs on. The reboot leg therefore
remains unqualified, and this record does not claim it. The boot-time job
runs the verify phase at the next boot of that host, which checks the
system-domain boot, the unprivileged identity, the preserved database and
client, the reconvergence, and the clean uninstall — and writes its evidence
to `/tmp/wgb-qual/evidence/c002-cold-reboot-verify.txt`.

## Security and ownership evidence

- `netd` is the only root component. `serve` is a dedicated unprivileged local
  principal, declared in the plist **and** observed at runtime by effective
  UID.
- The management account is preprovisioned and verified. The installer never
  creates accounts and never adopts an unknown identity; a renamed, reused, or
  reserved identity is refused.
- The privileged socket is `0660`, owned by root and the management group, and
  the privileged daemon admits only the management UID the verified receipt
  records.
- The layout is exact: a symlink anywhere in the owned layout is refused, a
  widened runtime directory is refused, and a modified binary, helper, or
  plist is refused by digest.
- The only process the product runs on Darwin is `launchctl`, from
  `src/launchd_install.rs`: an absolute path, a closed verb set, a closed
  target set, no shell. The pure layout module contains no process execution
  at all, and the architecture guards pin both facts.

## Docs and operations evidence

- `architecture/privilege-boundary.md` — the Darwin service identity, the
  socket ownership contract, and the isolated OS boundary.
- `architecture/overview.md` — the module index now names `src/launchd.rs`,
  `src/launchd_install.rs`, and `crates/darwin-sys`.
- `docs/development.md` — the Darwin gate list now includes the boundary
  crate's suite.

## Known limitations

1. **Cold-reboot persistence is unqualified.** Hosted macOS runners are
   discarded after the job, so a system-domain boot after a reboot, the
   database preservation across it, and the post-reboot reconvergence cannot
   be observed there. The three-phase qualification is written and its arm
   phase is observed and passing on a controlled arm64 host; the reboot
   itself has not been taken, so the leg is not claimed. The hosted restart
   cycle (SIGTERM → KeepAlive re-supervision → bootout → reinstall) is
   proven; the reboot is not.
2. **The management account must be provisioned out of band.** The installer
   deliberately does not create accounts, so a deployment needs a
   preprovisioned `_wg-basic-serve` account and group first. This is
   documented, not accidental.
3. **`serve` is now exercised as a paired deployment against real API
   traffic** on the arm64 controlled host — C001's product path drives the
   installer, the privileged daemon, the unprivileged management daemon, the
   authenticated HTTP surface, and an off-host peer. The native Intel arch of
   that pairing is still unqualified, because a hosted runner cannot reach
   the off-host peer.
4. **The controlled host is left armed.** The product is installed on it, a
   client is enrolled, and the boot-time job is in place: at the next boot of
   that host the verify phase runs, checks the deployment, uninstalls it, and
   writes its evidence. Until that happens the host carries the deployment.
5. **No release claim exists.** ADR-008/M007 still withhold every macOS
   release; this record changes nothing about that.

## Unresolved findings by severity

- **Medium (pre-existing, out of scope):** the `dependency-audit` CI job fails
  on three upstream `zip 6.0.0` advisories reached through `eggup-archive =
  "=0.1.3"`. Not resolvable in this repository without an upstream release.
- **Low (pre-existing, fixed here):** the dead `getsockopt`/`PeerCredentials`
  import in `src/protocol/socket.rs` had the branch's Linux `-D warnings` gate
  red before this change; it is removed here.
- **Low (introduced by this change, fixed here):** the cold-reboot qualification registered its boot-time job with `launchctl bootstrap`, which **starts a `RunAtLoad` job immediately**. The verify phase therefore ran against a host that had not rebooted yet, uninstalled the deployment it was supposed to check, and removed itself. The job is now installed by writing the plist only: a plist in `/Library/LaunchDaemons` is loaded by launchd at the next boot, which is the behaviour the leg has to prove.
- **Low (introduced by this change, fixed here):** the rewritten M006 live test
  first asserted the daemon socket was already gone five milliseconds after
  `launchctl bootout`. `bootout` is asynchronous — launchd unloads the job and
  then asks the daemon to stop — so the assertion raced the shutdown. The test
  now observes the socket's disappearance, and the wait that followed then
  exposed the product defect recorded above.
- **Low (pre-existing, fixed here):** the test scratch paths were suffixed with
  `SystemTime::now()` nanoseconds. The macOS wall clock is coarse enough that
  concurrent tests routinely receive the same value, so two tests collided on one
  directory (`AlreadyExists`) and the gate failed intermittently. Reproduced at
  the pre-C001 baseline `0887964`. The scratch paths now use a per-process
  counter.
- **Medium (introduced by this change, fixed here):** the install receipt lived
  inside the management-owned state directory but stayed root-owned with mode
  `0600`, so the management daemon could not read the receipt it needs for the
  helper digest and for its own identity. The receipt now belongs to the
  management identity.
- **Medium (introduced by this change, fixed here):** the privileged socket was
  created with the creating process's group and left with it. That group is not
  an identity this product chose, so a socket left with it would be reachable by
  every process in it. The privileged daemon now always sets the socket's
  ownership explicitly: the management group when an identity is recorded, and
  its owner alone otherwise. The hosted run observed exactly this — the socket
  was `root:daemon`, a group this product never chose.
- **Medium (introduced by this change, fixed here):** the stop handler was
  installed after the socket was bound, so a daemon that was asked to stop while
  it was still starting up was killed by the default signal action, never ran
  its cleanup, and left its socket file behind. The hosted qualification
  showed exactly this. The handler is now installed before the bind, and a
  stop request that arrived during the bind releases the socket.
- **Low (introduced by this change, fixed here):** the operational events
  fixture stopped the daemon as soon as its port accepted a connection. The
  readiness event is written after the listener is bound, so the stop could win
  that race and the fixture could observe a daemon that never reported that it
  started. It now waits for the event.
- **Low (introduced by this change, fixed here):** the Linux-only reconciliation
  test module lost two imports when the shared apply module was factored out,
  and a Linux-only import in the doctor fixture became unused. Neither is
  visible from a macOS build. The Linux test targets are now compiled locally
  as well, and `docs/development.md` records the cross-compile gate.

## Disposition

**Blocked.** The implementation is complete: the management daemon is a
dedicated unprivileged principal, the plist renderer is fully constrained, the
filesystem and IPC layout is exact, the installer is transactional, and the
helper's provenance is checked at execution time. The hosted qualification
run `39427791794` is green and the C002 claim itself is observed there: the
privileged daemon runs as root, the management daemon runs as the dedicated
unprivileged account, and the privileged socket is root-owned and reachable
only by the management group. The API-traffic leg is met on the arm64
controlled host by C001's product path, and the cold-reboot qualification is
written with its arm phase observed and passing.

What is still open is the reboot itself: the plan's acceptance explicitly
blocks closure when "reboot persistence cannot be demonstrated", and the
reboot has not been taken on the armed controlled host. Closure is therefore
not claimed from expected evidence. C005's hard dependency on C002 stays
**blocked**.
