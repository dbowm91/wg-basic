# macOS Native Server M007 — Native macOS End-to-End, Security, and Release Qualification

Disposition: **blocked** (verdict recorded; native dual-arch traffic unqualified — macOS server MUST NOT release).

Date: 2026-10-13

## Implementation revision

- Repository baseline: `48cf163` (M006 blocked closure).
- Verdict head: this record (no new runtime code; measurements + audit on `48cf163`).
- Source plan: `plans/implementation/macos-native-server/007-native-e2e-security-release-qualification.md` (blocked on M006 → verdict recorded here).

## Requirement-to-evidence matrix

| Requirement (plan) | Evidence | Result |
|---|---|---|
| §5.1 Reproducible release-like artifacts + SHA/metadata + helper provenance; executable/dependency/SBOM/advisory audit, helper license, platform privileges | `wg-basic 0.1.0` debug binary sha256 `d34651ae…`, `--help` retains Linux-native wording; helper `wireguard-go 0.0.20250522` (`f333402b…`, MIT) dev-built darwin/arm64 4,690,802 bytes sha256 `1339b938…`; `cargo` gates green on both Darwin triples + MSRV 1.89. Full SBOM/advisory scan and release-binary (release-mode) qualification deferred to live qualification | Partially passed (provenance); blocked (release-binary audit) |
| §5.2 Fresh non-dev host install + admin setup (stdin), HTTP auth, server setup, enrollment/export, handshake, telemetry | Portable flows proven on dev host loopback (M001/M002 smoke: init, stdin-only password, login cookie, session, health). Fresh-host install + enrollment-driven handshake need a disposable host | Partially passed (loopback); blocked (fresh host + handshake) |
| §5.3 Full/split-route IPv4+IPv6 interop to real Linux client; IPv4 NAT egress, IPv6 routed no-NAT66, endpoint/route accuracy across network change | NOT qualified: no tunnel exists without the M003 live helper; no client, no NAT, no traffic claimed | **Blocked** |
| §5.4 Malicious IPC client, socket/utun ownership attacks, PF collision, wrong binary/receipt, Internet Sharing, foreign VPN, modified plist; foreign preservation + actionable refusal | IPC/socket layer qualified (6/6 `darwin_ipc` + 10 portable socket unit tests + root-bypass/auth unit pins). utun/PF/binary/receipt/Sharing/VPN/plist attacks: logic layers modeled + unit-pinned (ownership matrix, attachment verification, receipt verification, installer tamper refusal); LIVE adversarial cases need the privileged stack | Partially passed (IPC + logic); blocked (live adversarial) |
| §5.5 Crash/reboot/restores: helper/netd/serve killed, sleep/wake, network switching, disabled state, uninstall + preserved reinstall; IDs/keys/routes compared; journal/lease recovery | Kill/restart/SIGTERM/lease covered for netd/serve (native tests + smoke: graceful stops, stale reclaim, restart rebind, singleton lease). Helper crash, sleep/wake, network switching, reboot, preserved-reinstall recovery need the live stack + disposable host | Partially passed (serve/netd); blocked (helper/reboot/sleep/switching) |
| §5.6 Combined RSS/CPU + startup latency benchmark vs Linux targets; host prerequisites + support chart | Measured (debug arm64, this session): serve startup-to-ready 0.097s; RSS 11,552 KiB (~11.3 MiB); idle CPU 0.0%; `/healthz` 3.3ms `degraded` (honest, no netd/empty install); SIGTERM graceful. Consistent with Linux release figures (13.34 MiB combined, 0 idle ticks) with debug-build margin; helper footprint unmeasured (no live helper) | Passed (serve baseline); blocked (helper + release-binary figures) |
| §5.7 Docs/README/CLI/architecture audit (planned vs current); registry + closure; no production release on unresolved signing/distribution | Audit done: only `docs/development.md` describes Darwin (explicitly "not a working VPN server"); `README`/architecture/CLI retain Linux-native wording; `--help` unchanged. Registry + all closures updated. Release decision below | Passed |
| Threat review (new trusted helper, launchd identities, Darwin IPC, privileged route/PF, backups, UAPI keys); no shell escapes, raw PF IPC, or unauthenticated management | Reviewed: helper pinned hash + fixed argv + `env_clear` (live spawn unqualified — residual); IPC getpeereid + no-root-bypass qualified; route/PF modeled unexecuted (residual: live ops unqualified); backups portable + qualified; UAPI codec bounded + secret-safe at codec level (live key handling unqualified). Guards green: no new shell/process beyond the two audited backends, no raw PF IPC anywhere, management auth unchanged | Passed (design); live handling residual → blocked |
| Support matrix agreement (build/release vs native host capability); fail-closed on missing PF/admin/unqualified networks | Matrix below: only loopback management + IPC qualified on arm64; everything network/installer/Intel recorded as unqualified | Passed (matrix recorded) |
| Linux kernel + packaging release tests keep passing; macOS never weakens them | Full `cargo test` green; Linux-only suites untouched (`cfg`); Linux CI runs on push | Passed |
| Stop: unresolved TN3165 gate, missing Intel evidence with Intel claims, trust assertions beyond checksums-only, failed NAT, destroyable foreign state | Honored: TN3165 resolved as advanced-admin-only (M005, no consumer claim); no Intel claim made (matrix says unqualified); checksums-only retained with no signing fiction; no NAT/traffic claimed; foreign state preserved everywhere by construction + test | Passed (by refusal) |

## Native support matrix (exact; claims only what is demonstrated)

| Configuration | Status | Evidence |
|---|---|---|
| Loopback management (`admin/state/health/doctor/serve`, auth, CSRF, export shapes) on macOS arm64 | Qualified | M001 smoke + full portable suite + `darwin_ipc` serve-probe |
| Privileged IPC (`netd` Ping/Capabilities, getpeereid auth, no root bypass, framing, socket lifecycle, SIGTERM/restart) on macOS arm64 | Qualified | 6/6 `darwin_ipc` + 10 socket unit tests + M002 smoke |
| Helper/UAPI/ownership/route/PF/installer logic layers | Unit-qualified only (mock/fixture/temp-root) | 9 + 6 + 6 + 4 new unit tests; must never be cited as live behavior |
| Tunnel handshake, tunnel traffic, NAT, routed IPv6, gateway mode | Unqualified | Blocked (M003–M005 live) |
| Launchd boot/install/reboot/recovery, uninstall/reinstall on device | Unqualified | Blocked (M006 live) |
| Intel (`x86_64-apple-darwin`) native behavior | Unqualified (compiles only) | No native Intel hardware in this session; Rosetta never counts |
| macOS release readiness (artifacts, signing, distribution) | Not ready | Checksums-only retained; no Darwin release target shipped |

Host facts recorded: macOS 26.6.2, SDK 26.5, rustc 1.89.0 host `aarch64-apple-darwin`
(shell `uname -m` reports `x86_64` under this session — a further reason no
arch claim beyond the toolchain host is made).

## Release decision (honest; binding until re-qualified)

**The headless macOS server MUST NOT release.** Linux `v0.1.0` (checksums-only,
stable) is unaffected. A macOS release additionally requires ALL of: disposable-host
live qualification of M003 (handshake/traffic), M004 (converged routes/preservation),
M005 (effective NAT + routed IPv6 as advanced-admin-only), M006 (launchd install/
reboot/recovery), native Intel evidence, release-binary footprint + advisory audit,
and maintainer re-authorization. If the macOS gateway ever ships, it ships labeled
advanced-administrator-only with the M005 decision cited — never general consumer support.

## Verification (this session, unprivileged only)

- Full gates on `48cf163` + verdict docs fix: `fmt --check`, `check/clippy
  --all-targets -D warnings` (native + both Darwin triples), `cargo test`
  (lib 376+, 57 guards, all integration green modulo the known transient
  parallel port race), `cargo +1.89.0 check` — passed.
- Artifact facts + footprint + docs audit above; zero host-network/sysctl/PF/
  launchd/system mutations performed (only reads: `pfctl -s` denied, `sysctl`
  forwarding observed `0`/`0`, temp-dir fixtures).

## Security and ownership evidence

- Per-surface verdict in the threat-review row above; residual risks are all
  of one kind — live privileged handling unqualified — and all fail closed
  (`UnsupportedBackend`/degraded/Unknown, never converged).
- Historical Linux closures untouched; Linux behavior unchanged by the
  portability work (cfg-gating + macOS symlink/`geteuid`/nonblocking fixes
  that preserve Linux semantics under the same tests).

## Documentation, limitations, and findings

- Current-behavior docs stay factual (Linux-native + explicit Darwin
  non-server notes); all forward-looking material lives in `plans/`.
- Blocker for the whole line's live tail: disposable macOS host(s)/VM(s) +
  non-interactive root + explicit host-mutation opt-in + native Intel hardware
  + release-binary audit + maintainer authorization.
- Unblock checklist: (1) provision disposable arm64 + Intel Mac hosts;
  (2) run privileged fixtures for M003→M006 in order; (3) flip each blocked
  closure to closed with exact native evidence; (4) re-run full + Linux
  rootful CI at each head; (5) record release decision under M007.
- Findings: no high/medium/low open items in the qualified scope. The one
  honest defect class found and fixed during the line: Darwin accepted
  sockets inherit nonblocking (slow-peer bound defeated) — fixed by forcing
  blocking first, proven by the previously-failing timing test.

The macOS native-server line is **closed as far as unprivileged qualification
can take it** (M001–M002 strictly closed; M003–M006 blocked with implemented
safe scopes + binding decisions) and **blocked for any release or gateway
claim** until the checklist above is satisfied.
