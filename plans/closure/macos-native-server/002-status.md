# macOS Native Server M002 — Darwin Privileged IPC, Identities, and Capability Discovery

Disposition: **closed**.

Date: 2026-10-13

## Implementation revision

- Repository baseline: `f736df8` (M001 closure; M002 ready).
- Qualified final head: `96075b50f2af8fd5cf953c3987358c5e144cfd3f`.
- Source plan: `plans/implementation/macos-native-server/002-darwin-privileged-ipc-and-capabilities.md` (blocked → ready → closed by this record).
- Roadmap: `plans/subsystems/macos-native-server-roadmap.md` M002.

## Requirement-to-evidence matrix

| Requirement (plan §5/§10) | Evidence | Result |
|---|---|---|
| §5.1 Safe audited `getpeereid` binding, Darwin-gated; confirm `nix` adequacy; isolate any FFI unsafe via ADR/lint exception, never weaken crate-wide `forbid` | `nix::unistd::getpeereid` (`#[cfg(bsd)]`, features `socket+user` already enabled) selected — Apple-documented API via audited upstream wrapper; zero new `unsafe` in this crate (`forbid(unsafe_code)` intact, no lint exception needed). Portable `auth::peer_identity()` selects `SO_PEERCRED`/Linux vs `getpeereid`/Darwin; `peer_identity_matches_kernel_credentials` unit test proves loopback credential round-trip on both | Passed |
| §5.2 Portable socket peer-identity + capability traits, Linux `SO_PEERCRED` intact; explicit allowlisted Darwin service UID/group, no blanket trust | `AuthorizationPolicy::current_user()` (self only, no root) added alongside unchanged `current_user_and_root()` (Linux default); Darwin netd uses former + `--allow-uid/--allow-user` extras. `darwin_default_policy_has_no_root_bypass` unit test: self permitted, root (uid 0) denied unless explicitly allowlisted | Passed |
| §5.3 Protected runtime socket directory/permissions; reject unsafe parents, foreign sockets, symlinks; preserve bind/cleanup inode checks; verify macOS semantics | `protocol/socket.rs` lifecycle (parent owned-by-euid + `0700`-family check, `0660` socket, stale owned-inode reclaim after failed connect + recheck, drop removes only matching device/inode/uid) made portable unchanged; macOS verified by `darwin_ipc` stale/foreign/symlink cases + all 10 portable `protocol::socket` unit tests green on Darwin. Genuine portability fix: accepted streams inherit nonblocking on Darwin (Linux does not observe this), so `handle_connection` now forces blocking before the 2s bound — the slow-peer DoS bound holds on both | Passed |
| §5.4 Darwin backend capability snapshot (utun, helper unknown→M003, PF unknown→M005, routes) without mutation; unavailable vs untested distinct | No wire change (judgment call below): `NetworkCapabilitySnapshot::observe` Darwin reports `os=macos`, `cap_net_admin=None`, `network_namespaces/wireguard_control/nftables=Unavailable` (Linux backends absent), `kernel_release` via `nix uname`, runtime-dir check portable. Helper/PF/route qualification tracked as untested in doctor evidence + roadmap until M003–M005; `BackendCapability::Unsupported` vs `Unknown` stays distinct in `platform` | Passed |
| §5.5 Native macOS netd + serve loopback fixtures: real OS accounts, bogus peers, races, SIGTERM, stale rebind, restarts | New `tests/darwin_ipc.rs` (6 tests, native only): authorized Ping + Darwin capability snapshot; allowlist extension keeps default + denial kernel-enforced (true self-excluded denial by portable unit test); 32 malformed/oversized/version-mismatch frames rejected without echo or crash + service answers afterwards; foreign-file/symlink preserved + SIGKILL-stale reclaimed + SIGTERM graceful + restart rebind; serve live-probe answered/unanswered with/without netd (no direct kernel path) | Passed |
| §10 Authorized serve-to-netd works; unauthorized refused | Smoke: real `netd` + `serve` + `doctor --json` → `netd:pass` (getpeereid-authorized IPC, uid 503/gid 20, runtime safe); authenticated `/api/v1/health` → `backend.answered:true, service:wg-basic-netd` with `netd_reachable:false` from record (honest: nothing applied). Unauthorized: portable unit test rejects before reading data; `darwin_ipc` allowlist test documents default-inclusion semantics | Passed |
| §10 No generic shell/PF/route/file/sysctl proxy; bounded framing + cleanup proven | `darwin_stubs_fail_closed_without_process_or_shell` + `process_execution_is_isolated_to_the_nft_backend` green; Darwin IPC fixtures prove 64 KiB framing, version/request-id correlation, no payload echo, inode-owned cleanup | Passed |
| §10 Doctor reports Darwin capabilities without Linux error text | `run_darwin_doctor` reports `netd:pass` with Darwin evidence (`CAP_NET_ADMIN none`, kernel `25.x`) + `unqualified helper (M003)/routes (M004)/PF (M005)` remediation; forwarding checks never read `/proc` | Passed |
| §10 Native fixture + all Linux privileged suites green | `cargo test` full green incl. 10 portable socket unit tests + 6 `darwin_ipc` + refined guards; Linux `privileged_protocol` untouched | Passed |
| §11 Stop: unsafe credential API, ambiguous UID mapping, bypassable ownership, netd-as-HTTP | None triggered: `nix getpeereid` safe; UID mapping exact (`u32` euid vs `u32` peer); ownership via inode/device/uid triple on both; netd never opens HTTP/SQLite (guards green) | Passed |

## Verification

Local commands actually run on native Darwin arm64 (macOS 26.6.2, SDK 26.5, rustc 1.89.0):

- `cargo fmt --all -- --check` — passed.
- `cargo check --locked --all-targets` — passed.
- `cargo clippy --all-targets --locked -- -D warnings` — passed.
- `cargo test --locked` — all green (lib 351 incl. 2 new `auth` + portable socket/capability cases; 6/6 `darwin_ipc`; 53/53 architecture guards).
- `cargo check/clippy --target aarch64-apple-darwin + x86_64-apple-darwin --locked --all-targets -- -D warnings` — passed.
- `cargo +1.89.0 check --locked --all-targets` — passed.
- Smoke (debug binary, disposable `/tmp/wg-basic-m002-smoke`): real `netd` binds `0660` socket; `doctor --json` → overall `pass` (empty install), `netd:pass` with getpeereid IPC + Darwin snapshot; `serve` loopback + login + `/api/v1/health` live probe `answered:true`; SIGTERM graceful for both roles; no `utun`/route/PF mutation performed.

Hosted Linux CI: runs on push (exact-head run ID recorded in registry §7). Linux `SO_PEERCRED` path, `privileged_protocol`, and rootful suites unmodified.

## Security and ownership evidence

- Credentials kernel-derived every connection on both OSes; no UID/GID/PID/socket-path value is read from the payload. Darwin default has no root bypass (unit-pinned); extras are explicit UIDs only — no group-blanket trust, no user-supplied paths/flags reach `exec` (netd launches nothing; helper arrives in M003 with fixed argv).
- Framing/version/correlation/bounds unchanged; malformed input never echoed (secret-free rejection proven by `malformed_frame_does_not_leak_payload` + Darwin 32-frame burst).
- Socket lifecycle preserves foreign files/sockets/symlinks and removes only the owned inode on both OSes; stale-crash reclaim proven by SIGKILL test.
- `serve` reaches the network only through the authorized socket (live-probe test with/without netd); management still never spawns or elevates netd.
- Guards refined honestly (not weakened): `std::env` → `std::env::var` (allows `consts::OS`), handler count 2→3 with `run_darwin_netd` pinned as the third; Darwin-only `allow(dead_code)` limited to netd-gated test helpers.

## Documentation, limitations, and findings

- Updated: `architecture/privilege-boundary.md` (getpeereid source, no-root-bypass default, blocking-accepted-streams fix, Darwin snapshot semantics); `docs/development.md` (Darwin netd runbook with explicit identities; launchd stays future tense).
- Judgment call (recorded, not silent): no `NetworkCapabilitySnapshot` wire fields added. The plan permits additive optional fields, but `deny_unknown_fields` would break mixed-version decoding without a negotiation test; Darwin helper/PF/route states are instead reported as untested in doctor evidence until M003–M005 need wire-visible states. Linux wire bytes unchanged.
- Corrective fix during qualification (portability bug, not a test tweak): Darwin accepted streams inherit nonblocking, defeating the 2s slow-peer bound; `handle_connection` now forces blocking first. Linux behavior identical (already blocking); the previously-passing Linux timing test now also passes on Darwin, proving the bound rather than assuming it.
- Limitations: no tunnel/route/PF/launchd behavior yet (M003–M006); Intel compiles, native Intel IPC evidence pending M007 hardware; `--allow-user` resolves via `nix` (same as Linux) with no separate group-membership check beyond UID allowlisting.
- Findings: no high/medium/low open items.

M002 is strictly closed. M003 is unblocked and becomes **ready**.
