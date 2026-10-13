# macOS Native Server M003 — wireguard-go utun Dataplane, Ownership, and UAPI

Disposition: **blocked** (safe unprivileged scope implemented; privileged native handshake unqualified).

Date: 2026-10-13

## Implementation revision

- Repository baseline: `2c931d7` (M002 closure; M003 ready).
- Qualified implementation head: `b1c831c7ffac01dd1c31cea1c8d5cb3a4a066c84`.
- Source plan: `plans/implementation/macos-native-server/003-wireguard-go-utun-backend.md` (ready → blocked by this record).
- Roadmap: `plans/subsystems/macos-native-server-roadmap.md` M003.

## Requirement-to-evidence matrix

| Requirement (plan §5/§10) | Evidence | Result |
|---|---|---|
| §5.1 Pin wireguard-go version/commit, MIT license, provenance; no Homebrew/runtime-Go production dependency | `src/wireguard/darwin.rs` pins tag `0.0.20250522`, peeled commit `f333402b…`, `MIT`, upstream URL; reference helper built from the pinned tag with Go 1.27.1 (darwin/arm64, 4.7 MiB, sha256 `1339b938…` recorded as dev reference; production bundling/signing is M006). `helper_provenance_is_pinned` unit test | Passed (unprivileged scope) |
| §5.2 Fixed-argv foreground supervisor, controlled env, root-owned runtime dir, bounded name file, exit handling, no PATH; hash/signature vs receipt | `HelperArgv` (absolute path only, argv exactly `[helper, "utun"]`), `helper_env()` (`WG_PROCESS_FOREGROUND=1` only, `env_clear`), `validate_helper_path` (absolute/file/symlink/exec), `verify_helper_sha256`, `SupervisedHelper::spawn` (no shell, piped bounded stdio, fail-fast on immediate exit, kill-on-drop). Unit tests with temp-dir mock helper (no interface created) | Passed (unprivileged scope) |
| §5.3 Bounded UAPI observation + typed patch serialization; finite bounds/timeouts/canonical encoding/secret scrubbing; never raw UAPI over IPC | `render_uapi_set` (typed keys/ports/peers, length/bound checks), `parse_uapi_get` (`errno` + bounded pairs + terminator), `uapi_round_trip` (5s bound, 256 KiB cap, `\n\n` framing) with socketpair round-trip test; secret-redaction preserved (no key material in `Debug`/errors) | Passed (unprivileged scope) |
| §5.4 Logical tunnel mapping + ownership proof; stale/PID-reuse/renumber/concurrent-VPN safety; never adopt/kill foreign | `interface_delta` (exactly-one-new-`utunN`, else `StartupFailed`), `verify_ownership` (claim vs live helper/socket/device/tag; every mismatch class fails closed), `uapi_socket_path` (`/var/run/wireguard/<utun>.sock`). Unit matrix covers crash, PID reuse, renumbering, foreign utun, stale receipt | Passed (unprivileged scope) |
| §5.5 Aggregate planner with one Darwin tunnel; unsupported route/firewall distinguished; Mac↔Linux interop + telemetry | NOT qualified: planner translation against a live Darwin backend needs the privileged helper running. `WireGuardBackend` Darwin still returns `UnsupportedBackend` (validated input first); no route/firewall behavior claimed | Blocked |
| §10 Native Mac hosts WireGuard, handshake + tunnel packets, counters/endpoint via API | NOT qualified: requires root (utun creation) on a disposable, explicitly opted-in host. This session has no non-interactive sudo (`sudo -n` fails), no disposable Mac VM, and no destructive-host opt-in; per M007 safety rule host default routing was never touched | **Blocked** |
| §10 Lost helper/stale/foreign/socket/identity cases fail closed | Proven at logic level (unit matrix); live kill/respawn/PID-reuse cases need the privileged helper | Partially passed (logic), blocked (live) |
| §10 Reconcile/restart keeps logical identity + truthful receipts | Logic holds (identity is UUID-based, receipts typed); live restart proof needs the helper | Partially passed (logic), blocked (live) |
| §10 Linux kernel WireGuard suites green | Untouched; `cargo test` full green | Passed |
| §11 Stop: unsuitable license/provenance, unsafe identity, unbounded privilege, wg-quick/shell traffic | None triggered in implemented scope: MIT provenance suitable; identity model proven at logic level; UAPI bounded with no global privilege beyond the helper itself; no `wg-quick`/shell anywhere (guard pins fixed argv, `process_execution_is_isolated_to_audited_backends` green) | Passed (implemented scope) |

## Verification

Local commands actually run on native Darwin arm64 (macOS 26.6.2, rustc 1.89.0):

- `cargo fmt --all -- --check` — passed.
- `cargo check --locked --all-targets` — passed.
- `cargo clippy --all-targets --locked -- -D warnings` — passed.
- `cargo test --locked` — green (lib 360 incl. 9 new `wireguard::darwin` + refined guards; 6/6 `darwin_ipc`; full integration green modulo one transient parallel port race that passes alone and on retry).
- `cargo check/clippy --target aarch64-apple-darwin + x86_64-apple-darwin` — passed.
- `cargo +1.89.0 check` — passed.
- Upstream evidence (unprivileged, no host mutation): `git ls-remote` tag `0.0.20250522` → `f333402b…`; `git clone --quiet` + `checkout 0.0.20250522`; `LICENSE` MIT text; `go build` darwin/arm64 → 4,690,802 bytes, sha256 `1339b938…`; source-confirmed argv (`utun`), foreground env, UAPI socket dir, `utun`/`utunN` Darwin tun requirement.

Privileged evidence NOT collected (blocker): real `utun` creation, pinned-helper child supervision against a live device, UAPI `set`/`get` over `/var/run/wireguard/*.sock`, peer add/update/delete, endpoint/keepalive/handshake/counters, tunnel traffic with a Linux peer, kill/restart/PID-reuse/stale/foreign live cases.

## Security and ownership evidence

- Second process boundary added deliberately and pinned: `PROCESS_MODULES = [nft.rs, wireguard/darwin.rs]`; Darwin supervisor asserts fixed `Command::new(&argv.helper)`, `.env_clear()`, `HELPER_INTERFACE_ARG`, no `sh/bash/wg-quick/PATH` resolution (new guard test green). No raw UAPI text crosses IPC (codec renders typed fields only; protocol `wire.rs` unchanged).
- Helper identity is hash-pinned before any privileged spawn; mismatch is a non-retryable conflict. UAPI I/O is bounded (16 KiB request / 256 KiB response / 5s) with no shell and no key logging.
- Ownership logic fails closed on every mismatch class (unit-proven); a stale receipt can never authorize foreign deletion because deletion itself is unimplemented until the live backend qualifies the proof.
- Linux `nl-wireguard` backend untouched; Darwin live methods return `UnsupportedBackend` after input validation (malformed input stays `InvalidInput` on both OSes — proven by the portable socket test).

## Documentation, limitations, and findings

- No current-behavior docs changed (per planning rule: no shipped macOS VPN behavior exists). Upstream facts that constrain the later live work are recorded in `src/wireguard/darwin.rs` module docs (argv, foreground env, UAPI socket path, delta-not-namefile mapping).
- Known limitation / hard blocker: privileged utun/handshake/traffic qualification needs (a) a disposable macOS host or VM, (b) non-interactive root or an operator-driven privileged fixture, and (c) explicit opt-in for host network mutation. None exists in this session, so no `utun` was created and no packet claim is made.
- Corrective note for M004+: the live backend must run its fixtures on such a host; mock-UAPI success must never be recorded as handshake evidence (this record does not).
- Findings: no high/medium/low open items in the implemented scope. One pre-existing flaky parallel port race observed once in `http::serve` (passes alone and on retry); unrelated to M003.

M003 is **blocked** on privileged-host qualification. M004–M007 remain gated; M004 becomes ready for its unprivileged modeling scope but its native apply carries the same blocker.
