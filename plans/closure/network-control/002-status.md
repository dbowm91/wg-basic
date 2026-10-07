# M002 Closure — Privileged Protocol and Host Capability Boundary

Disposition: **closed**

Implementation plan: `plans/implementation/network-control/002-privileged-protocol-and-capability-boundary.md`

Repository baseline: `2796220` (M001 strict closure)

Implementation commits: `fda3044`, `f888e35`

Final implementation head: `f888e359e4828f3499a4fb6dbe1fe251fd20bdce`

## Requirement-to-evidence matrix

| Requirement | Evidence | Result |
|---|---|---|
| Distinct `serve` and `netd` roles in one executable | `src/main.rs`; live CLI session | Pass. `serve` makes a protocol request; `netd` runs the service. HTTP is not claimed. |
| UDS only; safe socket directory and ownership | `src/protocol/server.rs`; `architecture/privilege-boundary.md` | Pass. No TCP listener; directory must be owned by netd and not group/world writable. |
| Socket mode and safe stale/conflict cleanup | `SocketServer::bind`, inode/UID checks in `Drop`; lifecycle tests | Pass. Mode `0660`; regular files, active sockets, and replaced paths are preserved; owned stale socket is recoverable. |
| Kernel peer credential authorization | `getsockopt(SO_PEERCRED)` in `handle_connection`; allowlist policy and denied-peer test | Pass. Authorization uses kernel UID, not a message field. Default allows effective UID and root; extra UIDs are explicit. |
| Bounded framing and payload | `src/protocol/framing.rs`; 64 KiB boundary/oversize/truncation tests | Pass. Four-byte big-endian length is checked before payload allocation. |
| Versioned typed protocol and correlation | `src/protocol/wire.rs`, server dispatch, client validation | Pass. Protocol v1, request IDs checked, unknown versions and operations rejected. |
| Bounded connections, timeouts, cancellation | `SocketServer::run_until_shutdown`; idle-client lifecycle test | Pass. One active connection, backlog of 16, one frame per connection, two-second read/write timeout, no spawned connection tasks. |
| Read-only capability snapshot | `src/protocol/capability.rs`; `doctor` live CLI output | Pass. Reports Linux/arch/UID/GID/CAP_NET_ADMIN/kernel/runtime path. Backend-owned namespace/WireGuard/nftables facts remain `unknown`. |
| No privileged generic escape hatch | operation enum has only Ping and InspectCapabilities; forbidden operation negative tests; source guard below | Pass. |
| Graceful shutdown and ownership-aware cleanup | Ctrl-C handler in `src/main.rs`; direct SIGINT run; socket replacement test | Pass. The process removed its own socket; cleanup checks type, device, inode, and owner first. |
| Current-behavior and operator documentation | `architecture/overview.md`, `architecture/privilege-boundary.md`, `docs/development.md`, README | Pass. All state that WireGuard and host-network mutation are not implemented. |

## Verification actually run

Local commands all exited successfully:

```text
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked                         # 20 passed
cargo test --locked --test privileged_protocol -- --nocapture  # 2 passed
cargo +1.89.0 check --all-targets --locked
```

Hosted CI run [37581275119](https://github.com/dbowm91/wg-basic/actions/runs/37581275119) completed successfully on the final implementation commit. It ran formatting, locked check, Clippy with warnings denied, and the complete unit/integration suite.

Live process check: `netd` bound `/tmp/wg-basic-m002-live/netd.sock`; `serve` received `wg-basic-netd 0.1.0`; `doctor` returned a secret-free capability JSON snapshot; the socket was mode `0660`; direct SIGINT shutdown removed the socket. Host network state was not mutated.

Source guard:

```text
rg -n 'std::process::Command|Command::new|\bCommandExt\b|\bExec\s*\{|\bShell\s*\{|\bWriteFile\s*\{|\bSetSysctl\s*\{|\bApplyNft\s*\{|\bSendNetlink\s*\{' src
```

Result: no matches. Protocol negative tests also reject `exec`, `shell`, `write_file`, `set_sysctl`, `apply_nft`, and `send_netlink`, including unexpected request parameters.

## Protocol and authorization details

- Encoding: Serde JSON inside a four-byte big-endian length frame.
- Maximum frame: 65,536 bytes.
- Operations: `ping`; `inspect_capabilities`.
- Version: major protocol version `1`; unknown version receives `unsupported_version` with the request ID echoed.
- Correlation: one request per connection; response version and request ID are validated by the client.
- Socket: configured path, default `/run/wg-basic/netd.sock`; parent must exist, be owned by effective netd UID, and have no group/world write bits; socket mode `0660`, group inherited from netd's effective GID.
- Authorization: `SO_PEERCRED` UID must be the effective netd UID, root, or an explicitly configured `--allow-uid`.
- Work bounds: one request handled at a time; listener queue capped at 16; 2-second I/O timeout; no task spawning.

The integration tests exercised both an authorized local UID and a denied peer by running the server with a nonmatching UID allowlist. A distinct second-UID fixture was not run; socket DAC and the available unprivileged environment make that qualification dependent on deployment credentials. Kernel credential extraction and denial are covered in the local Linux test environment and hosted CI.

## Dependency additions

| Dependency | Purpose |
|---|---|
| `serde_json` | Mature JSON framing payload; frame size is validated before decoding |
| `nix` (Linux target only) | `SO_PEERCRED`, effective UID/GID, and capability identity access without handwritten unsafe code |
| `ctrlc` (Linux target only) | Graceful `netd` shutdown |

No network-control, process-execution, or TLS dependency was added. The Linux-only dependencies are target-gated so the domain library remains separate from the Linux protocol layer.

## Capability snapshot example

The live snapshot had this shape (host-specific UID, kernel release, and capability value omitted):

```json
{
  "os": "linux",
  "architecture": "x86_64",
  "effective_uid": 1000,
  "effective_gid": 1000,
  "cap_net_admin": false,
  "kernel_release": "<kernel release>",
  "runtime_directory_safe": true,
  "network_namespaces": "unknown",
  "wireguard_control": "unknown",
  "nftables": "unknown"
}
```

## Limitations and unresolved findings

`serve` is currently a one-shot protocol client, not an HTTP service. The capability snapshot deliberately does not probe/create namespaces, load modules, or mutate network state. The network service has no WireGuard, RTNETLINK, nftables, forwarding, persistence, or installation behavior. No systemd unit is shipped; documentation states the intended privilege split and socket setup. No unresolved high/medium privilege or protocol findings were identified in M002 scope.

## Readiness recommendation

M002 is strictly closed. Promote M003 to **ready**. M003 must preserve M002 transport/authentication while adding only typed WireGuard operations and must obtain real Linux kernel handshake, telemetry, and preservation evidence from a qualifying rootful namespace runner. The current development environment cannot create network namespaces.
