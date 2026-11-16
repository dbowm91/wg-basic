# Windows Native Server M001 — Portable Boundaries and the windows-2025 Build

Status: **implemented; closure blocked** on `windows-2025` evidence
Primary class: infrastructure / invariant
Source: `plans/subsystems/windows-native-server-roadmap.md` M001
Baseline: `554de7a3b5ae83700222a290664fbbbeb3cd521a` (2026-11-10). Revalidate against the implementation head before editing.
Canonical: `plans/000-long-term-specification.md` §6.3; `plans/002-long-term-roadmap.md` §14B; `plans/003-planning-process.md`; `plans/adr/011-windows-server-wireguard-nt.md`. ADR-001–ADR-010 remain in force for Linux and macOS.
Dependencies: none. Linux phases 1–11 and the macOS line are untouched predecessors, not work inside this milestone.

## 1. Objective

Make the portable control plane, product, authentication, state, and HTTP layers compile and pass their unit tests on `windows-2025`. Network observation and apply fail closed as unsupported. Record a read-only `Get-NetNat` / default-route inventory for M005. Leave Linux and macOS behavior unchanged.

## 2. Non-goals

No `wireguard.dll` download, no adapter, no route or firewall mutation, no NAT creation, no Service Control Manager install, no schema migration, and no support claim. Do not rewrite the Linux netlink or nft backends, and do not retarget Phase 10.

## 3. Repository evidence

`nix` is unconditional. `src/protocol/socket.rs` and `src/protocol/auth.rs` import `std::os::unix`. State, backup, migrations, and the service lease use Unix permission bits. `Platform` is `Linux | Darwin | Unsupported`. `src/reconcile/mod.rs` exports the Darwin reconciliation service for every non-Linux target, while `service_darwin` is macOS-only, so a Windows build fails before the existing fail-closed stubs can run. Client export is already platform-neutral. CI has no Windows job.

## 4. Invariants

- Linux paths, receipts, and tests stay behaviorally identical. macOS paths stay behaviorally identical.
- Unsupported is distinct from a failed probe and from convergence.
- Logical `InterfaceId` / `InterfaceName` stay the desired-state identity. No LUID or GUID is persisted.
- The privileged vocabulary does not grow.
- Key generation, export, and secret redaction stay platform-neutral.
- The main crate keeps `forbid(unsafe_code)`. This milestone adds no Win32 crate.

## 5. Expected production changes

`Platform::Windows` exists and `Platform::current()` returns it on this target. `has_native_network_backend` stays false for Windows. `nix` and Unix socket code compile only on Unix. Windows `WireGuardBackend`, `ReconciliationService`, and `FirewallService` are the fail-closed stubs, including the reconciliation export that today points at Darwin. `serve`, `admin`, `state`, and product export run against a temp directory and report the network backend unavailable. `netd` on Windows binds nothing and exits with the unsupported-backend error until M002.

## 6. Ordered work packages

1. Split cfg gates so Unix-only modules (`nix`, `std::os::unix`, signal termination, mode bits) are `cfg(unix)`, Linux backends stay `cfg(target_os = "linux")`, and Darwin backends stay `cfg(target_os = "macos")`. Fix `src/reconcile/mod.rs` so Windows uses `service_other`.
2. Add `Platform::Windows` and tests that the current platform matches the compile target. Capability reports on Windows say unsupported, not available.
3. Give Windows state and backup paths a directory the test creates. Do not invent the ProgramData layout; that is M006. Permission checks that have no Windows equivalent fail closed rather than treating a missing mode bit as world-readable success.
4. Add a `windows-2025` CI job: `cargo test --locked` for the suites that are portable, `cargo clippy --locked --all-targets -- -D warnings`, and a read-only inventory step that runs `Get-NetNat`, `Get-NetRoute -DestinationPrefix 0.0.0.0/0`, and `Get-ComputerInfo` and uploads the transcript. The step creates nothing.
5. Extend `tests/architecture_guards.rs` so the Windows cfg split and the fail-closed stubs are pinned, and so `nix` is not an unconditional dependency.

## 7. Privilege, secrets, and host ownership

No privileged network mutation. The inventory step is read-only and is CI evidence, not a product operation. Credentials and the HTTP worker boundary stay as they are. No request field names an executable, a DLL, a registry key, or a NAT.

## 8. Persistence, protocol, compatibility, failure

No migration and no protocol version bump. A Linux or macOS database still opens. On Windows, a missing or unsupported backend is a named degraded health result, not a crash and not a successful apply. Cancellation of `serve` is Ctrl-C on the console; SCM stop is M006.

## 9. Tests and integration evidence

- `windows-2025`: portable unit tests, including auth, export, state open/backup, and the unsupported-backend tests.
- The uploaded inventory is present on success and on failure of later steps.
- Linux: the ordinary gate order and the rootful suites. macOS: the existing qualification workflow, unchanged in what it runs.
- This milestone claims no kernel dataplane. The namespace suites exist to prove Linux did not move.

## 10. Verification

On Linux, the commands in `docs/development.md`. On the new job, `cargo test --locked` and clippy as in package 4. Record the runner image version from the inventory.

## 11. Documentation

`docs/development.md` gains the `windows-2025` command once it has passed. README and architecture docs keep the current Linux-native description. They do not gain a Windows support sentence.

## 12. Acceptance criteria

- The `windows-2025` job is green and its inventory artifact is attached.
- Windows network apply returns unsupported.
- Linux rootful suites and the macOS workflow are green at the same head.
- No schema or protocol break.

## 13. Stop conditions

Stop if the portability split changes a Linux receipt, if Windows tests skip by ignoring the unsupported path, or if the inventory step creates or deletes a NetNAT. Do not start M002 inside this change.

## 14. Closure

`plans/closure/windows-native-server/001-status.md`, written only after the job evidence exists. Include the head, the exact commands, the inventory transcript, and the Linux and macOS results.
