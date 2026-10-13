# macOS Native Server M001 — Portable Boundaries and Native Darwin Build

Status: ready for implementation
Primary class: infrastructure / invariant
Source: plans/subsystems/macos-native-server-roadmap.md M001
Baseline: main 47c72b0e81d569d48396c615120453bf0cf1d46e (2026-10-11); rebase/revalidate against actual implementation head before applying.
Canonical: plans/000-long-term-specification.md; plans/002-long-term-roadmap.md; plans/003-planning-process.md; plans/adr/008-macos-headless-platform-backends.md; Linux ADR-001–007 are preserved.
Dependencies: Linux phases 1–11 already closed; no macOS predecessor.

## 1. Objective

Make all genuinely portable control-plane, product, authentication, state, release parsing, and HTTP layers compile and execute on Darwin without misrepresenting unsupported host mutation. Define lean platform traits, an OS-neutral logical tunnel identity and typed host-specific observations. Produce a first macOS local management loopback smoke test; it should show backend unavailable, not pretend convergence.

## 2. Non-goals

No utun creation, PF changes, route mutations, helper process, launchd installation, filesystem release installation, or claim of macOS VPN functionality. Do not broadly rewrite the Linux runtime or replace its existing netlink/nft backend.

## 3. Repository evidence

src/lib.rs gates aggregate/protocol/reconcile/firewall/wireguard/http, src/main.rs rejects all non-Linux roles; src/management/runtime.rs unconditionally uses aggregate/protocol despite Linux gating; Cargo.toml puts tokio, x25519-dalek, EggServe, serde_json, nix and other potentially shared dependencies under Linux only. src/domain/interface_name.rs assumes Linux IFNAMSIZ and src/reconcile/model.rs assumes ifindex and IFLA_IFALIAS. src/state/projection.rs Linux-gates typed network output. Release/installer modules include hard-coded Linux target logic.

## 4. Invariants

- Linux code paths are behaviorally identical and all existing Linux test/architecture guards remain active.
- No false-success macOS netd/host observation; capability unsupported is distinguishable from unavailable.
- Keep logical InterfaceId/InterfaceName stable across OS-generated utun names; avoid schema churn unless justified by explicit migration.
- Never widen the local privileged message vocabulary into a command tunnel.
- Preserve key generation, peer export and secret redaction across targets.

## 5. Ordered implementation packages

1. Inventory Linux cfg gates, cross-platform import edges and target-gated dependencies; document exact module/feature map; choose macOS minimum version from actual SDK/runner and both target triples; fail intentionally when SDK absent.
2. Extract shared domain, aggregate intent, protocol wire data, state projection and HTTP into portable compilation paths with Linux backend implementations behind narrow interfaces; separate Linux alias/ifindex-only fields from portable observation. Use deterministic test fakes; avoid sprawling framework or object model.
3. Refactor main role dispatch and doctor capability vocabulary; Darwin serve/admin/state/product export can run with an intentionally unsupported host backend. Do not allow a false network apply receipt.
4. Make Cargo target tables precise: truly common dependencies unconditional or unix-scoped, Linux crates under Linux cfg, future Darwin dependencies under Darwin cfg. Update architecture_guards with explicit source-boundary rules.
5. Establish macOS native build/format/clippy/unit workflow (arm64 and Intel compilation; native test where available); run full Linux CI, MSRV, and Linux integration suites. Capture binary/HTTP smoke output and diff audit.

## 6. Privilege, secrets, and host ownership

No privileged network access in this milestone. Retain HTTP -> bounded worker -> state/typed IPC structure, credentials and cookies. Darwin-only paths refuse network calls; avoid accidentally linking Linux-specific ioctl or netlink code. Validate no source path accepts untrusted executable, PF text, arbitrary sysctl or user-supplied filename.

## 7. Storage, protocol, compatibility and runtime failures

Existing SQLite migrations and wire protocol remain unchanged unless a justified additive field is needed; pin versioned enum/serde tests and backup fixture compatibility. A Linux desired-state DB must not become unreadable. Ensure on Darwin admin/serve can provide expected health degradation instead of crashing when netd is absent. Handle SIGTERM and unsupported capability deterministically.

## 8. Focused and integration tests

- Cargo check for x86_64-apple-darwin and aarch64-apple-darwin plus one native macOS cargo test on supported runner; report availability separately.
- Product auth/login, CSRF, API, export, state migration/restore and nonprivileged worker tests on Darwin.
- Compiler/mock tests for Linux/Darwin capability and logical-to-host locator separation; inspect serialized old receipts.
- Every existing Linux test, Linux native namespace fixture, architecture guard, and systemd qualification remains green.

## 9. Verification, documentation, and closure

Run cargo fmt --all -- --check; cargo check --locked --all-targets; cargo clippy --all-targets --locked -- -D warnings; cargo test --locked; cargo +1.89.0 check --locked --all-targets on Linux and native Darwin where tooling permits. Add Darwin commands and runner setup to docs/development.md only after verified. Retain no-macOS-support wording in README until later milestones.

## 10. Acceptance criteria

- Real arm64 macOS build/test run passes and Intel target compiles (record if native Intel test pending).
- Local macOS admin + HTTP serve/auth product read-only flows work and clearly report unavailable network backend.
- No regression in existing rootful Linux networking, HTTP, installation, and update flows.
- No accidental schema/protocol break or arbitrary path/command backend.

## 11. Stop conditions

If portability refactoring requires an unsafe downgrade of Linux ownership, all-target tests hide unsupported operations, or local HTTP has to run privileged: stop and revise backend seam before M002.

Closure record: plans/closure/macos-native-server/001-status.md, authored only after implementation and evidence. Record commit/PR, baseline and final head, passed/failed exact commands, native host/kernel traffic, foreign-state snapshots, security findings, documentation diffs, and strict disposition.
