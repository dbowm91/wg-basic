---
name: wg-basic-gates
description: "Run wg-basic's CI verification gates and test suites: fmt/check/clippy/test commands, MSRV check, unprivileged vs rootful invocation, sudo/CARGO_HOME form, upgrade-rehearsal env. Triggers: wg-basic gates, CI gates, clippy, fmt, rootful test, linux-integration, run the tests, verify change."
---

# wg-basic verification gates

Run from the repository root (`/home/sugarwookie/projects/wg-basic`).
Toolchain is pinned by `rust-toolchain.toml` (1.89.0 + `rustfmt` + `clippy`).

## Gate order (same as CI)

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
```

The ordinary suite (`cargo test --locked`) needs no privilege: no root,
no namespaces, loopback sockets only.

## Rootful suites (real kernel, disposable namespaces)

Prerequisites: root, `CAP_NET_ADMIN`, kernel WireGuard support,
`iproute2`, `iputils-ping` (handshake suites), `nftables`
(durable/doctor/maintenance suites). Serialize fixed-name-namespace
suites with `--test-threads=1`. `sudo` resets `HOME`, so use the
`-E env ... CARGO_HOME=...` form or Cargo cannot resolve its toolchain:

```sh
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test <target> -- --test-threads=1
```

Rootful targets: `wireguard_kernel`, `network_reconcile`,
`network_control_e2e`, `durable_owner`, `durable_restart`,
`durable_backup`, `product_management_rootful`, `maintenance_rootful`,
`doctor_readonly`, `service_rootful_e2e`. `durable_restart` needs a
built `wg-basic` binary (real `netd` + `reconcile` child processes).

## Upgrade rehearsal (Phase 9 old/new pair, ignored by default)

```sh
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  CARGO_TARGET_DIR=/tmp/wg-basic-upgrade-rootful-target \
  WGB_OLD_BINARY=/path/to/phase8/wg-basic \
  WGB_CANDIDATE_BINARY=/path/to/candidate/wg-basic \
  cargo test --locked --features linux-integration \
    --test upgrade_rehearsal_rootful -- --ignored --nocapture --test-threads=1
```

## Rules

- Never run rootful suites without explicit user request: they need
  `sudo`, mutate kernel state (in disposable namespaces), and take minutes.
- Never substitute mocked kernel behavior for real-kernel closure
  evidence; when `CI` is set, missing namespace/kernel prerequisites
  fail instead of skipping.
- Copy-pasteable per-suite commands live in `docs/development.md`;
  the suite catalog (what each target proves) is in
  `architecture/testing-qualification.md`.
