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

## Linux-gated code (the cross-clippy)

The rootful suites are `#![cfg(all(target_os = "linux", feature =
"linux-integration"))]`, so **nothing in the gate order above type-checks
them** when it runs on a Darwin host: there they compile to nothing. A change
to a shared type can therefore break every Linux job without any local gate
failing. The cross-clippy with the feature does type-check them, so it is
part of the gate order:

```sh
CC_x86_64_unknown_linux_gnu=$HOME/wg-toolchain/zigcc \
  AR_x86_64_unknown_linux_gnu="zig ar" \
  cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets \
  --features linux-integration -- -D warnings
```

Run it for any change to a shared model, type, or public API — not only for
Linux work. It is a compilation check, not a substitute for the rootful
suites.

## Rootful suites (real kernel, disposable namespaces)

Prerequisites: root, `CAP_NET_ADMIN`, kernel WireGuard support,
`iproute2`, `iputils-ping` (handshake suites), `nftables`
(durable/doctor/maintenance suites). Serialize fixed-name-namespace
suites with `--test-threads=1`. `sudo` resets `HOME`, so use the
`-E env ... CARGO_HOME=...` form or Cargo cannot resolve its toolchain:

```sh
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo CI=true \
  cargo test --locked --features linux-integration --test <target> -- --test-threads=1
```

`CI=true` is load-bearing: with it set, a suite whose namespace or kernel
prerequisites are missing **fails** instead of skipping the kernel evidence.
A rootful run that silently skipped its kernel proof is not evidence.

Rootful targets: `wireguard_kernel`, `network_reconcile`,
`network_control_e2e`, `durable_owner`, `durable_restart`,
`durable_backup`, `product_management_rootful`, `maintenance_rootful`,
`doctor_readonly`, `service_rootful_e2e`. `durable_restart` needs a
built `wg-basic` binary (real `netd` + `reconcile` child processes).

Two tests are **not** in that list and must not be run on a working host:
`system_installation`'s
`systemd_installation_ownership_reinstall_and_service_credentials` and
`update_transaction_rootful`'s `signed_systemd_update_rolls_back_and_retries`.
Both mutate the canonical installation paths (`/usr/local/bin/wg-basic`,
`/etc/wg-basic`) and the host's systemd units, and their own annotations mark
them "disposable systemd VM only". Run them on a disposable runner.

On a controlled Linux host, point `CARGO_HOME` at a directory of its own so a
root-owned file never lands in a developer's `~/.cargo`, and inventory the
host's unrelated state (namespaces, links, routes, nftables, units, canonical
paths) before and after so preservation can be proven. See
`docs/development.md`.

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
- A live-fixture **contention refusal is a legitimate outcome**, not a
  failure: on a host whose `utun` namespace churns, the product may find
  more than one new device and correctly refuse to identify its own. The
  live fixture waits for a quiescent `utun` inventory, retries a
  contention refusal a bounded number of times, records every attempt and
  every inventory, and still fails if the refusal persists. Never weaken
  the product's fail-closed adoption rule to make the fixture pass, and
  never retry an identity or executability refusal — retrying it only
  repeats a correct answer.
- The managed device is proved new from the **product's own** pre-spawn
  observation, not from an inventory snapshot taken at a different moment:
  macOS recycles `utun` indices, so a snapshot from another instant proves
  nothing and fires on correct product behaviour.
- Copy-pasteable per-suite commands live in `docs/development.md`;
  the suite catalog (what each target proves) is in
  `architecture/testing-qualification.md`.
