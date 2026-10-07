# Development

Install Rust 1.89.0 with the `rustfmt` and `clippy` components. The checked-in `rust-toolchain.toml` selects this toolchain.

Run the repository's CI gates from the root:

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
```

The default unit/protocol suite does not require root or network namespace setup. The Linux WireGuard backend mutates only through typed requests to an existing device; the real-kernel integration test creates temporary namespaces and fixture links and requires root, `CAP_NET_ADMIN`, `iproute2`, `iputils-ping`, and kernel WireGuard support.

## Local netd

Create a private runtime directory owned by the user running `netd`, then start:

```sh
install -d -m 700 /tmp/wg-basic-runtime
cargo run --locked -- netd --socket /tmp/wg-basic-runtime/netd.sock
```

In another terminal, use `cargo run --locked -- doctor --socket ...` or `cargo run --locked -- serve --socket ...`. The `serve` role currently checks local protocol connectivity; HTTP is not implemented. For a separate management UID, start netd with `--allow-uid UID` and arrange socket group access. `netd` exits on Ctrl-C and removes only the socket inode it created.

Run Linux IPC integration coverage with:

```sh
cargo test --locked --test privileged_protocol -- --nocapture
```

Run the real kernel WireGuard handshake, telemetry, peer update, and preservation fixture with:

```sh
sudo -E cargo test --locked --features linux-integration --test wireguard_kernel -- --nocapture
```

The test starts its netd workers inside the two temporary network namespaces so each typed request controls the device in that namespace. CI runs this target on a rootful Linux runner; when `CI` is set, unavailable namespace/kernel prerequisites fail the test instead of silently skipping kernel evidence.

## Durable ownership and restart fixtures

Two rootful suites qualify the durable-state milestones against the real kernel. Both need root, `iproute2`, `nftables`, and kernel WireGuard support, and both serialize with `--test-threads=1` because each creates disposable network namespaces with fixed names.

Owner tags and the generation-aware aggregate reconcile:

```sh
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test durable_owner -- --test-threads=1
```

Startup reconciliation and crash/restart recovery:

```sh
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test durable_restart -- --test-threads=1
```

Restored-state qualification (three namespaces, real handshake, forwarding, and NAT from a restored database):

```sh
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test durable_backup -- --test-threads=1
```

`durable_restart` is a process-level fixture: it runs the real `wg-basic netd` binary and the real `wg-basic reconcile` management role as separate child processes against a temporary on-disk SQLite file, disposable namespaces, real RTNETLINK, and real nftables. It proves restart recovery rather than in-process reconstruction, so it depends on a built `wg-basic` executable and leaves its `netd` children to be reaped by the harness. CI runs these as the `durable-owner`, `durable-restart`, and `durable-backup` jobs.

The `-E env ... CARGO_HOME=...` form exists because `sudo` resets `HOME`, and Cargo needs a writable home to resolve the toolchain and registry cache when the tests are run as root.
