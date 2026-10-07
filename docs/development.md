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

The current implementation is non-mutating. No root privileges or network namespace setup are needed for the unit suite.

## Local read-only netd

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
