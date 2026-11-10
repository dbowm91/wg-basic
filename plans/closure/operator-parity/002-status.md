# Operator parity M002 closure — client expiration

Status: closed.

Implementation commit: none. The work is the uncommitted tree on baseline
`a9b0c06af205b20923f7db350a65379cb176e56e`.
Planning baseline: `a9b0c06`.
Plan: `plans/implementation/operator-parity/002-client-expiration.md`.
Disposition: **closed**. A client deadline is nullable Unix seconds. Null does
not expire. A due client is disabled, in client-id order, with its row,
addresses, and keys kept. The audit action is `client_expire`.

## Requirement-to-evidence matrix

| Plan requirement | Evidence |
|---|---|
| Schema 9 leaves existing clients unexpired and does not advance desired generation | `src/state/migrations/009_client_expiration.sql` adds nullable `expires_at`. `a_schema_9_deadline_survives_the_mtu_migration` opens a schema 9 client, lands on schema 10, keeps the deadline, leaves `mtu` null, and keeps the generation. `a_real_v1_database_upgrades_to_head_and_preserves_desired_state` upgrades a v1 file to `current_schema_version()` without advancing generation or minting an installation id. |
| A past timestamp is refused; a future one is stored; a due client is disabled | `a_past_deadline_is_refused_and_a_due_client_is_disabled_in_id_order`. A past create is `InvalidClientExpiry` and the generation is unchanged. Two clients stored at one second ahead are disabled in sorted client-id order once the clock passes. The audit is `ClientExpire` with no principal. The disabled client's config still has its private key. The projected peer set is empty. |
| A second wake writes nothing | The same test calls `expire_due_clients` again and asserts no further generation. |
| Re-enable while the deadline is still past is refused; clearing it succeeds | The same test. Re-enable with the past deadline still set is `InvalidClientExpiry`. Re-enable with `expires_at: Some(None)` succeeds and `expiry_state` is `none`. |
| One sleep until the next deadline, and none when there is no deadline | `expiry_wait` in `src/management/worker.rs` returns one duration until the minimum future `expires_at` of an enabled client, and `None` when there is no such deadline. `serve` waits with `select!` of that sleep against the command queue. `expire_due` runs before the startup reconcile. There is no fixed interval. |
| The page can filter the loaded list | `architecture/product-management.md` and the shell describe name, address, enabled/disabled, and expiry filters over the existing list. `the_shell_exposes_the_product_api_workflows` covers the shell. |
| Docs | `architecture/product-management.md` documents the field, `client_expire`, and that expiry is a disable. `architecture/state-store.md` notes schema 9. `docs/client-enrollment.md` says a due client is disabled and the config remains exportable. |

## Verification performed

Commands run on this x86_64 Linux host, all exiting 0:

```text
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked                         # 44 suites; 684 passed, 0 failed, 3 ignored
cargo +1.89.0 check --all-targets --locked
cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets \
  --features linux-integration -- -D warnings
git diff --check
```

The three ignored tests are the pre-existing systemd-installation pair and the
Phase 8 upgrade rehearsal.

`$HOME/wg-toolchain/zigcc` is not installed. This host is already
`x86_64-unknown-linux-gnu`, so the Linux-integration clippy used the host
compiler. No rootful suite and no controlled-host macOS qualification were
run. Expiry is a product-state disable; the existing peer projection omits a
disabled client. The embedded page was not driven in a browser.

The architecture guard that counts migration 1 now matches `version: 1,`, so
schema 10 is not counted as version 1.

## Known limitations

The wake test calls `expire_due_clients` after the wall clock passes the
stored deadline. It does not drive the monotonic sleep itself. A wall-clock
step during that sleep is noticed when the sleep ends. NTP is not detected.
The command loop and the deadline sleep share one current-thread timer; if
that timer cannot be built, the worker cannot receive commands either.

The embedded-shell ceiling change is recorded in
`plans/closure/operator-parity/001-status.md`.

## Unresolved findings

None.
