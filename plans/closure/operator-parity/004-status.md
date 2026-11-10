# Operator parity M004 closure — client MTU in the exported config

Status: closed.

Implementation commit: none. The work is the uncommitted tree on baseline
`a9b0c06af205b20923f7db350a65379cb176e56e`.
Planning baseline: `a9b0c06`.
Plan: `plans/implementation/operator-parity/004-client-mtu.md`.
Disposition: **closed**. A client may store an MTU from 1280 through 9000.
The export writes that line. The server link is unchanged.

## Requirement-to-evidence matrix

| Plan requirement | Evidence |
|---|---|
| Null omits the line; 1280 and 9000 write one line after Address and before DNS | `an_mtu_line_sits_after_address_and_before_dns` in `src/product/export.rs`. None, 1280, and 9000 are rendered. A present value appears once, after `Address` and before `DNS`. The QR is produced from that same text. |
| 1279 and 9001 never persist | `client_mtu_is_bounded_and_does_not_change_the_address_plan` in `tests/product_management.rs`. Both are `InvalidClientMtu` and the generation is unchanged. Omit on create stores null and writes no line. 1280 does not change the desired address plan. Omit on update leaves 1280. Null clears it. 9000 writes `MTU = 9000`. |
| The golden fixture stays stable | `renders_exact_stable_config_and_redacts_debug` still equals the fixture text, which has no MTU line, on both renders. |
| Schema 10 preserves a schema 9 deadline | `src/state/migrations/010_client_mtu.sql`. `a_schema_9_deadline_survives_the_mtu_migration` keeps `expires_at`, leaves `mtu` null, and does not advance desired generation. |
| A client MTU change is not a link or peer-address change | The product test asserts the desired state and address plan are unchanged. No server-link MTU field and no netd field were added. |
| Docs | `architecture/product-management.md` documents the range, the export line, and that the server interface MTU is unchanged. `architecture/state-store.md` notes schema 10. `docs/client-enrollment.md` says a device must re-import to pick up a changed MTU. |

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
run. A namespace cannot show a line that exists only in the client config.
The embedded page was not driven in a browser.

Schema head is version 10. An older binary refuses a newer database. The
architecture guard that counts migration 1 now matches `version: 1,`, so
version 10 is not counted as version 1.

## Known limitations

The device must re-import to pick up a changed MTU. The server interface MTU
is a different change and was not made. The embedded-shell ceiling change is
recorded in `plans/closure/operator-parity/001-status.md`.

## Unresolved findings

None.
