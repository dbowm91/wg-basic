# Operator parity M003 closure — server-generated preshared keys

Status: closed.

Implementation commit: none. The work is the uncommitted tree on baseline
`a9b0c06af205b20923f7db350a65379cb176e56e`.
Planning baseline: `a9b0c06`.
Plan: `plans/implementation/operator-parity/003-client-preshared-keys.md`.
Disposition: **closed**. The server can generate or clear a client preshared
key. The summary carries a boolean and not the key. Both wire encoders
project set and clear.

## Requirement-to-evidence matrix

| Plan requirement | Evidence |
|---|---|
| The summary names the boolean and does not contain the key | `preshared_keys_are_generated_or_cleared_and_never_echoed` in `tests/product_management.rs`. Generate on create sets `preshared_key_configured`. The summary JSON contains that field and does not contain `PresharedKey`. The config contains one `PresharedKey` line. Create stays audit `ClientCreate`. |
| A caller-supplied key is rejected before it is stored | `a_caller_supplied_preshared_key_is_rejected_before_it_is_stored` in `src/http/service.rs`. Any JSON other than `"generate"` on create, or `"generate"` / `"clear"` on update, is rejected. |
| Generate replaces, clear removes, and an unrelated edit leaves the bytes | The product test. A label-only update leaves the key bytes and stays `client_update`. Generate plus a label rotates the key and audits `ClientPresharedKeySet` with the client id. Clear removes the config line and audits `ClientPresharedKeyClear`. Neither audit carries the secret. |
| Linux and Darwin encoders project set and clear | `a_stored_preshared_key_is_set_and_a_leftover_key_is_cleared` in `src/reconcile/planner.rs`: a stored key is `FieldUpdate::Set`, and an observed key with nothing stored is `Clear`. `a_nonzero_preshared_key_is_recorded_as_presence_and_then_wiped` records Linux presence before the secret is wiped; the all-zero key is not configured. `preshared_key_set_and_clear_are_rendered_and_only_presence_is_parsed` covers the Darwin UAPI set, clear, and presence parse. A residual plan that is only an unconfirmed preshared `Set` counts as converged. A residual `Clear` does not. |
| Docs | `architecture/product-management.md` documents the boolean, the generate and clear verbs, and the export rule. `docs/client-enrollment.md` says a device must re-import after a generate or a clear. |

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
compiler. No rootful handshake and no controlled-host macOS qualification
were run. The encoder assertions are the contract. The embedded page was not
driven in a browser. Generate and clear are separate requests; saving a
client does not send a preshared-key verb.

No schema migration. `peers.preshared_key` has existed since schema 1.

## Known limitations

A generated key is not rolled back if a later kernel patch fails. Generate is
not idempotent. The embedded-shell ceiling change is recorded in
`plans/closure/operator-parity/001-status.md`.

## Unresolved findings

None.
