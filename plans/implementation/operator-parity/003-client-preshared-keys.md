# Operator parity M003 — Server-generated preshared keys

Status: **closed** (2026-11-10). Closure: `plans/closure/operator-parity/003-status.md`.

Repository baseline: `a9b0c06af205b20923f7db350a65379cb176e56e`

Source roadmap: `plans/subsystems/operator-parity-roadmap.md`

Canonical requirements and ADRs:

- `plans/000-long-term-specification.md` §2.9 (standard config export) and §4 (no arbitrary fields)
- `plans/adr/004-product-management-enrollment-and-api-semantics.md`
- `architecture/wireguard-control.md` key handling (current behavior: preshared keys are never returned by observation)

Primary work class: capability / secret handling

Hard dependency: Operator parity M002 closed, so the client mutation JSON and schema head are the ones M002 shipped.

## Objective

Let an operator add, replace, or remove a client preshared key on Linux and on Apple silicon. The server generates the key. The browser never supplies the key bytes. The key appears in the downloaded config and the QR code, which already know how to print `PresharedKey`, and nowhere else.

## Explicit non-goals

- No caller-supplied key material, no paste-a-key field, and no key in the client summary.
- No implicit rotation on edit. A save that does not mention the key leaves it.
- No change to server key rotation. The product still does not rotate a client's identity key on edit.
- No schema migration. `peers.preshared_key` has existed since `001_initial.sql`.
- No MTU. That is M004.
- No change to the enrollment token format. A one-time link already reveals the config, so it will reveal a preshared key that is part of that config. That is the existing secret-bearing export, not a new channel.

## Current repository evidence

`create_client` sets `preshared_key: None`. `update_client` does not touch the field. Its comment says keys are not rotated implicitly. `src/product/export.rs` writes `PresharedKey = ...` when the material has one, and a unit test covers that line. Both the Linux netlink patch and the Darwin UAPI renderer already accept `FieldUpdate::Set` and `FieldUpdate::Clear` for the preshared key. Observation drops the key on read.

Client JSON types are documented as free of private keys and preshared keys (`architecture/product-management.md`).

## Invariants

- The summary, the audit row, telemetry, logs, and `Debug` of the domain type do not contain the key.
- Config and QR remain `Cache-Control: no-store` and are produced only by the explicit routes.
- A key change is a normal generation CAS. It is not converged until the peer patch receipt says so.
- Clearing the key removes it from the peer projection. It does not leave the previous key in the kernel by omission: the patch uses `FieldUpdate::Clear`, which both backends already encode.
- The identity key and the addresses do not change when only the preshared key changes.

## Expected production changes

On create, an optional `preshared_key` member whose only accepted value is `"generate"`. Omitted means none, which stays the default.

On update, an optional `preshared_key` member:

- omitted: leave the stored key;
- `"generate"`: replace with a new key from the same CSPRNG the identity keys use;
- `"clear"`: remove it.

Any other JSON type, including a string of key bytes, is `422`.

The client summary gains `preshared_key_configured: bool` and nothing else. The edit dialog offers generate and clear, and tells the operator that every device must import a fresh config or QR after a generate or a clear. The dialog does not display the key. Download and QR remain the explicit reveal, as they are for the private key.

Audit records `client_preshared_key_set` or `client_preshared_key_clear` with the client id and no secret.

The projected peer carries `FieldUpdate::Set` or `FieldUpdate::Clear` on the reconcile that follows the commit. Both platform encoders must emit it. A backend that ignores the field is a failed milestone, not a follow-up.

## Ordered work packages

1. Extend the product commands and the peer projection. Generate with the existing secret constructor. Zeroize the replaced value the way other secrets in the store already are.
2. Reject raw key JSON at the HTTP boundary before the worker sees it.
3. Add the two dialog actions and the re-import warning. Do not put the key in the DOM except through the existing config and QR actions.
4. Assert both encoders. Update the product doc's sentence that currently says preshared keys are absent from projections: summaries stay empty of the secret; the boolean is present; export still carries the secret.

## Privilege and security effects

The key is born in `serve` and crosses to `netd` only inside the typed peer patch that already has a secret field. Do not log the patch. Do not add the key to doctor output. Rate limits and CSRF on the update route are unchanged.

A generate is not idempotent. Repeating it replaces the key and invalidates distributed configs. The UI warning is part of the contract, not decoration.

## Persistence, protocol, and configuration compatibility

No migration. Databases at schema 8 and, after M002, schema 9 already have the column. Old rows remain null. A client that omits the new member keeps today's behavior. Backups already contain preshared keys (`src/state/backup.rs`); this milestone does not change that warning.

The new audit actions follow M002's rule: they are new strings, and the binary that writes them is the binary that reads them.

## Failure, cancellation, restart, and contention

- Validation failure: no write, previous key retained.
- Commit succeeds, peer patch fails: desired state holds the new key, enforcement is degraded, config export shows the new key. Say so. Do not roll the key back because the kernel patch failed; the database is the authority, and the next reconcile retries the patch.
- Clear uses `FieldUpdate::Clear` even when the observed kernel key cannot be read, because observation never returns it. The clear is absolute, not "remove the value I just read".
- Restart after commit: startup reconcile sends the stored key again.
- Concurrent update: `expected_generation` and `409`, as every other client edit.

## Focused tests

- Summary JSON for a client with a key does not contain the key and does contain `preshared_key_configured: true`.
- A body shaped like `{"preshared_key":"<base64>"}` is `422` and does not change the row.
- Generate then export: the config contains exactly one `PresharedKey` line. Clear then export: the line is absent.
- Audit text for both actions does not contain the key.
- Linux peer-patch encoding and Darwin UAPI encoding each include the set and the clear. Use the existing encoder tests; extend them rather than standing up a tunnel.
- A second update that omits the member leaves the key bytes unchanged.

## Linux and network-namespace integration evidence

No new traffic case. The field is already part of both wire protocols. A namespace handshake with a preshared key is not required to prove the product stored and projected the field. If an implementer wants one, it is extra, and it must not become the only evidence: the encoder assertions are the contract.

## Broad verification commands

The ordinary Rust gate order from `docs/development.md`. Include the architecture guards, which already forbid secret material in several projections; extend a guard if one already scans product summaries and would miss the new field.

## Documentation updates

`architecture/product-management.md`: the boolean, the generate/clear verbs, and the export rule. `docs/client-enrollment.md`: devices must be re-imported after a generate or a clear.

## Acceptance criteria

1. The default create still has no preshared key.
2. Generate, replace, and clear work through the authenticated API on the shared client model, and both wire encoders project them.
3. No API response except config and QR contains the key.
4. Raw key material in a request is rejected.
5. An unrelated edit does not rotate the key.

## Stop conditions

Stop if the UI or the API needs to accept a key the operator typed. Stop if one platform's encoder cannot represent a clear; that is a wire-backend defect and gets its own corrective rather than a Linux-only feature. Stop if satisfying the tests means logging the rendered config.

## Closure evidence requirements

`plans/closure/operator-parity/003-status.md` after implementation, including the summary-redaction test and both encoder tests. Do not write it in advance.
