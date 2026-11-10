# Operator parity M002 — Client expiration

Status: **closed** (2026-11-10). Closure: `plans/closure/operator-parity/002-status.md`.

Repository baseline: `a9b0c06af205b20923f7db350a65379cb176e56e`

Source roadmap: `plans/subsystems/operator-parity-roadmap.md`

Canonical requirements and ADRs:

- `plans/000-long-term-specification.md` §2.4 (disable/revoke) and §22 (no aggressive reconcile loop)
- `plans/adr/002-durable-state-generations-and-ownership.md`
- `plans/adr/004-product-management-enrollment-and-api-semantics.md`

Primary work class: capability

Hard dependency: Operator parity M001 closed. The client page and the product mutation path must be the ones M001 left, not a parallel edit.

## Objective

Let an operator set a time after which a client is disabled, on Linux and on Apple silicon, using the disable path that already exists.

An expired client keeps its row, addresses, keys, and config. Its peer leaves projected kernel intent, exactly as a manual disable does. Nothing about this milestone is platform-specific in the result. The worker that fires the expiry is the unprivileged management worker on both hosts.

## Explicit non-goals

- No deletion on expiry. wg-easy disables; this product disables.
- No periodic reconcile loop and no telemetry poll that doubles as a sweeper.
- No new privileged opcode. Expiry does not talk to `netd` except through the reconcile that a normal disable already triggers.
- No grace period and no calendar-library dependency. The value is a Unix second.
- No change to enrollment-link expiry. That clock already exists and is a different table.
- No preshared key and no MTU. Those are M003 and M004.

## Current repository evidence

`ProductClient` has no expiry. Schema head is version 8. `set_client_enabled` in `src/product/service.rs` flips `ClientEnabled`, writes one audit row, and the projection omits a disabled client's peer. The HTTP disable route carries `expected_generation` and reports `revocation_confirmed` false when the backend has not confirmed the removal.

The management worker reconciles on startup and on mutation. It does not wake on a timer except for the Darwin backend-readiness wait, which C009 set to zero on Linux. The long-term spec forbids a loop that wakes while the system is converged.

## Invariants

- DesiredGeneration advances only when a client is actually disabled or when an operator mutation commits. A migration does not advance it. A wake that finds nothing expired does not advance it.
- A disabled client, including an expired one, stays reserved and re-enableable under the rule below.
- The kernel projection for an expired client is the same projection as a manually disabled client.
- Late receipt rules are unchanged. Expiry does not mark a generation converged.
- Audit rows still contain no config and no key material.

## Expected production changes

Schema 9, `009_client_expiration.sql`, append-only: nullable `expires_at` integer Unix seconds on the client row. Null means never. Existing rows stay null.

Create and update accept an optional `expires_at`.

- Omit or null: never expires. Update can clear a previous value.
- A value at or before the worker's current time: `422`, no write.
- A future value: stored. The UI sends the operator's chosen instant as Unix seconds. The page may use a local datetime input; the API does not accept a timezone name.

When `expires_at` is in the past relative to the worker clock:

- the worker performs the existing disable mutation if the client is enabled;
- the audit action is a new `client_expire`, distinct from `client_disable`, so the activity list says why;
- `revocation_confirmed` follows the disable route's existing rule;
- a client that is already disabled is left unchanged, including its `expires_at`.

Re-enable of a client whose `expires_at` is still in the past is `422` unless the same request sets a future `expires_at` or clears it. Otherwise the next wake would disable it again and the operator would see a toggle that does not stick.

The client summary gains `expires_at` (nullable) and a derived `expiry_state` of `none`, `scheduled`, or `expired`. The list page can filter by name or address, by enabled/disabled, and by expiry. Filtering is in the page, over the list the API already returns. No new query language.

The worker arms at most one sleep, until the minimum future `expires_at`. On wake it expires due clients in stable client-id order, one generation each, then rearms. If no future deadline exists, it arms nothing. Startup runs the same pass before the startup reconcile, so a client that expired while `serve` was down is disabled before the peer is projected.

## Ordered work packages

1. Add the migration and the read/write of `expires_at` without bumping DesiredGeneration inside the migration.
2. Extend create, update, and the enable command. Keep address allocation and route policy as they are.
3. Add the one-shot wake beside the worker's existing lifecycle, not inside `netd`.
4. Surface the field, the activity row, and the filters in the embedded page.
5. Tests and the doc update listed below.

## Privilege and security effects

The wake runs in `serve`. It uses the same store mutation as an operator disable and then the same reconcile. An attacker who can set `expires_at` can already disable the client through the disable route; the new field does not widen authority. Session, Origin, and CSRF rules on the mutation routes stay as they are.

Clock rollback can postpone an expiry. Clock step-forward can fire it. The product does not try to detect NTP. Document that the worker clock is the authority.

## Persistence, protocol, and configuration compatibility

Schema 8 opens and migrates to 9. A binary that only understands schema 8 refuses a schema 9 file, which is the current opener behavior. Old clients with null expiry behave as they do today. The new JSON fields are additive. A create that omits `expires_at` stores null.

The new audit action is stored as its existing string form. Readers that only open schema 9 must accept `client_expire`. Do not reuse `client_disable` for this path.

## Failure, cancellation, restart, and contention

- Disable commit succeeds and enforcement is degraded: same `202` semantics as a clicked disable. The client stays disabled in desired state. The wake does not retry enforcement itself; the normal reconcile path does.
- Two expiries due together: client-id order, one generation each. A `409` cannot happen from the worker's own chain because it reads the generation it just wrote. An operator mutation in between returns the worker to a fresh read; it does not overwrite that mutation's other fields.
- Process stops during the sleep: nothing has been committed. Startup catches up.
- Process stops after the commit and before reconcile: startup reconcile applies the new generation, as it does for any other commit.
- The wake must not run a second copy. One worker thread owns it.

## Focused tests

- Migration from schema 8 leaves clients unexpired and does not change DesiredGeneration.
- Create and update reject a past timestamp and accept a future one and a clear.
- A wake at `expires_at + 1` disables an enabled client, writes `client_expire`, and leaves addresses and keys in place. The projected peer set omits that client.
- A second wake does not write another generation.
- Re-enable with the past timestamp still set is refused. Re-enable with a clear succeeds.
- No sleep is armed when every `expires_at` is null.
- The Linux and Darwin peer projections are the same for an expired client. One host-free projection test is enough if the projection is shared; do not fork the rule per platform.

## Linux and network-namespace integration evidence

Not a new network behavior. A disabled peer is already removed by the closed product path. Do not build a namespace just to watch an expiry. If the ordinary rootful gate is already required by `docs/development.md` for the tree, run it and record it; do not add a traffic case.

## Broad verification commands

The ordinary Rust gate order from `docs/development.md` on the implementation host. Schema migration tests run unprivileged.

## Documentation updates

`architecture/product-management.md` gains the field, the `client_expire` action, and the statement that expiry is a disable. `architecture/state-store.md` notes schema 9 once the migration exists. The UI section notes the filters.

## Acceptance criteria

1. A client with no expiry is unchanged on both platforms.
2. A future expiry becomes a disable at that time, including across a restart that covers the deadline, without a poll loop.
3. The address reservation and the config survive. The peer is gone from intent.
4. The activity list records `client_expire` rather than a manual disable.
5. Re-enable cannot stick while the deadline is still in the past, unless the deadline is cleared or moved forward in the same request.

## Stop conditions

Stop if enforcement seems to need a new netd operation, a cron entry, a `wg-quick` hook, or a loop that wakes on a fixed period while idle. Stop if expiry is implemented as a delete.

## Closure evidence requirements

`plans/closure/operator-parity/002-status.md` after implementation, with the migration test, the wake test, and the commands actually run. Do not write it in advance.
