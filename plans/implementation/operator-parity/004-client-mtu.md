# Operator parity M004 — Client MTU in the exported config

Status: **closed** (2026-11-10). Closure: `plans/closure/operator-parity/004-status.md`.

Repository baseline: `a9b0c06af205b20923f7db350a65379cb176e56e`

Source roadmap: `plans/subsystems/operator-parity-roadmap.md`

Canonical requirements and ADRs:

- `plans/000-long-term-specification.md` §2.9 and §4.2 (standard export, no extra arbitrary fields, no hooks)
- `plans/adr/004-product-management-enrollment-and-api-semantics.md`

Primary work class: capability

Hard dependency: Operator parity M003 closed. Schema head is then 9, from M002. M003 adds no migration.

## Objective

Let an operator set the MTU that a client's own WireGuard config will request, on Linux and on Apple silicon. The value is a line in `[Interface]` of the export. It is not applied to the server's link, the `utun`, or the kernel device.

wg-easy exposes this because some client networks need a smaller MTU than the default the client app would pick. The server dataplane does not need a matching change for that problem.

## Explicit non-goals

- No server-interface MTU, no `ip link set mtu`, no Darwin interface MTU ioctl, and no WireGuard device MTU in either backend.
- No per-client MTU inside the kernel peer. The WireGuard protocol does not negotiate it. The client app reads the config.
- No hooks and no comment lines added to the config to explain the value.
- No change to DNS, keepalive, routes, expiry, or preshared keys except that the renderer must keep their existing order and insert `MTU` in a fixed place.

## Current repository evidence

`src/product/export.rs` writes `PrivateKey`, `Address`, optional `DNS`, then the peer block. There is no MTU branch. The domain model has no MTU type. Schema head at the baseline is 8; after M002 it is 9. Interface reconciliation owns link MTU nowhere today, which is why this milestone must not grow that owner.

## Invariants

- Two clients with the same inputs and the same MTU produce byte-identical config text, as the renderer does today.
- Omitted MTU means the line is absent, not `MTU = 0` and not a commented default.
- The server's applied link state is identical before and after a client MTU change. No reconcile plan gains a link mutation from this field.
- The value is not a secret. It may appear in the client summary.

## Expected production changes

Schema 10, `010_client_mtu.sql`: nullable integer `mtu` on the client row. Null on existing rows.

Accepted values: an integer from 1280 through 9000 inclusive, or null to clear. Anything else, including 0 and a string, is `422`. 1280 is the IPv6 minimum that still carries a tunnel; 9000 covers a jumbo frame without pretending any integer is an MTU.

The summary returns `mtu` as a number or null. Create and update accept it as an optional field. Omit means leave it (on update) or null (on create).

The renderer writes `MTU = <n>` in the interface block after `Address` and before `DNS`, only when the value is present. QR uses that same text, so it needs no separate encoder.

The edit form gains the field and leaves it blank when null.

## Ordered work packages

1. Migration that does not advance DesiredGeneration.
2. Command, summary, and validation.
3. Renderer change and a golden config fixture for present and absent.
4. Form field.
5. A projection test that a client MTU change does not alter the link or peer address plan. The peer patch may still be a no-op update; it must not set a link MTU.

## Privilege and security effects

None. The field never crosses into `netd`. CSRF and generation CAS on create and update stay as they are.

## Persistence, protocol, and configuration compatibility

Schema 9 migrates to 10. Schema 8 migrates through 9 to 10 in order. Old configs stay byte-compatible when `mtu` is null: the new line is absent, so a previously exported config of an unedited client does not gain a line. Changing the value changes the export, which is the point, and devices pick it up only when they re-import. Say that next to the field.

## Failure, cancellation, restart, and contention

A rejected value does not write. A committed value is durable even if the network is degraded, because nothing network-facing depends on it. Restart does not re-apply it to a link. Concurrent edits use `expected_generation`.

## Focused tests

- Null stays absent from the config. 1280 and 9000 render one line in the specified place. 1279 and 9001 are `422`.
- Migration preserves a schema 9 client and its expiry column.
- Golden fixture stays stable across runs.
- The reconcile plan for a client whose only change is `mtu` contains no link-MTU action. Assert this on the shared planner input, not by bringing a link up.

## Linux and network-namespace integration evidence

None. A namespace cannot show a line that only the client config contains. Do not add one.

## Broad verification commands

The ordinary unprivileged Rust gate order from `docs/development.md`.

## Documentation updates

`architecture/product-management.md` documents the export line and the range, and says the server interface MTU is unchanged. `architecture/state-store.md` notes schema 10. `docs/client-enrollment.md` says the device must re-import to pick up a changed MTU.

## Acceptance criteria

1. Both platforms export the same `MTU` line for the same client, because export is shared.
2. Null omits the line and leaves old configs unchanged.
3. No link, route, firewall, or WireGuard device mutation is added.
4. Out-of-range values never persist.

## Stop conditions

Stop if an implementer starts setting the server link MTU "so the number does something" on the host. That is a different milestone with Linux netlink and Darwin interface evidence. Stop if the config gains a comment or a hook to apply the MTU.

## Closure evidence requirements

`plans/closure/operator-parity/004-status.md` after implementation, with the golden fixture result and the plan-diff test. Do not write it in advance.
