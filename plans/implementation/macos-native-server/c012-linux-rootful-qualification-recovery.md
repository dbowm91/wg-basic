# macOS Native Server C012 — the Linux rootful qualification compiles again

Status: **in implementation**. The defect this plan corrects was found in the
Linux CI runs of the C011 branch; the implementation and the evidence are
recorded in `plans/closure/macos-native-server-corrective/c012-status.md`.

Baseline: `plans/macos-native-support@ae98728`.

Source: C003's implementation (the routed-LAN policy model); the Linux CI runs
at `5238816` and after; `docs/development.md` §Linux gates.

Primary class: corrective / invariant.

## Objective

Make the Linux qualification compile again, and close the hole in the gate set
that let it break unnoticed.

C003 added two fields to the network-policy model — the routing `mode` and the
approved `destination_prefixes` — and updated the Darwin and portable paths.
It did not update the **Linux-only** test fixtures, and the Linux CI went red
on every job that compiles them. The Linux qualification is the canonical
platform's evidence, and it has not run since.

## Non-goals

No change to the policy model, the product's behaviour, or the desired-state
schema. No change to the Darwin line. The `dependency-audit` failure is a
separate condition and is not closed here (§Known limitations). No reopening of
C003's closed scope.

## The defect

`DesiredNetworkPolicy` gained `mode` and `destination_prefixes` in C003. The
Linux-only fixtures construct that struct directly, and their initializers
were left as they were:

| File | Constructors | Correct mode |
|---|---|---|
| `tests/durable_owner.rs` | `firewall::DesiredNetworkPolicy` × 4 | `HostOnly` — no forwarding, no NAT |
| `tests/durable_restart.rs` | `domain::DesiredNetworkPolicy` × 1 | `Gateway` — forwarding and masquerade |
| `tests/durable_backup.rs` | `domain::DesiredNetworkPolicy` × 1 | `Gateway` — forwarding and masquerade |
| `tests/network_control_e2e.rs` | `firewall::DesiredNetworkPolicy` × 1 | `Gateway` — forwarding required |
| `tests/doctor_readonly.rs` | `product::ServerSetupCommand` × 1 | `None` — derives `HostOnly` |
| `tests/maintenance_rootful.rs` | `product::ServerSetupCommand` × 1 | `None` — derives `HostOnly` |
| `tests/product_management_rootful.rs` | `product::ServerSetupCommand` × 1 | `None` — derives `HostOnly` |

The mode is not a new requirement the fixtures have to satisfy — it is the
statement of what each fixture always meant. `HostOnly` refuses forwarding,
masquerade, and destinations; `Gateway` is the mode that carries forwarding
and the optional masquerade. The Linux-only fixtures that ask for forwarding
and masquerade therefore cannot be host-only, and saying so is what C003's
validation requires.

The product's behaviour is unchanged: the fixtures state the same routing
intent they always had, and no product code changes.

## Why the previous evidence missed it

The Linux fixtures are compiled only on Linux with the `linux-integration`
feature:

```rust
#![cfg(all(target_os = "linux", feature = "linux-integration"))]
```

The standard gate set runs on the developer's Mac, where those files
compile to nothing. The gate order in `.skills/wg-basic-gates/SKILL.md` is
`fmt`, `check`, `clippy`, `test`, and the MSRV check — none of them type-check
a Linux-gated file from a Darwin host. `docs/development.md` documents a Linux
cross-clippy *with* `--features linux-integration`, which would have caught
this, but it is not in the gate order, so it was not run for C003.

The CI shows the break exactly. At `92af9f5` — the C010 baseline — every Linux
job was green and the only failure was `dependency-audit`. At `5238816` — C003's
closure commit — ten jobs failed, and every one of them is a Linux job that
compiles a policy initializer.

## Implementation work

1. **The fixtures state their mode.** Every affected initializer names the
   mode its own settings require, and the approved destinations are empty
   where the mode forbids them.
2. **The gate order type-checks the Linux-gated code.** The canonical gate
   order gains the Linux cross-clippy with `--features linux-integration`, so
   a change that breaks Linux-only code fails on the Mac instead of in CI.

## Qualification and security evidence

- The Linux cross-clippy with `--features linux-integration` is clean.
- The Linux CI on the final head is green on every Linux job.
- The ordinary suite and the Darwin gates are unchanged.

The evidence this plan adds is **compilation** evidence, not new runtime
evidence: the qualification that the Linux jobs carry is unchanged, and what
this restores is the ability to run it at all.

## Known limitations

- The `dependency-audit` job stays red. The advisories are against `zip`
  6.0.0, which `eggup-archive` 0.1.3 requires as `^6.0.0`, and `eggup-eggpack`
  is pinned to `=0.1.3` here, so the fix needs a new upstream release. This is
  a separate condition, it predates C003, and it belongs to the release
  authority line (C005, M007).
- The Linux cross-clippy proves the Linux-gated code **compiles** on a Darwin
  host. It does not run it: the rootful suites still need Linux, root, and the
  kernel, and their evidence is the CI's.
