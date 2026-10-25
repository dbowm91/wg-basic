# C012 — the Linux rootful qualification compiles again: closure record

Milestone: **C012** (C003's corrective).
Class: corrective / invariant.
Date: 2026-10-22.

Source plan: `plans/implementation/macos-native-server/c012-linux-rootful-qualification-recovery.md`.
Corrects: C003's implementation — the routed-LAN policy model and the schema-8
migration — which left the Linux qualification uncompilable.

Baseline: `plans/macos-native-support@ae98728`.
Implementation head: `66c078e` — *linux(c012): make the rootful qualification
compile again*, on top of `ae98728`.
Follow-ups: `3aeae59` — *linux(c012): rehearse the migration against the
schema a current binary writes*; `b302e74` — *linux(c012): assert the migrated
schema against the schema contract too*. The Linux CI run below is the one on
the final head; `39812428119` is the same code on `b302e74`.

C003's own closure record is **not** rewritten. It records what that run
observed; the silence in the Linux CI afterwards is recorded here.

## 1. Disposition

**Closed.** The Linux qualification compiles again and every Linux job is
green on the final head. The defect was C003's: a shared model changed and
the Linux-only fixtures and rehearsals were not taught the change, so the
canonical platform's entire qualification stopped running at `5238816` and
nothing on the developer's Mac noticed.

The one red job on the final head is `dependency-audit`, and it is a separate
condition that predates C003 and is not fixable in this repository (§9). The
gate that would have caught this class of break on the Mac is now part of the
gate order, so the next occurrence fails locally instead of in CI.

## 2. What the defect was

C003 added two fields to the network-policy model — the routing `mode` and the
approved `destination_prefixes` — and moved the schema to version 8. It
updated the Darwin and portable paths. It did not update the code that only
compiles on Linux.

Two distinct failures followed.

**The fixtures did not compile.** The Linux-only fixtures construct
`DesiredNetworkPolicy` directly, and their initializers still named only the
old fields:

```
error[E0063]: missing fields `destination_prefixes` and `mode` in initializer of
  `wg_basic::firewall::DesiredNetworkPolicy`
  --> tests/durable_owner.rs:559:18
```

The same error appeared in `durable_owner.rs`, `durable_restart.rs`,
`durable_backup.rs`, `network_control_e2e.rs`, `doctor_readonly.rs`,
`maintenance_rootful.rs`, and `product_management_rootful.rs`.

**The rehearsals asserted a version that had moved.** Three rehearsals wrote
the schema version a migrated state carries into the assertion:

```
assert!(migrated.contains("schema version:     7"), "{migrated}");
assert_eq!(migrated_snapshot.schema_version, 7);
failure.contains("candidate health passed with state schema 7")
```

The candidate in the update transaction is built from the current source with
a strictly newer package version, so it writes the current schema, and the
assertion was one migration behind.

## 3. Why the previous evidence missed it

The rootful suites are compiled only on Linux with the integration feature:

```rust
#![cfg(all(target_os = "linux", feature = "linux-integration"))]
```

The gate order in `.skills/wg-basic-gates/SKILL.md` is `fmt`, `check`,
`clippy`, `test`, and the MSRV check. Every one of those runs on the
developer's Mac, where those files compile to nothing. The gate order had no
step that type-checked a Linux-gated file from a Darwin host, so a change to a
shared model could break every Linux job without a single local gate failing.

`docs/development.md` documented a Linux cross-clippy *with*
`--features linux-integration` — the check that would have caught this — but
it was not part of the gate order, so it was not run for C003.

The CI shows the break exactly. At `92af9f5`, the C010 baseline, every Linux
job was green and the only failure was `dependency-audit`. At `5238816`,
C003's closure commit, ten jobs failed: the nine that compile a policy
initializer or assert a schema version, plus the three rehearsals. No Linux
job had run since.

## 4. Requirement-to-evidence matrix

| # | Requirement | Evidence | Where |
|---|---|---|---|
| R1 | The Linux-only fixtures compile | the Linux cross-clippy with `--features linux-integration` is clean | §5 |
| R2 | Each fixture states the mode its own settings require | host-only where nothing is forwarded or masqueraded, gateway where forwarding or masquerade is asked for | `tests/durable_owner.rs`, `tests/durable_restart.rs`, `tests/durable_backup.rs`, `tests/network_control_e2e.rs` |
| R3 | The setup commands keep deriving the mode | `mode: None`, which derives the mode from the forwarding and masquerade settings | `tests/doctor_readonly.rs`, `tests/maintenance_rootful.rs`, `tests/product_management_rootful.rs` |
| R4 | The rehearsals assert the version a current binary writes | the schema's public contract reports it; no literal remains | `src/state/schema/migrations.rs`, the three rehearsal files |
| R5 | The update-fixture override is unchanged | it still pins the *old* fixture binary to schema 4, and the candidate still writes the current schema | `src/state/schema/migrations.rs` |
| R6 | The Linux qualification runs again | every Linux job is green on the final head | §8 |
| R7 | The gate catches this class on the Mac | the gate order includes the feature-bearing Linux cross-clippy | `.skills/wg-basic-gates/SKILL.md`, `docs/development.md` |
| R8 | Nothing else regressed | the ordinary suite, the Darwin gates, and the cross-build are unchanged | §5 |
| R9 | No product behaviour changed | the fixtures and the rehearsals state the same intent they always had; the product's code changes are one read-only accessor | §4 |

## 5. What changed

| File | Change |
|---|---|
| `tests/durable_owner.rs` | four host-only policies name their mode |
| `tests/durable_restart.rs`, `tests/durable_backup.rs` | the masquerading gateway policies name their mode |
| `tests/network_control_e2e.rs` | the forwarding policy names its mode |
| `tests/doctor_readonly.rs`, `tests/maintenance_rootful.rs`, `tests/product_management_rootful.rs` | the setup commands keep deriving the mode |
| `src/state/schema/migrations.rs` | `current_schema_version()` — the schema version a current binary writes, without the update-fixture override |
| `src/state/schema/mod.rs`, `src/state/mod.rs` | that version is part of the state contract |
| `tests/upgrade_rehearsal.rs`, `tests/upgrade_rehearsal_rootful.rs`, `tests/update_transaction_rootful.rs` | the rehearsals ask for the version instead of writing one down |
| `.skills/wg-basic-gates/SKILL.md`, `docs/development.md` | the gate order type-checks the Linux-gated code, and says why |

The product's behaviour is unchanged. The only product change is a read-only
accessor on the state contract, and the rehearsals still assert the same
migration they always rehearsed.

## 6. Commands and results

Run on the development host (Apple silicon, macOS 26.6.2) on 2026-10-22.

```
cargo fmt --all -- --check                                    clean
cargo check --all-targets --locked                            clean
cargo clippy --all-targets --locked -- -D warnings            clean
cargo test --locked                                           429 unit tests, 0 failed; every integration suite passed
cargo test --locked -p wg-basic-darwin-sys                    13 passed
cargo +1.89.0 check --all-targets --locked                    clean
cargo check --locked --target aarch64-apple-darwin --all-targets   clean
cargo zigbuild --locked --target x86_64-unknown-linux-gnu --all-targets   clean
CC_x86_64_unknown_linux_gnu=$HOME/wg-toolchain/zigcc AR_x86_64_unknown_linux_gnu="zig ar" \
  cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets -- -D warnings   clean
CC_x86_64_unknown_linux_gnu=$HOME/wg-toolchain/zigcc AR_x86_64_unknown_linux_gnu="zig ar" \
  cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets \
  --features linux-integration -- -D warnings   clean
```

The last command is the one this milestone adds to the gate order. It is what
would have caught C003's break on the Mac.

## 7. Kernel and network evidence

This milestone changes no network control, no ownership, and no privilege
boundary, so there is no kernel or network evidence to produce, and none is
claimed. The qualification the Linux jobs carry — the nftables contract, the
ownership markers, the durable restart, the backup and restore, the read-only
doctor, the product management — is unchanged, and its evidence is the CI's
own (§8).

The one product change is a read-only accessor on the state contract. It
reports the head of the migration list and nothing else, so it cannot reveal
a key, a secret, or a host resource.

## 8. Controlled-host evidence

The evidence is the Linux CI on the final head, which is the only place the
rootful qualification can run: run `39813848250`, on the final head `b84cb8c`
(`39812428119` is the same code on `b302e74`).

| Job | `5238816` (C003's closure) | Final head |
|---|---|---|
| `rust` | success | success |
| `wireguard-kernel` | success | success |
| `network-reconcile-kernel` | success | success |
| `system-install-systemd` | success | success |
| `network-control-e2e` | **failure** | success |
| `durable-owner` | **failure** | success |
| `durable-restart` | **failure** | success |
| `durable-backup` | **failure** | success |
| `doctor-readonly` | **failure** | success |
| `maintenance-rootful` | **failure** | success |
| `product-management-rootful` | **failure** | success |
| `upgrade-rehearsal` | **failure** | success |
| `upgrade-rehearsal-rootful` | **failure** | success |
| `update-transaction-rootful` | **failure** | success |
| `dependency-audit` | failure | failure (not fixable here — §9) |

The baseline for the comparison is `92af9f5`, the C010 closure, where every
Linux job was green.

## 9. Known limitations

- **`dependency-audit` stays red.** The advisories are against `zip` 6.0.0 —
  one of them critical (9.1), all three fixed in `zip >= 9.0.0`. `eggup-archive`
  0.1.3 requires `zip = "^6.0.0"` and `eggup-eggpack` is pinned to `=0.1.3`
  here, so the fix needs a new upstream release:
  `cargo update -p zip --precise 9.0.0` fails with "candidate versions found
  which didn't match: 9.0.0". Checked against the registry on 2026-10-22,
  `eggup-archive`'s newest published version is still 0.1.3 and it requires
  `zip ^6.0.0` non-optionally, and `eggup-eggpack`'s newest is 0.1.3, so
  there is no upstream release this repository could move to. This condition
  predates C003 — it was the only red job at the C010 baseline — and the
  product's install and update path is Phase 10 work that is not implemented,
  so the advisory is in a path that does not yet run. It belongs to the
  release-authority line (C005, M007), and clearing it needs either a new
  `eggup-archive` release or a maintainer's decision about how to carry a
  patched dependency.
- **The Linux cross-clippy is a compilation check.** It proves the
  Linux-gated code type-checks on a Darwin host; it does not run it. The
  rootful suites still need Linux, root, and the kernel, and their evidence
  is the CI's.
- **The CI's Linux environment is the evidence, not a controlled host.** The
  C003 and C011 legs ran on a disposable macOS guest; the Linux qualification
  has no equivalent, and this milestone does not add one.

## 10. Severity-rated findings

| Finding | Severity | Evidence | Disposition |
|---|---|---|---|
| **F6 — the Linux qualification stopped running at C003 and nothing noticed.** C003 changed a shared model and the schema version; the code that only compiles on Linux was not taught the change, so nine Linux jobs stopped compiling and three rehearsals asserted a version that had moved. The canonical platform's entire qualification had not run since `5238816`, and the developer's gate set could not see it. | high (qualification integrity) | The CI at `5238816` against the CI at `92af9f5`: ten jobs green become red. The same ten jobs are green on the final head | **Corrected.** The fixtures state their mode, the rehearsals ask for the version instead of writing one down, and the gate order type-checks the Linux-gated code from a Darwin host. |
| **F7 — the gate order had no step that type-checked Linux-gated code.** Every gate in the canonical order runs on the developer's Mac, where `#![cfg(all(target_os = "linux", feature = "linux-integration"))]` files compile to nothing. `docs/development.md` documented the check that would have caught it, but the gate order did not include it, so it was not run. | medium (process) | The gate order in `.skills/wg-basic-gates/SKILL.md` | **Corrected.** The Linux cross-clippy with `--features linux-integration` is part of the gate order, for any change to a shared model, type, or public API. |
| **F8 — a schema version written into an assertion rots with the next migration.** Three rehearsals asserted the version a migrated state carries by writing the number down, so the first migration after that took a job red for a reason that had nothing to do with the change under test. | medium (maintenance) | The three rehearsals' assertions against the schema-8 migration | **Corrected.** The schema's public contract reports the version a current binary writes, and the rehearsals use it. |

## 11. Disposition

**Closed.** The Linux qualification compiles and runs again: every Linux job
is green on the final head, where ten were red at C003's closure commit. The
hole that let it break silently — a gate order with no step that
type-checked Linux-gated code — is closed, so the next occurrence of this
class fails on the developer's Mac.

Three findings are recorded and corrected: F6, the qualification's silence;
F7, the gate hole; and F8, the assertion that rots. The `dependency-audit`
advisory is recorded as open and is not fixable in this repository: it needs
a new `eggup-archive` release, it predates C003, and it belongs to the
release-authority line.

Nothing in this record changes M007's MUST-NOT-release standing, and nothing
in it claims installation or transactional self-update.
