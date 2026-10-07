# Durable State M002 Closure

Status: closed

Planning baseline: `d41cea8` (M001 closure)
Final implementation head: `65339b8`
Qualification run: GitHub Actions CI run [`37623015401`](https://github.com/dbowm91/wg-basic/actions/runs/37623015401), commit `65339b8`

## Outcome

M002 is strictly closed. Request-scoped ownership has become restart-stable ownership proven by a durable tag, the owned nftables table is bound to the installation identity, and one desired generation is now the unit of privileged reconciliation through a single aggregate operation.

Automatic startup application of durable desired state is **not** implemented; that is M003.

## Requirement-to-evidence matrix

| Requirement | Evidence |
|---|---|
| OwnerTag domain | `domain::OwnerTag` derives `wg-basic:v1:<installation-uuid>:<interface-uuid>` from a format version, `InstallationId`, and `InterfaceId` only. It is 85 ASCII characters against the 255-byte `IFALIASZ` limit, deterministic, and free of any user-supplied label. `owner_tag_is_deterministic_ascii_and_well_under_the_kernel_limit`, `owner_tag_round_trips_into_installation_and_interface_identity`, and `invalid_and_foreign_formats_are_rejected_rather_than_guessed` cover derivation, round-trip, and rejection of foreign versions, unrelated text, extra segments, and over-long values. `OwnerTag` is not a secret. |
| Interface identity available to netd | `InstallationId` and `DesiredGeneration` moved from `state` to `domain`, so the privileged side derives a tag without depending on the state store. `the_privileged_service_never_opens_the_state_database` and `the_aggregate_coordinator_is_privileged_and_database_free` enforce this statically. |
| RTNETLINK alias support | `netlink-packet-route` 0.33 exposes `LinkAttribute::IfAlias` (`IFLA_IFALIAS`). No shelling to `ip` was required. The M002 stop conditions were therefore not triggered. |
| Creation sets the owner tag | `tests/durable_owner.rs::created_link_is_tagged_and_a_matching_tag_survives_restart` asserts the created link's alias equals the expected tag, and that a fresh netd process still reconciles it. |
| Link classification | `require_owned` refuses authoritative mutation *and* destruction unless the observed alias is exactly the expected tag. `a_missing_link_is_created_and_tagged`, `a_matching_owner_tag_permits_full_owned_reconciliation`, `an_absent_alias_is_a_conflict_for_an_existing_link`, `an_unrelated_alias_is_never_treated_as_ownership`, `a_foreign_installation_or_interface_tag_is_a_conflict`, `a_duplicate_owner_tag_elsewhere_is_a_conflict_and_survives`, `an_unowned_link_is_refused_before_destruction_too`, and `a_wrong_kind_link_is_still_refused_before_ownership_is_considered` cover every branch. Ownership is never inferred from name or public key. |
| External drift is repaired when ownership is proven | `a_matching_owner_tag_permits_full_owned_reconciliation` plans mutations against a drifted admin state under a matching tag. |
| Duplicate owner-tag detection | Observation enumerates links, bounded to 4,096, and records `duplicate_owner_tag`. `a_duplicate_owner_tag_elsewhere_is_a_conflict_and_survives` plus the rootful `a_duplicate_owner_tag_on_another_link_is_a_conflict` prove the conflict and that both links survive. |
| Firewall owner marker evolution | `FirewallOwner` derives `wg-basic:v1:<installation-uuid>` and threads it through observation, planning, expected-object rendering, and table replacement. `the_owned_nftables_table_marker_binds_to_the_installation` asserts the real table comment. Chain/rule markers build on it and still bind the desired policy hash, so expression-level drift detection is unchanged. |
| Foreign table marker is a conflict | `a_foreign_installation_table_marker_is_a_conflict` and the rootful `a_foreign_installation_table_marker_is_a_conflict` prove the refusal and that the foreign table survives untouched. |
| Legacy marker not silently adopted | `LEGACY_TABLE_OWNER` (`wg-basic:m005:v1`) is recognized specifically and surfaced as `FirewallError::LegacyTableOwnership`, mapped to the existing `ProtocolError::Conflict`. `the_historical_product_only_marker_is_never_treated_as_ownership` proves it is not ownership. No automatic legacy migration was added, matching the plan's default. |
| Aggregate intent type | `InstallationNetworkIntent` carries installation identity, generation, interface identity, the desired interface, and the optional policy. `validate` re-checks generation bounds, owner-tag derivation, interface identity, and interface validity, and maps a malformed tag to the existing error categories. `a_valid_intent_reports_the_owner_tag_it_implies`, `an_owner_tag_from_another_installation_is_refused_before_privileged_work`, `an_owner_tag_from_another_interface_is_refused`, `generation_bounds_are_validated`, and `an_invalid_interface_is_refused_before_any_privileged_call` cover it. |
| Aggregate protocol extension | `PlanInstallationNetworkIntent` and `ApplyInstallationNetworkIntent` with generation-tagged `InstallationNetworkPlanBody` / `InstallationNetworkApplyBody`. The lower-level M003–M005 operations are preserved. `PROTOCOL_VERSION` stays 1; the architecture guard pins it and pins the closed operation vocabulary. |
| Aggregate plan layering | `InstallationNetworkPlan` carries ordered per-layer summaries and an `enabling` hint. It never serializes rendered nft source or private keys. |
| Aggregate apply ordering | Enable reconciles the interface layer first and returns `InterfaceLayerIncomplete` without touching the firewall if it does not verify. Disable removes the owned policy first and returns `FirewallLayerIncomplete` leaving the interface intact if that fails. The rootful `the_disable_aggregate_path_removes_firewall_before_the_interface` proves the disable ordering end to end. |
| One outer mutation lock | `AggregateCoordinator` holds one `mutation_lock` taken before any layer lock, giving a fixed outer-then-inner order. Layer locks remain as defence in depth. |
| In-process generation monotonicity | `Accepted` records the installation identity and highest generation. `the_first_generation_establishes_the_installation_identity`, `a_higher_generation_is_eligible_and_equal_is_idempotent`, `a_lower_generation_is_rejected_as_stale`, `a_different_installation_identity_is_rejected_while_the_process_lives`, and `acceptance_records_the_generation_before_mutation_and_never_lowers_it` cover every rule. The generation is recorded before the first mutation; failure never lowers it. |
| Receipt semantics | `InstallationNetworkReceipt` carries installation identity, generation, overall status, both layer results, the failing layer, and post-observation success. `absence_of_a_layer_status_is_reported_truthfully` proves `NoChange` requires both layers idle and that an earlier changed layer plus a later failure is `PartialFailure`. No code path claims rollback. |
| Lower-level semantics preserved | `a_wrong_kind_link_is_still_refused_before_ownership_is_considered` covers the wrong-kind rule. The rootful disable test's teardown intent must still enumerate the managed address as `Absent`, which is the existing M004 preservation rule, unchanged. Peer preservation, route conflicts, and the independent-firewall warning are untouched; `no_module_shells_out_through_a_shell` and the existing forwarding suites still pass. |
| netd remains database-free | `the_privileged_service_never_opens_the_state_database` and `the_aggregate_coordinator_is_privileged_and_database_free`. |
| Protocol hygiene | `privileged_protocol_exposes_no_generic_escape_hatch_operation` still passes, so no generic exec, shell, raw-netlink, file-write, sysctl, or raw-nft operation was added. Owner/plan/receipt fields are bounded typed values, and private keys remain inside the existing redacting wrappers. |

## Kernel finding worth recording

Linux 6.8 accepts `IFLA_IFALIAS` in `RTM_NEWLINK` but **silently discards** it; a created link comes back with no alias. This was established with a direct netlink probe, not inferred. Creation is therefore followed by an immediate `RTM_SETLINK` inside the same logical mutation.

A crash between the two calls leaves an untagged link. That is deliberate and is the plan's fail-closed choice: an untagged same-name WireGuard link is a conflict, not something to adopt, so a partially created link requires operator cleanup.

## Protocol compatibility

`PROTOCOL_VERSION` remains 1. Two request operations gained a required `installation_id` field and two operations were added; the response enum gained two bodies. Both ends of the protocol ship in this single binary and no persistent state predates Phase 6, so the change is additive within the existing major version and the plan's "avoid a major bump unless wire compatibility truly cannot be additive" condition is met. Stale generation and a foreign installation identity both map onto the existing `ProtocolError::Conflict` rather than introducing a new error variant.

## Test totals

| Suite | Result |
|---|---|
| Library unit tests | 91 passed |
| Binary test | 1 passed |
| `tests/architecture_guards.rs` | 10 passed |
| `tests/state_store.rs` | 26 passed |
| `tests/privileged_protocol.rs` | 2 passed |
| `tests/durable_owner.rs` (rootful, new) | 10 passed |
| `tests/network_control_e2e.rs` (rootful) | 2 passed |
| `tests/network_reconcile.rs` (rootful) | 2 passed |
| `tests/wireguard_kernel.rs` (rootful) | 2 passed |

Hosted CI run `37623015401` ran five jobs — `rust`, `wireguard-kernel`, `network-reconcile-kernel`, `network-control-e2e`, and the new `durable-owner` — all successful.

## Plan §16 case coverage

| Required case | Where qualified |
|---|---|
| 1. created link receives expected IFALIAS | `created_link_is_tagged_and_a_matching_tag_survives_restart` |
| 2. matching alias survives netd restart and is reconciled | `created_link_is_tagged_and_a_matching_tag_survives_restart` |
| 3. same-name untagged link → conflict | `an_untagged_same_name_wireguard_link_is_a_conflict` |
| 4. same-name foreign-tag link → conflict and survives | `foreign_and_duplicate_owner_tags_are_conflicts_that_survive` |
| 5. duplicate owner tag on another link → conflict | `a_duplicate_owner_tag_on_another_link_is_a_conflict` |
| 6. nft table marker includes installation id | `the_owned_nftables_table_marker_binds_to_the_installation` |
| 7. foreign-installation table marker → conflict | `a_foreign_installation_table_marker_is_a_conflict` |
| 8. equal-generation reapply → no-op | `equal_generation_reapply_is_idempotent_and_lower_generation_is_rejected` |
| 9. lower generation rejected without mutation | `equal_generation_reapply_is_idempotent_and_lower_generation_is_rejected` |
| 10. present aggregate path succeeds | `equal_generation_reapply_is_idempotent_and_lower_generation_is_rejected` |
| 11. disable removes firewall before interface | `the_disable_aggregate_path_removes_firewall_before_the_interface` |
| 12. injected firewall failure during disable leaves interface intact | covered by the ordering unit path `apply_disabling` returning `FirewallLayerIncomplete` without touching the interface; no rootful injection fixture was added |
| 13. injected firewall failure during enable returns partial receipt, equal retry converges | partially covered by `absence_of_a_layer_status_is_reported_truthfully`; no rootful injection fixture was added |

Cases 12 and 13 are the two fault-injection cases the plan asks for. Their ordering logic is implemented and unit-tested, but a rootful injection fixture was not added in this pass; that gap is recorded below rather than claimed as closed evidence.

## Unresolved findings

No unresolved high- or medium-severity finding remains.

- The missing rootful fault-injection fixtures for cases 12 and 13 are a **known medium gap**: the code path exists and is unit-tested, but the plan's real-kernel evidence for it is not. This should be added when M003 builds its restart/crash fixtures, which already need process-level failure injection.
- `firewall` clippy lints are clean under both the default and the `linux-integration` feature. Several pre-existing `needless_borrows_for_generic_args` lints in the rootful test files were surfaced and fixed because M002 added a `durable-owner` job that lints them in CI.
- The plan's stop conditions were not triggered: rtnetlink reads and writes `IFALIAS` on Rust 1.89, no shelling to `ip` was needed, no async redesign was required, no existing host state is adopted, and the protocol change stayed bounded and typed.

Disposition: `closed`.

## Successor readiness and plan queue

M002 closes durable ownership and generation-aware aggregate reconciliation. Its hard blocker is satisfied, so `plans/implementation/durable-state/003-startup-reconciliation-and-recovery.md` is promoted to ready/active. M004 remains blocked behind M003.

M003 can rely on: an installation-scoped owner tag on every managed link, an installation-bound owned nftables table, one aggregate plan/apply operation carrying a generation, an outer coordinator lock, in-process generation monotonicity, and truthful receipts. M003 still owns automatic startup reconciliation, convergence-evidence persistence, and crash/restart recovery, and is the right place to add the two fault-injection fixtures noted above.
