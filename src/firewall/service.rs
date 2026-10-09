//! Serialized application of a firewall plan and receipt reporting.

use super::nft::{
    observe_firewall, remove_table, replace_table, set_ipv4_forwarding, set_ipv6_forwarding,
};
use super::planner::{matches_policy, plan_firewall};
use super::policy::{
    DesiredNetworkPolicy, FirewallActionKind, FirewallApplyReceipt, FirewallError, FirewallFailure,
    FirewallOwner, FirewallPlanSummary,
};
use crate::{
    domain::{InstallationId, InterfaceName},
    reconcile::ApplyStatus,
};
use std::sync::Mutex;

/// The sole owned firewall table is `inet wg_basic`; unrelated tables are never flushed.
pub struct FirewallService {
    mutation_lock: Mutex<()>,
}

impl Default for FirewallService {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallService {
    pub fn new() -> Self {
        Self {
            mutation_lock: Mutex::new(()),
        }
    }

    /// Plans the owned table for one installation identity.
    ///
    /// `installation_id` selects which installation may own `inet wg_basic`.
    /// A table carrying another installation's marker, or the historical M005
    /// product-only marker, is a conflict and is never adopted.
    pub fn plan(
        &self,
        installation_id: InstallationId,
        wireguard_interface: &InterfaceName,
        policy: Option<&DesiredNetworkPolicy>,
    ) -> Result<FirewallPlanSummary, FirewallError> {
        if let Some(policy) = policy {
            policy.validate(wireguard_interface)?;
        }
        let owner = FirewallOwner::new(installation_id);
        let observation = observe_firewall(&owner, requires_ipv6_forwarding(policy))?;
        Ok(plan_firewall(&owner, wireguard_interface, policy, &observation)?.summary)
    }

    pub fn apply(
        &self,
        installation_id: InstallationId,
        wireguard_interface: &InterfaceName,
        policy: Option<&DesiredNetworkPolicy>,
    ) -> Result<FirewallApplyReceipt, FirewallError> {
        if let Some(policy) = policy {
            policy.validate(wireguard_interface)?;
        }
        let owner = FirewallOwner::new(installation_id);
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| FirewallError::BackendFailure)?;
        let before = observe_firewall(&owner, requires_ipv6_forwarding(policy))?;
        let plan = plan_firewall(&owner, wireguard_interface, policy, &before)?;
        if plan.summary.actions.is_empty() {
            return Ok(FirewallApplyReceipt {
                wireguard_interface: wireguard_interface.clone(),
                status: ApplyStatus::NoChange,
                actions: Vec::new(),
                forwarding_changed: false,
                table_changed: false,
                failure: None,
                warnings: plan.summary.warnings,
            });
        }
        let mut forwarding_applied = false;
        for result in [
            plan.summary
                .actions
                .contains(&FirewallActionKind::EnableIpv4Forwarding)
                .then(|| set_ipv4_forwarding(true)),
            plan.summary
                .actions
                .contains(&FirewallActionKind::EnableIpv6Forwarding)
                .then(set_ipv6_forwarding),
        ]
        .into_iter()
        .flatten()
        {
            if let Err(error) = result {
                return Ok(FirewallApplyReceipt {
                    wireguard_interface: wireguard_interface.clone(),
                    status: if forwarding_applied {
                        ApplyStatus::PartialFailure
                    } else {
                        ApplyStatus::FailedBeforeMutation
                    },
                    actions: plan.summary.actions.clone(),
                    forwarding_changed: forwarding_applied,
                    table_changed: false,
                    failure: Some(failure_from(&error)),
                    warnings: plan.summary.warnings.clone(),
                });
            }
            forwarding_applied = true;
        }
        let table_changed = plan.summary.actions.iter().any(|action| {
            matches!(
                action,
                FirewallActionKind::ReplaceOwnedNftablesTable
                    | FirewallActionKind::RemoveOwnedNftablesTable
            )
        });
        if table_changed {
            let result = match policy {
                Some(policy) => replace_table(
                    &owner,
                    wireguard_interface,
                    policy,
                    plan.desired_hash.as_deref().unwrap_or(""),
                    before.table.present,
                    &before.table.chain_names,
                ),
                None => remove_table(),
            };
            if let Err(error) = result {
                return Ok(FirewallApplyReceipt {
                    wireguard_interface: wireguard_interface.clone(),
                    status: if forwarding_applied {
                        ApplyStatus::PartialFailure
                    } else {
                        ApplyStatus::FailedBeforeMutation
                    },
                    actions: plan.summary.actions.clone(),
                    forwarding_changed: forwarding_applied,
                    table_changed: false,
                    failure: Some(failure_from(&error)),
                    warnings: plan.summary.warnings.clone(),
                });
            }
        }
        let after = match observe_firewall(&owner, requires_ipv6_forwarding(policy)) {
            Ok(after) => after,
            Err(error) => {
                return Ok(FirewallApplyReceipt {
                    wireguard_interface: wireguard_interface.clone(),
                    status: ApplyStatus::PartialFailure,
                    actions: plan.summary.actions,
                    forwarding_changed: forwarding_applied,
                    table_changed,
                    failure: Some(failure_from(&error)),
                    warnings: plan.summary.warnings,
                });
            }
        };
        let verified = matches_policy(&owner, policy, wireguard_interface, &after)?;
        Ok(FirewallApplyReceipt {
            wireguard_interface: wireguard_interface.clone(),
            status: if verified {
                ApplyStatus::Applied
            } else {
                ApplyStatus::VerificationFailed
            },
            actions: plan.summary.actions,
            forwarding_changed: forwarding_applied,
            table_changed,
            failure: (!verified).then_some(FirewallFailure::BackendFailure),
            warnings: plan.summary.warnings,
        })
    }
}

fn failure_from(error: &FirewallError) -> FirewallFailure {
    match error {
        FirewallError::PermissionDenied => FirewallFailure::PermissionDenied,
        FirewallError::Unsupported => FirewallFailure::Unsupported,
        FirewallError::TableOwnershipConflict | FirewallError::LegacyTableOwnership => {
            FirewallFailure::Conflict
        }
        FirewallError::InvalidPolicy
        | FirewallError::BackendFailure
        | FirewallError::ResourceLimitExceeded => FirewallFailure::BackendFailure,
    }
}

fn requires_ipv6_forwarding(policy: Option<&DesiredNetworkPolicy>) -> bool {
    policy.is_some_and(|policy| policy.ipv6_forwarding == super::policy::Ipv6Forwarding::Required)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipts_preserve_bounded_forwarding_failure_categories() {
        assert_eq!(
            failure_from(&FirewallError::PermissionDenied),
            FirewallFailure::PermissionDenied
        );
        assert_eq!(
            failure_from(&FirewallError::Unsupported),
            FirewallFailure::Unsupported
        );
        assert_eq!(
            failure_from(&FirewallError::TableOwnershipConflict),
            FirewallFailure::Conflict
        );
        assert_eq!(
            failure_from(&FirewallError::BackendFailure),
            FirewallFailure::BackendFailure
        );
    }
}
