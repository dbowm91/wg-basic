//! Serialized application of a firewall plan and receipt reporting.

use super::nft::{observe_firewall, remove_table, replace_table, set_ipv4_forwarding};
use super::planner::{matches_policy, plan_firewall};
use super::policy::{
    DesiredNetworkPolicy, FirewallActionKind, FirewallApplyReceipt, FirewallError, FirewallFailure,
    FirewallPlanSummary, FirewallWarning,
};
use crate::{domain::InterfaceName, reconcile::ApplyStatus};
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

    pub fn plan(
        &self,
        wireguard_interface: &InterfaceName,
        policy: Option<&DesiredNetworkPolicy>,
    ) -> Result<FirewallPlanSummary, FirewallError> {
        if let Some(policy) = policy {
            policy.validate(wireguard_interface)?;
        }
        let observation = observe_firewall()?;
        Ok(plan_firewall(wireguard_interface, policy, &observation)?.summary)
    }

    pub fn apply(
        &self,
        wireguard_interface: &InterfaceName,
        policy: Option<&DesiredNetworkPolicy>,
    ) -> Result<FirewallApplyReceipt, FirewallError> {
        if let Some(policy) = policy {
            policy.validate(wireguard_interface)?;
        }
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| FirewallError::BackendFailure)?;
        let before = observe_firewall()?;
        let plan = plan_firewall(wireguard_interface, policy, &before)?;
        if plan.summary.actions.is_empty() {
            return Ok(FirewallApplyReceipt {
                wireguard_interface: wireguard_interface.clone(),
                status: ApplyStatus::NoChange,
                actions: Vec::new(),
                forwarding_changed: false,
                table_changed: false,
                failure: None,
                warnings: vec![FirewallWarning::IndependentFirewallMayStillBlockForwardedTraffic],
            });
        }
        let forwarding_changed = plan
            .summary
            .actions
            .contains(&FirewallActionKind::EnableIpv4Forwarding);
        if forwarding_changed {
            set_ipv4_forwarding(true)?;
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
                    wireguard_interface,
                    policy,
                    plan.desired_hash.as_deref().unwrap_or(""),
                    before.table.present,
                    &before.table.chain_names,
                ),
                None => remove_table(),
            };
            if result.is_err() {
                return Ok(FirewallApplyReceipt {
                    wireguard_interface: wireguard_interface.clone(),
                    status: if forwarding_changed {
                        ApplyStatus::PartialFailure
                    } else {
                        ApplyStatus::FailedBeforeMutation
                    },
                    actions: plan.summary.actions,
                    forwarding_changed,
                    table_changed: false,
                    failure: Some(FirewallFailure::BackendFailure),
                    warnings: vec![
                        FirewallWarning::IndependentFirewallMayStillBlockForwardedTraffic,
                    ],
                });
            }
        }
        let after = observe_firewall()?;
        let verified = matches_policy(policy, wireguard_interface, &after)?;
        Ok(FirewallApplyReceipt {
            wireguard_interface: wireguard_interface.clone(),
            status: if verified {
                ApplyStatus::Applied
            } else {
                ApplyStatus::VerificationFailed
            },
            actions: plan.summary.actions,
            forwarding_changed,
            table_changed,
            failure: (!verified).then_some(FirewallFailure::BackendFailure),
            warnings: vec![FirewallWarning::IndependentFirewallMayStillBlockForwardedTraffic],
        })
    }
}
