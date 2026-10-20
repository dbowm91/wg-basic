//! The Darwin firewall service: explicit host-only semantics (C001).
//!
//! C001 delivers a **host-only** Darwin server. The managed tunnel carries the
//! host's own traffic and the machine's own services reach the tunnel's
//! peers. There is no forwarding, no NAT, no routed LAN, and no PF anchor.
//!
//! The service therefore does exactly two things, and both are honest:
//!
//! 1. it **refuses** any policy that requires forwarding or NAT with
//!    [`FirewallError::Unsupported`], instead of silently ignoring the request
//!    and reporting a success that did nothing; and
//! 2. it **reports** the host's global forwarding state, which is host-global
//!    state this product does not own and never changes.
//!
//! Nothing here writes PF state, forwarding sysctls, or host routes. The PF
//! backend lands in C003 behind an explicit distribution decision; until then
//! the host-only contract is the whole firewall surface.

use super::policy::{
    DesiredNetworkPolicy, FirewallApplyReceipt, FirewallError, FirewallPlanSummary, Ipv4Forwarding,
    Ipv6Forwarding, NatMode,
};
use crate::domain::{InstallationId, InterfaceName};
use crate::reconcile::ApplyStatus;

/// The Darwin firewall service.
#[derive(Debug, Default)]
pub struct FirewallService {
    _private: (),
}

impl FirewallService {
    /// Builds the service.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Plans the firewall work for one installation identity.
    ///
    /// The host-only contract has no firewall actions: there is no table to
    /// replace and no forwarding to enable. A policy that needs either is
    /// refused.
    pub fn plan(
        &self,
        _installation_id: InstallationId,
        wireguard_interface: &InterfaceName,
        policy: Option<&DesiredNetworkPolicy>,
    ) -> Result<FirewallPlanSummary, FirewallError> {
        if let Some(policy) = policy {
            policy.validate(wireguard_interface)?;
            require_host_only(policy)?;
        }
        Ok(FirewallPlanSummary {
            wireguard_interface: wireguard_interface.clone(),
            actions: Vec::new(),
            warnings: Vec::new(),
        })
    }

    /// Applies the firewall plan.
    ///
    /// On Darwin the host-only plan is empty, so the honest receipt is
    /// `NoChange`: nothing was written, nothing was claimed, and the host's
    /// forwarding state was read but not touched.
    pub fn apply(
        &self,
        installation_id: InstallationId,
        wireguard_interface: &InterfaceName,
        policy: Option<&DesiredNetworkPolicy>,
    ) -> Result<FirewallApplyReceipt, FirewallError> {
        let plan = self.plan(installation_id, wireguard_interface, policy)?;
        Ok(FirewallApplyReceipt {
            wireguard_interface: wireguard_interface.clone(),
            status: ApplyStatus::NoChange,
            actions: plan.actions,
            forwarding_changed: false,
            table_changed: false,
            failure: None,
            warnings: plan.warnings,
        })
    }
}

/// Refuses any policy that is not host-only.
fn require_host_only(policy: &DesiredNetworkPolicy) -> Result<(), FirewallError> {
    if policy.ipv4_forwarding == Ipv4Forwarding::Required
        || policy.ipv6_forwarding == Ipv6Forwarding::Required
        || policy.nat == NatMode::Masquerade
    {
        return Err(FirewallError::Unsupported);
    }
    Ok(())
}

/// The host's global forwarding state, read but never changed.
///
/// `None` means the state could not be read, which is reported as unknown
/// rather than as "forwarding is off".
pub fn host_forwarding_state() -> (Option<bool>, Option<bool>) {
    (
        wg_basic_darwin_sys::ipv4_forwarding_enabled(),
        wg_basic_darwin_sys::ipv6_forwarding_enabled(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::NetworkPrefix;

    fn interface() -> InterfaceName {
        InterfaceName::new("wg-test").unwrap()
    }

    fn host_only_policy() -> DesiredNetworkPolicy {
        DesiredNetworkPolicy {
            ipv4_forwarding: Ipv4Forwarding::NotRequired,
            ipv6_forwarding: Ipv6Forwarding::NotRequired,
            egress_interface: InterfaceName::new("en0").unwrap(),
            source_prefixes: vec!["10.0.0.0/24".parse::<NetworkPrefix>().unwrap()],
            nat: NatMode::Disabled,
        }
    }

    #[test]
    fn a_host_only_policy_needs_no_firewall_action() {
        let service = FirewallService::new();
        let policy = host_only_policy();
        let plan = service
            .plan(
                "00000000-0000-4000-8000-0000000000a1".parse().unwrap(),
                &interface(),
                Some(&policy),
            )
            .unwrap();
        assert!(plan.actions.is_empty());
    }

    #[test]
    fn a_forwarding_or_nat_policy_is_refused_rather_than_ignored() {
        let service = FirewallService::new();
        let mut policy = host_only_policy();
        policy.ipv4_forwarding = Ipv4Forwarding::Required;
        assert_eq!(
            service
                .plan(
                    "00000000-0000-4000-8000-0000000000a1".parse().unwrap(),
                    &interface(),
                    Some(&policy),
                )
                .unwrap_err(),
            FirewallError::Unsupported
        );

        let mut policy = host_only_policy();
        policy.nat = NatMode::Masquerade;
        assert_eq!(
            service
                .plan(
                    "00000000-0000-4000-8000-0000000000a1".parse().unwrap(),
                    &interface(),
                    Some(&policy),
                )
                .unwrap_err(),
            FirewallError::Unsupported
        );
    }

    #[test]
    fn applying_a_host_only_policy_reports_no_change() {
        let service = FirewallService::new();
        let receipt = service
            .apply(
                "00000000-0000-4000-8000-0000000000a1".parse().unwrap(),
                &interface(),
                None,
            )
            .unwrap();
        assert_eq!(receipt.status, ApplyStatus::NoChange);
        assert!(!receipt.table_changed);
        assert!(!receipt.forwarding_changed);
    }
}
