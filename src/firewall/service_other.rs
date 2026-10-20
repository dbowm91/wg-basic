//! Stub firewall service for platforms that are neither Linux nor macOS.
//!
//! These platforms are not a supported deployment target. The service exists
//! only so the crate still compiles, and every operation fails closed as
//! unsupported rather than pretending convergence.

use super::policy::{
    DesiredNetworkPolicy, FirewallApplyReceipt, FirewallError, FirewallPlanSummary,
};
use crate::domain::{InstallationId, InterfaceName};

/// Darwin placeholder. Never touches PF, forwarding sysctls, or host routes.
#[derive(Debug, Default)]
pub struct FirewallService {
    _private: (),
}

impl FirewallService {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn plan(
        &self,
        _installation_id: InstallationId,
        _wireguard_interface: &InterfaceName,
        _policy: Option<&DesiredNetworkPolicy>,
    ) -> Result<FirewallPlanSummary, FirewallError> {
        Err(FirewallError::Unsupported)
    }

    pub fn apply(
        &self,
        _installation_id: InstallationId,
        _wireguard_interface: &InterfaceName,
        _policy: Option<&DesiredNetworkPolicy>,
    ) -> Result<FirewallApplyReceipt, FirewallError> {
        Err(FirewallError::Unsupported)
    }
}
