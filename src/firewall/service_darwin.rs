//! M001 Darwin stub for the firewall service.
//!
//! The Darwin PF/NAT backend lands in M005 behind an explicit Apple TN3165
//! distribution decision. This stub compiles on Darwin so portable intent,
//! protocol, and management code can target both OSes, but every operation
//! fails closed as unsupported. No PF state is touched.

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
