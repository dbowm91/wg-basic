//! Typed network policy and its bounds.
//!
//! Callers choose forwarding mode, one managed interface, one explicit egress, a
//! bounded set of source prefixes, and the NAT mode. Nothing else is expressible.

use crate::{
    domain::{InterfaceName, NetworkPrefix},
    reconcile::ApplyStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Upper bound on caller-supplied source prefixes.
pub(crate) const MAX_PREFIXES: usize = 64;
/// The single nftables table this subsystem is allowed to own.
pub(crate) const TABLE_NAME: &str = "wg_basic";
/// Ownership marker embedded in the owned table and its objects.
pub(crate) const TABLE_OWNER: &str = "wg-basic:m005:v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NatMode {
    Disabled,
    Masquerade,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ipv4Forwarding {
    Required,
    NotRequired,
}

/// A bounded IPv4 policy. Interface names and source prefixes use validated domain types.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredNetworkPolicy {
    pub ipv4_forwarding: Ipv4Forwarding,
    pub egress_interface: InterfaceName,
    pub source_prefixes: Vec<NetworkPrefix>,
    pub nat: NatMode,
}

impl DesiredNetworkPolicy {
    pub fn validate(&self, wireguard_interface: &InterfaceName) -> Result<(), FirewallError> {
        if self.egress_interface == *wireguard_interface
            || self.source_prefixes.is_empty()
            || self.source_prefixes.len() > MAX_PREFIXES
        {
            return Err(FirewallError::InvalidPolicy);
        }
        let mut prefixes = BTreeSet::new();
        for prefix in &self.source_prefixes {
            let network = prefix.network();
            if !network.addr().is_ipv4()
                || !prefixes.insert(prefix.to_string())
                || network.addr().is_unspecified()
            {
                return Err(FirewallError::InvalidPolicy);
            }
        }
        Ok(())
    }

    pub(crate) fn sorted_prefixes(&self) -> Vec<&NetworkPrefix> {
        let mut prefixes = self.source_prefixes.iter().collect::<Vec<_>>();
        prefixes.sort_by_key(|prefix| prefix.to_string());
        prefixes
    }

    pub(crate) fn rule_markers(
        &self,
        hash: &str,
        wireguard_interface: &InterfaceName,
    ) -> BTreeSet<String> {
        let mut markers = BTreeSet::new();
        markers.insert(format!("{TABLE_OWNER}:chain:forward:{hash}"));
        markers.insert(format!("{TABLE_OWNER}:rule:return:{hash}"));
        for (index, _) in self.sorted_prefixes().iter().enumerate() {
            markers.insert(format!("{TABLE_OWNER}:rule:allow:{index}:{hash}"));
        }
        markers.insert(format!("{TABLE_OWNER}:rule:drop:{hash}"));
        if self.nat == NatMode::Masquerade {
            markers.insert(format!("{TABLE_OWNER}:chain:postrouting:{hash}"));
            for (index, _) in self.sorted_prefixes().iter().enumerate() {
                markers.insert(format!("{TABLE_OWNER}:rule:nat:{index}:{hash}"));
            }
        }
        let _ = wireguard_interface;
        markers
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallActionKind {
    EnableIpv4Forwarding,
    ReplaceOwnedNftablesTable,
    RemoveOwnedNftablesTable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallWarning {
    IndependentFirewallMayStillBlockForwardedTraffic,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallPlanSummary {
    pub wireguard_interface: InterfaceName,
    pub actions: Vec<FirewallActionKind>,
    pub warnings: Vec<FirewallWarning>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallFailure {
    PermissionDenied,
    Unsupported,
    Conflict,
    BackendFailure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallApplyReceipt {
    pub wireguard_interface: InterfaceName,
    pub status: ApplyStatus,
    pub actions: Vec<FirewallActionKind>,
    pub forwarding_changed: bool,
    pub table_changed: bool,
    pub failure: Option<FirewallFailure>,
    pub warnings: Vec<FirewallWarning>,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FirewallError {
    #[error("desired forwarding policy is invalid")]
    InvalidPolicy,
    #[error("an nftables table with the wg-basic name has unrecognized ownership")]
    TableOwnershipConflict,
    #[error("nftables or forwarding backend failed")]
    BackendFailure,
    #[error("nftables or forwarding backend is unavailable")]
    Unsupported,
    #[error("permission denied for firewall or forwarding operation")]
    PermissionDenied,
    #[error("nftables command output or desired policy exceeds its bound")]
    ResourceLimitExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (InterfaceName, DesiredNetworkPolicy) {
        (
            "wg0".parse().unwrap(),
            DesiredNetworkPolicy {
                ipv4_forwarding: Ipv4Forwarding::Required,
                egress_interface: "eth0".parse().unwrap(),
                source_prefixes: vec!["10.8.0.0/24".parse().unwrap()],
                nat: NatMode::Masquerade,
            },
        )
    }

    #[test]
    fn policy_validation_is_bounded_ipv4_and_rejects_unsafe_names() {
        let (interface, policy) = fixture();
        assert!(policy.validate(&interface).is_ok());
        let mut invalid = policy.clone();
        invalid.egress_interface = interface.clone();
        assert_eq!(
            invalid.validate(&interface),
            Err(FirewallError::InvalidPolicy)
        );
        let mut invalid = policy.clone();
        invalid.source_prefixes = vec!["2001:db8::/64".parse().unwrap()];
        assert_eq!(
            invalid.validate(&interface),
            Err(FirewallError::InvalidPolicy)
        );
        let mut invalid = policy;
        invalid.source_prefixes = vec!["0.0.0.0/0".parse().unwrap()];
        assert_eq!(
            invalid.validate(&interface),
            Err(FirewallError::InvalidPolicy)
        );
    }
}
