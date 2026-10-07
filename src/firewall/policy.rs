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
/// The historical pre-Phase-6 product-only marker.
///
/// It is deliberately *not* recognized as ownership: an M005-era table must be
/// reported as a conflict rather than silently adopted by a durable
/// installation identity.
pub(crate) const LEGACY_TABLE_OWNER: &str = "wg-basic:m005:v1";

/// Installation-scoped ownership marker for the single owned table.
///
/// The table comment binds to the `InstallationId`, so two installations on one
/// host cannot both believe they own `inet wg_basic`. Chain and rule markers
/// build on this value and additionally bind to the exact desired policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FirewallOwner {
    marker: String,
}

impl FirewallOwner {
    pub(crate) fn new(installation_id: crate::domain::InstallationId) -> Self {
        Self {
            marker: format!("wg-basic:v1:{installation_id}"),
        }
    }

    /// Whether an observed table comment proves ownership by this installation.
    pub(crate) fn owns_table(&self, comment: Option<&str>) -> bool {
        comment == Some(self.marker.as_str())
    }
}

impl std::fmt::Display for FirewallOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.marker)
    }
}

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
        owner: &FirewallOwner,
        hash: &str,
        wireguard_interface: &InterfaceName,
    ) -> BTreeSet<String> {
        let mut markers = BTreeSet::new();
        markers.insert(format!("{owner}:chain:forward:{hash}"));
        markers.insert(format!("{owner}:rule:return:{hash}"));
        for (index, _) in self.sorted_prefixes().iter().enumerate() {
            markers.insert(format!("{owner}:rule:allow:{index}:{hash}"));
        }
        markers.insert(format!("{owner}:rule:drop:{hash}"));
        if self.nat == NatMode::Masquerade {
            markers.insert(format!("{owner}:chain:postrouting:{hash}"));
            for (index, _) in self.sorted_prefixes().iter().enumerate() {
                markers.insert(format!("{owner}:rule:nat:{index}:{hash}"));
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
    #[error("the owned nftables table carries the pre-Phase-6 product-only marker")]
    LegacyTableOwnership,
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
    use crate::domain::InstallationId;

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
    fn the_historical_product_only_marker_is_never_treated_as_ownership() {
        // M005 wrote a product-only marker. Phase 6 binds ownership to an
        // installation identity, and an M005-era table must be reported as a
        // conflict for operator cleanup rather than silently adopted.
        let owner = FirewallOwner::new(InstallationId::new());
        assert!(!owner.owns_table(Some(LEGACY_TABLE_OWNER)));
        assert!(owner.owns_table(Some(&owner.to_string())));

        let other = FirewallOwner::new(InstallationId::new());
        assert!(!owner.owns_table(Some(&other.to_string())));
    }

    #[test]
    fn the_installation_marker_is_bounded_and_ascii() {
        let owner = FirewallOwner::new(InstallationId::new());
        let marker = owner.to_string();
        assert!(marker.starts_with("wg-basic:v1:"));
        assert!(marker.is_ascii());
        assert!(
            marker.len() <= 48,
            "marker must stay well bounded: {marker}"
        );
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
