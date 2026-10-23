//! Typed network policy and its bounds.
//!
//! Callers choose forwarding mode, one managed interface, one explicit egress, a
//! bounded set of source prefixes, and the NAT mode. Nothing else is expressible.

use crate::{
    domain::{InterfaceName, NetworkPolicyMode, NetworkPrefix},
    reconcile::ApplyStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Upper bound on caller-supplied source prefixes.
pub(crate) const MAX_PREFIXES: usize = 64;
/// Upper bound on the downstream prefixes a routed-LAN policy may approve.
///
/// The allowlist becomes one filter rule per source and destination pair, so
/// it is bounded rather than open-ended.
pub(crate) const MAX_DESTINATION_PREFIXES: usize = 16;
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ipv6Forwarding {
    Required,
    NotRequired,
}

/// A bounded dual-stack forwarding policy. NAT remains IPv4 masquerade only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredNetworkPolicy {
    /// The routing intent this policy declares.
    ///
    /// The mode is the contract: it says whether the tunnel carries only this
    /// host's traffic, forwards to an explicit downstream allowlist, or acts
    /// as a gateway. Each mode is validated against its own rules.
    #[serde(default)]
    pub mode: NetworkPolicyMode,
    pub ipv4_forwarding: Ipv4Forwarding,
    pub ipv6_forwarding: Ipv6Forwarding,
    pub egress_interface: InterfaceName,
    pub source_prefixes: Vec<NetworkPrefix>,
    /// The approved downstream prefixes.
    ///
    /// Only a routed-LAN policy may name any.
    #[serde(default)]
    pub destination_prefixes: Vec<NetworkPrefix>,
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
            let ipv6_link_local = match network.addr() {
                std::net::IpAddr::V6(address) => address.is_unicast_link_local(),
                std::net::IpAddr::V4(_) => false,
            };
            if !prefixes.insert(prefix.to_string())
                || network.addr().is_unspecified()
                || network.addr().is_multicast()
                || ipv6_link_local
                || (network.addr().is_ipv6() && self.ipv6_forwarding != Ipv6Forwarding::Required)
            {
                return Err(FirewallError::InvalidPolicy);
            }
        }
        if self.nat == NatMode::Masquerade
            && !self
                .source_prefixes
                .iter()
                .any(|prefix| prefix.network().addr().is_ipv4())
        {
            return Err(FirewallError::InvalidPolicy);
        }
        self.validate_mode()
    }

    /// Validates the mode-specific contract.
    ///
    /// A host-only policy carries no forwarding obligation and no destination
    /// allowlist. A gateway policy carries no allowlist either: it forwards
    /// anywhere, which is the shape that already existed. A routed-LAN policy
    /// carries exactly one bounded allowlist and never masquerades, because
    /// its whole security argument rests on the approved destinations.
    fn validate_mode(&self) -> Result<(), FirewallError> {
        match self.mode {
            NetworkPolicyMode::HostOnly => {
                if self.ipv4_forwarding != Ipv4Forwarding::NotRequired
                    || self.ipv6_forwarding != Ipv6Forwarding::NotRequired
                    || self.nat != NatMode::Disabled
                    || !self.destination_prefixes.is_empty()
                {
                    return Err(FirewallError::InvalidPolicy);
                }
            }
            NetworkPolicyMode::Gateway => {
                if !self.destination_prefixes.is_empty() {
                    return Err(FirewallError::InvalidPolicy);
                }
            }
            NetworkPolicyMode::RoutedLan => {
                if self.nat != NatMode::Disabled
                    || self.destination_prefixes.is_empty()
                    || self.destination_prefixes.len() > MAX_DESTINATION_PREFIXES
                {
                    return Err(FirewallError::InvalidPolicy);
                }
                let mut destinations = BTreeSet::new();
                let mut has_v4 = false;
                let mut has_v6 = false;
                for destination in &self.destination_prefixes {
                    let network = destination.network();
                    let addr = network.addr();
                    let ipv6_link_local = match addr {
                        std::net::IpAddr::V6(address) => address.is_unicast_link_local(),
                        std::net::IpAddr::V4(_) => false,
                    };
                    if !destinations.insert(destination.to_string())
                        || addr.is_unspecified()
                        || addr.is_multicast()
                        || addr.is_loopback()
                        || ipv6_link_local
                        || network.prefix_len() == 0
                    {
                        return Err(FirewallError::InvalidPolicy);
                    }
                    if self.source_prefixes.iter().any(|source| {
                        let source = source.network();
                        source.contains(&network.addr()) || network.contains(&source.addr())
                    }) {
                        return Err(FirewallError::InvalidPolicy);
                    }
                    if addr.is_ipv4() {
                        has_v4 = true;
                    } else {
                        has_v6 = true;
                    }
                }
                if (has_v4 && self.ipv4_forwarding != Ipv4Forwarding::Required)
                    || (has_v6 && self.ipv6_forwarding != Ipv6Forwarding::Required)
                {
                    return Err(FirewallError::InvalidPolicy);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn sorted_prefixes(&self) -> Vec<&NetworkPrefix> {
        let mut prefixes = self.source_prefixes.iter().collect::<Vec<_>>();
        prefixes.sort_by_key(|prefix| prefix.to_string());
        prefixes
    }

    pub(crate) fn sorted_ipv4_prefixes(&self) -> Vec<&NetworkPrefix> {
        self.sorted_prefixes()
            .into_iter()
            .filter(|prefix| prefix.network().addr().is_ipv4())
            .collect()
    }

    pub(crate) fn sorted_allowed_prefixes(&self) -> Vec<&NetworkPrefix> {
        self.sorted_prefixes()
            .into_iter()
            .filter(|prefix| {
                prefix.network().addr().is_ipv4()
                    || self.ipv6_forwarding == Ipv6Forwarding::Required
            })
            .collect()
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
        for (index, _) in self.sorted_allowed_prefixes().iter().enumerate() {
            markers.insert(format!("{owner}:rule:allow:{index}:{hash}"));
        }
        markers.insert(format!("{owner}:rule:drop:{hash}"));
        if self.nat == NatMode::Masquerade {
            markers.insert(format!("{owner}:chain:postrouting:{hash}"));
            for (index, _) in self.sorted_ipv4_prefixes().iter().enumerate() {
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
    EnableIpv6Forwarding,
    ReplaceOwnedNftablesTable,
    RemoveOwnedNftablesTable,
    /// The product wrote its own anchor's rules and loaded them into its own
    /// anchor.
    ///
    /// This is the macOS gateway mode's only write. It names the installation's
    /// own anchor and the installation's own anchor file; it never loads the
    /// root ruleset and never touches a foreign anchor.
    InstallManagedPfAnchor,
    /// The product emptied its own anchor's rules in both rule classes.
    RemoveManagedPfAnchor,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallWarning {
    IndependentFirewallMayStillBlockForwardedTraffic,
    Ipv6ForwardingIsHostGlobalAndRemainsEnabled,
    /// The routed-LAN filter is operator-managed: the product observes it and
    /// never installs, edits, or removes it.
    RoutedLanFilterIsOperatorManaged,
    /// The operator-managed filter still references the managed tunnel.
    ///
    /// The product does not own that filter, so it reports the residue
    /// instead of removing it. Removing it is the operator's action.
    RoutedLanFilterResidueObserved,
    /// The managed anchor still holds rules the product did not install.
    ///
    /// The product owns exactly one anchor file, and it proves that ownership
    /// from the file's own marker. A file without the marker belongs to
    /// somebody else, so the product reports the residue and leaves it alone.
    ManagedAnchorResidueObserved,
}

/// The verdict of a routed-LAN prerequisite check.
///
/// The verdict is what turns "a routed LAN is not available here" into an
/// actionable statement. Each reason names a different operator action, so
/// they are never collapsed into one.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutedLanVerdict {
    /// Every prerequisite is in place.
    Ready,
    /// The host's global forwarding is not enabled for a family the policy
    /// requires.
    ForwardingDisabled,
    /// The operator-managed filter is absent or is not attached.
    FilterMissing,
    /// The operator-managed filter does not match the rendered policy.
    FilterDrift,
    /// No observed route carries traffic back to the tunnel pool.
    MissingReturnRoute,
    /// A foreign or ambiguous route covers an approved destination.
    RouteConflict,
    /// The approved destinations are not reachable through the declared egress
    /// interface.
    UnsupportedTopology,
    /// The managed tunnel is not up, so its device cannot be bound.
    TunnelUnavailable,
}

/// The verdict of a gateway prerequisite check.
///
/// The verdict is what turns "the gateway is not available here" into an
/// actionable statement. Each reason names a different administrator action,
/// so they are never collapsed into one.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayVerdict {
    /// Every prerequisite is in place.
    Ready,
    /// The host's global forwarding is not enabled for a family the policy
    /// requires.
    ForwardingDisabled,
    /// The administrator's parent does not invoke the managed anchor in both
    /// rule classes.
    ///
    /// The filter class and the NAT class are verified independently, exactly
    /// as C007's verifier does, and a parent that invokes only one of them
    /// never satisfies the requirement for both.
    AttachmentMissing,
    /// The managed anchor's filter rules are not the rendered policy.
    FilterDrift,
    /// The managed anchor's NAT rules are not the rendered policy.
    ///
    /// The NAT class is a different table from the filter class and is
    /// verified separately: an anchor that carries the right filter rules and
    /// the wrong translation rule translates traffic the policy never
    /// approved.
    NatDrift,
    /// The managed tunnel is not up, so its device cannot be bound.
    TunnelUnavailable,
    /// The product could not install or remove its anchor.
    ApplyRefused,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallPlanSummary {
    pub wireguard_interface: InterfaceName,
    pub actions: Vec<FirewallActionKind>,
    pub warnings: Vec<FirewallWarning>,
    /// The filter rules an operator has to install for this policy.
    ///
    /// This is populated only for a routed-LAN policy, whose filter is
    /// operator-managed: the product observes the installed rules and refuses
    /// to claim convergence when they differ, so it has to say what the
    /// correct rules are. It is empty for every policy whose filter the
    /// product owns.
    #[serde(default)]
    pub required_filter_rules: Vec<String>,
    /// The routed-LAN prerequisite verdict, when the policy is a routed LAN.
    ///
    /// A plan reports what it observed; the apply is what refuses. That
    /// split is what lets the diagnostics name the exact missing
    /// prerequisite instead of reporting a bare failure.
    #[serde(default)]
    pub routed_lan: Option<RoutedLanVerdict>,
    /// The gateway prerequisite verdict, when the policy is a gateway.
    ///
    /// A plan reports what it observed; the apply is what refuses. That
    /// split is what lets the diagnostics name the exact missing
    /// prerequisite instead of reporting a bare failure.
    #[serde(default)]
    pub gateway: Option<GatewayVerdict>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallFailure {
    PermissionDenied,
    Unsupported,
    Conflict,
    BackendFailure,
    /// The host's global forwarding is not enabled for a family the policy needs.
    ForwardingDisabled,
    /// The operator-managed filter policy is absent or not attached.
    FilterMissing,
    /// The operator-managed filter policy no longer matches the rendered policy.
    FilterDrift,
    /// No observed route carries traffic back to the tunnel pool.
    MissingReturnRoute,
    /// A foreign or ambiguous route covers an approved destination.
    RouteConflict,
    /// The approved destinations are not reachable through the declared egress.
    UnsupportedTopology,
    /// The administrator's parent does not invoke the managed anchor in both
    /// rule classes.
    GatewayAttachmentMissing,
    /// The managed anchor's NAT rules are not the rendered policy.
    NatDrift,
    /// The managed anchor carries rules whose ownership cannot be proven.
    AnchorConflict,
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
    #[error("the host's global forwarding is not enabled for a family this policy requires")]
    ForwardingDisabled,
    #[error("the operator-managed filter policy is absent or is not attached")]
    FilterMissing,
    #[error("the operator-managed filter policy does not match the rendered policy")]
    FilterDrift,
    #[error("no observed route carries traffic back to the tunnel pool")]
    MissingReturnRoute,
    #[error("a foreign or ambiguous route covers an approved destination")]
    RouteConflict,
    #[error("the approved destinations are not reachable through the declared egress interface")]
    UnsupportedTopology,
    #[error("the administrator's PF configuration does not invoke the installation anchor in both rule classes")]
    GatewayAttachmentMissing,
    #[error("the managed anchor's NAT rules do not match the rendered policy")]
    NatDrift,
    #[error("the managed anchor carries rules whose ownership cannot be proven")]
    AnchorConflict,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::InstallationId;

    fn fixture() -> (InterfaceName, DesiredNetworkPolicy) {
        (
            "wg0".parse().unwrap(),
            DesiredNetworkPolicy {
                mode: crate::domain::NetworkPolicyMode::Gateway,
                ipv4_forwarding: Ipv4Forwarding::Required,
                ipv6_forwarding: Ipv6Forwarding::NotRequired,
                egress_interface: "eth0".parse().unwrap(),
                source_prefixes: vec!["10.8.0.0/24".parse().unwrap()],
                destination_prefixes: Vec::new(),
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

    /// A routed-LAN policy with one source and one approved destination.
    fn routed_lan() -> (InterfaceName, DesiredNetworkPolicy) {
        (
            "wg0".parse().unwrap(),
            DesiredNetworkPolicy {
                mode: NetworkPolicyMode::RoutedLan,
                ipv4_forwarding: Ipv4Forwarding::Required,
                ipv6_forwarding: Ipv6Forwarding::NotRequired,
                egress_interface: "eth0".parse().unwrap(),
                source_prefixes: vec!["10.77.0.0/24".parse().unwrap()],
                destination_prefixes: vec!["192.168.9.0/24".parse().unwrap()],
                nat: NatMode::Disabled,
            },
        )
    }

    #[test]
    fn a_routed_lan_policy_needs_one_allowlist_and_never_masquerades() {
        let (interface, policy) = routed_lan();
        assert!(policy.validate(&interface).is_ok());

        let mut invalid = policy.clone();
        invalid.destination_prefixes.clear();
        assert_eq!(
            invalid.validate(&interface),
            Err(FirewallError::InvalidPolicy)
        );

        let mut invalid = policy.clone();
        invalid.nat = NatMode::Masquerade;
        assert_eq!(
            invalid.validate(&interface),
            Err(FirewallError::InvalidPolicy)
        );

        // A default route is never an approved destination.
        let mut invalid = policy.clone();
        invalid.destination_prefixes = vec!["0.0.0.0/0".parse().unwrap()];
        assert_eq!(
            invalid.validate(&interface),
            Err(FirewallError::InvalidPolicy)
        );

        // A destination that overlaps the tunnel pool is never approved.
        let mut invalid = policy.clone();
        invalid.destination_prefixes = vec!["10.77.0.0/16".parse().unwrap()];
        assert_eq!(
            invalid.validate(&interface),
            Err(FirewallError::InvalidPolicy)
        );

        // A destination family the policy does not forward for is refused.
        let mut invalid = policy;
        invalid.destination_prefixes = vec!["2001:db8:9::/64".parse().unwrap()];
        assert_eq!(
            invalid.validate(&interface),
            Err(FirewallError::InvalidPolicy)
        );
    }

    #[test]
    fn a_host_only_policy_carries_no_forwarding_and_no_allowlist() {
        let (interface, mut policy) = fixture();
        policy.mode = NetworkPolicyMode::HostOnly;
        policy.ipv4_forwarding = Ipv4Forwarding::NotRequired;
        policy.nat = NatMode::Disabled;
        assert!(policy.validate(&interface).is_ok());

        let mut invalid = policy.clone();
        invalid.ipv4_forwarding = Ipv4Forwarding::Required;
        assert_eq!(
            invalid.validate(&interface),
            Err(FirewallError::InvalidPolicy)
        );

        let mut invalid = policy.clone();
        invalid.destination_prefixes = vec!["192.168.9.0/24".parse().unwrap()];
        assert_eq!(
            invalid.validate(&interface),
            Err(FirewallError::InvalidPolicy)
        );
    }
}
