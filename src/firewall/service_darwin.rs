//! The Darwin firewall service: the host-only and routed-LAN contracts.
//!
//! Two contracts live here, and they are deliberately different.
//!
//! **Host only (C001).** The managed tunnel carries the host's own traffic
//! and the machine's own services reach the tunnel's peers. There is no
//! forwarding, no NAT, no routed LAN, and no PF anchor. The service refuses
//! any policy that needs forwarding or NAT with [`FirewallError::Unsupported`]
//! instead of silently ignoring the request and reporting a success that did
//! nothing.
//!
//! **Routed LAN (C003).** The managed tunnel forwards authorized client
//! traffic to an explicit allowlist of downstream LAN prefixes. Nothing here
//! writes PF state, forwarding sysctls, or host routes. Instead the service
//! *proves* that a routed LAN is actually available on this host, and refuses
//! to claim convergence when it is not:
//!
//! 1. the host's global forwarding must already be enabled for every family
//!    the policy requires. That setting is host-global, shared with whatever
//!    else on the machine routes packets, and the product never changes it;
//! 2. the operator-managed filter must be **attached** and must be **exactly**
//!    the rendered policy. The filter is operator-managed under Apple TN3165:
//!    the administrator installs the rules and attaches the installation
//!    anchor from their own PF configuration, and the product observes what is
//!    in effect and never repairs a drift by guessing;
//! 3. every approved destination must be reachable through the declared
//!    egress interface by a specific route, never by the default route, and no
//!    foreign route may compete with it; and
//! 4. the route that carries traffic back to the tunnel pool must exist and
//!    must be scoped to the managed tunnel device.
//!
//! Each of those failures has its own refusal, because "routed LAN is not
//! available here" and "the upstream route back to the pool is missing" call
//! for different operator actions.

use super::pf;
use super::pfctl;
use super::policy::{
    DesiredNetworkPolicy, FirewallApplyReceipt, FirewallError, FirewallPlanSummary,
    FirewallWarning, Ipv4Forwarding, Ipv6Forwarding, RoutedLanVerdict,
};
use crate::domain::{InstallationId, InterfaceName, NetworkPolicyMode};
use crate::reconcile::ApplyStatus;
use std::sync::Arc;

/// The Darwin firewall service.
pub struct FirewallService {
    /// The managed tunnel runtime registry, when the helper backend is live.
    ///
    /// It is the only source of the kernel-assigned `utun` device that backs
    /// a logical managed interface. Without it the routed-LAN contract cannot
    /// be checked at all, because the filter is bound to that device.
    registry: Option<Arc<crate::wireguard::RuntimeRegistry>>,
}

impl std::fmt::Debug for FirewallService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirewallService")
            .field("registry", &self.registry.is_some())
            .finish()
    }
}

impl Default for FirewallService {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallService {
    /// Builds the service.
    pub fn new() -> Self {
        Self {
            registry: crate::wireguard::darwin_backend::DarwinWireGuardBackend::shared_registry()
                .ok(),
        }
    }

    /// Plans the firewall work for one installation identity.
    ///
    /// The host-only contract has no firewall actions: there is no table to
    /// replace and no forwarding to enable. A policy that needs either is
    /// refused.
    pub fn plan(
        &self,
        installation_id: InstallationId,
        wireguard_interface: &InterfaceName,
        policy: Option<&DesiredNetworkPolicy>,
    ) -> Result<FirewallPlanSummary, FirewallError> {
        let Some(policy) = policy else {
            return Ok(empty_plan(wireguard_interface));
        };
        policy.validate(wireguard_interface)?;
        match policy.mode {
            NetworkPolicyMode::HostOnly => Ok(empty_plan(wireguard_interface)),
            // The internet exit gateway is a different contract with a
            // different filter and NAT surface. It is refused rather than
            // half-applied.
            NetworkPolicyMode::Gateway => Err(FirewallError::Unsupported),
            NetworkPolicyMode::RoutedLan => {
                let device = self.tunnel_device(wireguard_interface);
                let verdict = self.observe_routed_lan(installation_id, policy, device.as_deref());
                Ok(FirewallPlanSummary {
                    wireguard_interface: wireguard_interface.clone(),
                    actions: Vec::new(),
                    warnings: vec![FirewallWarning::RoutedLanFilterIsOperatorManaged],
                    required_filter_rules: device
                        .as_deref()
                        .map(|device| render_routed_rules(policy, device))
                        .unwrap_or_default(),
                    routed_lan: Some(verdict),
                })
            }
        }
    }

    /// Applies the firewall plan.
    ///
    /// On Darwin the plan writes nothing: the product owns no PF state, no
    /// forwarding sysctl, and no host route. The honest receipt is therefore
    /// `NoChange` — nothing was written and nothing is claimed to have been
    /// written. What the receipt *does* carry is the verification that the
    /// routed-LAN prerequisites are actually in place, because a refusal is
    /// returned as an error rather than dressed up as a success.
    pub fn apply(
        &self,
        installation_id: InstallationId,
        wireguard_interface: &InterfaceName,
        policy: Option<&DesiredNetworkPolicy>,
    ) -> Result<FirewallApplyReceipt, FirewallError> {
        let plan = self.plan(installation_id, wireguard_interface, policy)?;
        let mut warnings = plan.warnings.clone();
        if let Some(policy) = policy {
            if policy.mode == NetworkPolicyMode::RoutedLan {
                // The apply is what refuses. The plan only reports.
                let device = self.tunnel_device(wireguard_interface);
                let verdict = self.observe_routed_lan(installation_id, policy, device.as_deref());
                if let Some(error) = verdict.error() {
                    return Err(error);
                }
            } else {
                // A teardown does not remove the operator-managed filter; it
                // reports the residue so the operator can act on it.
                if self.operator_filter_residue(installation_id).is_some() {
                    warnings.push(FirewallWarning::RoutedLanFilterResidueObserved);
                }
            }
        }
        Ok(FirewallApplyReceipt {
            wireguard_interface: wireguard_interface.clone(),
            status: ApplyStatus::NoChange,
            actions: plan.actions,
            forwarding_changed: false,
            table_changed: false,
            failure: None,
            warnings,
        })
    }

    /// The kernel device that currently backs the logical managed interface.
    fn tunnel_device(&self, wireguard_interface: &InterfaceName) -> Option<String> {
        self.registry
            .as_ref()?
            .get(wireguard_interface)
            .map(|runtime| runtime.utun_name)
    }

    /// Proves that a routed LAN is actually available on this host.
    ///
    /// Every check is an observation. Nothing here writes PF state, a
    /// forwarding sysctl, or a host route.
    fn observe_routed_lan(
        &self,
        installation_id: InstallationId,
        policy: &DesiredNetworkPolicy,
        device: Option<&str>,
    ) -> RoutedLanVerdict {
        if let Err(error) = require_forwarding(policy) {
            return match error {
                FirewallError::ForwardingDisabled => RoutedLanVerdict::ForwardingDisabled,
                _ => RoutedLanVerdict::ForwardingDisabled,
            };
        }
        let Some(device) = device else {
            // Without a proven managed tunnel there is no device to bind the
            // filter to, so the filter contract cannot be checked at all.
            return RoutedLanVerdict::TunnelUnavailable;
        };
        if let Err(verdict) = self.observe_operator_filter(installation_id, policy, device) {
            return verdict;
        }
        if let Err(verdict) = self.observe_routes(policy, device) {
            return verdict;
        }
        RoutedLanVerdict::Ready
    }

    /// Proves that the operator-managed filter is attached and is exactly the
    /// rendered policy.
    fn observe_operator_filter(
        &self,
        installation_id: InstallationId,
        policy: &DesiredNetworkPolicy,
        device: &str,
    ) -> Result<(), RoutedLanVerdict> {
        let anchor = pf::anchor_name(installation_id);
        let observation = match pfctl::observe(&anchor) {
            Ok(observation) => observation,
            Err(error) => return Err(verdict_for_observation(error)),
        };
        if !pf::attachment_verified(
            &observation.parent_filter,
            &observation.parent_nat,
            &anchor,
            pf::RequiredAttachments::FILTER_ONLY,
        ) {
            return Err(RoutedLanVerdict::FilterMissing);
        }
        let Some(content) = observation.anchor_filter.as_deref() else {
            return Err(RoutedLanVerdict::FilterMissing);
        };
        let expected = pf::render_routed_policy(
            &policy.source_prefixes,
            &policy.destination_prefixes,
            &policy.egress_interface,
            &tunnel_interface(device),
        );
        if !pf::anchor_content_matches(content, &expected) {
            return Err(RoutedLanVerdict::FilterDrift);
        }
        Ok(())
    }

    /// Whether the operator-managed filter still exists and still names the
    /// managed tunnel's pool.
    fn operator_filter_residue(&self, installation_id: InstallationId) -> Option<String> {
        let anchor = pf::anchor_name(installation_id);
        let observation = pfctl::observe(&anchor).ok()?;
        observation.anchor_filter
    }

    /// Proves that the approved destinations are reachable the way the policy
    /// says they are, and that traffic can get back to the tunnel pool.
    fn observe_routes(
        &self,
        policy: &DesiredNetworkPolicy,
        device: &str,
    ) -> Result<(), RoutedLanVerdict> {
        let interfaces = match wg_basic_darwin_sys::interfaces() {
            Ok(interfaces) => interfaces,
            Err(_) => return Err(RoutedLanVerdict::UnsupportedTopology),
        };
        let routes = match wg_basic_darwin_sys::routes() {
            Ok(routes) => routes,
            Err(_) => return Err(RoutedLanVerdict::UnsupportedTopology),
        };

        // The egress interface has to be a real, up interface with an
        // address: it is the address an upstream router would send the
        // return traffic to.
        let egress = interfaces
            .iter()
            .find(|interface| interface.name == policy.egress_interface.as_str());
        match egress {
            Some(egress) if egress.is_up() && !egress.addresses.is_empty() => {}
            _ => return Err(RoutedLanVerdict::UnsupportedTopology),
        }

        for destination in &policy.destination_prefixes {
            require_destination_route(&routes, destination, &policy.egress_interface)?;
        }

        // The return leg: the route that carries traffic addressed to the
        // tunnel pool must exist and must be scoped to the managed device.
        for source in &policy.source_prefixes {
            let pool = source.network();
            let mut devices = routes
                .iter()
                .filter(|route| {
                    route.destination.network() == pool.network()
                        && route.destination.prefix_len() == pool.prefix_len()
                })
                .map(|route| route.interface_name.as_str());
            let Some(interface) = devices.next() else {
                return Err(RoutedLanVerdict::MissingReturnRoute);
            };
            if interface != device {
                return Err(RoutedLanVerdict::MissingReturnRoute);
            }
            if devices.next().is_some() {
                // Two routes claim the same pool: the return path is
                // ambiguous, so the product refuses to call it proven.
                return Err(RoutedLanVerdict::RouteConflict);
            }
        }
        Ok(())
    }
}

/// The plan for a policy that needs no firewall action.
fn empty_plan(wireguard_interface: &InterfaceName) -> FirewallPlanSummary {
    FirewallPlanSummary {
        wireguard_interface: wireguard_interface.clone(),
        actions: Vec::new(),
        warnings: Vec::new(),
        required_filter_rules: Vec::new(),
        routed_lan: None,
    }
}

/// The filter rules an operator has to install for one routed-LAN policy.
fn render_routed_rules(policy: &DesiredNetworkPolicy, device: &str) -> Vec<String> {
    pf::render_routed_policy(
        &policy.source_prefixes,
        &policy.destination_prefixes,
        &policy.egress_interface,
        &tunnel_interface(device),
    )
    .filter
}

/// The interface name for a kernel tunnel device.
fn tunnel_interface(device: &str) -> InterfaceName {
    InterfaceName::new(device).unwrap_or_else(|_| InterfaceName::new("utun0").expect("static"))
}

/// Refuses a policy whose families need forwarding the host does not have.
///
/// The host's forwarding switches are global and shared with everything else
/// on the machine. The product reads them, reports them, and never writes
/// them, so a routed LAN is only ever advertised when an administrator has
/// already enabled forwarding.
fn require_forwarding(policy: &DesiredNetworkPolicy) -> Result<(), FirewallError> {
    require_forwarding_with(policy, host_forwarding_state())
}

/// The pure forwarding prerequisite rule.
///
/// The observed state is a parameter so the rule can be exercised without
/// depending on whatever the host running the test happens to be set to.
fn require_forwarding_with(
    policy: &DesiredNetworkPolicy,
    state: (Option<bool>, Option<bool>),
) -> Result<(), FirewallError> {
    let (ipv4, ipv6) = state;
    if policy.ipv4_forwarding == Ipv4Forwarding::Required && ipv4 != Some(true) {
        return Err(FirewallError::ForwardingDisabled);
    }
    if policy.ipv6_forwarding == Ipv6Forwarding::Required && ipv6 != Some(true) {
        return Err(FirewallError::ForwardingDisabled);
    }
    Ok(())
}

/// Proves that one approved destination is reached by a specific route
/// through the declared egress interface.
fn require_destination_route(
    routes: &[wg_basic_darwin_sys::RouteInfo],
    destination: &crate::domain::NetworkPrefix,
    egress: &InterfaceName,
) -> Result<(), RoutedLanVerdict> {
    let address = destination.network().addr();
    let mut covering: Vec<&wg_basic_darwin_sys::RouteInfo> = routes
        .iter()
        .filter(|route| route.destination.contains(&address))
        .collect();
    if covering.is_empty() {
        return Err(RoutedLanVerdict::UnsupportedTopology);
    }
    covering.sort_by_key(|route| route.destination.prefix_len());
    let longest_prefix = covering[covering.len() - 1].destination.prefix_len();
    let longest = covering
        .iter()
        .filter(|route| route.destination.prefix_len() == longest_prefix)
        .collect::<Vec<_>>();
    let best = longest[0];
    if best.destination.prefix_len() == 0 {
        // Only the default route reaches this destination. A routed LAN must
        // never depend on the default route: taking it over would seize the
        // host's global routing.
        return Err(RoutedLanVerdict::UnsupportedTopology);
    }
    if longest
        .iter()
        .any(|route| route.interface_name != best.interface_name)
    {
        // Two routes of the same specificity disagree about where the traffic
        // goes. The product refuses to pick one.
        return Err(RoutedLanVerdict::RouteConflict);
    }
    if best.interface_name != egress.as_str() {
        // The destination is reachable, but not through the declared egress
        // interface. That is a foreign route covering an approved prefix.
        return Err(RoutedLanVerdict::RouteConflict);
    }
    Ok(())
}

/// Maps a PF observation failure onto a routed-LAN verdict.
fn verdict_for_observation(error: pfctl::ObservationError) -> RoutedLanVerdict {
    match error {
        pfctl::ObservationError::AnchorAbsent => RoutedLanVerdict::FilterMissing,
        // A host that refuses the read cannot prove the filter, so it is
        // reported as an absent filter rather than as a pass.
        pfctl::ObservationError::Unavailable
        | pfctl::ObservationError::OutputTooLarge
        | pfctl::ObservationError::TimedOut => RoutedLanVerdict::FilterMissing,
    }
}

/// Maps a PF observation failure onto the firewall's error vocabulary.
fn map_observation_error(error: pfctl::ObservationError) -> FirewallError {
    match error {
        pfctl::ObservationError::Unavailable => FirewallError::PermissionDenied,
        pfctl::ObservationError::OutputTooLarge => FirewallError::ResourceLimitExceeded,
        pfctl::ObservationError::TimedOut => FirewallError::BackendFailure,
        pfctl::ObservationError::AnchorAbsent => FirewallError::FilterMissing,
    }
}

impl RoutedLanVerdict {
    /// The refusal this verdict produces when the apply refuses it.
    pub(crate) fn error(self) -> Option<FirewallError> {
        match self {
            RoutedLanVerdict::Ready => None,
            RoutedLanVerdict::ForwardingDisabled => Some(FirewallError::ForwardingDisabled),
            RoutedLanVerdict::FilterMissing => Some(FirewallError::FilterMissing),
            RoutedLanVerdict::FilterDrift => Some(FirewallError::FilterDrift),
            RoutedLanVerdict::MissingReturnRoute => Some(FirewallError::MissingReturnRoute),
            RoutedLanVerdict::RouteConflict => Some(FirewallError::RouteConflict),
            RoutedLanVerdict::UnsupportedTopology => Some(FirewallError::UnsupportedTopology),
            RoutedLanVerdict::TunnelUnavailable => Some(FirewallError::BackendFailure),
        }
    }
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

    fn installation() -> InstallationId {
        "00000000-0000-4000-8000-0000000000a1".parse().unwrap()
    }

    fn host_only_policy() -> DesiredNetworkPolicy {
        DesiredNetworkPolicy {
            mode: NetworkPolicyMode::HostOnly,
            ipv4_forwarding: Ipv4Forwarding::NotRequired,
            ipv6_forwarding: Ipv6Forwarding::NotRequired,
            egress_interface: InterfaceName::new("en0").unwrap(),
            source_prefixes: vec!["10.0.0.0/24".parse::<NetworkPrefix>().unwrap()],
            destination_prefixes: Vec::new(),
            nat: super::super::policy::NatMode::Disabled,
        }
    }

    fn routed_lan_policy() -> DesiredNetworkPolicy {
        DesiredNetworkPolicy {
            mode: NetworkPolicyMode::RoutedLan,
            ipv4_forwarding: Ipv4Forwarding::Required,
            ipv6_forwarding: Ipv6Forwarding::NotRequired,
            egress_interface: InterfaceName::new("en0").unwrap(),
            source_prefixes: vec!["10.0.0.0/24".parse::<NetworkPrefix>().unwrap()],
            destination_prefixes: vec!["192.168.9.0/24".parse::<NetworkPrefix>().unwrap()],
            nat: super::super::policy::NatMode::Disabled,
        }
    }

    #[test]
    fn a_host_only_policy_needs_no_firewall_action() {
        let service = FirewallService::new();
        let policy = host_only_policy();
        let plan = service
            .plan(installation(), &interface(), Some(&policy))
            .unwrap();
        assert!(plan.actions.is_empty());
        assert!(plan.required_filter_rules.is_empty());
    }

    #[test]
    fn a_gateway_policy_is_refused_rather_than_ignored() {
        let service = FirewallService::new();
        let mut policy = host_only_policy();
        policy.mode = NetworkPolicyMode::Gateway;
        policy.ipv4_forwarding = Ipv4Forwarding::Required;
        assert_eq!(
            service
                .plan(installation(), &interface(), Some(&policy))
                .unwrap_err(),
            FirewallError::Unsupported
        );
    }

    #[test]
    fn a_routed_lan_policy_is_refused_when_forwarding_is_off() {
        let policy = routed_lan_policy();
        assert_eq!(
            require_forwarding_with(&policy, (Some(false), Some(true))),
            Err(FirewallError::ForwardingDisabled)
        );
        assert_eq!(
            require_forwarding_with(&policy, (Some(true), Some(false))),
            Ok(())
        );
        // An unreadable host state is not "forwarding is off", but it is also
        // not a proven prerequisite, so it is refused the same way.
        assert_eq!(
            require_forwarding_with(&policy, (None, Some(true))),
            Err(FirewallError::ForwardingDisabled)
        );
    }

    #[test]
    fn a_routed_lan_policy_needs_ipv6_forwarding_for_ipv6_destinations() {
        let mut policy = routed_lan_policy();
        policy.ipv6_forwarding = Ipv6Forwarding::Required;
        policy.destination_prefixes = vec![
            "192.168.9.0/24".parse::<NetworkPrefix>().unwrap(),
            "2001:db8:9::/64".parse::<NetworkPrefix>().unwrap(),
        ];
        assert_eq!(
            require_forwarding_with(&policy, (Some(true), Some(false))),
            Err(FirewallError::ForwardingDisabled)
        );
        assert_eq!(
            require_forwarding_with(&policy, (Some(true), Some(true))),
            Ok(())
        );
    }

    #[test]
    fn applying_a_host_only_policy_reports_no_change() {
        let service = FirewallService::new();
        let receipt = service.apply(installation(), &interface(), None).unwrap();
        assert_eq!(receipt.status, ApplyStatus::NoChange);
        assert!(!receipt.table_changed);
        assert!(!receipt.forwarding_changed);
    }
}
