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
//!
//! **Gateway (C004).** The managed tunnel is an IPv4 Internet-egress gateway:
//! the client's traffic leaves with a translated source, and IPv6 is routed and
//! never NAT66. This is the one mode in which the product **writes** anything,
//! and what it writes is bounded to the installation's own anchor:
//!
//! 1. the product owns one installation-scoped anchor and one anchor file,
//!    and it writes neither `/etc/pf.conf` nor any foreign anchor;
//! 2. the **administrator** attaches the parent. The filter table's parent
//!    must invoke the managed anchor and the NAT table's parent must invoke
//!    it, independently, as whole tokens. Without both the backend reports
//!    degraded and applies nothing;
//! 3. PF is never enabled or disabled by the product, no table is ever
//!    flushed, and the root ruleset is never loaded;
//! 4. the host's global forwarding switches are read-only to the product,
//!    sticky, and left as the administrator set them (ADR-007);
//! 5. IPv4 masquerade is IPv4 only. IPv6 is routed and never translated.
//!
//! The product's ownership of the anchor file is **provable from the host's
//! state**: the file carries a marker comment that the product writes and
//! recognises. The routed-LAN mode's filter belongs to the administrator and
//! carries no marker, so the product never removes it and reports it as
//! residue instead.

use super::pf;
use super::pfctl;
use super::policy::{
    DesiredNetworkPolicy, FirewallActionKind, FirewallApplyReceipt, FirewallError,
    FirewallPlanSummary, FirewallWarning, GatewayVerdict, Ipv4Forwarding, Ipv6Forwarding, NatMode,
    RoutedLanVerdict,
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
            // The internet exit gateway is the one mode the product writes
            // for: it installs the installation's own anchor's rules, and it
            // refuses when the administrator has not attached the parent.
            NetworkPolicyMode::Gateway => {
                let device = self.tunnel_device(wireguard_interface);
                let verdict = self.observe_gateway(installation_id, policy, device.as_deref());
                Ok(FirewallPlanSummary {
                    wireguard_interface: wireguard_interface.clone(),
                    actions: Vec::new(),
                    warnings: Vec::new(),
                    required_filter_rules: Vec::new(),
                    routed_lan: None,
                    gateway: Some(verdict),
                })
            }
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
                    gateway: None,
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
        let mut actions = plan.actions.clone();
        let mut status = ApplyStatus::NoChange;
        if let Some(policy) = policy {
            match policy.mode {
                NetworkPolicyMode::RoutedLan => {
                    // The product releases whatever it installed itself before
                    // it looks at the operator's filter: the routed-LAN filter
                    // belongs to the administrator, and the product's own
                    // gateway rules would otherwise still be live.
                    self.release_if_owned(
                        installation_id,
                        &mut warnings,
                        &mut actions,
                        &mut status,
                    )?;
                    // The apply is what refuses. The plan only reports.
                    let device = self.tunnel_device(wireguard_interface);
                    let verdict =
                        self.observe_routed_lan(installation_id, policy, device.as_deref());
                    if let Some(error) = verdict.error() {
                        return Err(error);
                    }
                    // A teardown does not remove the operator-managed filter; it
                    // reports the residue so the operator can act on it.
                    if self.operator_filter_residue(installation_id).is_some() {
                        warnings.push(FirewallWarning::RoutedLanFilterResidueObserved);
                    }
                }
                NetworkPolicyMode::Gateway => {
                    let device = self.tunnel_device(wireguard_interface);
                    let verdict = self.observe_gateway(installation_id, policy, device.as_deref());
                    if let Some(error) = verdict.error() {
                        return Err(error);
                    }
                    let Some(device) = device else {
                        return Err(FirewallError::BackendFailure);
                    };
                    self.install_gateway_anchor(installation_id, policy, &device)?;
                    actions.push(FirewallActionKind::InstallManagedPfAnchor);
                    status = ApplyStatus::Applied;
                }
                NetworkPolicyMode::HostOnly => {
                    // The product owns nothing in this mode except what it
                    // installed itself, and it proves that ownership from the
                    // anchor file's own marker.
                    self.release_if_owned(
                        installation_id,
                        &mut warnings,
                        &mut actions,
                        &mut status,
                    )?;
                }
            }
        } else {
            // A teardown: the managed network is being removed, so the
            // product's own anchor goes with it.
            self.release_if_owned(installation_id, &mut warnings, &mut actions, &mut status)?;
        }
        Ok(FirewallApplyReceipt {
            wireguard_interface: wireguard_interface.clone(),
            status,
            actions,
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

    /// Proves that the gateway prerequisites are in place, and reports which
    /// one is missing.
    ///
    /// Every check is an observation. Nothing here writes PF state, a
    /// forwarding sysctl, or a host route.
    fn observe_gateway(
        &self,
        installation_id: InstallationId,
        policy: &DesiredNetworkPolicy,
        device: Option<&str>,
    ) -> GatewayVerdict {
        let forwarding_ok = require_forwarding(policy).is_ok();
        let anchor = pf::anchor_name(installation_id);
        let expected = device.map(|device| render_gateway_rules(policy, device));
        let observation = pfctl::observe(&anchor).ok();
        gateway_verdict(
            forwarding_ok,
            &anchor,
            observation.as_ref(),
            expected.as_ref(),
        )
    }

    /// Installs the installation's own anchor's rules and proves they took.
    ///
    /// The product writes one file, loads it into one anchor, and then
    /// re-observes both rule classes. It claims convergence only when the
    /// loaded rules are exactly the rules it wrote: a rule set that PF
    /// refused, or that something else overwrote, is reported rather than
    /// repaired by guessing.
    fn install_gateway_anchor(
        &self,
        installation_id: InstallationId,
        policy: &DesiredNetworkPolicy,
        device: &str,
    ) -> Result<(), FirewallError> {
        let anchor = pf::anchor_name(installation_id);
        let expected = render_gateway_rules(policy, device);
        let content = pf::anchor_file_content(installation_id, &expected);
        pfctl::install_anchor(&anchor, &content).map_err(map_apply_error)?;
        let observation = pfctl::observe(&anchor).map_err(map_observation_error)?;
        let filter = observation.anchor_filter.as_deref().unwrap_or_default();
        if !pf::anchor_content_matches(filter, &expected) {
            return Err(FirewallError::FilterDrift);
        }
        let nat = observation.anchor_nat.as_deref().unwrap_or_default();
        if !pf::nat_content_matches(nat, &expected) {
            return Err(FirewallError::NatDrift);
        }
        Ok(())
    }

    /// Empties the installation's own anchor when the product owns it.
    ///
    /// The product proves that ownership from the anchor file's own marker. A
    /// file without the marker belongs to somebody else — the administrator's
    /// routed-LAN filter, most often — so the product leaves it alone and
    /// reports the residue instead.
    ///
    /// The file is **not** removed. The administrator's `load anchor` line
    /// names it, and a missing file makes the next `pfctl -f /etc/pf.conf`
    /// fail outright, which would break the host's whole packet-filter
    /// configuration. The file is rewritten to its marker line alone, which is
    /// a valid, empty rules file, and PF never destroys an anchor object
    /// anyway — the kernel accumulates them.
    ///
    /// A file the product **cannot read** is not evidence of anything: the
    /// product does not claim a residue it did not observe, and it does not
    /// remove an anchor it cannot prove it owns. A process that cannot read
    /// the anchor file could not have written it either.
    fn release_managed_anchor(
        &self,
        installation_id: InstallationId,
    ) -> Result<AnchorRelease, FirewallError> {
        let anchor = pf::anchor_name(installation_id);
        let file = match pfctl::read_anchor_file(&anchor) {
            Ok(file) => file,
            Err(_) => return Ok(AnchorRelease::Nothing),
        };
        let owns = file
            .as_deref()
            .is_some_and(|content| pf::owns_anchor_file(content, installation_id));
        if owns {
            let marker_only = format!("{}\n", pf::anchor_file_marker(installation_id));
            pfctl::clear_anchor(&anchor, &marker_only).map_err(map_apply_error)?;
            return Ok(AnchorRelease::Released);
        }
        // The file is not the product's, or there is no file at all. Anything
        // the anchor still holds belongs to somebody else, and the product
        // does not remove it. A packet filter that cannot be read is not
        // evidence of residue either.
        let observation = match pfctl::observe(&anchor) {
            Ok(observation) => observation,
            Err(_) => return Ok(AnchorRelease::Nothing),
        };
        let holds_rules = observation
            .anchor_filter
            .as_deref()
            .is_some_and(|content| !content.trim().is_empty())
            || observation
                .anchor_nat
                .as_deref()
                .is_some_and(|content| !content.trim().is_empty());
        Ok(if holds_rules {
            AnchorRelease::Foreign
        } else {
            AnchorRelease::Nothing
        })
    }

    /// Releases the managed anchor when the product owns it, and records what
    /// it did.
    ///
    /// The three outcomes are three different facts and each one says
    /// something different: the product's own anchor was emptied, somebody
    /// else's anchor holds rules and is left alone, or there was nothing of the
    /// product's to release.
    fn release_if_owned(
        &self,
        installation_id: InstallationId,
        warnings: &mut Vec<FirewallWarning>,
        actions: &mut Vec<FirewallActionKind>,
        status: &mut ApplyStatus,
    ) -> Result<(), FirewallError> {
        match self.release_managed_anchor(installation_id)? {
            AnchorRelease::Released => {
                actions.push(FirewallActionKind::RemoveManagedPfAnchor);
                *status = ApplyStatus::Applied;
            }
            AnchorRelease::Foreign => {
                warnings.push(FirewallWarning::ManagedAnchorResidueObserved);
            }
            AnchorRelease::Nothing => {}
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
        gateway: None,
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

/// The gateway verdict, decided from facts already gathered.
///
/// The facts are passed in rather than read here, because "which prerequisite
/// is missing" is a decision, and a decision that can only be made on a live
/// host is a decision nobody can test.
///
/// The order matters. Forwarding is the first thing a gateway needs, the
/// administrator's attachment is the second, and the anchor's own content is
/// the third: an administrator who has not attached the parent has not had a
/// chance to install anything, so reporting drift before the attachment would
/// name the wrong problem.
fn gateway_verdict(
    forwarding_ok: bool,
    anchor: &str,
    observation: Option<&pfctl::PfObservation>,
    expected: Option<&pf::PfRuleSet>,
) -> GatewayVerdict {
    if !forwarding_ok {
        return GatewayVerdict::ForwardingDisabled;
    }
    let Some(expected) = expected else {
        // Without a proven managed tunnel there is no device to bind the rules
        // to, so the anchor's contract cannot be checked at all.
        return GatewayVerdict::TunnelUnavailable;
    };
    let Some(observation) = observation else {
        return GatewayVerdict::ApplyRefused;
    };
    // The administrator's parent has to invoke the managed anchor in the
    // filter table and in the NAT table, independently. A parent that invokes
    // only one of them never satisfies the requirement for both.
    if !pf::attachment_verified(
        &observation.parent_filter,
        &observation.parent_nat,
        anchor,
        pf::RequiredAttachments::FILTER_AND_NAT,
    ) {
        return GatewayVerdict::AttachmentMissing;
    }
    // An anchor that holds no rules at all is not drift: it is an anchor the
    // product has yet to install into. An anchor that holds rules the product
    // did not render is drift, and the two classes are checked separately
    // because the NAT table is a different table.
    if let Some(content) = observation.anchor_filter.as_deref() {
        if !content.trim().is_empty() && !pf::anchor_content_matches(content, expected) {
            return GatewayVerdict::FilterDrift;
        }
    }
    if let Some(content) = observation.anchor_nat.as_deref() {
        if !content.trim().is_empty() && !pf::nat_content_matches(content, expected) {
            return GatewayVerdict::NatDrift;
        }
    }
    GatewayVerdict::Ready
}

/// The rules the product installs for one gateway policy.
///
/// The gateway translates IPv4 and routes IPv6: the masquerade is decided by
/// the policy's NAT mode, and the renderer never emits a translation rule for
/// an IPv6 prefix.
fn render_gateway_rules(policy: &DesiredNetworkPolicy, device: &str) -> pf::PfRuleSet {
    pf::render_policy(
        &policy.source_prefixes,
        &policy.egress_interface,
        &tunnel_interface(device),
        policy.nat == NatMode::Masquerade,
    )
}

/// What releasing the managed anchor did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AnchorRelease {
    /// The product owned the anchor and emptied it.
    Released,
    /// Nothing of the product's was installed.
    Nothing,
    /// The anchor belongs to somebody else; the product left it alone.
    Foreign,
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

/// Maps a PF apply failure onto the firewall's error vocabulary.
///
/// Every failure keeps its own category. A refusal by the host's packet
/// filter, a file the product could not write, and an anchor name the
/// product may not use are different facts and call for different operator
/// actions.
fn map_apply_error(error: pfctl::ApplyError) -> FirewallError {
    match error {
        pfctl::ApplyError::Unavailable => FirewallError::PermissionDenied,
        pfctl::ApplyError::OutputTooLarge => FirewallError::ResourceLimitExceeded,
        pfctl::ApplyError::TimedOut => FirewallError::BackendFailure,
        pfctl::ApplyError::Refused(_) => FirewallError::BackendFailure,
        pfctl::ApplyError::WriteFailed => FirewallError::BackendFailure,
        pfctl::ApplyError::DigestMismatch => FirewallError::BackendFailure,
        pfctl::ApplyError::InvalidAnchor => FirewallError::AnchorConflict,
    }
}

impl GatewayVerdict {
    /// The refusal this verdict produces when the apply refuses it.
    pub(crate) fn error(self) -> Option<FirewallError> {
        match self {
            GatewayVerdict::Ready => None,
            GatewayVerdict::ForwardingDisabled => Some(FirewallError::ForwardingDisabled),
            GatewayVerdict::AttachmentMissing => Some(FirewallError::GatewayAttachmentMissing),
            GatewayVerdict::FilterDrift => Some(FirewallError::FilterDrift),
            GatewayVerdict::NatDrift => Some(FirewallError::NatDrift),
            GatewayVerdict::TunnelUnavailable => Some(FirewallError::BackendFailure),
            GatewayVerdict::ApplyRefused => Some(FirewallError::BackendFailure),
        }
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

    fn gateway_policy() -> DesiredNetworkPolicy {
        DesiredNetworkPolicy {
            mode: NetworkPolicyMode::Gateway,
            ipv4_forwarding: Ipv4Forwarding::Required,
            ipv6_forwarding: Ipv6Forwarding::NotRequired,
            egress_interface: InterfaceName::new("en0").unwrap(),
            source_prefixes: vec!["10.77.0.0/24".parse::<NetworkPrefix>().unwrap()],
            destination_prefixes: Vec::new(),
            nat: super::super::policy::NatMode::Masquerade,
        }
    }

    #[test]
    fn a_gateway_policy_is_reported_rather_than_refused() {
        let service = FirewallService::new();
        let policy = gateway_policy();
        // The gateway mode is no longer refused outright: the plan reports
        // which prerequisite is missing, and the apply is what refuses. The
        // verdict itself depends on the host, so the decision is exercised by
        // `the_gateway_verdict_names_the_missing_prerequisite` below.
        let plan = service
            .plan(installation(), &interface(), Some(&policy))
            .unwrap();
        assert!(plan.gateway.is_some());
        assert!(plan.routed_lan.is_none());
    }

    #[test]
    fn the_gateway_verdict_names_the_missing_prerequisite() {
        let anchor = "wg-basic-v1-1c0ffee";
        let expected = render_gateway_rules(&gateway_policy(), "utun7");
        let attached = pfctl::PfObservation {
            parent_filter: format!("anchor \"com.apple/*\" all\nanchor \"{anchor}\" all\n"),
            parent_nat: format!("nat-anchor \"com.apple/*\" all\nnat-anchor \"{anchor}\" all\n"),
            anchor_filter: None,
            anchor_nat: None,
        };

        // Forwarding comes first: it is the first thing a gateway needs, and
        // an administrator who has not enabled it cannot have attached the
        // parent either.
        assert_eq!(
            gateway_verdict(false, anchor, Some(&attached), Some(&expected)),
            GatewayVerdict::ForwardingDisabled
        );
        // Without a managed tunnel there is no device to bind the rules to.
        assert_eq!(
            gateway_verdict(true, anchor, Some(&attached), None),
            GatewayVerdict::TunnelUnavailable
        );
        // A packet filter that cannot be read cannot be proven.
        assert_eq!(
            gateway_verdict(true, anchor, None, Some(&expected)),
            GatewayVerdict::ApplyRefused
        );

        // A parent that invokes the anchor in only one rule class is not
        // enough: the NAT table is a different table.
        let filter_only = pfctl::PfObservation {
            parent_filter: attached.parent_filter.clone(),
            parent_nat: "nat-anchor \"com.apple/*\" all\n".to_owned(),
            anchor_filter: None,
            anchor_nat: None,
        };
        assert_eq!(
            gateway_verdict(true, anchor, Some(&filter_only), Some(&expected)),
            GatewayVerdict::AttachmentMissing
        );

        // An anchor with nothing in it is an anchor the product has yet to
        // install into, not drift.
        assert_eq!(
            gateway_verdict(true, anchor, Some(&attached), Some(&expected)),
            GatewayVerdict::Ready
        );

        // An anchor holding rules the product did not render is drift, and the
        // two rule classes are judged separately.
        let filter_drifted = pfctl::PfObservation {
            parent_filter: attached.parent_filter.clone(),
            parent_nat: attached.parent_nat.clone(),
            anchor_filter: Some(
                "pass in on utun7 inet from 10.88.0.0/24 to any flags S/SA keep state\n".to_owned(),
            ),
            anchor_nat: None,
        };
        assert_eq!(
            gateway_verdict(true, anchor, Some(&filter_drifted), Some(&expected)),
            GatewayVerdict::FilterDrift
        );
        let nat_drifted = pfctl::PfObservation {
            parent_filter: attached.parent_filter.clone(),
            parent_nat: attached.parent_nat.clone(),
            anchor_filter: None,
            anchor_nat: Some(
                "nat on en0 inet from 10.88.0.0/24 to any -> (en0) round-robin\n".to_owned(),
            ),
        };
        assert_eq!(
            gateway_verdict(true, anchor, Some(&nat_drifted), Some(&expected)),
            GatewayVerdict::NatDrift
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
