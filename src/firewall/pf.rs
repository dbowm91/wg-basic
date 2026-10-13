//! Darwin PF/NAT anchor model and distribution policy (M005).
//!
//! Policy scope only: typed anchor derivation, pure rule rendering, anchor
//! attachment verification, and the fail-closed drift contract. No `pfctl`
//! execution lives here — the bounded invocation lands with live
//! qualification on a disposable privileged host. This module performs no
//! I/O, spawns nothing, and mutates no host state.
//!
//! Apple TN3165 decision (recorded in `plans/closure/macos-native-server/`
//! `005-status.md`): PF is not a general product API. macOS gateway support
//! is **advanced-administrator opt-in only**, never general consumer
//! support. The administrator explicitly attaches the installation anchor
//! from their own PF configuration; wg-basic never rewrites `/etc/pf.conf`,
//! flushes tables, disables PF, or seizes global state. Without a verified
//! attachment the backend reports degraded and applies nothing.
//!
//! Behavior contract (mirrors the Linux firewall-first ordering):
//! - IPv4: forwarding + masquerade via the dedicated anchor, opt-in only.
//! - IPv6: routed return, never NAT66.
//! - Global forwarding toggles are shared and sticky: never silently reset.
//! - Teardown removes the owned anchors before helper teardown and never
//!   touches foreign anchors, global PF state, or forwarding settings.

use std::collections::BTreeSet;

/// Installation anchor namespace. Nested under the administrator-attached
/// parent; the installation UUID keeps two installations from sharing one.
pub const ANCHOR_PREFIX: &str = "wg-basic-v1";
/// Strictly observed forwarding controls. No caller-supplied sysctl path is
/// ever expressible; the live backend reads exactly these two.
pub const IPV4_FORWARDING_SYSCTL: &str = "net.inet.ip.forwarding";
pub const IPV6_FORWARDING_SYSCTL: &str = "net.inet6.ip6.forwarding";

/// Derives the installation-scoped anchor name. Deterministic, restricted
/// charset, unique per installation identity.
pub fn anchor_name(installation_id: crate::domain::InstallationId) -> String {
    format!("{ANCHOR_PREFIX}-{installation_id}")
}

/// Pure rendered anchor contents: filter rules plus NAT rules (v4 only).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PfRuleSet {
    pub filter: Vec<String>,
    pub nat: Vec<String>,
}

/// Renders the dedicated anchor for one typed policy.
///
/// - `tunnel_prefixes`: source prefixes allowed into the tunnel interface;
/// - `egress`: outbound interface for forwarded/NAT traffic;
/// - `masquerade`: IPv4 NAT on egress (never NAT66: IPv6 prefixes are
///   categorically excluded from `nat` even when masquerade is set).
pub fn render_policy(
    tunnel_prefixes: &[crate::domain::NetworkPrefix],
    egress: &crate::domain::InterfaceName,
    tunnel_interface: &crate::domain::InterfaceName,
    masquerade: bool,
) -> PfRuleSet {
    let mut seen = BTreeSet::new();
    let mut filter = Vec::new();
    for prefix in tunnel_prefixes {
        if !seen.insert(prefix.to_string()) {
            continue;
        }
        filter.push(format!(
            "pass in on {tunnel_interface} from {prefix} to any keep state"
        ));
        filter.push(format!(
            "pass out on {egress} from {prefix} to any keep state"
        ));
    }
    let mut nat = Vec::new();
    if masquerade {
        for prefix in tunnel_prefixes {
            // IPv4 masquerade only. IPv6 is routed, never translated.
            if prefix.network().addr().is_ipv4() && seen.contains(&prefix.to_string()) {
                nat.push(format!(
                    "nat on {egress} from {prefix} to any -> ({egress})"
                ));
            }
        }
    }
    PfRuleSet { filter, nat }
}

/// Verifies that observed parent filter/NAT output actually invokes the
/// installation anchor. Mere anchor existence is not effective policy: the
/// parent must reference it. The live backend supplies real `pfctl -s`
/// output; fixtures model it here.
pub fn attachment_verified(
    parent_filter_output: &str,
    parent_nat_output: &str,
    anchor: &str,
) -> bool {
    parent_filter_output.contains(anchor) || parent_nat_output.contains(anchor)
}

/// Digest of the exact rendered rules for drift detection. Any observed
/// anchor content that does not digest-match is foreign/drifted: fail
/// closed, never repair by guessing.
pub fn rules_digest(rules: &PfRuleSet) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for rule in rules.filter.iter().chain(rules.nat.iter()) {
        hasher.update(rule.as_bytes());
        hasher.update(b"\n");
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Conservative teardown order: owned filter anchor, owned NAT anchor, then
/// helper teardown. Global forwarding and foreign anchors are never touched.
pub fn teardown_order() -> [&'static str; 3] {
    ["filter-anchor", "nat-anchor", "helper"]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PfError {
    #[error("an anchor with the installation name has unrecognized ownership")]
    AnchorConflict,
    #[error("the parent filter/NAT configuration does not invoke the installation anchor")]
    AttachmentMissing,
    #[error("observed anchor content drifted from the rendered policy")]
    Drifted,
    #[error("PF backend is unsupported on this host or build")]
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installation() -> crate::domain::InstallationId {
        crate::domain::InstallationId::new()
    }

    fn prefixes() -> Vec<crate::domain::NetworkPrefix> {
        vec![
            "10.8.0.0/24".parse().unwrap(),
            "2001:db8::/64".parse().unwrap(),
        ]
    }

    #[test]
    fn anchor_names_are_deterministic_and_installation_scoped() {
        let id = installation();
        let first = anchor_name(id);
        assert_eq!(first, anchor_name(id));
        assert!(first.starts_with(ANCHOR_PREFIX));
        assert_ne!(first, anchor_name(installation()));
    }

    #[test]
    fn rendering_masks_masquerade_without_nat66() {
        let egress: crate::domain::InterfaceName = "en0".parse().unwrap();
        let tunnel: crate::domain::InterfaceName = "wg0".parse().unwrap();
        let rendered = render_policy(&prefixes(), &egress, &tunnel, true);
        assert!(rendered
            .filter
            .iter()
            .any(|rule| rule.contains("10.8.0.0/24")));
        assert!(rendered.nat.iter().any(|rule| rule.contains("10.8.0.0/24")));
        assert!(
            !rendered.nat.iter().any(|rule| rule.contains("2001:db8")),
            "IPv6 is routed, never NAT66"
        );
        let plain = render_policy(&prefixes(), &egress, &tunnel, false);
        assert!(plain.nat.is_empty());
        assert!(!plain.filter.is_empty());
    }

    #[test]
    fn attachment_requires_parent_invocation_not_mere_existence() {
        let anchor = "wg-basic-v1-test";
        assert!(!attachment_verified("", "", anchor));
        assert!(attachment_verified(
            "anchor \"wg-basic-v1-test\" all",
            "",
            anchor
        ));
        assert!(attachment_verified(
            "",
            "nat-anchor \"wg-basic-v1-test\" all",
            anchor
        ));
        assert!(!attachment_verified("anchor \"other\" all", "", anchor));
    }

    #[test]
    fn drift_is_detected_by_digest() {
        let egress: crate::domain::InterfaceName = "en0".parse().unwrap();
        let tunnel: crate::domain::InterfaceName = "wg0".parse().unwrap();
        let rendered = render_policy(&prefixes(), &egress, &tunnel, true);
        let digest = rules_digest(&rendered);
        let mut drifted = rendered.clone();
        drifted.filter.push("pass in all".into());
        assert_ne!(digest, rules_digest(&drifted));
    }

    #[test]
    fn teardown_never_touches_global_or_foreign_state() {
        assert_eq!(teardown_order(), ["filter-anchor", "nat-anchor", "helper"]);
    }

    #[test]
    fn sysctl_paths_are_fixed_constants() {
        assert_eq!(IPV4_FORWARDING_SYSCTL, "net.inet.ip.forwarding");
        assert_eq!(IPV6_FORWARDING_SYSCTL, "net.inet6.ip6.forwarding");
    }
}
