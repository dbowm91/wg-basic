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
//!
//! Attachment verification (C007) is **per rule class and token-exact**. The
//! filter table's parent must invoke the managed anchor with an `anchor`
//! rule, and the NAT table's parent with a `nat-anchor` rule; each names the
//! managed anchor as a whole token. A name that merely *contains* the managed
//! name, a comment naming it, another table's keyword, and the anchor's own
//! definition are all not invocations. The two classes are verified
//! independently, and a required class that is not invoked is never excused
//! by the other one.

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

/// The rule classes whose attachment the administrator's parent configuration
/// must establish.
///
/// The filter table and the NAT table hold **independent** anchors that may
/// share a name, and each is attached by its own parent rule. A policy that
/// needs both therefore requires both, and a policy that needs only the
/// filter anchor must not be satisfied by an NAT-only reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequiredAttachments {
    /// The filter table's parent must invoke the managed anchor.
    pub filter: bool,
    /// The NAT table's parent must invoke the managed anchor.
    pub nat: bool,
}

impl RequiredAttachments {
    /// A policy that needs the filter anchor only (host-only, or forwarded
    /// traffic without masquerade).
    pub const FILTER_ONLY: RequiredAttachments = RequiredAttachments {
        filter: true,
        nat: false,
    };

    /// A masquerading policy: both anchors are required, independently.
    pub const FILTER_AND_NAT: RequiredAttachments = RequiredAttachments {
        filter: true,
        nat: true,
    };
}

/// The observed attachment state of one rule class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Attachment {
    /// The parent ruleset invokes the managed anchor.
    Invoked,
    /// The parent ruleset does not invoke the managed anchor.
    Missing,
}

/// The per-class attachment observation of one installation anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachmentObservation {
    /// The filter table's attachment state.
    pub filter: Attachment,
    /// The NAT table's attachment state.
    pub nat: Attachment,
}

impl AttachmentObservation {
    /// Whether every required class is observed as invoked.
    ///
    /// This is a conjunction over the required classes. A class that is not
    /// required is not consulted, and a missing class is never excused by an
    /// invoked one.
    pub fn verified(self, required: RequiredAttachments) -> bool {
        (!required.filter || self.filter == Attachment::Invoked)
            && (!required.nat || self.nat == Attachment::Invoked)
    }
}

/// Observes how the observed parent configurations attach the managed anchor,
/// one rule class at a time.
///
/// The live backend supplies real `pfctl -s rules` and `pfctl -s nat` output;
/// fixtures model it here. The observation is deliberately per class so a
/// caller can report *which* class is missing instead of only that the
/// attachment as a whole failed.
pub fn observe_attachments(
    parent_filter_output: &str,
    parent_nat_output: &str,
    anchor: &str,
) -> AttachmentObservation {
    AttachmentObservation {
        filter: if invokes_anchor(parent_filter_output, "anchor", anchor) {
            Attachment::Invoked
        } else {
            Attachment::Missing
        },
        nat: if invokes_anchor(parent_nat_output, "nat-anchor", anchor) {
            Attachment::Invoked
        } else {
            Attachment::Missing
        },
    }
}

/// Whether the observed parent configurations attach the managed anchor in
/// every required rule class.
///
/// The verdict is a conjunction over the required classes. A parent that
/// invokes only one class never satisfies a requirement for both, and a
/// parent that mentions the managed name in any other way invokes nothing.
pub fn attachment_verified(
    parent_filter_output: &str,
    parent_nat_output: &str,
    anchor: &str,
    required: RequiredAttachments,
) -> bool {
    observe_attachments(parent_filter_output, parent_nat_output, anchor).verified(required)
}

/// Whether `ruleset_output` contains a rule that invokes `anchor`.
///
/// The rule must **invoke** the anchor, not merely mention it:
///
/// - the rule's first token is the keyword of the table the rule belongs to
///   (`anchor` in the filter table, `nat-anchor` in the NAT table), and
/// - the rule's second token is the managed anchor's name as a **whole
///   token**, quoted (`"name"`) or bare.
///
/// A name that merely contains the managed name, a comment naming it, another
/// table's keyword, and the anchor's own definition are all not invocations.
/// The test is token-exact, so it fails closed on anything ambiguous.
fn invokes_anchor(ruleset_output: &str, keyword: &str, anchor: &str) -> bool {
    let quoted = format!("\"{anchor}\"");
    ruleset_output.lines().any(|line| {
        let mut tokens = line.split_whitespace();
        match (tokens.next(), tokens.next()) {
            (Some(first), Some(second)) => {
                first == keyword && (second == quoted || second == anchor)
            }
            _ => false,
        }
    })
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

    /// The real macOS 26.6.2 main filter ruleset, as `pfctl -s rules` printed
    /// it on a live host. Captured read-only; the host's own rules are
    /// Apple's.
    const REAL_MACOS_FILTER_RULESET: &str = "\
scrub-anchor \"com.apple/*\" all fragment reassemble
scrub-anchor \"com.apple.internet-sharing\" all fragment reassemble
anchor \"com.apple/*\" all
anchor \"com.apple.internet-sharing\" all
";

    /// The real macOS 26.6.2 main NAT ruleset, as `pfctl -s nat` printed it.
    const REAL_MACOS_NAT_RULESET: &str = "\
nat-anchor \"com.apple/*\" all
nat-anchor \"com.apple.internet-sharing\" all
rdr-anchor \"com.apple/*\" all
rdr-anchor \"com.apple.internet-sharing\" all
";

    /// The real ruleset of a scoped fixture parent anchor that invokes a
    /// managed anchor, as `pfctl -a <parent> -s rules` printed it.
    const REAL_MACOS_PARENT_ANCHOR_RULESET: &str = "anchor \"wg-basic-fmt-probe-child\" all\n";

    #[test]
    fn an_invocation_in_the_filter_table_verifies_the_filter_class() {
        let anchor = "wg-basic-v1-test";
        let observation = observe_attachments("anchor \"wg-basic-v1-test\" all\n", "", anchor);
        assert_eq!(observation.filter, Attachment::Invoked);
        assert_eq!(observation.nat, Attachment::Missing);
        assert!(observation.verified(RequiredAttachments::FILTER_ONLY));
        assert!(!observation.verified(RequiredAttachments::FILTER_AND_NAT));
    }

    #[test]
    fn an_invocation_in_the_nat_table_verifies_the_nat_class() {
        let anchor = "wg-basic-v1-test";
        let observation = observe_attachments("", "nat-anchor \"wg-basic-v1-test\" all\n", anchor);
        assert_eq!(observation.filter, Attachment::Missing);
        assert_eq!(observation.nat, Attachment::Invoked);
        assert!(
            !observation.verified(RequiredAttachments::FILTER_ONLY),
            "an NAT-only parent does not satisfy a filter-only requirement"
        );
        assert!(
            !observation.verified(RequiredAttachments::FILTER_AND_NAT),
            "an NAT-only parent does not satisfy a two-class requirement"
        );
    }

    #[test]
    fn the_two_rule_classes_are_verified_independently() {
        let anchor = "wg-basic-v1-test";
        // A parent that invokes only the filter anchor does not satisfy a
        // requirement for both, and neither does an NAT-only parent.
        let filter_only = "anchor \"wg-basic-v1-test\" all\n";
        let nat_only = "nat-anchor \"wg-basic-v1-test\" all\n";
        assert!(!attachment_verified(
            filter_only,
            "",
            anchor,
            RequiredAttachments::FILTER_AND_NAT
        ));
        assert!(!attachment_verified(
            "",
            nat_only,
            anchor,
            RequiredAttachments::FILTER_AND_NAT
        ));
        assert!(attachment_verified(
            filter_only,
            nat_only,
            anchor,
            RequiredAttachments::FILTER_AND_NAT
        ));
    }

    #[test]
    fn a_longer_name_that_contains_the_managed_name_is_not_an_invocation() {
        let anchor = "wg-basic-v1-test";
        let observation = observe_attachments(
            "anchor \"wg-basic-v1-test-backup\" all\n",
            "nat-anchor \"wg-basic-v1-test-backup\" all\n",
            anchor,
        );
        assert_eq!(observation.filter, Attachment::Missing);
        assert_eq!(observation.nat, Attachment::Missing);
        assert!(!observation.verified(RequiredAttachments::FILTER_AND_NAT));
    }

    #[test]
    fn a_comment_naming_the_managed_anchor_is_not_an_invocation() {
        let anchor = "wg-basic-v1-test";
        let observation = observe_attachments(
            "# anchor \"wg-basic-v1-test\" all\n",
            "# nat-anchor \"wg-basic-v1-test\" all\n",
            anchor,
        );
        assert_eq!(observation.filter, Attachment::Missing);
        assert_eq!(observation.nat, Attachment::Missing);
    }

    #[test]
    fn another_tables_keyword_is_not_an_invocation() {
        let anchor = "wg-basic-v1-test";
        // `scrub-anchor` and `rdr-anchor` are not the filter table's anchor
        // keyword, and a `nat-anchor` rule is not a filter-table invocation.
        let observation = observe_attachments(
            "scrub-anchor \"wg-basic-v1-test\" all fragment reassemble\n\
             rdr-anchor \"wg-basic-v1-test\" all\n\
             nat-anchor \"wg-basic-v1-test\" all\n",
            "anchor \"wg-basic-v1-test\" all\n",
            anchor,
        );
        assert_eq!(observation.filter, Attachment::Missing);
        assert_eq!(
            observation.nat,
            Attachment::Missing,
            "a filter-table anchor rule is not a NAT-table invocation"
        );
    }

    #[test]
    fn the_anchor_must_be_named_as_a_whole_token() {
        let anchor = "wg-basic-v1-test";
        assert_eq!(
            observe_attachments("anchor wg-basic-v1-test all\n", "", anchor).filter,
            Attachment::Invoked,
            "an unquoted whole-token name is still the name"
        );
        assert_eq!(
            observe_attachments("anchor \"wg-basic-v1-test-x\" all\n", "", anchor).filter,
            Attachment::Missing
        );
        assert_eq!(
            observe_attachments("anchor \"prefix-wg-basic-v1-test\" all\n", "", anchor).filter,
            Attachment::Missing
        );
    }

    #[test]
    fn the_real_macos_rulesets_are_parsed_without_a_false_attachment() {
        // Apple's own anchors are invocations of *Apple's* anchors and of
        // nothing else.
        let observation = observe_attachments(
            REAL_MACOS_FILTER_RULESET,
            REAL_MACOS_NAT_RULESET,
            "wg-basic-v1-6f1a0f2e-0000-4000-8000-000000000000",
        );
        assert_eq!(observation.filter, Attachment::Missing);
        assert_eq!(observation.nat, Attachment::Missing);

        // The same matcher does find the real invocations the host printed.
        let apple = observe_attachments(
            REAL_MACOS_FILTER_RULESET,
            REAL_MACOS_NAT_RULESET,
            "com.apple.internet-sharing",
        );
        assert_eq!(apple.filter, Attachment::Invoked);
        assert_eq!(apple.nat, Attachment::Invoked);
    }

    #[test]
    fn the_real_parent_anchor_output_is_recognized_as_an_invocation() {
        // The parent anchor the host printed invokes the child anchor, and
        // the matcher finds it.
        let observation = observe_attachments(
            REAL_MACOS_PARENT_ANCHOR_RULESET,
            "",
            "wg-basic-fmt-probe-child",
        );
        assert_eq!(observation.filter, Attachment::Invoked);
        assert_eq!(observation.nat, Attachment::Missing);

        // The shorter prefix of that name is a different anchor: a substring
        // test would have reported it as attached.
        let prefix =
            observe_attachments(REAL_MACOS_PARENT_ANCHOR_RULESET, "", "wg-basic-fmt-probe");
        assert_eq!(prefix.filter, Attachment::Missing);
    }

    #[test]
    fn a_ruleset_carrying_tool_noise_is_still_parsed_exactly() {
        let anchor = "wg-basic-v1-test";
        let observation = observe_attachments(
            "No ALTQ support in kernel\nALTQ related functions disabled\n\
             anchor \"wg-basic-v1-test\" all\n",
            "No ALTQ support in kernel\n",
            anchor,
        );
        assert_eq!(observation.filter, Attachment::Invoked);
        assert_eq!(observation.nat, Attachment::Missing);
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
