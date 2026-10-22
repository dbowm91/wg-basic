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

/// Renders the dedicated anchor for a routed-LAN policy.
///
/// A routed-LAN policy forwards only to an explicit allowlist of downstream
/// prefixes, so every rule names **both** ends: the source prefix inside the
/// tunnel and the approved destination. There is deliberately no `to any`
/// rule, and there is no NAT rule, because a routed LAN is a routing decision
/// and not a masquerade.
///
/// The ingress rule names the tunnel device, which is the dynamic `utun` the
/// helper currently holds. That is what rejects a spoofed source arriving on
/// some other interface, and it is also why the rendered rules have to be
/// re-installed when the helper is renumbered.
///
/// The policy is **bidirectional**: the return leg is rendered as well, from the
/// approved destination back to the tunnel pool. A routed LAN is a routing
/// decision, and a route that only carries traffic one way is not a route: the
/// approved host's own traffic has to reach the pool, and the reply to a
/// forwarded packet must not depend on a state entry that the operator's
/// filter never created. The return rules are bounded exactly like the
/// forward ones — only the approved destination may originate towards the
/// pool, and only towards the pool — so they widen nothing.
///
/// A PF rule matches a single address family: an IPv4 source with an IPv6
/// destination can never match a packet, and PF refuses to load a rule that
/// expands to no valid combination. The pairs are therefore rendered per
/// family, which is also what the routing means — carrying traffic between
/// the two families would need a translation, and a routed LAN never
/// translates.
pub fn render_routed_policy(
    source_prefixes: &[crate::domain::NetworkPrefix],
    destination_prefixes: &[crate::domain::NetworkPrefix],
    egress: &crate::domain::InterfaceName,
    tunnel_interface: &crate::domain::InterfaceName,
) -> PfRuleSet {
    let mut filter = Vec::new();
    for source in source_prefixes {
        for destination in destination_prefixes {
            if source.network().addr().is_ipv4() != destination.network().addr().is_ipv4() {
                continue;
            }
            // The forward leg: the pool's traffic towards the approved
            // destination, in through the tunnel and out through the egress.
            filter.push(format!(
                "pass in on {tunnel_interface} from {source} to {destination} keep state"
            ));
            filter.push(format!(
                "pass out on {egress} from {source} to {destination} keep state"
            ));
            // The return leg: the approved destination's own traffic towards
            // the pool, in through the egress and out through the tunnel.
            filter.push(format!(
                "pass in on {egress} from {destination} to {source} keep state"
            ));
            filter.push(format!(
                "pass out on {tunnel_interface} from {destination} to {source} keep state"
            ));
        }
    }
    PfRuleSet {
        filter,
        nat: Vec::new(),
    }
}

/// One normalized filter rule.
///
/// The product renders a deliberately small rule grammar, so the observed
/// anchor content is normalized into the same shape before it is compared.
/// Normalizing rather than comparing raw text keeps the comparison stable
/// across the whitespace and annotations `pfctl` adds when it prints a
/// ruleset.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FilterRule {
    direction: String,
    interface: String,
    source: String,
    destination: String,
    keep_state: bool,
}

/// Parses one line of observed anchor content into a normalized rule.
///
/// The observed content is PF's own canonical rendering of the rule, not the
/// text the operator wrote. PF resolves the address family it matched and
/// prints it (`inet`, `inet6`), and it resolves `keep state` into the state
/// flags it applied and prints those (`flags S/SA keep state`). The parser
/// therefore accepts the family keyword and the flags as optional, so that a
/// rule the product rendered and an operator installed compare equal.
///
/// Returns `None` for anything the product's grammar does not cover, which
/// makes the comparison fail closed: an anchor carrying a rule the product
/// did not render is drift, not a near miss.
fn parse_filter_rule(line: &str) -> Option<FilterRule> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 8 || tokens[0] != "pass" {
        return None;
    }
    let direction = match tokens[1] {
        "in" => "in",
        "out" => "out",
        _ => return None,
    };
    if tokens[2] != "on" {
        return None;
    }
    let interface = tokens[3].to_owned();
    let mut index = 4;
    // PF prints the address family the rule resolved to.
    if matches!(tokens.get(index), Some(&"inet") | Some(&"inet6")) {
        index += 1;
    }
    if tokens.get(index) != Some(&"from") {
        return None;
    }
    let source = (*tokens.get(index + 1)?).to_owned();
    if tokens.get(index + 2) != Some(&"to") {
        return None;
    }
    let destination = (*tokens.get(index + 3)?).to_owned();
    index += 4;
    // PF prints the state flags the rule resolved to, before the `keep state`
    // it resolved them from.
    if tokens.get(index) == Some(&"flags") {
        index += 1;
        while index < tokens.len() && tokens[index] != "keep" && tokens[index] != "state" {
            index += 1;
        }
    }
    let tail = &tokens[index..];
    Some(FilterRule {
        direction: direction.to_owned(),
        interface,
        source,
        destination,
        // A stateful rule is what lets the return traffic come back, so
        // `keep` and `state` are both required.
        keep_state: tail.contains(&"keep") && tail.contains(&"state"),
    })
}

/// Normalizes a rendered or observed rule list.
fn normalize_rules(rules: &[String]) -> Option<Vec<FilterRule>> {
    rules
        .iter()
        .map(|rule| parse_filter_rule(rule))
        .collect::<Option<Vec<_>>>()
}

/// Whether the observed anchor content is exactly the rendered filter policy.
///
/// The comparison is a multiset equality over the normalized rules: a missing
/// rule, an extra rule, a different interface, a different prefix, or a rule
/// that is not stateful all make the observed content drift. Nothing is
/// repaired by guessing.
pub fn anchor_content_matches(observed: &str, expected: &PfRuleSet) -> bool {
    let mut observed_rules = Vec::new();
    for line in observed.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(rule) = parse_filter_rule(line) else {
            return false;
        };
        observed_rules.push(rule);
    }
    let Some(expected_rules) = normalize_rules(&expected.filter) else {
        return false;
    };
    if observed_rules.len() != expected_rules.len() {
        return false;
    }
    observed_rules.sort();
    let mut expected_rules = expected_rules;
    expected_rules.sort();
    observed_rules == expected_rules
}

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

    /// A routed-LAN source and destination pair.
    fn routed() -> (
        Vec<crate::domain::NetworkPrefix>,
        Vec<crate::domain::NetworkPrefix>,
    ) {
        (
            vec!["10.77.0.0/24".parse().unwrap()],
            vec!["192.168.9.0/24".parse().unwrap()],
        )
    }

    #[test]
    fn a_routed_policy_names_both_ends_and_never_any() {
        let egress: crate::domain::InterfaceName = "en0".parse().unwrap();
        let tunnel: crate::domain::InterfaceName = "utun7".parse().unwrap();
        let (sources, destinations) = routed();
        let rendered = render_routed_policy(&sources, &destinations, &egress, &tunnel);
        assert!(rendered.nat.is_empty(), "a routed LAN never NATs");
        assert_eq!(rendered.filter.len(), 4);
        assert!(rendered
            .filter
            .iter()
            .any(|rule| rule.contains("from 10.77.0.0/24 to 192.168.9.0/24")));
        assert!(rendered.filter.iter().all(|rule| !rule.contains(" to any")));
        // The ingress rule is bound to the tunnel device, which is what
        // rejects a spoofed source arriving on some other interface.
        assert!(rendered
            .filter
            .iter()
            .any(|rule| rule.starts_with("pass in on utun7")));
    }

    /// A routed LAN carries traffic both ways.
    ///
    /// The forward rules alone leave the approved host unable to reach the
    /// pool, and leave the reply to a forwarded packet resting on a state
    /// entry the operator's own filter never created. The return leg is
    /// rendered, and it is bounded exactly like the forward one.
    #[test]
    fn a_routed_policy_carries_the_return_leg_as_well() {
        let egress: crate::domain::InterfaceName = "en0".parse().unwrap();
        let tunnel: crate::domain::InterfaceName = "utun7".parse().unwrap();
        let (sources, destinations) = routed();
        let rendered = render_routed_policy(&sources, &destinations, &egress, &tunnel);
        assert!(rendered
            .filter
            .iter()
            .any(|rule| rule == "pass in on en0 from 192.168.9.0/24 to 10.77.0.0/24 keep state"));
        assert!(
            rendered
                .filter
                .iter()
                .any(|rule| rule
                    == "pass out on utun7 from 192.168.9.0/24 to 10.77.0.0/24 keep state")
        );
        // The return leg reaches the pool and nothing else: there is still no
        // `to any`, and the destination is still an approved one.
        assert!(rendered.filter.iter().all(|rule| !rule.contains(" to any")));
        assert!(rendered
            .filter
            .iter()
            .all(|rule| rule.contains("to 10.77.0.0/24") || rule.contains("to 192.168.9.0/24")));
    }

    /// A routed-LAN policy that carries both families.
    ///
    /// The tunnel pool holds an IPv4 and an IPv6 prefix, and the approved
    /// destinations may too. PF refuses to load a rule that mixes the two
    /// families, and carrying traffic between them would need a translation
    /// that a routed LAN never performs, so the rules are rendered per family.
    #[test]
    fn a_routed_policy_pairs_each_destination_with_its_own_family() {
        let egress: crate::domain::InterfaceName = "en0".parse().unwrap();
        let tunnel: crate::domain::InterfaceName = "utun7".parse().unwrap();
        let sources = vec![
            "10.77.0.0/24".parse().unwrap(),
            "2001:db8:77::/64".parse().unwrap(),
        ];
        let destinations = vec![
            "10.20.20.0/24".parse().unwrap(),
            "2001:db8:20::/64".parse().unwrap(),
        ];
        let rendered = render_routed_policy(&sources, &destinations, &egress, &tunnel);
        // Two legs, an ingress and an egress rule each, per family: eight
        // rules in all.
        assert_eq!(rendered.filter.len(), 8);
        for rule in &rendered.filter {
            // Both ends of a rule belong to the same family: the forward leg
            // carries the pool to the destination, the return leg carries the
            // destination back to the pool, and neither crosses the families.
            let ipv4_ends =
                rule.contains("from 10.77.0.0/24") || rule.contains("from 10.20.20.0/24");
            let ipv6_ends =
                rule.contains("from 2001:db8:77::/64") || rule.contains("from 2001:db8:20::/64");
            assert!(
                ipv4_ends ^ ipv6_ends,
                "a rule may not mix the address families: {rule}"
            );
            let ipv4_pair = rule.contains("to 10.77.0.0/24") || rule.contains("to 10.20.20.0/24");
            let ipv6_pair =
                rule.contains("to 2001:db8:77::/64") || rule.contains("to 2001:db8:20::/64");
            assert!(
                ipv4_pair ^ ipv6_pair,
                "a rule may not mix the address families: {rule}"
            );
            assert!(
                ipv4_ends == ipv4_pair,
                "a rule's two ends belong to one family: {rule}"
            );
        }
        assert!(rendered
            .filter
            .iter()
            .any(|rule| rule == "pass in on utun7 from 10.77.0.0/24 to 10.20.20.0/24 keep state"));
        assert!(rendered
            .filter
            .iter()
            .any(|rule| rule
                == "pass out on en0 from 2001:db8:77::/64 to 2001:db8:20::/64 keep state"));
    }

    /// The real macOS 26.6.2 rendering of a routed-LAN anchor, as
    /// `pfctl -a <anchor> -s rules` printed it on a live host after the
    /// operator installed the rules the product reported.
    ///
    /// PF resolves the address family it matched and the state flags it
    /// applied, and prints both. The comparison has to survive that
    /// canonicalization: an operator who installed exactly the reported rules
    /// must not be told the filter drifted.
    const REAL_MACOS_ROUTED_ANCHOR_RULESET: &str = "\
pass in on utun0 inet from 10.77.0.0/24 to 10.20.20.0/24 flags S/SA keep state
pass in on utun0 inet6 from 2001:db8:77::/64 to 2001:db8:20::/64 flags S/SA keep state
pass out on en0 inet from 10.77.0.0/24 to 10.20.20.0/24 flags S/SA keep state
pass out on en0 inet6 from 2001:db8:77::/64 to 2001:db8:20::/64 flags S/SA keep state
pass in on en0 inet from 10.20.20.0/24 to 10.77.0.0/24 flags S/SA keep state
pass in on en0 inet6 from 2001:db8:20::/64 to 2001:db8:77::/64 flags S/SA keep state
pass out on utun0 inet from 10.20.20.0/24 to 10.77.0.0/24 flags S/SA keep state
pass out on utun0 inet6 from 2001:db8:20::/64 to 2001:db8:77::/64 flags S/SA keep state
";

    #[test]
    fn the_pf_canonical_rendering_of_the_reported_rules_is_not_drift() {
        let egress: crate::domain::InterfaceName = "en0".parse().unwrap();
        let tunnel: crate::domain::InterfaceName = "utun0".parse().unwrap();
        let sources = vec![
            "10.77.0.0/24".parse().unwrap(),
            "2001:db8:77::/64".parse().unwrap(),
        ];
        let destinations = vec![
            "10.20.20.0/24".parse().unwrap(),
            "2001:db8:20::/64".parse().unwrap(),
        ];
        let rendered = render_routed_policy(&sources, &destinations, &egress, &tunnel);
        assert!(
            anchor_content_matches(REAL_MACOS_ROUTED_ANCHOR_RULESET, &rendered),
            "the rules PF prints back are the rules the product rendered"
        );
    }

    /// A rule that PF would print without the state flags is not stateful, and
    /// a rule that lost its state is not an accepted near miss.
    #[test]
    fn a_canonical_rule_without_state_is_drift() {
        let egress: crate::domain::InterfaceName = "en0".parse().unwrap();
        let tunnel: crate::domain::InterfaceName = "utun0".parse().unwrap();
        let sources = vec![
            "10.77.0.0/24".parse().unwrap(),
            "2001:db8:77::/64".parse().unwrap(),
        ];
        let destinations = vec![
            "10.20.20.0/24".parse().unwrap(),
            "2001:db8:20::/64".parse().unwrap(),
        ];
        let rendered = render_routed_policy(&sources, &destinations, &egress, &tunnel);
        let stateless = "\
pass in on utun0 inet from 10.77.0.0/24 to 10.20.20.0/24
pass in on utun0 inet6 from 2001:db8:77::/64 to 2001:db8:20::/64 flags S/SA keep state
pass out on en0 inet from 10.77.0.0/24 to 10.20.20.0/24 flags S/SA keep state
pass out on en0 inet6 from 2001:db8:77::/64 to 2001:db8:20::/64 flags S/SA keep state
";
        assert!(!anchor_content_matches(stateless, &rendered));
    }

    #[test]
    fn an_anchor_that_matches_the_rendered_policy_is_accepted() {
        let egress: crate::domain::InterfaceName = "en0".parse().unwrap();
        let tunnel: crate::domain::InterfaceName = "utun7".parse().unwrap();
        let (sources, destinations) = routed();
        let rendered = render_routed_policy(&sources, &destinations, &egress, &tunnel);
        let observed = format!("{}\n", rendered.filter.join("\n"));
        assert!(anchor_content_matches(&observed, &rendered));
    }

    #[test]
    fn an_anchor_that_differs_from_the_rendered_policy_is_drift() {
        let egress: crate::domain::InterfaceName = "en0".parse().unwrap();
        let tunnel: crate::domain::InterfaceName = "utun7".parse().unwrap();
        let (sources, destinations) = routed();
        let rendered = render_routed_policy(&sources, &destinations, &egress, &tunnel);

        // An extra rule widens the policy and is never accepted.
        let mut widened = rendered.filter.clone();
        widened.push("pass in on utun7 from any to any keep state".into());
        assert!(!anchor_content_matches(
            &format!("{}\n", widened.join("\n")),
            &rendered
        ));

        // A missing rule is drift too.
        let mut narrowed = rendered.filter.clone();
        narrowed.pop();
        assert!(!anchor_content_matches(
            &format!("{}\n", narrowed.join("\n")),
            &rendered
        ));

        // A different tunnel device is drift: the filter has to name the
        // device that actually holds the tunnel.
        let mut renamed = rendered.filter.clone();
        renamed[0] = renamed[0].replace("utun7", "utun9");
        assert!(!anchor_content_matches(
            &format!("{}\n", renamed.join("\n")),
            &rendered
        ));

        // A rule that is not stateful does not allow the return traffic, so
        // it is drift rather than an accepted near miss.
        let mut stateless = rendered.filter.clone();
        stateless[0] = stateless[0].replace(" keep state", "");
        assert!(!anchor_content_matches(
            &format!("{}\n", stateless.join("\n")),
            &rendered
        ));

        // A rule the product's grammar does not cover is never accepted.
        assert!(!anchor_content_matches(
            "pass in on utun7 from 10.77.0.0/24 to 192.168.9.0/24\n",
            &rendered
        ));
    }
}
