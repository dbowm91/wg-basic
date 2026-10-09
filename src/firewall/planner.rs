//! Observation-to-plan translation for the owned nftables table.
//!
//! Planning is pure: it compares a normalized observation against the objects the
//! policy renders to, and refuses to touch an unowned same-name table.

use super::policy::{
    DesiredNetworkPolicy, FirewallActionKind, FirewallError, FirewallOwner, FirewallPlanSummary,
    FirewallWarning, Ipv4Forwarding, Ipv6Forwarding, NatMode, TABLE_NAME,
};
use crate::domain::InterfaceName;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TableObservation {
    pub(crate) present: bool,
    pub(crate) owned: bool,
    /// The table carries the pre-Phase-6 product-only marker.
    pub(crate) legacy_marker: bool,
    pub(crate) rule_markers: BTreeSet<String>,
    pub(crate) chain_count: usize,
    pub(crate) rule_count: usize,
    pub(crate) chain_names: BTreeSet<String>,
    pub(crate) chains: BTreeMap<String, serde_json::Value>,
    pub(crate) rules: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FirewallObservation {
    pub(crate) forwarding_enabled: bool,
    pub(crate) ipv6_forwarding_enabled: Option<bool>,
    pub(crate) table: TableObservation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FirewallPlan {
    pub(crate) summary: FirewallPlanSummary,
    pub(crate) desired_hash: Option<String>,
}

pub(crate) fn plan_firewall(
    owner: &FirewallOwner,
    wireguard_interface: &InterfaceName,
    policy: Option<&DesiredNetworkPolicy>,
    observation: &FirewallObservation,
) -> Result<FirewallPlan, FirewallError> {
    if observation.table.present && !observation.table.owned {
        // An M005-era table is a conflict for operator cleanup, never an
        // automatic adoption: ownership now binds to an installation identity.
        return Err(if observation.table.legacy_marker {
            FirewallError::LegacyTableOwnership
        } else {
            FirewallError::TableOwnershipConflict
        });
    }
    if observation
        .table
        .chain_names
        .iter()
        .any(|name| name != "forward" && name != "postrouting")
    {
        return Err(FirewallError::TableOwnershipConflict);
    }
    let mut actions = Vec::new();
    let desired_hash = if let Some(policy) = policy {
        policy.validate(wireguard_interface)?;
        let hash = policy_hash(policy, wireguard_interface);
        let desired_markers = policy.rule_markers(owner, &hash, wireguard_interface);
        if policy.ipv4_forwarding == Ipv4Forwarding::Required && !observation.forwarding_enabled {
            actions.push(FirewallActionKind::EnableIpv4Forwarding);
        }
        if policy.ipv6_forwarding == Ipv6Forwarding::Required {
            match observation.ipv6_forwarding_enabled {
                Some(true) => {}
                Some(false) => actions.push(FirewallActionKind::EnableIpv6Forwarding),
                None => return Err(FirewallError::BackendFailure),
            }
        }
        let expected_chains = 1 + usize::from(policy.nat == NatMode::Masquerade);
        let expected_rules = 2
            + policy.sorted_allowed_prefixes().len()
            + if policy.nat == NatMode::Masquerade {
                policy.sorted_ipv4_prefixes().len()
            } else {
                0
            };
        let (expected_chain_objects, expected_rule_objects) =
            expected_objects(owner, policy, wireguard_interface, &hash);
        if !observation.table.present
            || observation.table.rule_markers != desired_markers
            || observation.table.chain_count != expected_chains
            || observation.table.rule_count != expected_rules
            || observation.table.chains != expected_chain_objects
            || observation.table.rules != expected_rule_objects
        {
            actions.push(FirewallActionKind::ReplaceOwnedNftablesTable);
        }
        Some(hash)
    } else {
        if observation.table.present {
            actions.push(FirewallActionKind::RemoveOwnedNftablesTable);
        }
        None
    };
    Ok(FirewallPlan {
        summary: FirewallPlanSummary {
            wireguard_interface: wireguard_interface.clone(),
            actions,
            warnings: if policy
                .is_some_and(|policy| policy.ipv6_forwarding == Ipv6Forwarding::Required)
            {
                vec![
                    FirewallWarning::IndependentFirewallMayStillBlockForwardedTraffic,
                    FirewallWarning::Ipv6ForwardingIsHostGlobalAndRemainsEnabled,
                ]
            } else {
                vec![FirewallWarning::IndependentFirewallMayStillBlockForwardedTraffic]
            },
        },
        desired_hash,
    })
}

pub(crate) fn matches_policy(
    owner: &FirewallOwner,
    policy: Option<&DesiredNetworkPolicy>,
    interface: &InterfaceName,
    observation: &FirewallObservation,
) -> Result<bool, FirewallError> {
    if let Some(policy) = policy {
        if (policy.ipv4_forwarding == Ipv4Forwarding::Required && !observation.forwarding_enabled)
            || (policy.ipv6_forwarding == Ipv6Forwarding::Required
                && observation.ipv6_forwarding_enabled != Some(true))
            || !observation.table.present
            || !observation.table.owned
        {
            return Ok(false);
        }
        let hash = policy_hash(policy, interface);
        let expected_chains = 1 + usize::from(policy.nat == NatMode::Masquerade);
        let expected_rules = 2
            + policy.sorted_allowed_prefixes().len()
            + if policy.nat == NatMode::Masquerade {
                policy.sorted_ipv4_prefixes().len()
            } else {
                0
            };
        let (expected_chain_objects, expected_rule_objects) =
            expected_objects(owner, policy, interface, &hash);
        Ok(
            observation.table.rule_markers == policy.rule_markers(owner, &hash, interface)
                && observation.table.chain_count == expected_chains
                && observation.table.rule_count == expected_rules
                && observation.table.chains == expected_chain_objects
                && observation.table.rules == expected_rule_objects,
        )
    } else {
        Ok(!observation.table.present)
    }
}

pub(crate) fn policy_hash(policy: &DesiredNetworkPolicy, interface: &InterfaceName) -> String {
    let mut bytes = format!(
        "{}|{:?}|{:?}|{:?}|",
        interface.as_str(),
        policy.ipv4_forwarding,
        policy.ipv6_forwarding,
        policy.nat
    )
    .into_bytes();
    bytes.extend_from_slice(policy.egress_interface.as_str().as_bytes());
    for prefix in policy.sorted_prefixes() {
        bytes.push(b'|');
        bytes.extend_from_slice(prefix.to_string().as_bytes());
    }
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

pub(crate) fn expected_objects(
    owner: &FirewallOwner,
    policy: &DesiredNetworkPolicy,
    interface: &InterfaceName,
    hash: &str,
) -> (
    BTreeMap<String, serde_json::Value>,
    BTreeMap<String, serde_json::Value>,
) {
    let mut chains = BTreeMap::new();
    let mut rules = BTreeMap::new();
    chains.insert(
        "forward".to_owned(),
        serde_json::json!({
            "family": "inet",
            "table": TABLE_NAME,
            "name": "forward",
            "comment": format!("{owner}:chain:forward:{hash}"),
            "type": "filter",
            "hook": "forward",
            "prio": 0,
            "policy": "accept"
        }),
    );
    if policy.nat == NatMode::Masquerade {
        chains.insert(
            "postrouting".to_owned(),
            serde_json::json!({
                "family": "inet",
                "table": TABLE_NAME,
                "name": "postrouting",
                "comment": format!("{owner}:chain:postrouting:{hash}"),
                "type": "nat",
                "hook": "postrouting",
                "prio": 100,
                "policy": "accept"
            }),
        );
    }

    let return_comment = format!("{owner}:rule:return:{hash}");
    rules.insert(
        return_comment.clone(),
        serde_json::json!({
            "family": "inet",
            "table": TABLE_NAME,
            "chain": "forward",
            "comment": return_comment,
            "expr": [
                {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": interface.as_str()}},
                {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}},
                {"accept": null}
            ]
        }),
    );
    for (index, prefix) in policy.sorted_allowed_prefixes().iter().enumerate() {
        let network = prefix.network();
        let family = if network.addr().is_ipv4() {
            "ip"
        } else {
            "ip6"
        };
        let prefix_expr = serde_json::json!({
            "match": {
                "op": "==",
                "left": {"payload": {"protocol": family, "field": "saddr"}},
                "right": {"prefix": {"addr": network.addr().to_string(), "len": network.prefix_len()}}
            }
        });
        let allow_comment = format!("{owner}:rule:allow:{index}:{hash}");
        rules.insert(
            allow_comment.clone(),
            serde_json::json!({
                "family": "inet",
                "table": TABLE_NAME,
                "chain": "forward",
                "comment": allow_comment,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": interface.as_str()}},
                    {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": policy.egress_interface.as_str()}},
                    prefix_expr.clone(),
                    {"accept": null}
                ]
            }),
        );
    }
    if policy.nat == NatMode::Masquerade {
        for (index, prefix) in policy.sorted_ipv4_prefixes().iter().enumerate() {
            let network = prefix.network();
            let nat_comment = format!("{owner}:rule:nat:{index}:{hash}");
            rules.insert(
                nat_comment.clone(),
                serde_json::json!({
                    "family": "inet",
                    "table": TABLE_NAME,
                    "chain": "postrouting",
                    "comment": nat_comment,
                    "expr": [
                        {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": policy.egress_interface.as_str()}},
                        {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": network.addr().to_string(), "len": network.prefix_len()}}}},
                        {"masquerade": null}
                    ]
                }),
            );
        }
    }
    let drop_comment = format!("{owner}:rule:drop:{hash}");
    rules.insert(
        drop_comment.clone(),
        serde_json::json!({
            "family": "inet",
            "table": TABLE_NAME,
            "chain": "forward",
            "comment": drop_comment,
            "expr": [
                {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": interface.as_str()}},
                {"drop": null}
            ]
        }),
    );
    (chains, rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One stable installation identity for the whole module: the table marker
    /// must match between observation and the expected objects, so it cannot be
    /// regenerated per call.
    fn owner() -> FirewallOwner {
        FirewallOwner::new(
            "00000000-0000-4000-8000-0000000000a1"
                .parse::<crate::domain::InstallationId>()
                .unwrap(),
        )
    }

    fn fixture() -> (InterfaceName, DesiredNetworkPolicy) {
        (
            "wg0".parse().unwrap(),
            DesiredNetworkPolicy {
                ipv4_forwarding: Ipv4Forwarding::Required,
                ipv6_forwarding: Ipv6Forwarding::NotRequired,
                egress_interface: "eth0".parse().unwrap(),
                source_prefixes: vec!["10.8.0.0/24".parse().unwrap()],
                nat: NatMode::Masquerade,
            },
        )
    }

    #[test]
    fn planner_is_deterministic_and_refuses_unowned_table_collisions() {
        let (interface, policy) = fixture();
        let observation = FirewallObservation {
            forwarding_enabled: false,
            ipv6_forwarding_enabled: None,
            table: TableObservation {
                present: false,
                owned: false,
                legacy_marker: false,
                rule_markers: BTreeSet::new(),
                chain_count: 0,
                rule_count: 0,
                chain_names: BTreeSet::new(),
                chains: BTreeMap::new(),
                rules: BTreeMap::new(),
            },
        };
        let first = plan_firewall(&owner(), &interface, Some(&policy), &observation).unwrap();
        assert_eq!(
            first.summary.actions,
            vec![
                FirewallActionKind::EnableIpv4Forwarding,
                FirewallActionKind::ReplaceOwnedNftablesTable
            ]
        );
        assert_eq!(
            first.summary.warnings,
            vec![FirewallWarning::IndependentFirewallMayStillBlockForwardedTraffic]
        );
        let collision = FirewallObservation {
            forwarding_enabled: false,
            ipv6_forwarding_enabled: None,
            table: TableObservation {
                present: true,
                owned: false,
                legacy_marker: false,
                rule_markers: BTreeSet::new(),
                chain_count: 0,
                rule_count: 0,
                chain_names: BTreeSet::new(),
                chains: BTreeMap::new(),
                rules: BTreeMap::new(),
            },
        };
        assert_eq!(
            plan_firewall(&owner(), &interface, Some(&policy), &collision),
            Err(FirewallError::TableOwnershipConflict)
        );
    }

    #[test]
    fn repeated_desired_policy_is_a_noop_and_disable_preserves_forwarding() {
        let (interface, policy) = fixture();
        let hash = policy_hash(&policy, &interface);
        let (chains, rules) = expected_objects(&owner(), &policy, &interface, &hash);
        let observation = FirewallObservation {
            forwarding_enabled: true,
            ipv6_forwarding_enabled: None,
            table: TableObservation {
                present: true,
                owned: true,
                legacy_marker: false,
                rule_markers: policy.rule_markers(&owner(), &hash, &interface),
                chain_count: 2,
                rule_count: 4,
                chain_names: BTreeSet::from(["forward".to_owned(), "postrouting".to_owned()]),
                chains,
                rules,
            },
        };
        assert!(
            plan_firewall(&owner(), &interface, Some(&policy), &observation)
                .unwrap()
                .summary
                .actions
                .is_empty()
        );
        let hash = policy_hash(&policy, &interface);
        let (chains, rules) = expected_objects(&owner(), &policy, &interface, &hash);
        let mut applied = observation.clone();
        applied.table = TableObservation {
            present: true,
            owned: true,
            legacy_marker: false,
            rule_markers: policy.rule_markers(&owner(), &hash, &interface),
            chain_count: chains.len(),
            rule_count: rules.len(),
            chain_names: chains.keys().cloned().collect(),
            chains,
            rules,
        };
        assert_eq!(
            plan_firewall(&owner(), &interface, None, &applied)
                .unwrap()
                .summary
                .actions,
            vec![FirewallActionKind::RemoveOwnedNftablesTable]
        );
    }

    #[test]
    fn owned_expression_drift_plans_replacement_even_if_markers_remain() {
        let (interface, policy) = fixture();
        let hash = policy_hash(&policy, &interface);
        let (chains, mut rules) = expected_objects(&owner(), &policy, &interface, &hash);
        rules
            .get_mut(&format!("{}:rule:allow:0:{hash}", owner()))
            .unwrap()["expr"][0]["match"]["right"] = serde_json::json!("wg-other");
        let observation = FirewallObservation {
            forwarding_enabled: true,
            ipv6_forwarding_enabled: None,
            table: TableObservation {
                present: true,
                owned: true,
                legacy_marker: false,
                rule_markers: policy.rule_markers(&owner(), &hash, &interface),
                chain_count: 2,
                rule_count: 4,
                chain_names: BTreeSet::from(["forward".to_owned(), "postrouting".to_owned()]),
                chains,
                rules,
            },
        };
        assert_eq!(
            plan_firewall(&owner(), &interface, Some(&policy), &observation)
                .unwrap()
                .summary
                .actions,
            vec![FirewallActionKind::ReplaceOwnedNftablesTable]
        );
    }

    #[test]
    fn ipv6_policy_enables_forwarding_and_renders_routed_v6_without_nat66() {
        let (interface, mut policy) = fixture();
        policy.ipv6_forwarding = Ipv6Forwarding::Required;
        policy
            .source_prefixes
            .push("2001:db8:42::/64".parse().unwrap());
        let observation = FirewallObservation {
            forwarding_enabled: true,
            ipv6_forwarding_enabled: Some(false),
            table: TableObservation {
                present: false,
                owned: false,
                legacy_marker: false,
                rule_markers: BTreeSet::new(),
                chain_count: 0,
                rule_count: 0,
                chain_names: BTreeSet::new(),
                chains: BTreeMap::new(),
                rules: BTreeMap::new(),
            },
        };
        let plan = plan_firewall(&owner(), &interface, Some(&policy), &observation).unwrap();
        assert_eq!(
            plan.summary.actions,
            vec![
                FirewallActionKind::EnableIpv6Forwarding,
                FirewallActionKind::ReplaceOwnedNftablesTable
            ]
        );
        assert!(plan
            .summary
            .warnings
            .contains(&FirewallWarning::Ipv6ForwardingIsHostGlobalAndRemainsEnabled));
        let (_, rules) = expected_objects(
            &owner(),
            &policy,
            &interface,
            plan.desired_hash.as_deref().unwrap(),
        );
        let allow_v6 = rules
            .values()
            .find(|rule| rule.to_string().contains("ip6"))
            .expect("IPv6 allow rule is rendered");
        assert!(allow_v6.to_string().contains("2001:db8:42::"));
        let nat_rules = rules
            .values()
            .filter(|rule| rule.to_string().contains("masquerade"))
            .collect::<Vec<_>>();
        assert_eq!(nat_rules.len(), 1);
        assert!(!nat_rules[0].to_string().contains("ip6"));
        let (chains, rules) = expected_objects(
            &owner(),
            &policy,
            &interface,
            plan.desired_hash.as_deref().unwrap(),
        );
        let mut applied = observation.clone();
        applied.table = TableObservation {
            present: true,
            owned: true,
            legacy_marker: false,
            rule_markers: policy.rule_markers(
                &owner(),
                plan.desired_hash.as_deref().unwrap(),
                &interface,
            ),
            chain_count: chains.len(),
            rule_count: rules.len(),
            chain_names: chains.keys().cloned().collect(),
            chains,
            rules,
        };
        assert_eq!(
            plan_firewall(&owner(), &interface, None, &applied)
                .unwrap()
                .summary
                .actions,
            vec![FirewallActionKind::RemoveOwnedNftablesTable]
        );
    }
}
