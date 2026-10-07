//! Typed, bounded Linux forwarding and nftables ownership for M005.

use crate::{
    domain::{InterfaceName, NetworkPrefix},
    reconcile::ApplyStatus,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    process::{Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

const TABLE_NAME: &str = "wg_basic";
const TABLE_OWNER: &str = "wg-basic:m005:v1";
const MAX_PREFIXES: usize = 64;
const MAX_NFT_INPUT: usize = 32 * 1024;
const MAX_NFT_OUTPUT: usize = 256 * 1024;
const NFT_TIMEOUT: Duration = Duration::from_secs(5);
const MIN_NFT_VERSION: (u32, u32, u32) = (0, 9, 0);

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

    fn sorted_prefixes(&self) -> Vec<&NetworkPrefix> {
        let mut prefixes = self.source_prefixes.iter().collect::<Vec<_>>();
        prefixes.sort_by_key(|prefix| prefix.to_string());
        prefixes
    }

    fn rule_markers(&self, hash: &str, wireguard_interface: &InterfaceName) -> BTreeSet<String> {
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct TableObservation {
    present: bool,
    owned: bool,
    rule_markers: BTreeSet<String>,
    chain_count: usize,
    rule_count: usize,
    chain_names: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FirewallObservation {
    forwarding_enabled: bool,
    table: TableObservation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FirewallPlan {
    summary: FirewallPlanSummary,
    desired_hash: Option<String>,
}

pub struct FirewallService {
    mutation_lock: Mutex<()>,
}

impl Default for FirewallService {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallService {
    pub fn new() -> Self {
        Self {
            mutation_lock: Mutex::new(()),
        }
    }

    pub fn plan(
        &self,
        wireguard_interface: &InterfaceName,
        policy: Option<&DesiredNetworkPolicy>,
    ) -> Result<FirewallPlanSummary, FirewallError> {
        if let Some(policy) = policy {
            policy.validate(wireguard_interface)?;
        }
        let observation = observe_firewall()?;
        Ok(plan_firewall(wireguard_interface, policy, &observation)?.summary)
    }

    pub fn apply(
        &self,
        wireguard_interface: &InterfaceName,
        policy: Option<&DesiredNetworkPolicy>,
    ) -> Result<FirewallApplyReceipt, FirewallError> {
        if let Some(policy) = policy {
            policy.validate(wireguard_interface)?;
        }
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| FirewallError::BackendFailure)?;
        let before = observe_firewall()?;
        let plan = plan_firewall(wireguard_interface, policy, &before)?;
        if plan.summary.actions.is_empty() {
            return Ok(FirewallApplyReceipt {
                wireguard_interface: wireguard_interface.clone(),
                status: ApplyStatus::NoChange,
                actions: Vec::new(),
                forwarding_changed: false,
                table_changed: false,
                failure: None,
                warnings: vec![FirewallWarning::IndependentFirewallMayStillBlockForwardedTraffic],
            });
        }
        let forwarding_changed = plan
            .summary
            .actions
            .contains(&FirewallActionKind::EnableIpv4Forwarding);
        if forwarding_changed {
            set_ipv4_forwarding(true)?;
        }
        let table_changed = plan.summary.actions.iter().any(|action| {
            matches!(
                action,
                FirewallActionKind::ReplaceOwnedNftablesTable
                    | FirewallActionKind::RemoveOwnedNftablesTable
            )
        });
        if table_changed {
            let result = match policy {
                Some(policy) => replace_table(
                    wireguard_interface,
                    policy,
                    plan.desired_hash.as_deref().unwrap_or(""),
                    before.table.present,
                    &before.table.chain_names,
                ),
                None => remove_table(),
            };
            if result.is_err() {
                return Ok(FirewallApplyReceipt {
                    wireguard_interface: wireguard_interface.clone(),
                    status: if forwarding_changed {
                        ApplyStatus::PartialFailure
                    } else {
                        ApplyStatus::FailedBeforeMutation
                    },
                    actions: plan.summary.actions,
                    forwarding_changed,
                    table_changed: false,
                    failure: Some(FirewallFailure::BackendFailure),
                    warnings: vec![
                        FirewallWarning::IndependentFirewallMayStillBlockForwardedTraffic,
                    ],
                });
            }
        }
        let after = observe_firewall()?;
        let verified = matches_policy(policy, wireguard_interface, &after)?;
        Ok(FirewallApplyReceipt {
            wireguard_interface: wireguard_interface.clone(),
            status: if verified {
                ApplyStatus::Applied
            } else {
                ApplyStatus::VerificationFailed
            },
            actions: plan.summary.actions,
            forwarding_changed,
            table_changed,
            failure: (!verified).then_some(FirewallFailure::BackendFailure),
            warnings: vec![FirewallWarning::IndependentFirewallMayStillBlockForwardedTraffic],
        })
    }
}

fn plan_firewall(
    wireguard_interface: &InterfaceName,
    policy: Option<&DesiredNetworkPolicy>,
    observation: &FirewallObservation,
) -> Result<FirewallPlan, FirewallError> {
    if observation.table.present && !observation.table.owned {
        return Err(FirewallError::TableOwnershipConflict);
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
        let desired_markers = policy.rule_markers(&hash, wireguard_interface);
        if policy.ipv4_forwarding == Ipv4Forwarding::Required && !observation.forwarding_enabled {
            actions.push(FirewallActionKind::EnableIpv4Forwarding);
        }
        let expected_chains = 1 + usize::from(policy.nat == NatMode::Masquerade);
        let expected_rules = 2
            + policy.source_prefixes.len()
            + if policy.nat == NatMode::Masquerade {
                policy.source_prefixes.len()
            } else {
                0
            };
        if !observation.table.present
            || observation.table.rule_markers != desired_markers
            || observation.table.chain_count != expected_chains
            || observation.table.rule_count != expected_rules
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
            warnings: vec![FirewallWarning::IndependentFirewallMayStillBlockForwardedTraffic],
        },
        desired_hash,
    })
}

fn matches_policy(
    policy: Option<&DesiredNetworkPolicy>,
    interface: &InterfaceName,
    observation: &FirewallObservation,
) -> Result<bool, FirewallError> {
    if let Some(policy) = policy {
        if (policy.ipv4_forwarding == Ipv4Forwarding::Required && !observation.forwarding_enabled)
            || !observation.table.present
            || !observation.table.owned
        {
            return Ok(false);
        }
        let hash = policy_hash(policy, interface);
        let expected_chains = 1 + usize::from(policy.nat == NatMode::Masquerade);
        let expected_rules = 2
            + policy.source_prefixes.len()
            + if policy.nat == NatMode::Masquerade {
                policy.source_prefixes.len()
            } else {
                0
            };
        Ok(
            observation.table.rule_markers == policy.rule_markers(&hash, interface)
                && observation.table.chain_count == expected_chains
                && observation.table.rule_count == expected_rules,
        )
    } else {
        Ok(!observation.table.present)
    }
}

fn policy_hash(policy: &DesiredNetworkPolicy, interface: &InterfaceName) -> String {
    let mut bytes = format!(
        "{}|{:?}|{:?}|",
        interface.as_str(),
        policy.ipv4_forwarding,
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

fn observe_firewall() -> Result<FirewallObservation, FirewallError> {
    let forwarding = fs::read_to_string("/proc/sys/net/ipv4/ip_forward").map_err(map_io_error)?;
    let forwarding_enabled = match forwarding.trim() {
        "0" => false,
        "1" => true,
        _ => return Err(FirewallError::BackendFailure),
    };
    let output = run_nft(&["-j", "list", "tables"], None)?;
    let json: serde_json::Value =
        serde_json::from_slice(&output).map_err(|_| FirewallError::BackendFailure)?;
    let tables = json
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or(FirewallError::BackendFailure)?;
    let found = tables.iter().find_map(|object| {
        let table = object.get("table")?;
        (table.get("family")?.as_str()? == "inet" && table.get("name")?.as_str()? == TABLE_NAME)
            .then_some(table)
    });
    let Some(table) = found else {
        return Ok(FirewallObservation {
            forwarding_enabled,
            table: TableObservation {
                present: false,
                owned: false,
                rule_markers: BTreeSet::new(),
                chain_count: 0,
                rule_count: 0,
                chain_names: BTreeSet::new(),
            },
        });
    };
    let owned = table.get("comment").and_then(serde_json::Value::as_str) == Some(TABLE_OWNER);
    if !owned {
        return Ok(FirewallObservation {
            forwarding_enabled,
            table: TableObservation {
                present: true,
                owned: false,
                rule_markers: BTreeSet::new(),
                chain_count: 0,
                rule_count: 0,
                chain_names: BTreeSet::new(),
            },
        });
    }
    let output = run_nft(&["-j", "list", "table", "inet", TABLE_NAME], None)?;
    let json: serde_json::Value =
        serde_json::from_slice(&output).map_err(|_| FirewallError::BackendFailure)?;
    let mut markers = BTreeSet::new();
    let mut chain_count = 0;
    let mut rule_count = 0;
    let mut chain_names = BTreeSet::new();
    if let Some(objects) = json.get("nftables").and_then(serde_json::Value::as_array) {
        for object in objects {
            if let Some(chain) = object.get("chain") {
                chain_count += 1;
                if let Some(name) = chain.get("name").and_then(serde_json::Value::as_str) {
                    chain_names.insert(name.to_owned());
                }
                if let Some(comment) = chain.get("comment").and_then(serde_json::Value::as_str) {
                    markers.insert(comment.to_owned());
                }
            }
            if let Some(rule) = object.get("rule") {
                rule_count += 1;
                if let Some(comment) = rule.get("comment").and_then(serde_json::Value::as_str) {
                    markers.insert(comment.to_owned());
                }
            }
        }
    }
    Ok(FirewallObservation {
        forwarding_enabled,
        table: TableObservation {
            present: true,
            owned: true,
            rule_markers: markers,
            chain_count,
            rule_count,
            chain_names,
        },
    })
}

fn set_ipv4_forwarding(enabled: bool) -> Result<(), FirewallError> {
    fs::write(
        "/proc/sys/net/ipv4/ip_forward",
        if enabled { "1" } else { "0" },
    )
    .map_err(map_io_error)
}

fn replace_table(
    wireguard_interface: &InterfaceName,
    policy: &DesiredNetworkPolicy,
    hash: &str,
    table_present: bool,
    existing_chains: &BTreeSet<String>,
) -> Result<(), FirewallError> {
    let wireguard_interface = nft_quoted(wireguard_interface.as_str());
    let egress_interface = nft_quoted(policy.egress_interface.as_str());
    let mut script = String::new();
    if table_present {
        script.push_str(&format!("flush table inet {TABLE_NAME}\n"));
        if existing_chains.contains("forward") {
            script.push_str(&format!("delete chain inet {TABLE_NAME} forward\n"));
        }
        if existing_chains.contains("postrouting") {
            script.push_str(&format!("delete chain inet {TABLE_NAME} postrouting\n"));
        }
    } else {
        script.push_str(&format!(
            r#"add table inet {TABLE_NAME} {{ comment "{TABLE_OWNER}"; }}"#
        ));
        script.push('\n');
    }
    script.push_str(&format!(r#"add chain inet {TABLE_NAME} forward {{ type filter hook forward priority filter; policy accept; comment "{TABLE_OWNER}:chain:forward:{hash}"; }}"#));
    script.push('\n');
    script.push_str(&format!(r#"add rule inet {TABLE_NAME} forward oifname "{wireguard_interface}" ct state established,related accept comment "{TABLE_OWNER}:rule:return:{hash}""#));
    script.push('\n');
    for (index, prefix) in policy.sorted_prefixes().iter().enumerate() {
        script.push_str(&format!(r#"add rule inet {TABLE_NAME} forward iifname "{wireguard_interface}" oifname "{egress_interface}" ip saddr {} accept comment "{TABLE_OWNER}:rule:allow:{index}:{hash}""#, prefix));
        script.push('\n');
    }
    script.push_str(&format!(r#"add rule inet {TABLE_NAME} forward iifname "{wireguard_interface}" drop comment "{TABLE_OWNER}:rule:drop:{hash}""#));
    script.push('\n');
    if policy.nat == NatMode::Masquerade {
        script.push_str(&format!(r#"add chain inet {TABLE_NAME} postrouting {{ type nat hook postrouting priority srcnat; comment "{TABLE_OWNER}:chain:postrouting:{hash}"; }}"#));
        script.push('\n');
        for (index, prefix) in policy.sorted_prefixes().iter().enumerate() {
            script.push_str(&format!(r#"add rule inet {TABLE_NAME} postrouting oifname "{egress_interface}" ip saddr {} masquerade comment "{TABLE_OWNER}:rule:nat:{index}:{hash}""#, prefix));
            script.push('\n');
        }
    }
    if script.len() > MAX_NFT_INPUT {
        return Err(FirewallError::ResourceLimitExceeded);
    }
    run_nft(&["-f", "-"], Some(script.as_bytes())).map(|_| ())
}

fn nft_quoted(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn remove_table() -> Result<(), FirewallError> {
    run_nft(&["delete", "table", "inet", TABLE_NAME], None).map(|_| ())
}

fn run_nft(args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>, FirewallError> {
    let version = run_nft_unchecked(&["--version"], None)?;
    if !nft_version_supported(&version) {
        return Err(FirewallError::Unsupported);
    }
    run_nft_unchecked(args, input)
}

fn nft_version_supported(output: &[u8]) -> bool {
    let Ok(output) = std::str::from_utf8(output) else {
        return false;
    };
    let Some(version) = output.split('v').nth(1) else {
        return false;
    };
    let mut parts = version
        .split(|character: char| !character.is_ascii_digit() && character != '.')
        .next()
        .unwrap_or_default()
        .split('.');
    let parsed = (
        parts.next().and_then(|part| part.parse::<u32>().ok()),
        parts.next().and_then(|part| part.parse::<u32>().ok()),
        parts.next().and_then(|part| part.parse::<u32>().ok()),
    );
    let (Some(major), Some(minor), Some(patch)) = parsed else {
        return false;
    };
    (major, minor, patch) >= MIN_NFT_VERSION
}

fn run_nft_unchecked(args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>, FirewallError> {
    if input.is_some_and(|input| input.len() > MAX_NFT_INPUT) {
        return Err(FirewallError::ResourceLimitExceeded);
    }
    let mut child = Command::new("nft")
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(map_io_error)?;
    if let Some(input) = input {
        if let Err(error) = child
            .stdin
            .take()
            .ok_or(FirewallError::BackendFailure)?
            .write_all(input)
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(map_io_error(error));
        }
    }
    let mut stdout = child.stdout.take().ok_or(FirewallError::BackendFailure)?;
    let mut stderr = child.stderr.take().ok_or(FirewallError::BackendFailure)?;
    let stdout_reader = thread::spawn(move || read_limited(&mut stdout, MAX_NFT_OUTPUT));
    let stderr_reader = thread::spawn(move || read_limited(&mut stderr, MAX_NFT_OUTPUT));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(map_io_error)? {
            break status;
        }
        if started.elapsed() >= NFT_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(FirewallError::BackendFailure);
        }
        thread::sleep(Duration::from_millis(10));
    };
    let output = stdout_reader
        .join()
        .map_err(|_| FirewallError::BackendFailure)??;
    let _ = stderr_reader
        .join()
        .map_err(|_| FirewallError::BackendFailure)??;
    if !status.success() {
        return Err(FirewallError::BackendFailure);
    }
    Ok(output)
}

fn read_limited(reader: &mut impl Read, limit: usize) -> Result<Vec<u8>, FirewallError> {
    let mut output = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut output)
        .map_err(|_| FirewallError::BackendFailure)?;
    if output.len() > limit {
        return Err(FirewallError::ResourceLimitExceeded);
    }
    Ok(output)
}

fn map_io_error(error: std::io::Error) -> FirewallError {
    match error.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::Unsupported => {
            FirewallError::Unsupported
        }
        std::io::ErrorKind::PermissionDenied => FirewallError::PermissionDenied,
        _ => FirewallError::BackendFailure,
    }
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

    #[test]
    fn nft_quoted_values_escape_string_delimiters() {
        assert_eq!(
            nft_quoted(r#"wan\"; flush ruleset"#),
            r#"wan\\\"; flush ruleset"#
        );
    }

    #[test]
    fn nft_version_gate_accepts_the_minimum_and_newer_versions() {
        assert!(!nft_version_supported(b"nftables v0.8.9 (Old Dog)"));
        assert!(nft_version_supported(b"nftables v0.9.0 (Old Dog)"));
        assert!(nft_version_supported(b"nftables v1.0.9 (Old Dog)"));
        assert!(!nft_version_supported(b"not an nft version"));
    }

    #[test]
    fn planner_is_deterministic_and_refuses_unowned_table_collisions() {
        let (interface, policy) = fixture();
        let observation = FirewallObservation {
            forwarding_enabled: false,
            table: TableObservation {
                present: false,
                owned: false,
                rule_markers: BTreeSet::new(),
                chain_count: 0,
                rule_count: 0,
                chain_names: BTreeSet::new(),
            },
        };
        let first = plan_firewall(&interface, Some(&policy), &observation).unwrap();
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
            table: TableObservation {
                present: true,
                owned: false,
                rule_markers: BTreeSet::new(),
                chain_count: 0,
                rule_count: 0,
                chain_names: BTreeSet::new(),
            },
        };
        assert_eq!(
            plan_firewall(&interface, Some(&policy), &collision),
            Err(FirewallError::TableOwnershipConflict)
        );
    }

    #[test]
    fn repeated_desired_policy_is_a_noop_and_disable_preserves_forwarding() {
        let (interface, policy) = fixture();
        let hash = policy_hash(&policy, &interface);
        let observation = FirewallObservation {
            forwarding_enabled: true,
            table: TableObservation {
                present: true,
                owned: true,
                rule_markers: policy.rule_markers(&hash, &interface),
                chain_count: 2,
                rule_count: 4,
                chain_names: BTreeSet::from(["forward".to_owned(), "postrouting".to_owned()]),
            },
        };
        assert!(plan_firewall(&interface, Some(&policy), &observation)
            .unwrap()
            .summary
            .actions
            .is_empty());
        assert_eq!(
            plan_firewall(&interface, None, &observation)
                .unwrap()
                .summary
                .actions,
            vec![FirewallActionKind::RemoveOwnedNftablesTable]
        );
    }
}
