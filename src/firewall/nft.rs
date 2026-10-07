//! The only process, filesystem, and rendering boundary in this subsystem.
//!
//! `nft` is executed directly with internally rendered batch input, bounded by a
//! version floor, input/output caps, and a timeout. No shell is involved and no
//! caller-authored nft source is accepted.

use super::planner::{FirewallObservation, TableObservation};
use super::policy::{DesiredNetworkPolicy, FirewallError, NatMode, TABLE_NAME, TABLE_OWNER};
use crate::domain::InterfaceName;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Maximum bytes of internally rendered nft batch input.
pub(crate) const MAX_NFT_INPUT: usize = 32 * 1024;
/// Maximum bytes read from each nft output stream.
pub(crate) const MAX_NFT_OUTPUT: usize = 256 * 1024;
/// Wall-clock bound for a single nft invocation.
pub(crate) const NFT_TIMEOUT: Duration = Duration::from_secs(5);
/// Minimum supported nft userspace version.
pub(crate) const MIN_NFT_VERSION: (u32, u32, u32) = (0, 9, 0);

pub(crate) fn observe_firewall() -> Result<FirewallObservation, FirewallError> {
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
                chains: BTreeMap::new(),
                rules: BTreeMap::new(),
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
                chains: BTreeMap::new(),
                rules: BTreeMap::new(),
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
    let mut chains = BTreeMap::new();
    let mut rules = BTreeMap::new();
    if let Some(objects) = json.get("nftables").and_then(serde_json::Value::as_array) {
        for object in objects {
            if let Some(chain) = object.get("chain") {
                chain_count += 1;
                let mut observed = chain.clone();
                if let Some(observed) = observed.as_object_mut() {
                    observed.remove("handle");
                }
                let name = chain
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("__unmarked_chain_{chain_count}"));
                if !name.starts_with("__unmarked_chain_") {
                    chain_names.insert(name.clone());
                }
                if let Some(comment) = chain.get("comment").and_then(serde_json::Value::as_str) {
                    markers.insert(comment.to_owned());
                }
                chains.insert(name, observed);
            }
            if let Some(rule) = object.get("rule") {
                rule_count += 1;
                let mut observed = rule.clone();
                if let Some(observed) = observed.as_object_mut() {
                    observed.remove("handle");
                }
                let comment = rule
                    .get("comment")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("__unmarked_rule_{rule_count}"));
                if let Some(comment) = rule.get("comment").and_then(serde_json::Value::as_str) {
                    markers.insert(comment.to_owned());
                }
                rules.insert(comment, observed);
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
            chains,
            rules,
        },
    })
}

pub(crate) fn set_ipv4_forwarding(enabled: bool) -> Result<(), FirewallError> {
    fs::write(
        "/proc/sys/net/ipv4/ip_forward",
        if enabled { "1" } else { "0" },
    )
    .map_err(map_io_error)
}

pub(crate) fn replace_table(
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

pub(crate) fn remove_table() -> Result<(), FirewallError> {
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
    fn backend_output_and_error_details_are_bounded_and_redacted() {
        assert_eq!(
            read_limited(&mut std::io::Cursor::new(b"oversized"), 4),
            Err(FirewallError::ResourceLimitExceeded)
        );
        assert_eq!(
            map_io_error(std::io::Error::from(std::io::ErrorKind::NotFound)),
            FirewallError::Unsupported
        );
        assert_eq!(
            FirewallError::BackendFailure.to_string(),
            "nftables or forwarding backend failed"
        );
    }
}
