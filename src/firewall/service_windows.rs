//! One WinNAT, IPv4 forwarding under the restore rule, and one scoped UDP filter.
//!
//! A NetNAT this installation does not own is a refusal. Nothing here deletes
//! that object. `table_changed` stays false: there is no nftables table.

use super::policy::{
    DesiredNetworkPolicy, FirewallApplyReceipt, FirewallError, FirewallPlanSummary, Ipv4Forwarding,
    NatMode,
};
use crate::domain::{InstallationId, InterfaceName, NetworkPolicyMode};
use crate::platform::windows::{self, DefaultRoute, ForwardingRecord, NatDecision, ObservedNat};
use crate::reconcile::ApplyStatus;
use std::path::Path;

#[derive(Debug, Default)]
pub struct FirewallService {
    _private: (),
}

#[derive(serde::Serialize, serde::Deserialize)]
struct GatewayReceipt {
    nat_name: String,
    filter_name: Option<String>,
    previous_enabled: bool,
    changed_by_us: bool,
}

impl FirewallService {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn plan(
        &self,
        _installation_id: InstallationId,
        wireguard_interface: &InterfaceName,
        policy: Option<&DesiredNetworkPolicy>,
    ) -> Result<FirewallPlanSummary, FirewallError> {
        if let Some(policy) = policy {
            policy.validate(wireguard_interface)?;
            if policy.mode == NetworkPolicyMode::RoutedLan {
                return Err(FirewallError::Unsupported);
            }
        }
        let actions = match policy {
            Some(policy) if gateway(policy) => {
                vec![super::policy::FirewallActionKind::EnableIpv4Forwarding]
            }
            _ => Vec::new(),
        };
        Ok(FirewallPlanSummary {
            wireguard_interface: wireguard_interface.clone(),
            actions,
            warnings: Vec::new(),
            required_filter_rules: Vec::new(),
            routed_lan: None,
            gateway: None,
            observed_ipv4_forwarding: None,
            observed_ipv6_forwarding: None,
        })
    }

    pub fn apply(
        &self,
        installation_id: InstallationId,
        wireguard_interface: &InterfaceName,
        policy: Option<&DesiredNetworkPolicy>,
    ) -> Result<FirewallApplyReceipt, FirewallError> {
        if let Some(policy) = policy {
            policy.validate(wireguard_interface)?;
        }
        match policy {
            None => self.teardown(wireguard_interface),
            Some(policy) if policy.mode == NetworkPolicyMode::RoutedLan => {
                Err(FirewallError::Unsupported)
            }
            Some(policy) if gateway(policy) => {
                self.apply_gateway(installation_id, wireguard_interface, policy)
            }
            Some(_) => Ok(unchanged(wireguard_interface)),
        }
    }

    fn apply_gateway(
        &self,
        installation_id: InstallationId,
        interface: &InterfaceName,
        policy: &DesiredNetworkPolicy,
    ) -> Result<FirewallApplyReceipt, FirewallError> {
        let prefix = ipv4_prefix(policy).ok_or(FirewallError::InvalidPolicy)?;
        let _egress = egress(interface)?;
        let owned = windows::owned_nat_name(installation_id);
        let existing =
            wg_basic_win32_sys::list_nats().map_err(|_| FirewallError::BackendFailure)?;
        let observed: Vec<ObservedNat> = existing
            .into_iter()
            .map(|nat| ObservedNat {
                name: nat.name,
                internal_prefix: nat.internal_prefix,
            })
            .collect();
        let decision = windows::decide_nat(&observed, &owned, &prefix);
        let previous = wg_basic_win32_sys::ipv4_forwarding_enabled()
            .map_err(|_| FirewallError::BackendFailure)?;
        let record = match read_receipt() {
            Some(receipt) => ForwardingRecord {
                previous_enabled: receipt.previous_enabled,
                changed_by_us: receipt.changed_by_us,
            },
            None => windows::forwarding_on_apply(previous),
        };
        if !previous {
            wg_basic_win32_sys::set_ipv4_forwarding(true)
                .map_err(|_| FirewallError::BackendFailure)?;
        }
        let _created = match decision {
            NatDecision::Refuse { .. } => return Err(FirewallError::ForeignNetNat),
            NatDecision::Adopt { .. } => false,
            NatDecision::Create { name, prefix } => {
                wg_basic_win32_sys::create_nat(&name, &prefix)
                    .map_err(|_| FirewallError::BackendFailure)?;
                true
            }
        };
        let filter_name = listen_filter(installation_id, interface)?;
        if let Some(name) = &filter_name {
            wg_basic_win32_sys::install_filter(name, listen_port(interface)?)
                .map_err(|_| FirewallError::BackendFailure)?;
        }
        write_receipt(&GatewayReceipt {
            nat_name: owned,
            filter_name,
            previous_enabled: record.previous_enabled,
            changed_by_us: record.changed_by_us,
        })?;
        Ok(FirewallApplyReceipt {
            wireguard_interface: interface.clone(),
            status: ApplyStatus::Applied,
            actions: vec![super::policy::FirewallActionKind::EnableIpv4Forwarding],
            forwarding_changed: record.changed_by_us && !previous,
            table_changed: false,
            failure: None,
            warnings: Vec::new(),
        })
    }

    fn teardown(&self, interface: &InterfaceName) -> Result<FirewallApplyReceipt, FirewallError> {
        let Some(receipt) = read_receipt() else {
            return Ok(unchanged(interface));
        };
        if let Some(filter) = &receipt.filter_name {
            let _ = wg_basic_win32_sys::delete_filter(filter);
        }
        let _ = wg_basic_win32_sys::delete_nat(&receipt.nat_name);
        let live = wg_basic_win32_sys::ipv4_forwarding_enabled().unwrap_or(true);
        let restore = windows::forwarding_restore(
            ForwardingRecord {
                previous_enabled: receipt.previous_enabled,
                changed_by_us: receipt.changed_by_us,
            },
            live,
        );
        if let Some(value) = restore {
            wg_basic_win32_sys::set_ipv4_forwarding(value)
                .map_err(|_| FirewallError::BackendFailure)?;
        }
        let _ = std::fs::remove_file(receipt_path());
        Ok(FirewallApplyReceipt {
            wireguard_interface: interface.clone(),
            status: ApplyStatus::Applied,
            actions: Vec::new(),
            forwarding_changed: restore.is_some(),
            table_changed: false,
            failure: None,
            warnings: Vec::new(),
        })
    }
}

fn gateway(policy: &DesiredNetworkPolicy) -> bool {
    policy.mode == NetworkPolicyMode::Gateway
        && policy.nat == NatMode::Masquerade
        && policy.ipv4_forwarding == Ipv4Forwarding::Required
}

fn unchanged(interface: &InterfaceName) -> FirewallApplyReceipt {
    FirewallApplyReceipt {
        wireguard_interface: interface.clone(),
        status: ApplyStatus::NoChange,
        actions: Vec::new(),
        forwarding_changed: false,
        table_changed: false,
        failure: None,
        warnings: Vec::new(),
    }
}

fn ipv4_prefix(policy: &DesiredNetworkPolicy) -> Option<String> {
    let prefixes: Vec<_> = policy
        .source_prefixes
        .iter()
        .filter(|prefix| prefix.network().addr().is_ipv4())
        .map(|prefix| prefix.network().to_string())
        .collect();
    match prefixes.as_slice() {
        [only] => Some(only.clone()),
        _ => None,
    }
}

fn egress(interface: &InterfaceName) -> Result<u64, FirewallError> {
    let tunnel = crate::wireguard::windows::luid(interface).ok();
    let routes = wg_basic_win32_sys::default_route_luids()
        .map_err(|_| FirewallError::BackendFailure)?
        .into_iter()
        .map(|luid| DefaultRoute {
            interface_luid: luid,
            is_tunnel: tunnel == Some(luid),
        })
        .collect::<Vec<_>>();
    windows::select_egress(&routes).map_err(|_| FirewallError::BackendFailure)
}

fn listen_port(interface: &InterfaceName) -> Result<u16, FirewallError> {
    let device = crate::wireguard::windows::observe_device(interface)
        .map_err(|_| FirewallError::BackendFailure)?;
    device.listen_port.ok_or(FirewallError::BackendFailure)
}

fn listen_filter(
    installation: InstallationId,
    interface: &InterfaceName,
) -> Result<Option<String>, FirewallError> {
    let port = listen_port(interface)?;
    Ok(Some(format!("wg-basic-{installation}-udp-{port}")))
}

fn receipt_path() -> std::path::PathBuf {
    Path::new(windows::RUNTIME_DIR).join("gateway.json")
}

fn read_receipt() -> Option<GatewayReceipt> {
    let bytes = std::fs::read(receipt_path()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_receipt(receipt: &GatewayReceipt) -> Result<(), FirewallError> {
    let directory = Path::new(windows::RUNTIME_DIR);
    std::fs::create_dir_all(directory).map_err(|_| FirewallError::BackendFailure)?;
    let _ = wg_basic_win32_sys::restrict_to_current_user(directory);
    let path = receipt_path();
    std::fs::write(
        &path,
        serde_json::to_vec(receipt).map_err(|_| FirewallError::BackendFailure)?,
    )
    .map_err(|_| FirewallError::BackendFailure)?;
    wg_basic_win32_sys::restrict_to_current_user(&path)
        .map_err(|_| FirewallError::BackendFailure)?;
    Ok(())
}
