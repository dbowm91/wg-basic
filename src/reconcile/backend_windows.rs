//! IP Helper address and route reconciliation for one wireguard-nt adapter.
//!
//! Ownership is the adapter GUID derived from the installation and the
//! interface, plus the runtime receipt. A matching name with a different GUID
//! is left in place. Default routes are not tunnel routes.

use super::{
    Mutation, ObservedLinkKind, ObservedManagedInterface, ObservedRoute, ReconcileBackend,
    ReconcileError,
};
use crate::domain::{InterfaceName, NetworkPrefix, OwnerTag};
use crate::platform::windows::adapter_guid;
use crate::wireguard::windows as nt;
use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsNetworkBackend;

impl ReconcileBackend for WindowsNetworkBackend {
    fn observe(
        &self,
        interface: &InterfaceName,
        owner_tag: &OwnerTag,
    ) -> Result<ObservedManagedInterface, ReconcileError> {
        let guid = adapter_guid(owner_tag.installation_id(), owner_tag.interface_id());
        match nt::probe(interface, guid) {
            Ok(nt::Presence::Absent)
            | Err(crate::wireguard::WireGuardValidationError::UnsupportedBackend) => {
                return absent(interface);
            }
            Ok(nt::Presence::Foreign) => return Ok(unowned(interface)),
            Ok(nt::Presence::Owned) => {}
            Err(_) => return Err(ReconcileError::BackendFailure),
        }
        let luid = nt::luid(interface).map_err(map_wg)?;
        let index = luid_index(luid);
        let addresses = wg_basic_win32_sys::addresses_on(luid)
            .map_err(|_| ReconcileError::BackendFailure)?
            .into_iter()
            .filter_map(|address| IpNet::new(address.addr, address.prefix_len).ok())
            .collect();
        let routes = wg_basic_win32_sys::routes_on(luid)
            .map_err(|_| ReconcileError::BackendFailure)?
            .into_iter()
            .filter(|route| route.prefix_len != 0)
            .filter_map(|route| {
                let destination = IpNet::new(route.destination, route.prefix_len).ok()?;
                Some(ObservedRoute {
                    destination: NetworkPrefix::new(destination),
                    gateway: route.gateway,
                    output_interface: Some(index),
                })
            })
            .collect();
        let wireguard = nt::observe_device(interface).ok();
        let admin_up = nt::is_up(interface).ok();
        Ok(ObservedManagedInterface {
            interface: interface.clone(),
            ifindex: Some(index),
            link_kind: Some(ObservedLinkKind::WireGuard),
            admin_up,
            addresses,
            routes,
            unsupported_route_count: 0,
            interface_alias: Some(owner_tag.as_str()),
            duplicate_owner_tag: false,
            wireguard,
        })
    }

    fn apply(&self, interface: &InterfaceName, mutation: Mutation) -> Result<(), ReconcileError> {
        match mutation {
            Mutation::CreateWireGuardLink { owner_tag } => {
                let guid = adapter_guid(owner_tag.installation_id(), owner_tag.interface_id());
                nt::create_adapter(interface, guid).map_err(map_wg)
            }
            Mutation::DeleteLink => nt::delete_adapter(interface).map_err(map_wg),
            Mutation::SetLinkUp(up) => nt::set_up(interface, up).map_err(map_wg),
            Mutation::ConfigureWireGuard(patch) => crate::wireguard::WireGuardBackend::default()
                .apply_patch(interface, patch)
                .map(|_| ())
                .map_err(ReconcileError::WireGuard),
            Mutation::AddAddress(address) => {
                let luid = nt::luid(interface).map_err(map_wg)?;
                wg_basic_win32_sys::add_address(
                    luid,
                    &wg_basic_win32_sys::HostAddress {
                        addr: address.addr(),
                        prefix_len: address.prefix_len(),
                    },
                )
                .map_err(|_| ReconcileError::BackendFailure)
            }
            Mutation::RemoveAddress(address) => {
                let luid = nt::luid(interface).map_err(map_wg)?;
                wg_basic_win32_sys::delete_address(
                    luid,
                    &wg_basic_win32_sys::HostAddress {
                        addr: address.addr(),
                        prefix_len: address.prefix_len(),
                    },
                )
                .map_err(|_| ReconcileError::BackendFailure)
            }
            Mutation::AddRoute(route) => apply_route(interface, &route, true),
            Mutation::RemoveRoute(route) => apply_route(interface, &route, false),
        }
    }
}

fn apply_route(
    interface: &InterfaceName,
    route: &ObservedRoute,
    add: bool,
) -> Result<(), ReconcileError> {
    if route.destination.network().prefix_len() == 0 {
        return Err(ReconcileError::Conflict);
    }
    let luid = nt::luid(interface).map_err(map_wg)?;
    let host = wg_basic_win32_sys::HostRoute {
        destination: route.destination.network().addr(),
        prefix_len: route.destination.network().prefix_len(),
        gateway: route.gateway,
        luid,
        metric: 0,
    };
    let result = if add {
        wg_basic_win32_sys::add_route(&host)
    } else {
        wg_basic_win32_sys::delete_route(&host)
    };
    result.map_err(|_| ReconcileError::BackendFailure)
}

fn absent(interface: &InterfaceName) -> Result<ObservedManagedInterface, ReconcileError> {
    Ok(ObservedManagedInterface {
        interface: interface.clone(),
        ifindex: None,
        link_kind: None,
        admin_up: None,
        addresses: Vec::new(),
        routes: Vec::new(),
        unsupported_route_count: 0,
        interface_alias: None,
        duplicate_owner_tag: false,
        wireguard: None,
    })
}

fn unowned(interface: &InterfaceName) -> ObservedManagedInterface {
    ObservedManagedInterface {
        interface: interface.clone(),
        ifindex: None,
        link_kind: Some(ObservedLinkKind::Other),
        admin_up: None,
        addresses: Vec::new(),
        routes: Vec::new(),
        unsupported_route_count: 0,
        interface_alias: None,
        duplicate_owner_tag: false,
        wireguard: None,
    }
}

fn luid_index(luid: u64) -> u32 {
    let low = luid as u32;
    if low == 0 {
        1
    } else {
        low
    }
}

fn map_wg(error: crate::wireguard::WireGuardValidationError) -> ReconcileError {
    ReconcileError::WireGuard(error)
}

#[allow(dead_code)]
fn _gateway_type(gateway: Option<IpAddr>) -> Option<IpAddr> {
    gateway
}
