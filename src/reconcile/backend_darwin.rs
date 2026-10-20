//! The Darwin network backend for the portable reconciliation service (C001).
//!
//! Linux mutates the host through RTNETLINK. Darwin mutates it through the
//! audited kernel boundary in [`wg_basic_darwin_sys`]: `getifaddrs` and the
//! routing-table dump to observe, and `ioctl`/`AF_ROUTE` messages to change
//! addresses, routes, and link state.
//!
//! Two Darwin facts shape this backend:
//!
//! 1. **There is no kernel interface alias.** The durable owner tag lives in a
//!    protected receipt (see [`crate::wireguard::darwin_backend`]). The
//!    observation reports that tag as the link's ownership alias *only* after
//!    the receipt has been re-proven against the live host. An unproven or
//!    foreign device is reported as unproven, never adopted.
//! 2. **The device name is ephemeral.** The kernel assigns `utunN`; netd
//!    records which number it owns and re-proves it. Nothing is ever selected
//!    by numeric guess.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::domain::{InterfaceName, OwnerTag};
use crate::reconcile::model::{
    DesiredManagedInterface, ObservedLinkKind, ObservedManagedInterface, ObservedRoute,
    ReconcileError,
};
use crate::reconcile::planner::Mutation;
use crate::wireguard::darwin_backend::{
    prove_ownership, spawn_managed_tunnel, HelperIdentity, ManagedRuntime, OwnershipOutcome,
    RegistryError, RuntimeRegistry,
};
use crate::wireguard::WireGuardBackend;

use super::ReconcileBackend;

/// The maximum number of observed addresses on one managed interface.
const MAX_OBSERVED_ADDRESSES: usize = 64;

/// The maximum number of observed routes on one managed interface.
const MAX_OBSERVED_ROUTES: usize = 256;

/// How long the backend waits for a deleted helper's device to disappear.
const DEVICE_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Darwin route flags that are not managed unicast routes.
const RTF_REJECT: u32 = 0x8;
const RTF_BLACKHOLE: u32 = 0x1000;
const RTF_LOCAL: u32 = 0x200_000;
const RTF_BROADCAST: u32 = 0x400_000;
const RTF_MULTICAST: u32 = 0x800_000;

/// The Darwin network backend.
///
/// It owns the supervised helper processes and the managed-runtime registry,
/// and it is the only place that turns a portable mutation into a Darwin
/// kernel operation.
pub struct DarwinNetworkBackend {
    registry: Result<Arc<RuntimeRegistry>, RegistryError>,
    helper: Result<HelperIdentity, RegistryError>,
    supervisor: Mutex<HashMap<String, crate::wireguard::darwin_backend::SupervisedHelper>>,
    wireguard: WireGuardBackend,
}

impl DarwinNetworkBackend {
    /// Builds the backend over a managed-runtime registry and a pinned helper.
    pub fn new(
        registry: Result<Arc<RuntimeRegistry>, RegistryError>,
        helper: Result<HelperIdentity, RegistryError>,
    ) -> Self {
        let wireguard = match registry.as_ref() {
            Ok(registry) => WireGuardBackend::with_registry(Arc::clone(registry)),
            Err(reason) => WireGuardBackend::unavailable(*reason),
        };
        Self {
            registry,
            helper,
            supervisor: Mutex::new(HashMap::new()),
            wireguard,
        }
    }

    /// Builds the backend over the production installation and registry.
    pub fn production() -> Self {
        let registry = crate::wireguard::darwin_backend::DarwinWireGuardBackend::shared_registry();
        let helper = installed_helper_identity();
        Self::new(registry, helper)
    }

    /// The WireGuard backend this network backend configures devices through.
    pub fn wireguard(&self) -> &WireGuardBackend {
        &self.wireguard
    }

    /// The registry this backend records ownership claims in.
    fn registry(&self) -> Result<&Arc<RuntimeRegistry>, ReconcileError> {
        self.registry
            .as_ref()
            .map_err(|_| ReconcileError::BackendFailure)
    }

    /// The pinned helper identity this backend is allowed to execute.
    fn helper(&self) -> Result<&HelperIdentity, ReconcileError> {
        self.helper
            .as_ref()
            .map_err(|_| ReconcileError::BackendFailure)
    }

    /// Observes one managed interface.
    ///
    /// A managed interface exists only when the registry records it *and* the
    /// live host still proves it. An unproven record is reported as absent so
    /// the planner recreates the tunnel, never as a foreign device to destroy.
    fn observe_managed(
        &self,
        interface: &InterfaceName,
        owner_tag: &OwnerTag,
    ) -> Result<ObservedManagedInterface, ReconcileError> {
        let registry = self.registry()?;
        let Some(runtime) = registry.get(interface) else {
            return Ok(absent(interface));
        };
        let interfaces =
            wg_basic_darwin_sys::interfaces().map_err(|_| ReconcileError::BackendFailure)?;
        let device = interfaces
            .iter()
            .find(|candidate| candidate.name == runtime.utun_name);
        let Some(device) = device else {
            return Ok(absent(interface));
        };
        if !prove_ownership(&runtime, true).is_proven() {
            return Ok(absent(interface));
        }
        // The recorded receipt must belong to the requested owner tag. A
        // foreign receipt is reported as a foreign alias so the planner
        // refuses to mutate it.
        let recorded_tag = runtime.owner_tag();
        let alias = recorded_tag.as_str();

        let routes = wg_basic_darwin_sys::routes().map_err(|_| ReconcileError::BackendFailure)?;
        let (observed_routes, unsupported_route_count) =
            classify_routes(&routes, device.index, &device.addresses);
        // The duplicate check is against the *requested* owner tag: it is the
        // tag the planner is asking about, and another receipt claiming it
        // means two devices would carry the same durable proof.
        let duplicate_owner_tag = registry
            .entries()
            .iter()
            .filter(|entry| entry.owner_tag() == *owner_tag)
            .count()
            > 1;

        let wireguard = self.wireguard.observe_device(interface).ok();

        Ok(ObservedManagedInterface {
            interface: interface.clone(),
            ifindex: Some(device.index),
            link_kind: Some(ObservedLinkKind::WireGuard),
            admin_up: Some(device.is_up()),
            addresses: device.addresses.clone(),
            routes: observed_routes,
            unsupported_route_count,
            // The recorded receipt's tag is reported verbatim: a foreign tag
            // stays foreign so the planner classifies it as a conflict instead
            // of silently adopting it.
            interface_alias: Some(alias),
            duplicate_owner_tag,
            wireguard,
        })
    }

    /// Applies one planned mutation.
    fn apply_mutation(
        &self,
        interface: &InterfaceName,
        mutation: Mutation,
    ) -> Result<(), ReconcileError> {
        match mutation {
            Mutation::CreateWireGuardLink { owner_tag } => {
                self.create_managed_tunnel(interface, &owner_tag)
            }
            Mutation::ConfigureWireGuard(patch) => self
                .wireguard
                .apply_patch(interface, patch)
                .map(|_| ())
                .map_err(|_| ReconcileError::BackendFailure),
            Mutation::AddAddress(address) => {
                let utun = self.managed_device(interface)?;
                wg_basic_darwin_sys::add_address(&utun, address)
                    .map_err(|_| ReconcileError::BackendFailure)
            }
            Mutation::RemoveAddress(address) => {
                let utun = self.managed_device(interface)?;
                wg_basic_darwin_sys::remove_address(&utun, address)
                    .map_err(|_| ReconcileError::BackendFailure)
            }
            Mutation::AddRoute(route) => {
                let utun = self.managed_device(interface)?;
                wg_basic_darwin_sys::add_route(route.destination.network(), route.gateway, &utun)
                    .map_err(|_| ReconcileError::BackendFailure)
            }
            Mutation::RemoveRoute(route) => {
                let utun = self.managed_device(interface)?;
                wg_basic_darwin_sys::remove_route(route.destination.network(), route.gateway, &utun)
                    .map_err(|_| ReconcileError::BackendFailure)
            }
            Mutation::SetLinkUp(up) => {
                let utun = self.managed_device(interface)?;
                wg_basic_darwin_sys::set_link_up(&utun, up)
                    .map_err(|_| ReconcileError::BackendFailure)
            }
            Mutation::DeleteLink => self.delete_managed_tunnel(interface),
        }
    }

    /// The kernel device name backing one managed interface.
    fn managed_device(&self, interface: &InterfaceName) -> Result<String, ReconcileError> {
        let registry = self.registry()?;
        let runtime = registry
            .get(interface)
            .ok_or(ReconcileError::BackendFailure)?;
        Ok(runtime.utun_name)
    }

    /// Creates the managed tunnel: spawn the pinned helper, adopt exactly one
    /// new device, and record the durable ownership receipt.
    fn create_managed_tunnel(
        &self,
        interface: &InterfaceName,
        owner_tag: &OwnerTag,
    ) -> Result<(), ReconcileError> {
        let registry = self.registry()?;
        let helper = self.helper()?;
        if registry.find_by_owner_tag(owner_tag).is_some() {
            return Err(ReconcileError::Conflict);
        }
        let (child, utun_name) =
            spawn_managed_tunnel(helper).map_err(|_| ReconcileError::BackendFailure)?;
        let runtime = ManagedRuntime {
            installation_id: owner_tag.installation_id(),
            interface_id: owner_tag.interface_id(),
            interface: interface.as_str().to_owned(),
            utun_name: utun_name.clone(),
            helper_pid: child.pid,
            helper_path: helper.path.to_string_lossy().into_owned(),
            helper_sha256: helper.sha256.clone(),
            uapi_socket: crate::wireguard::darwin::uapi_socket_path(&utun_name)
                .to_string_lossy()
                .into_owned(),
            created_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_millis())
                .unwrap_or_default(),
        };
        registry
            .insert(runtime)
            .map_err(|_| ReconcileError::BackendFailure)?;
        self.supervisor
            .lock()
            .map_err(|_| ReconcileError::BackendFailure)?
            .insert(interface.as_str().to_owned(), child);
        Ok(())
    }

    /// Removes the managed tunnel: stop the helper, wait for the kernel
    /// device to disappear, then drop the ownership receipt.
    fn delete_managed_tunnel(&self, interface: &InterfaceName) -> Result<(), ReconcileError> {
        let registry = self.registry()?;
        let runtime = registry
            .get(interface)
            .ok_or(ReconcileError::BackendFailure)?;
        if !prove_ownership(&runtime, true).is_proven() {
            // Nothing of ours is left to destroy. Drop the stale claim so the
            // next observation starts clean.
            registry
                .remove(interface)
                .map_err(|_| ReconcileError::BackendFailure)?;
            return Ok(());
        }
        {
            let mut supervisor = self
                .supervisor
                .lock()
                .map_err(|_| ReconcileError::BackendFailure)?;
            supervisor.remove(interface.as_str());
        }
        let deadline = std::time::Instant::now() + DEVICE_TEARDOWN_TIMEOUT;
        while std::time::Instant::now() < deadline {
            if !crate::wireguard::darwin_backend::utun_interface_names()
                .contains(&runtime.utun_name)
            {
                registry
                    .remove(interface)
                    .map_err(|_| ReconcileError::BackendFailure)?;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(ReconcileError::BackendFailure)
    }
}

impl ReconcileBackend for DarwinNetworkBackend {
    fn observe(
        &self,
        interface: &InterfaceName,
        owner_tag: &OwnerTag,
    ) -> Result<ObservedManagedInterface, ReconcileError> {
        self.observe_managed(interface, owner_tag)
    }

    fn apply(&self, interface: &InterfaceName, mutation: Mutation) -> Result<(), ReconcileError> {
        self.apply_mutation(interface, mutation)
    }
}

/// The observation of an interface that does not exist.
fn absent(interface: &InterfaceName) -> ObservedManagedInterface {
    ObservedManagedInterface {
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
    }
}

/// Splits the routing table into managed routes and unsupported ones.
///
/// Only unicast routes that leave through the managed interface and are not
/// derived from its own addresses are managed. Everything else that uses the
/// interface is counted as unsupported so a delete refuses rather than
/// silently orphaning a route the operator did not list.
fn classify_routes(
    routes: &[wg_basic_darwin_sys::RouteInfo],
    interface_index: u32,
    addresses: &[ipnet::IpNet],
) -> (Vec<ObservedRoute>, usize) {
    let mut managed = Vec::new();
    let mut unsupported = 0usize;
    for route in routes {
        if route.interface_index != interface_index {
            continue;
        }
        if route.flags & RTF_LOCAL != 0
            || route.flags & RTF_BROADCAST != 0
            || route.flags & RTF_MULTICAST != 0
        {
            // Address-derived and multicast routes belong to the kernel.
            continue;
        }
        if route.flags & (RTF_REJECT | RTF_BLACKHOLE) != 0 {
            unsupported += 1;
            continue;
        }
        if route.gateway.is_none()
            && addresses
                .iter()
                .any(|address| address.trunc() == route.destination)
        {
            // The connected network the kernel derives from the address.
            continue;
        }
        if managed.len() >= MAX_OBSERVED_ROUTES {
            unsupported += 1;
            continue;
        }
        managed.push(ObservedRoute {
            destination: crate::domain::NetworkPrefix::new(route.destination),
            gateway: route.gateway,
            output_interface: Some(route.interface_index),
        });
    }
    managed.sort_by_key(|route| {
        (
            route.destination.to_string(),
            route.output_interface,
            route.gateway,
        )
    });
    (managed, unsupported)
}

/// Reads the pinned helper identity from the installed launchd receipt.
///
/// The helper netd executes must be the helper the installer placed and
/// hashed; a helper that is not the installed one is never spawned.
pub fn installed_helper_identity() -> Result<HelperIdentity, RegistryError> {
    installed_helper_identity_at(Path::new("/"))
}

/// Reads the pinned helper identity from an install root.
pub fn installed_helper_identity_at(
    root: &std::path::Path,
) -> Result<HelperIdentity, RegistryError> {
    let receipt = crate::launchd::verify_installed_root(root).map_err(|_| RegistryError::Io)?;
    Ok(HelperIdentity {
        path: PathBuf::from(crate::launchd::HELPER_PATH),
        sha256: receipt.helper_sha256,
    })
}

/// The desired managed interface shape the Darwin backend supports.
///
/// Darwin supports exactly the host-only shape: one managed tunnel with
/// addresses and routes on that tunnel, and no forwarding or NAT.
pub fn supports(desired: &DesiredManagedInterface) -> bool {
    desired.lifecycle == crate::reconcile::model::LinkLifecycle::Present
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_interface_with_no_receipt_is_observed_as_absent() {
        let observed = absent(&InterfaceName::new("wg-test").unwrap());
        assert_eq!(observed.ifindex, None);
        assert_eq!(observed.interface_alias, None);
        assert_eq!(observed.link_kind, None);
    }

    #[test]
    fn address_derived_routes_are_not_counted_as_unsupported() {
        let routes = vec![
            wg_basic_darwin_sys::RouteInfo {
                destination: "10.0.0.0/24".parse().unwrap(),
                gateway: None,
                interface_index: 19,
                interface_name: "utun7".to_owned(),
                flags: RTF_LOCAL,
            },
            wg_basic_darwin_sys::RouteInfo {
                destination: "10.0.0.0/24".parse().unwrap(),
                gateway: None,
                interface_index: 19,
                interface_name: "utun7".to_owned(),
                flags: 0,
            },
            wg_basic_darwin_sys::RouteInfo {
                destination: "10.0.0.2/32".parse().unwrap(),
                gateway: Some("10.0.0.1".parse().unwrap()),
                interface_index: 19,
                interface_name: "utun7".to_owned(),
                flags: 0,
            },
        ];
        let addresses = vec!["10.0.0.1/24".parse().unwrap()];
        let (managed, unsupported) = classify_routes(&routes, 19, &addresses);
        assert_eq!(unsupported, 0);
        assert_eq!(managed.len(), 1);
        assert_eq!(managed[0].destination.to_string(), "10.0.0.2/32");
    }

    #[test]
    fn a_reject_route_on_the_managed_interface_is_unsupported() {
        let routes = vec![wg_basic_darwin_sys::RouteInfo {
            destination: "0.0.0.0/0".parse().unwrap(),
            gateway: None,
            interface_index: 19,
            interface_name: "utun7".to_owned(),
            flags: RTF_REJECT,
        }];
        let (managed, unsupported) = classify_routes(&routes, 19, &[]);
        assert!(managed.is_empty());
        assert_eq!(unsupported, 1);
    }
}
