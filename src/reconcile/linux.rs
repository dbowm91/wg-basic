use super::{
    Mutation, ObservedLinkKind, ObservedManagedInterface, ObservedRoute, ReconcileBackend,
    ReconcileError,
};
use crate::{domain::InterfaceName, wireguard::WireGuardBackend};
use futures_util::TryStreamExt;
use ipnet::IpNet;
use rtnetlink::{
    new_connection,
    packet_route::{
        address::AddressAttribute,
        link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo},
        route::{RouteAddress, RouteAttribute, RouteMessage, RouteType},
        AddressFamily,
    },
    AddressMessageBuilder, LinkUnspec, LinkWireguard, RouteMessageBuilder,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAX_OBSERVED_ADDRESSES: usize = 4096;
const MAX_OBSERVED_ROUTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxNetworkBackend {
    wireguard: WireGuardBackend,
}

impl ReconcileBackend for LinuxNetworkBackend {
    fn observe(
        &self,
        interface: &InterfaceName,
    ) -> Result<ObservedManagedInterface, ReconcileError> {
        let runtime = backend_runtime()?;
        let mut observed = runtime.block_on(async {
            let (connection, handle, _) =
                new_connection().map_err(|_| ReconcileError::BackendFailure)?;
            let _connection = tokio::spawn(connection);

            let mut links = handle.link().get().match_name(interface.as_str()).execute();
            let link = links.try_next().await.map_err(|error| {
                eprintln!("link observation failed: {error:?}");
                ReconcileError::BackendFailure
            })?;
            let Some(link) = link else {
                return Ok(ObservedManagedInterface {
                    interface: interface.clone(),
                    ifindex: None,
                    link_kind: None,
                    admin_up: None,
                    addresses: Vec::new(),
                    routes: Vec::new(),
                    unsupported_route_count: 0,
                    wireguard: None,
                });
            };

            let ifindex = link.header.index;
            let is_wireguard = link.attributes.iter().any(|attribute| match attribute {
                LinkAttribute::LinkInfo(infos) => infos
                    .iter()
                    .any(|info| matches!(info, LinkInfo::Kind(InfoKind::Wireguard))),
                _ => false,
            });
            let mut addresses = Vec::new();
            let mut address_stream = handle
                .address()
                .get()
                .set_link_index_filter(ifindex)
                .execute();
            while let Some(message) = address_stream.try_next().await.map_err(|error| {
                eprintln!("address observation failed: {error:?}");
                ReconcileError::BackendFailure
            })? {
                if let Some(address) = address_from_message(&message) {
                    if !addresses.contains(&address) {
                        addresses.push(address);
                        if addresses.len() > MAX_OBSERVED_ADDRESSES {
                            return Err(ReconcileError::ResourceLimitExceeded);
                        }
                    }
                }
            }
            addresses.sort_by_key(ToString::to_string);

            let mut routes = Vec::new();
            let mut unsupported_route_count = 0;
            let mut route_stream = handle.route().get(RouteMessage::default()).execute();
            while let Some(message) = route_stream.try_next().await.map_err(|error| {
                eprintln!("route observation failed: {error:?}");
                ReconcileError::BackendFailure
            })? {
                if route_output_interface(&message) != Some(ifindex) {
                    continue;
                }
                if message.header.kind != RouteType::Unicast || route_table(&message) != 254 {
                    unsupported_route_count += 1;
                    continue;
                }
                if let Some(route) = route_from_message(&message) {
                    routes.push(route);
                    if routes.len() > MAX_OBSERVED_ROUTES {
                        return Err(ReconcileError::ResourceLimitExceeded);
                    }
                } else {
                    unsupported_route_count += 1;
                }
            }
            routes.sort_by_key(|route| {
                (
                    route.destination.to_string(),
                    route.output_interface,
                    route.gateway,
                )
            });

            Ok(ObservedManagedInterface {
                interface: interface.clone(),
                ifindex: Some(ifindex),
                link_kind: Some(if is_wireguard {
                    ObservedLinkKind::WireGuard
                } else {
                    ObservedLinkKind::Other
                }),
                admin_up: Some(link.header.flags.contains(LinkFlags::Up)),
                addresses,
                routes,
                unsupported_route_count,
                wireguard: None,
            })
        })?;
        if observed.link_kind == Some(ObservedLinkKind::WireGuard) {
            observed.wireguard = Some(
                self.wireguard
                    .observe_device(interface)
                    .map_err(ReconcileError::WireGuard)?,
            );
        }
        Ok(observed)
    }

    fn apply(&self, interface: &InterfaceName, mutation: Mutation) -> Result<(), ReconcileError> {
        match mutation {
            Mutation::ConfigureWireGuard(patch) => self
                .wireguard
                .apply_patch(interface, patch)
                .map(|_| ())
                .map_err(ReconcileError::WireGuard),
            Mutation::CreateWireGuardLink => self.with_handle(|handle| async move {
                handle
                    .link()
                    .add(LinkWireguard::new(interface.as_str()).build())
                    .execute()
                    .await
                    .map_err(|_| ReconcileError::BackendFailure)
            }),
            Mutation::DeleteLink => self.with_handle(|handle| async move {
                let index = lookup_link_index(&handle, interface).await?;
                handle
                    .link()
                    .del(index)
                    .execute()
                    .await
                    .map_err(|_| ReconcileError::BackendFailure)
            }),
            Mutation::SetLinkUp(up) => self.with_handle(|handle| async move {
                let builder = LinkUnspec::new_with_name(interface.as_str());
                let message = if up {
                    builder.up().build()
                } else {
                    builder.down().build()
                };
                handle
                    .link()
                    .set(message)
                    .execute()
                    .await
                    .map_err(|_| ReconcileError::BackendFailure)
            }),
            Mutation::AddAddress(address) => self.with_handle(|handle| async move {
                let index = lookup_link_index(&handle, interface).await?;
                handle
                    .address()
                    .add(index, address.addr(), address.prefix_len())
                    .execute()
                    .await
                    .map_err(|_| ReconcileError::BackendFailure)
            }),
            Mutation::RemoveAddress(address) => self.with_handle(|handle| async move {
                let index = lookup_link_index(&handle, interface).await?;
                handle
                    .address()
                    .del(address_message(address, index))
                    .execute()
                    .await
                    .map_err(|_| ReconcileError::BackendFailure)
            }),
            Mutation::AddRoute(route) => self.with_handle(|handle| async move {
                let index = lookup_link_index(&handle, interface).await?;
                handle
                    .route()
                    .add(route_message(&route, index)?)
                    .execute()
                    .await
                    .map_err(|_| ReconcileError::BackendFailure)
            }),
            Mutation::RemoveRoute(route) => self.with_handle(|handle| async move {
                let index = lookup_link_index(&handle, interface).await?;
                handle
                    .route()
                    .del(route_message(&route, index)?)
                    .execute()
                    .await
                    .map_err(|_| ReconcileError::BackendFailure)
            }),
        }
    }
}

impl LinuxNetworkBackend {
    fn with_handle<T, F>(
        &self,
        operation: impl FnOnce(rtnetlink::Handle) -> F,
    ) -> Result<T, ReconcileError>
    where
        F: std::future::Future<Output = Result<T, ReconcileError>>,
    {
        let runtime = backend_runtime()?;
        runtime.block_on(async {
            let (connection, handle, _) =
                new_connection().map_err(|_| ReconcileError::BackendFailure)?;
            let _connection = tokio::spawn(connection);
            operation(handle).await
        })
    }
}

fn backend_runtime() -> Result<tokio::runtime::Runtime, ReconcileError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ReconcileError::BackendFailure)
}

async fn lookup_link_index(
    handle: &rtnetlink::Handle,
    interface: &InterfaceName,
) -> Result<u32, ReconcileError> {
    let mut links = handle.link().get().match_name(interface.as_str()).execute();
    let link = links
        .try_next()
        .await
        .map_err(|_| ReconcileError::BackendFailure)?
        .ok_or(ReconcileError::BackendFailure)?;
    Ok(link.header.index)
}

fn address_from_message(
    message: &rtnetlink::packet_route::address::AddressMessage,
) -> Option<IpNet> {
    let address = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            AddressAttribute::Local(address) => Some(*address),
            _ => None,
        })
        .or_else(|| {
            message
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    AddressAttribute::Address(address) => Some(*address),
                    _ => None,
                })
        })?;
    IpNet::new(address, message.header.prefix_len).ok()
}

fn address_message(address: IpNet, index: u32) -> rtnetlink::packet_route::address::AddressMessage {
    let prefix_len = address.prefix_len();
    match address.addr() {
        IpAddr::V4(address) => AddressMessageBuilder::<Ipv4Addr>::new()
            .index(index)
            .address(address, prefix_len)
            .build(),
        IpAddr::V6(address) => AddressMessageBuilder::<Ipv6Addr>::new()
            .index(index)
            .address(address, prefix_len)
            .build(),
    }
}

fn route_from_message(message: &RouteMessage) -> Option<ObservedRoute> {
    let destination = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(address)) => Some(IpAddr::V4(*address)),
            RouteAttribute::Destination(RouteAddress::Inet6(address)) => Some(IpAddr::V6(*address)),
            _ => None,
        });
    let destination = match destination {
        Some(destination) => destination,
        None => match message.header.address_family {
            AddressFamily::Inet => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            AddressFamily::Inet6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            _ => return None,
        },
    };
    let destination = IpNet::new(destination, message.header.destination_prefix_length).ok()?;
    let gateway = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Gateway(RouteAddress::Inet(address)) => Some(IpAddr::V4(*address)),
            RouteAttribute::Gateway(RouteAddress::Inet6(address)) => Some(IpAddr::V6(*address)),
            _ => None,
        });
    let output_interface = route_output_interface(message);
    Some(ObservedRoute {
        destination: destination.to_string().parse().ok()?,
        gateway,
        output_interface,
    })
}

fn route_output_interface(message: &RouteMessage) -> Option<u32> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Oif(index) => Some(*index),
            _ => None,
        })
}

fn route_table(message: &RouteMessage) -> u32 {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(u32::from(message.header.table))
}

fn route_message(route: &ObservedRoute, ifindex: u32) -> Result<RouteMessage, ReconcileError> {
    let network = route.destination.network();
    let builder = RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(network.addr(), network.prefix_len())
        .map_err(|_| ReconcileError::InvalidDesiredState)?
        .output_interface(ifindex)
        .table_id(254)
        .kind(RouteType::Unicast);
    let builder = if let Some(gateway) = route.gateway {
        builder
            .gateway(gateway)
            .map_err(|_| ReconcileError::InvalidDesiredState)?
    } else {
        builder
    };
    Ok(builder.build())
}
