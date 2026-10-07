use super::{
    Mutation, ObservedLinkKind, ObservedManagedInterface, ObservedRoute, ReconcileBackend,
    ReconcileError,
};
use crate::domain::OwnerTag;
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
/// Bound on the link enumeration used to prove owner-tag uniqueness.
const MAX_OBSERVED_LINKS: usize = 4_096;

#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxNetworkBackend {
    wireguard: WireGuardBackend,
}

impl ReconcileBackend for LinuxNetworkBackend {
    fn observe(
        &self,
        interface: &InterfaceName,
        owner_tag: &OwnerTag,
    ) -> Result<ObservedManagedInterface, ReconcileError> {
        let runtime = backend_runtime()?;
        let mut observed = runtime.block_on(async {
            let (connection, handle, _) =
                new_connection().map_err(|_| ReconcileError::BackendFailure)?;
            let _connection = tokio::spawn(connection);

            let mut links = handle.link().get().match_name(interface.as_str()).execute();
            let link = match links.try_next().await {
                Ok(link) => link,
                Err(error) if is_no_such_device(&error) => None,
                Err(_) => return Err(ReconcileError::BackendFailure),
            };
            let Some(link) = link else {
                return Ok(ObservedManagedInterface {
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
                });
            };

            let ifindex = link.header.index;
            let duplicate_owner_tag =
                duplicate_owner_tag_elsewhere(&handle, owner_tag, ifindex).await?;
            let interface_alias = link
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    LinkAttribute::IfAlias(alias) => Some(alias.clone()),
                    _ => None,
                });
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
            while let Some(message) = address_stream
                .try_next()
                .await
                .map_err(|_| ReconcileError::BackendFailure)?
            {
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
            while let Some(message) = route_stream
                .try_next()
                .await
                .map_err(|_| ReconcileError::BackendFailure)?
            {
                if route_output_interface(&message) != Some(ifindex) {
                    continue;
                }
                if route_table(&message) != 254 {
                    // The kernel creates local-table routes for assigned addresses;
                    // those are address-derived, not independently managed routes.
                    continue;
                }
                if message.header.kind != RouteType::Unicast {
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
            routes.retain(|route| {
                !(route.output_interface == Some(ifindex)
                    && route.gateway.is_none()
                    && addresses
                        .iter()
                        .any(|address| address.trunc() == route.destination.network()))
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
                interface_alias,
                duplicate_owner_tag,
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
            Mutation::CreateWireGuardLink { owner_tag } => {
                self.with_handle(|handle| async move {
                    // The kernel accepts IFLA_IFALIAS in RTM_NEWLINK but
                    // silently discards it, so a created link is tagged with an
                    // immediate follow-up RTM_SETLINK. Both calls belong to this
                    // one logical mutation.
                    //
                    // A crash between the two leaves an untagged link. That is
                    // deliberate: the planner treats an untagged same-name
                    // WireGuard link as a conflict rather than adopting it, so a
                    // partially created link requires operator cleanup instead
                    // of silent adoption.
                    handle
                        .link()
                        .add(LinkWireguard::new(interface.as_str()).build())
                        .execute()
                        .await
                        .map_err(|_| ReconcileError::BackendFailure)?;

                    let index = lookup_link_index(&handle, interface).await?;
                    let message = LinkUnspec::new_with_index(index)
                        .append_extra_attribute(LinkAttribute::IfAlias(owner_tag.as_str()))
                        .build();
                    handle
                        .link()
                        .set(message)
                        .execute()
                        .await
                        .map_err(|_| ReconcileError::BackendFailure)
                })
            }
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

/// Reports whether another link on this host carries the same owner tag.
///
/// Owner-tag uniqueness must be proven, but a duplicate is an operator problem
/// rather than something to resolve by guessing which interface is canonical.
/// The enumeration is bounded so a pathological host cannot make one apply
/// unbounded.
async fn duplicate_owner_tag_elsewhere(
    handle: &rtnetlink::Handle,
    owner_tag: &OwnerTag,
    exclude_index: u32,
) -> Result<bool, ReconcileError> {
    let expected = owner_tag.as_str();
    let mut links = handle.link().get().execute();
    let mut examined = 0usize;
    while let Some(link) = links
        .try_next()
        .await
        .map_err(|_| ReconcileError::BackendFailure)?
    {
        examined += 1;
        if examined > MAX_OBSERVED_LINKS {
            return Err(ReconcileError::ResourceLimitExceeded);
        }
        if link.header.index == exclude_index {
            continue;
        }
        if link.attributes.iter().any(
            |attribute| matches!(attribute, LinkAttribute::IfAlias(alias) if *alias == expected),
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn backend_runtime() -> Result<tokio::runtime::Runtime, ReconcileError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ReconcileError::BackendFailure)
}

fn is_no_such_device(error: &rtnetlink::Error) -> bool {
    matches!(error, rtnetlink::Error::NetlinkError(message)
        if message.to_io().raw_os_error() == Some(nix::libc::ENODEV))
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
