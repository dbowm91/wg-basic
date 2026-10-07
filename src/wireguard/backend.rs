use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use nl_wireguard::{
    new_connection, WireguardHandle, WireguardParsed, WireguardParsedPeerFlags, WireguardPeerParsed,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};
use zeroize::Zeroize;

const MAX_OBSERVED_PEERS: usize = 4096;

#[derive(Clone, Copy, Debug, Default)]
pub struct WireGuardBackend;

impl WireGuardBackend {
    pub fn observe_device(
        &self,
        interface: &InterfaceName,
    ) -> Result<ObservedWireGuardDevice, WireGuardValidationError> {
        let runtime = backend_runtime()?;
        runtime.block_on(async {
            let (connection, mut handle, _) = new_connection().map_err(classify_io_error)?;
            let _connection = tokio::spawn(connection);
            let mut parsed = get_device(&mut handle, interface).await?;
            let observed = convert_observed(interface.clone(), &parsed);
            zeroize_kernel_secrets(&mut parsed);
            observed
        })
    }

    pub fn apply_patch(
        &self,
        interface: &InterfaceName,
        patch: WireGuardDevicePatch,
    ) -> Result<WireGuardApplyReceipt, WireGuardValidationError> {
        validate_device_patch(&patch)?;
        let runtime = backend_runtime()?;
        runtime.block_on(async {
            let (connection, mut handle, _) = new_connection().map_err(classify_io_error)?;
            let _connection = tokio::spawn(connection);
            let mut observed = get_device(&mut handle, interface).await?;
            let mut no_change = false;
            let config = match build_patch(interface, patch, &observed, &mut no_change) {
                Ok(config) => config,
                Err(error) => {
                    zeroize_kernel_secrets(&mut observed);
                    return Err(error);
                }
            };
            if !no_change {
                if let Err(error) = handle.set(config).await {
                    zeroize_kernel_secrets(&mut observed);
                    return Err(classify_netlink_error(error));
                }
            }
            zeroize_kernel_secrets(&mut observed);
            Ok(WireGuardApplyReceipt {
                interface: interface.clone(),
                disposition: if no_change {
                    ApplyDisposition::NoChange
                } else {
                    ApplyDisposition::Applied
                },
            })
        })
    }
}

fn backend_runtime() -> Result<tokio::runtime::Runtime, WireGuardValidationError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| WireGuardValidationError::BackendFailure)
}

async fn get_device(
    handle: &mut WireguardHandle,
    interface: &InterfaceName,
) -> Result<WireguardParsed, WireGuardValidationError> {
    handle
        .get_by_name(interface.as_str())
        .await
        .map_err(classify_netlink_error)
}

fn classify_io_error(error: std::io::Error) -> WireGuardValidationError {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => WireGuardValidationError::PermissionDenied,
        std::io::ErrorKind::Unsupported => WireGuardValidationError::UnsupportedBackend,
        _ => WireGuardValidationError::BackendFailure,
    }
}

fn classify_netlink_error(error: nl_wireguard::WireguardError) -> WireGuardValidationError {
    match error.kind {
        nl_wireguard::ErrorKind::InvalidKey => WireGuardValidationError::InvalidKey,
        nl_wireguard::ErrorKind::InvalidInput => WireGuardValidationError::InvalidBackendInput,
        nl_wireguard::ErrorKind::NetlinkError => {
            let message = error.msg.to_ascii_lowercase();
            if message.contains("operation not permitted") || message.contains("permission denied")
            {
                WireGuardValidationError::PermissionDenied
            } else if message.contains("operation not supported")
                || message.contains("protocol not supported")
            {
                WireGuardValidationError::UnsupportedBackend
            } else if message.contains("no such device") || message.contains("device not found") {
                WireGuardValidationError::InterfaceUnavailable
            } else {
                WireGuardValidationError::KernelRejected
            }
        }
        _ => WireGuardValidationError::BackendFailure,
    }
}

fn convert_observed(
    interface: InterfaceName,
    parsed: &WireguardParsed,
) -> Result<ObservedWireGuardDevice, WireGuardValidationError> {
    let peers = parsed.peers.as_deref().unwrap_or_default();
    if peers.len() > MAX_OBSERVED_PEERS {
        return Err(WireGuardValidationError::BackendFailure);
    }
    let mut observed_peers = Vec::with_capacity(peers.len());
    for peer in peers {
        let Some(key) = &peer.public_key else {
            continue;
        };
        let public_key =
            PublicKey::new(key.clone()).map_err(|_| WireGuardValidationError::BackendFailure)?;
        let allowed_ips = peer
            .allowed_ips
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|ip| {
                let network = match ip.ip_addr {
                    IpAddr::V4(addr) => format!("{addr}/{}", ip.prefix_length),
                    IpAddr::V6(addr) => format!("{addr}/{}", ip.prefix_length),
                };
                NetworkPrefix::from_str(&network)
                    .map_err(|_| WireGuardValidationError::BackendFailure)
            })
            .collect::<Result<Vec<_>, _>>()?;
        observed_peers.push(ObservedWireGuardPeer {
            public_key,
            allowed_ips,
            persistent_keepalive_seconds: peer.persistent_keepalive.filter(|seconds| *seconds != 0),
            endpoint: peer
                .endpoint
                .filter(|endpoint| !(endpoint.ip().is_unspecified() && endpoint.port() == 0)),
            latest_handshake: peer.last_handshake,
            rx_bytes: peer.rx_bytes,
            tx_bytes: peer.tx_bytes,
        });
    }
    Ok(ObservedWireGuardDevice {
        interface,
        public_key: parsed
            .public_key
            .as_ref()
            .and_then(|key| PublicKey::new(key.clone()).ok()),
        listen_port: parsed.listen_port,
        peers: observed_peers,
    })
}

fn build_patch(
    interface: &InterfaceName,
    patch: WireGuardDevicePatch,
    observed: &WireguardParsed,
    no_change: &mut bool,
) -> Result<WireguardParsed, WireGuardValidationError> {
    let mut config = WireguardParsed::default();
    config.iface_name = Some(interface.as_str().to_owned());
    match patch.private_key {
        FieldUpdate::Keep => {}
        FieldUpdate::Clear => config.private_key = Some(STANDARD.encode([0_u8; 32])),
        FieldUpdate::Set(key) => config.private_key = Some(key.expose_secret().to_owned()),
    }
    match patch.listen_port {
        FieldUpdate::Keep => {}
        FieldUpdate::Clear => config.listen_port = Some(0),
        FieldUpdate::Set(port) => config.listen_port = Some(port),
    }
    if let Some(peer_mutation) = patch.peer {
        match peer_mutation {
            PeerMutation::Add(peer) => {
                if peer_exists(observed, peer.public_key.expose()) {
                    return Err(WireGuardValidationError::PeerAlreadyExists);
                }
                validate_new_peer_prefixes(observed, peer.public_key.expose(), &peer.allowed_ips)?;
                config.peers = Some(vec![make_peer(peer)?]);
            }
            PeerMutation::Update(peer) => {
                if !peer_exists(observed, peer.public_key.expose()) {
                    return Err(WireGuardValidationError::PeerNotFound);
                }
                if let FieldUpdate::Set(prefixes) = &peer.allowed_ips {
                    validate_new_peer_prefixes(observed, peer.public_key.expose(), prefixes)?;
                }
                config.peers = Some(vec![update_peer(peer)?]);
            }
            PeerMutation::Remove { public_key } => {
                if !peer_exists(observed, public_key.expose()) {
                    *no_change = config.private_key.is_none() && config.listen_port.is_none();
                } else {
                    config.peers = Some(vec![WireguardPeerParsed::remove(public_key.expose())]);
                }
            }
        }
    }
    if *no_change && (config.private_key.is_some() || config.listen_port.is_some()) {
        return Err(WireGuardValidationError::EmptyPatch);
    }
    Ok(config)
}

fn make_peer(peer: DesiredWireGuardPeer) -> Result<WireguardPeerParsed, WireGuardValidationError> {
    let mut parsed = WireguardPeerParsed::default();
    parsed.public_key = Some(peer.public_key.expose().to_owned());
    parsed.preshared_key = peer.preshared_key.map(|key| key.expose_secret().to_owned());
    parsed.allowed_ips = Some(to_kernel_allowed_ips(&peer.allowed_ips)?);
    parsed.persistent_keepalive = peer.persistent_keepalive_seconds;
    parsed.endpoint = peer.endpoint;
    parsed.flags = Some(vec![WireguardParsedPeerFlags::ReplaceAllowedIps]);
    Ok(parsed)
}

fn update_peer(peer: WireGuardPeerPatch) -> Result<WireguardPeerParsed, WireGuardValidationError> {
    let mut parsed = WireguardPeerParsed::default();
    parsed.public_key = Some(peer.public_key.expose().to_owned());
    match peer.preshared_key {
        FieldUpdate::Keep => {}
        FieldUpdate::Clear => parsed.preshared_key = Some(STANDARD.encode([0_u8; 32])),
        FieldUpdate::Set(key) => parsed.preshared_key = Some(key.expose_secret().to_owned()),
    }
    match peer.allowed_ips {
        FieldUpdate::Keep => {}
        FieldUpdate::Clear => {
            parsed.allowed_ips = Some(Vec::new());
            parsed.flags = Some(vec![WireguardParsedPeerFlags::ReplaceAllowedIps]);
        }
        FieldUpdate::Set(prefixes) => {
            parsed.allowed_ips = Some(to_kernel_allowed_ips(&prefixes)?);
            parsed.flags = Some(vec![WireguardParsedPeerFlags::ReplaceAllowedIps]);
        }
    }
    match peer.persistent_keepalive_seconds {
        FieldUpdate::Keep => {}
        FieldUpdate::Clear => parsed.persistent_keepalive = Some(0),
        FieldUpdate::Set(seconds) => parsed.persistent_keepalive = Some(seconds),
    }
    match peer.endpoint {
        FieldUpdate::Keep => {}
        FieldUpdate::Clear => {
            parsed.endpoint = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
        FieldUpdate::Set(endpoint) => parsed.endpoint = Some(endpoint),
    }
    Ok(parsed)
}

fn to_kernel_allowed_ips(
    prefixes: &[NetworkPrefix],
) -> Result<Vec<nl_wireguard::WireguardIpAddress>, WireGuardValidationError> {
    validate_allowed_ips(prefixes)?;
    prefixes
        .iter()
        .map(|prefix| {
            let network = prefix.network();
            Ok(nl_wireguard::WireguardIpAddress {
                ip_addr: network.addr(),
                prefix_length: network.prefix_len(),
                flags: None,
            })
        })
        .collect()
}

fn peer_exists(device: &WireguardParsed, key: &str) -> bool {
    device
        .peers
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|peer| peer.public_key.as_deref() == Some(key))
}

fn validate_new_peer_prefixes(
    device: &WireguardParsed,
    key: &str,
    prefixes: &[NetworkPrefix],
) -> Result<(), WireGuardValidationError> {
    validate_allowed_ips(prefixes)?;
    for existing in device.peers.as_deref().unwrap_or_default() {
        if existing.public_key.as_deref() == Some(key) {
            continue;
        }
        for current in existing.allowed_ips.as_deref().unwrap_or_default() {
            let current = match current.ip_addr {
                IpAddr::V4(addr) => format!("{addr}/{}", current.prefix_length),
                IpAddr::V6(addr) => format!("{addr}/{}", current.prefix_length),
            }
            .parse::<NetworkPrefix>()
            .map_err(|_| WireGuardValidationError::BackendFailure)?;
            if prefixes
                .iter()
                .any(|prefix| prefixes_overlap(prefix, &current))
            {
                return Err(WireGuardValidationError::ConflictingAllowedIps);
            }
        }
    }
    Ok(())
}

fn zeroize_kernel_secrets(parsed: &mut WireguardParsed) {
    if let Some(private_key) = &mut parsed.private_key {
        private_key.zeroize();
    }
    for peer in parsed.peers.iter_mut().flatten() {
        if let Some(preshared_key) = &mut peer.preshared_key {
            preshared_key.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_device_conversion_omits_secrets_and_preserves_telemetry() {
        let mut peer = WireguardPeerParsed::default();
        peer.public_key = Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into());
        peer.preshared_key = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into());
        peer.allowed_ips = Some(vec![nl_wireguard::WireguardIpAddress {
            ip_addr: "10.8.0.2".parse().unwrap(),
            prefix_length: 32,
            flags: None,
        }]);
        peer.persistent_keepalive = Some(25);
        peer.endpoint = Some("192.0.2.1:51820".parse().unwrap());
        peer.last_handshake = Some(std::time::Duration::from_secs(5));
        peer.rx_bytes = Some(10);
        peer.tx_bytes = Some(20);
        let mut parsed = WireguardParsed::default();
        parsed.iface_name = Some("wg0".into());
        parsed.public_key = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into());
        parsed.private_key = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into());
        parsed.listen_port = Some(51820);
        parsed.peers = Some(vec![peer]);
        let observed = convert_observed("wg0".parse().unwrap(), &parsed).unwrap();
        let display = format!("{observed:?}");
        assert!(!display.contains("preshared_key"));
        assert!(display.contains("10"));
        assert_eq!(observed.peers[0].rx_bytes, Some(10));
    }

    #[test]
    fn observed_device_normalizes_disabled_keepalive_to_none() {
        let mut peer = WireguardPeerParsed::default();
        peer.public_key = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into());
        peer.persistent_keepalive = Some(0);
        peer.endpoint = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        let mut parsed = WireguardParsed::default();
        parsed.peers = Some(vec![peer]);
        let observed = convert_observed("wg0".parse().unwrap(), &parsed).unwrap();
        assert_eq!(observed.peers[0].persistent_keepalive_seconds, None);
        assert_eq!(observed.peers[0].endpoint, None);
    }
}
