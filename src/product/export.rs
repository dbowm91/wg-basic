//! Secret-bearing WireGuard client artifact rendering.
//!
//! The renderer is pure: it accepts validated typed state and emits one
//! deterministic standard configuration. It has no hook, comment, or arbitrary
//! extension field, and neither the secret wrapper nor its debug form reveals
//! the rendered credential.

use crate::domain::{NetworkPrefix, PresharedKey, PrivateKey, PublicKey};
use std::{fmt, net::IpAddr};
use zeroize::Zeroize;

pub const MAX_CLIENT_CONFIG_BYTES: usize = 16 * 1024;
pub const MAX_QR_SVG_BYTES: usize = 256 * 1024;
const QUIET_ZONE: i32 = 4;

/// Validated material needed for one ordinary client configuration.
pub struct ClientConfigMaterial {
    pub private_key: PrivateKey,
    pub address: IpAddr,
    pub dns_servers: Vec<IpAddr>,
    pub server_public_key: PublicKey,
    pub preshared_key: Option<PresharedKey>,
    pub endpoint: String,
    pub allowed_ips: Vec<NetworkPrefix>,
    pub keepalive_seconds: Option<u16>,
}

/// A rendered secret artifact. Formatting never reveals it; dropping it wipes
/// the owned UTF-8 allocation.
pub struct SecretArtifact(String);

impl SecretArtifact {
    fn new(mut value: String, max_bytes: usize) -> Result<Self, ArtifactError> {
        if value.len() > max_bytes {
            value.zeroize();
            return Err(ArtifactError::TooLarge);
        }
        Ok(Self(value))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn into_bytes(mut self) -> Vec<u8> {
        let bytes = self.0.as_bytes().to_vec();
        self.0.zeroize();
        bytes
    }
}
impl Drop for SecretArtifact {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl fmt::Debug for SecretArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretArtifact([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ArtifactError {
    #[error("client private key is not available")]
    PrivateKeyUnavailable,
    #[error("client artifact exceeds its size bound")]
    TooLarge,
    #[error("QR encoding could not represent this artifact")]
    QrEncodingFailed,
    #[error("client has no allowed routes to export")]
    NoAllowedRoutes,
}

/// Renders one deterministic, standard WireGuard configuration.
pub fn render_config(material: &ClientConfigMaterial) -> Result<SecretArtifact, ArtifactError> {
    if material.allowed_ips.is_empty() {
        return Err(ArtifactError::NoAllowedRoutes);
    }
    let mut output = String::with_capacity(512);
    use std::fmt::Write as _;
    writeln!(&mut output, "[Interface]").unwrap();
    writeln!(
        &mut output,
        "PrivateKey = {}",
        material.private_key.expose_secret()
    )
    .unwrap();
    writeln!(
        &mut output,
        "Address = {}/{}",
        material.address,
        if material.address.is_ipv4() { 32 } else { 128 }
    )
    .unwrap();
    if !material.dns_servers.is_empty() {
        let dns = material
            .dns_servers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(&mut output, "DNS = {dns}").unwrap();
    }
    output.push('\n');
    writeln!(&mut output, "[Peer]").unwrap();
    writeln!(
        &mut output,
        "PublicKey = {}",
        material.server_public_key.expose()
    )
    .unwrap();
    if let Some(key) = &material.preshared_key {
        writeln!(&mut output, "PresharedKey = {}", key.expose_secret()).unwrap();
    }
    writeln!(&mut output, "Endpoint = {}", material.endpoint).unwrap();
    let mut routes = material
        .allowed_ips
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    routes.sort();
    writeln!(&mut output, "AllowedIPs = {}", routes.join(", ")).unwrap();
    if let Some(keepalive) = material.keepalive_seconds {
        writeln!(&mut output, "PersistentKeepalive = {keepalive}").unwrap();
    }
    SecretArtifact::new(output, MAX_CLIENT_CONFIG_BYTES)
}

/// Encodes config text as a fixed-vocabulary SVG QR image with a four-module
/// quiet zone. Coordinates are integers and configuration text is never copied
/// into the SVG as visible text.
pub fn render_qr_svg(config: &str) -> Result<SecretArtifact, ArtifactError> {
    use qrcodegen::{QrCode, QrCodeEcc};
    let qr = QrCode::encode_text(config, QrCodeEcc::Medium)
        .map_err(|_| ArtifactError::QrEncodingFailed)?;
    let size = qr.size();
    let dimension = size + 2 * QUIET_ZONE;
    let mut path = String::new();
    use std::fmt::Write as _;
    for y in 0..size {
        for x in 0..size {
            if qr.get_module(x, y) {
                write!(&mut path, "M{} {}h1v1h-1z", x + QUIET_ZONE, y + QUIET_ZONE).unwrap();
            }
        }
    }
    let svg = format!("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {dimension} {dimension}\" role=\"img\" aria-label=\"WireGuard configuration QR code\"><rect width=\"100%\" height=\"100%\" fill=\"white\"/><path d=\"{path}\" fill=\"black\"/></svg>");
    if svg.len() > MAX_QR_SVG_BYTES {
        return Err(ArtifactError::TooLarge);
    }
    SecretArtifact::new(svg, MAX_QR_SVG_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{NetworkPrefix, PresharedKey, PrivateKey, PublicKey};
    use std::net::{IpAddr, Ipv4Addr};

    fn fixture() -> ClientConfigMaterial {
        ClientConfigMaterial {
            private_key: PrivateKey::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into())
                .unwrap(),
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dns_servers: vec!["1.1.1.1".parse().unwrap()],
            server_public_key: PublicKey::new(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            )
            .unwrap(),
            preshared_key: None,
            endpoint: "vpn.example.test:51820".into(),
            allowed_ips: vec!["0.0.0.0/0".parse::<NetworkPrefix>().unwrap()],
            keepalive_seconds: Some(25),
        }
    }
    #[test]
    fn renders_exact_stable_config_and_redacts_debug() {
        let material = fixture();
        let first = render_config(&material).unwrap();
        let second = render_config(&material).unwrap();
        assert_eq!(first.expose(), second.expose());
        assert_eq!(first.expose(), "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n");
        assert!(!format!("{first:?}").contains("AAAAAAAA"));
    }
    #[test]
    fn qr_svg_has_only_fixed_elements_and_integer_coordinates() {
        let config = render_config(&fixture()).unwrap();
        let svg = render_qr_svg(config.expose()).unwrap();
        assert!(svg
            .expose()
            .starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\""));
        assert!(svg.expose().contains("<path d=\"M"));
        assert!(!svg.expose().contains("PrivateKey"));
        assert!(!svg.expose().contains("script"));
        assert!(svg.expose().len() <= MAX_QR_SVG_BYTES);
    }

    #[test]
    fn config_without_a_route_policy_is_not_exported_as_invalid_wireguard_syntax() {
        let mut material = fixture();
        material.allowed_ips.clear();
        assert_eq!(
            render_config(&material).unwrap_err(),
            ArtifactError::NoAllowedRoutes
        );
    }

    #[test]
    fn configured_preshared_key_is_written_only_in_the_peer_section() {
        let mut material = fixture();
        material.preshared_key =
            Some(PresharedKey::new("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBE=".into()).unwrap());
        let config = render_config(&material).unwrap();
        assert!(config.expose().contains("[Peer]\nPublicKey = "));
        assert!(config
            .expose()
            .contains("PresharedKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBE=\n"));
        let (interface, peer) = config.expose().split_once("[Peer]\n").unwrap();
        assert!(!interface.contains("PresharedKey = "));
        assert!(peer.contains("PresharedKey = "));
    }

    #[test]
    fn qr_rejects_input_that_exceeds_the_encoder_bound() {
        assert_eq!(
            render_qr_svg(&"x".repeat(MAX_CLIENT_CONFIG_BYTES + 1)).unwrap_err(),
            ArtifactError::QrEncodingFailed
        );
    }
}
