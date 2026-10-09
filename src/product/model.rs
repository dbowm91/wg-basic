//! The product application model.
//!
//! These types are the Phase 8 vocabulary. They exist so that no HTTP layer,
//! and no privileged worker, ever has to invent a product fact on the fly: a
//! label, an advertised endpoint, an enable bit, and a mutation receipt each
//! have exactly one representation, one validation rule, and one rendering.
//!
//! Two rules shape everything here.
//!
//! * **No secret is representable.** Nothing in this module can hold a private
//!   or preshared key. A summary built from these types is therefore secret-safe
//!   by construction rather than by remembering to redact a field.
//! * **Text is text.** A [`ClientLabel`] and an [`AdvertisedEndpoint`] host are
//!   bounded and character-checked so neither can become WireGuard config
//!   directive syntax. The failure mode being designed against is a value that
//!   round-trips through a config file and means something else on the way back.

use crate::domain::{
    ClientId, DesiredGeneration, InterfaceId, NetworkPrefix, PeerId, PrincipalId, PublicKey,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr, str::FromStr};
use uuid::Uuid;

/// Longest accepted advertised host, in bytes.
///
/// Comfortably below any DNS name limit and well below a config line's
/// practical width, so a rendered `Endpoint = host:port` stays a single
/// ordinary line.
pub const MAX_ADVERTISED_HOST_BYTES: usize = 253;

/// Longest accepted client label, in bytes.
///
/// Bounded on bytes rather than characters so the storage CHECK constraint and
/// this limit are the same number, and so a label of multi-byte text cannot
/// silently cost twice its apparent size.
pub const MAX_CLIENT_LABEL_BYTES: usize = 128;

/// The address and port a client is told to dial.
///
/// Deliberately not a [`std::net::SocketAddr`]: a server is routinely
/// published as a DNS name, and refusing that would push operators toward
/// rewriting their own hostname as a bare literal. A literal IPv4 or IPv6
/// address is equally valid and equally representable.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AdvertisedEndpoint {
    host: String,
    port: u16,
}

impl AdvertisedEndpoint {
    /// Validates a host/port pair as an advertised endpoint.
    ///
    /// Rejects, in order: an empty or over-long host, any ASCII control
    /// character or whitespace anywhere in the host, and any of the URI syntax
    /// that would change what a rendered endpoint means -- scheme separator,
    /// path, query, fragment, and userinfo. An IPv6 literal may appear in its
    /// conventional bracketed form or bare; it is stored bare and rendered
    /// bracketed exactly once.
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, AdvertisedEndpointError> {
        let host = host.into();
        if host.is_empty() {
            return Err(AdvertisedEndpointError::EmptyHost);
        }
        if host.len() > MAX_ADVERTISED_HOST_BYTES {
            return Err(AdvertisedEndpointError::HostTooLong);
        }
        if host
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(AdvertisedEndpointError::InvalidHostCharacter);
        }
        if host.contains('/') || host.contains('?') || host.contains('#') || host.contains('@') {
            return Err(AdvertisedEndpointError::UriSyntaxNotAllowed);
        }

        let host = host
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .map(str::to_owned)
            .unwrap_or(host);
        if host.is_empty() {
            return Err(AdvertisedEndpointError::EmptyHost);
        }

        // `scheme:` is only meaningful as a scheme separator when what precedes
        // it is a valid DNS label, so checking for a colon here is enough to
        // reject `https://…` and `host:port` smuggling without rejecting a
        // bare IPv6 literal, whose colons are already covered by the parse
        // below succeeding.
        if !host.contains(':') && host.contains("://") {
            return Err(AdvertisedEndpointError::UriSyntaxNotAllowed);
        }
        if !host.contains(':') {
            validate_dns_host(&host)?;
        } else if host.parse::<IpAddr>().is_err() {
            // The only colon-bearing host allowed is an IPv6 literal. A bare
            // `host:port` pair must not be accepted here, or a caller could
            // smuggle a second port through a field that has exactly one.
            return Err(AdvertisedEndpointError::InvalidHostCharacter);
        }

        if port == 0 {
            return Err(AdvertisedEndpointError::InvalidPort);
        }
        Ok(Self { host, port })
    }

    /// Builds an endpoint from a `host:port` string.
    pub fn parse(value: &str) -> Result<Self, AdvertisedEndpointError> {
        let (host, port) = split_host_port(value)?;
        Self::new(host, port)
    }

    /// The validated host: a DNS name, IPv4 literal, or bare IPv6 literal.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The UDP port clients dial.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether the host is an IPv6 literal and therefore needs bracketing.
    pub fn is_ipv6_literal(&self) -> bool {
        self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6())
    }

    /// Renders the exact text a WireGuard config's `Endpoint =` expects.
    ///
    /// Bracketing an IPv6 literal exactly once is the whole reason this is a
    /// function rather than a `Display` passthrough: `[::1]` must not become
    /// `[[::1]]`, and `::1` must not become an ambiguous `::1:51820`.
    pub fn render(&self) -> String {
        if self.is_ipv6_literal() {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Splits `host:port`, refusing a bare IPv6 literal that carries no port.
fn split_host_port(value: &str) -> Result<(&str, u16), AdvertisedEndpointError> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or(AdvertisedEndpointError::InvalidHostCharacter)?;
        let port = tail
            .strip_prefix(':')
            .ok_or(AdvertisedEndpointError::InvalidPort)?;
        return parse_port(port).map(|port| (host, port));
    }
    match value.rsplit_once(':') {
        Some((host, port)) => parse_port(port).map(|port| (host, port)),
        None => Err(AdvertisedEndpointError::InvalidPort),
    }
}

fn parse_port(value: &str) -> Result<u16, AdvertisedEndpointError> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(AdvertisedEndpointError::InvalidPort)
}

/// Validates an ASCII DNS host: non-empty labels of letters, digits, and
/// inner hyphens, joined by dots. A trailing dot is refused so that one
/// hostname has exactly one stored spelling.
fn validate_dns_host(host: &str) -> Result<(), AdvertisedEndpointError> {
    if !host.is_ascii() {
        return Err(AdvertisedEndpointError::InvalidHostCharacter);
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(AdvertisedEndpointError::InvalidHostCharacter);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(AdvertisedEndpointError::InvalidHostCharacter);
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(AdvertisedEndpointError::InvalidHostCharacter);
        }
    }
    Ok(())
}

impl TryFrom<String> for AdvertisedEndpoint {
    type Error = AdvertisedEndpointError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}
impl From<AdvertisedEndpoint> for String {
    fn from(value: AdvertisedEndpoint) -> Self {
        value.render()
    }
}
impl fmt::Display for AdvertisedEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdvertisedEndpointError {
    #[error("advertised host must not be empty")]
    EmptyHost,
    #[error("advertised host exceeds {MAX_ADVERTISED_HOST_BYTES} bytes")]
    HostTooLong,
    #[error("advertised host contains whitespace, a control character, or a colon-delimited port")]
    InvalidHostCharacter,
    #[error("advertised host must not contain scheme, path, query, fragment, or userinfo syntax")]
    UriSyntaxNotAllowed,
    #[error("advertised port must be between 1 and 65535")]
    InvalidPort,
}

/// Operator-facing display text for a managed client.
///
/// Ordinary Unicode is allowed on purpose: an operator names their own
/// devices. What is refused is anything that could terminate a line or change
/// the meaning of a rendered configuration, because a label is display text and
/// nothing more. It is never interpolated into a WireGuard directive.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ClientLabel(String);

impl ClientLabel {
    pub fn new(value: impl Into<String>) -> Result<Self, ClientLabelError> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(ClientLabelError::Empty);
        }
        if trimmed.len() > MAX_CLIENT_LABEL_BYTES {
            return Err(ClientLabelError::TooLong);
        }
        // ASCII line separators, and the C0/C1 control ranges, would let a
        // label break out of the single line it is rendered on. NUL is the
        // dangerous one in particular: it truncates in C consumers.
        if trimmed.chars().any(is_forbidden_label_character) {
            return Err(ClientLabelError::ForbiddenCharacter);
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// The label text, already trimmed.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The label an existing client is given when it predates product labels.
    ///
    /// Derived from the stable `ClientId` rather than a counter, so the same
    /// client yields the same label on every host that backfills it.
    pub fn derived_from_client_id(id: ClientId) -> Self {
        let id = id.to_string();
        Self(format!("client-{}", &id[..8.min(id.len())]))
    }
}

fn is_forbidden_label_character(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}')
        || c.is_control()
        || matches!(c as u32, 0x7f..=0x9f)
}

impl TryFrom<String> for ClientLabel {
    type Error = ClientLabelError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl From<ClientLabel> for String {
    fn from(value: ClientLabel) -> Self {
        value.0
    }
}
impl fmt::Display for ClientLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClientLabelError {
    #[error("client label must not be empty after trimming")]
    Empty,
    #[error("client label exceeds {MAX_CLIENT_LABEL_BYTES} bytes")]
    TooLong,
    #[error("client label must not contain line separators or control characters")]
    ForbiddenCharacter,
}

/// Whether a managed client's peer is currently projected into kernel intent.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientEnabled {
    Enabled,
    Disabled,
}

impl ClientEnabled {
    pub fn is_enabled(self) -> bool {
        matches!(self, ClientEnabled::Enabled)
    }
}

/// Product metadata for one managed client, composed with its desired client.
///
/// Deliberately composed rather than merged into [`crate::domain::DesiredClient`]:
/// the desired client is kernel intent and is read by the reconciler, while
/// this is operator-facing product state. Keeping them separate is what lets a
/// label change avoid touching projected intent at all.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClientProductSettings {
    pub label: ClientLabel,
    pub enabled: ClientEnabled,
    /// Client-side keepalive exported into this peer's own config.
    ///
    /// Distinct from the server-side `DesiredPeer::persistent_keepalive_seconds`,
    /// which is what authorizes the peer to send. Conflating them would make
    /// "stop pinging me" indistinguishable from "stop talking to me".
    pub client_keepalive_seconds: Option<u16>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// A managed client as the product surface presents it.
///
/// This is a projection and not a store record: it is assembled from the
/// desired client, the peer, and the product settings. It has no private-key
/// field, so every value built from it is secret-safe.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProductClient {
    pub client_id: ClientId,
    pub peer_id: PeerId,
    pub interface_id: InterfaceId,
    pub public_key: PublicKey,
    pub assigned_address: IpNet,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_ipv6_address: Option<IpNet>,
    pub settings: ClientProductSettings,
    pub route_policy: crate::domain::ClientRoutePolicy,
    pub dns_servers: Vec<IpAddr>,
}

/// Operator-facing summary of the managed server.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProductServer {
    pub interface_id: InterfaceId,
    pub name: crate::domain::InterfaceName,
    pub tunnel_prefix: NetworkPrefix,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_tunnel_prefix: Option<NetworkPrefix>,
    pub server_address: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_server_address: Option<IpAddr>,
    pub listen_port: u16,
    pub advertised_endpoint: AdvertisedEndpoint,
    pub public_key: PublicKey,
    pub egress_interface: crate::domain::InterfaceName,
    pub ipv4_forwarding_required: bool,
    pub masquerade: bool,
    pub default_client_route_policy: crate::domain::ClientRoutePolicy,
}

/// Identity of one audit row.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditEventId(Uuid);

impl AuditEventId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

/// Identifier of one one-time enrollment capability. The bearer token is a
/// separate secret and is never derived from or encoded into this identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EnrollmentCapabilityId(Uuid);
impl EnrollmentCapabilityId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}
impl Default for EnrollmentCapabilityId {
    fn default() -> Self {
        Self::new()
    }
}
impl fmt::Display for EnrollmentCapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl FromStr for EnrollmentCapabilityId {
    type Err = uuid::Error;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

impl Default for AuditEventId {
    fn default() -> Self {
        Self::new()
    }
}
impl fmt::Display for AuditEventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl FromStr for AuditEventId {
    type Err = uuid::Error;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

/// A bounded verb describing what an operator asked for.
///
/// A closed set rather than a string, so an audit row cannot grow a vocabulary
/// and so "what actions exist" is answered by the type system.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    ServerSetup,
    ClientCreate,
    ClientUpdate,
    ClientEnable,
    ClientDisable,
    ClientDelete,
    NetworkEnable,
    NetworkDisable,
    /// A post-commit reconciliation outcome, recorded separately because the
    /// kernel's answer is not inside the transaction that wrote the mutation.
    EnforcementDegraded,
    EnrollmentCapabilityCreated,
    EnrollmentCapabilityRevoked,
    EnrollmentCapabilityConsumed,
}

impl AuditAction {
    /// The exact text stored in `audit_events.action`.
    pub fn as_str(self) -> &'static str {
        match self {
            AuditAction::ServerSetup => "server_setup",
            AuditAction::ClientCreate => "client_create",
            AuditAction::ClientUpdate => "client_update",
            AuditAction::ClientEnable => "client_enable",
            AuditAction::ClientDisable => "client_disable",
            AuditAction::ClientDelete => "client_delete",
            AuditAction::NetworkEnable => "network_enable",
            AuditAction::NetworkDisable => "network_disable",
            AuditAction::EnforcementDegraded => "enforcement_degraded",
            AuditAction::EnrollmentCapabilityCreated => "enrollment_capability_created",
            AuditAction::EnrollmentCapabilityRevoked => "enrollment_capability_revoked",
            AuditAction::EnrollmentCapabilityConsumed => "enrollment_capability_consumed",
        }
    }
}

impl fmt::Display for AuditAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A bounded resource category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResourceKind {
    Server,
    Client,
    EnrollmentCapability,
}

impl AuditResourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditResourceKind::Server => "server",
            AuditResourceKind::Client => "client",
            AuditResourceKind::EnrollmentCapability => "enrollment_capability",
        }
    }
}

impl fmt::Display for AuditResourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A bounded outcome category.
///
/// `Committed` is the only value that means "durable state changed". There is
/// deliberately no free-form message: the trail records that a category of
/// change happened, never why in the operator's own words.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Committed,
    Rejected,
    Conflicted,
}

impl AuditOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditOutcome::Committed => "committed",
            AuditOutcome::Rejected => "rejected",
            AuditOutcome::Conflicted => "conflicted",
        }
    }
}

impl fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One secret-safe audit row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditEvent {
    pub event_id: AuditEventId,
    pub occurred_at: i64,
    pub principal_id: Option<PrincipalId>,
    pub action: AuditAction,
    pub resource_kind: AuditResourceKind,
    pub resource_id: Option<String>,
    pub generation_before: Option<DesiredGeneration>,
    pub generation_after: Option<DesiredGeneration>,
    pub outcome: AuditOutcome,
}

/// Stable cursor for audit pages, ordered by timestamp and insertion order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditCursor {
    pub occurred_at: i64,
    pub event_id: AuditEventId,
}

/// One bounded newest-first audit page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditPage {
    pub events: Vec<AuditEvent>,
    pub next_cursor: Option<AuditCursor>,
}

/// Whether a managed client peer appears in the current kernel observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientObservationStatus {
    Present,
    Missing,
}

/// Fresh, non-persistent peer telemetry joined to stable product IDs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClientTelemetry {
    pub client_id: ClientId,
    pub peer_id: PeerId,
    pub enabled: bool,
    pub observation: ClientObservationStatus,
    pub drift: bool,
    pub endpoint: Option<std::net::SocketAddr>,
    /// Absolute Unix seconds from the WireGuard kernel's last-handshake value.
    pub latest_handshake_unix_seconds: Option<u64>,
    pub latest_handshake_age_seconds: Option<u64>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
}

/// Bounded response for one live device observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClientTelemetrySnapshot {
    pub observed_at_unix_seconds: u64,
    pub clients: Vec<ClientTelemetry>,
    pub unassociated_peer_count: usize,
    pub truncated: bool,
}

/// Why kernel enforcement is not confirmed, in bounded categories.
///
/// A category, not an error string. An operator needs to know that a
/// committed change has not reached the kernel and roughly why; they do not
/// need the backend's internal message reproduced into a receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradedCategory {
    BackendUnreachable,
    BackendRefused,
    BackendTimeout,
}

impl DegradedCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            DegradedCategory::BackendUnreachable => "backend_unreachable",
            DegradedCategory::BackendRefused => "backend_refused",
            DegradedCategory::BackendTimeout => "backend_timeout",
        }
    }
}

impl fmt::Display for DegradedCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a committed mutation has been confirmed in the kernel.
///
/// This is the distinction that lets a receipt say "the database commit
/// succeeded, the kernel enforcement did not" without either pretending the
/// mutation was rejected or hiding the fact that traffic may not match the
/// new intent yet.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementState {
    /// The kernel agrees with the committed generation.
    Converged,
    /// The commit succeeded and enforcement has not been attempted or has not
    /// been reported yet.
    Pending,
    /// The commit succeeded; enforcement was attempted and did not succeed.
    /// The reconciler will converge it on a later pass.
    Degraded(DegradedCategory),
}

impl EnforcementState {
    /// Whether kernel state is confirmed to match the committed generation.
    pub fn is_converged(self) -> bool {
        matches!(self, EnforcementState::Converged)
    }

    /// The degraded category, when enforcement failed.
    pub fn degraded_category(self) -> Option<DegradedCategory> {
        match self {
            EnforcementState::Degraded(category) => Some(category),
            _ => None,
        }
    }
}

/// The outcome of one committed product mutation.
///
/// `generation` is durable truth: it advanced and will not move back, whatever
/// happened to the kernel. `enforcement` is a separate, later fact. Collapsing
/// them into a single error is exactly the ambiguity this type exists to
/// prevent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductMutationReceipt {
    pub generation: DesiredGeneration,
    pub enforcement: EnforcementState,
}

impl ProductMutationReceipt {
    pub fn converged(generation: DesiredGeneration) -> Self {
        Self {
            generation,
            enforcement: EnforcementState::Converged,
        }
    }

    pub fn pending(generation: DesiredGeneration) -> Self {
        Self {
            generation,
            enforcement: EnforcementState::Pending,
        }
    }

    pub fn degraded(generation: DesiredGeneration, category: DegradedCategory) -> Self {
        Self {
            generation,
            enforcement: EnforcementState::Degraded(category),
        }
    }

    /// Whether the kernel is confirmed to match the committed generation.
    pub fn is_enforced(self) -> bool {
        self.enforcement.is_converged()
    }
}

/// An IPv4 client address is returned by the allocator directly; there is no
/// wrapper type, because a reservation and its value are the same fact.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_dns_ipv4_and_ipv6_hosts() {
        let dns = AdvertisedEndpoint::new("vpn.example.com", 51820).unwrap();
        assert_eq!(dns.render(), "vpn.example.com:51820");

        let v4 = AdvertisedEndpoint::new("203.0.113.7", 51820).unwrap();
        assert_eq!(v4.render(), "203.0.113.7:51820");

        let v6 = AdvertisedEndpoint::new("2001:db8::1", 51820).unwrap();
        assert!(v6.is_ipv6_literal());
        assert_eq!(v6.render(), "[2001:db8::1]:51820");
    }

    #[test]
    fn brackets_an_ipv6_literal_exactly_once_in_both_input_forms() {
        let bracketed = AdvertisedEndpoint::parse("[2001:db8::1]:51820").unwrap();
        let bare = AdvertisedEndpoint::parse("2001:db8::1:51820").unwrap();
        assert_eq!(bracketed, bare, "one literal has one representation");
        assert_eq!(bracketed.render(), "[2001:db8::1]:51820");
        assert!(!bracketed.render().starts_with("[["));
        // Re-parsing the rendering must be stable, not doubly bracketed.
        assert_eq!(
            AdvertisedEndpoint::parse(&bracketed.render()).unwrap(),
            bracketed
        );
    }

    #[test]
    fn rejects_uri_syntax_whitespace_and_control_characters() {
        for host in [
            "https://vpn.example.com",
            "vpn.example.com/path",
            "vpn.example.com?a=b",
            "vpn.example.com#frag",
            "user@vpn.example.com",
            "vpn example.com",
            "vpn\nexample.com",
            "vpn\texample.com",
            "",
        ] {
            assert!(
                AdvertisedEndpoint::new(host, 51820).is_err(),
                "must reject {host:?}"
            );
        }
    }

    #[test]
    fn refuses_a_second_port_smuggled_into_the_host() {
        // `host:port` inside the host field would give the endpoint two ports.
        assert!(AdvertisedEndpoint::new("vpn.example.com:1234", 51820).is_err());
        assert!(AdvertisedEndpoint::new("vpn.example.com:", 51820).is_err());
        assert!(AdvertisedEndpoint::parse("vpn.example.com").is_err());
    }

    #[test]
    fn bounds_host_length_and_port_range() {
        let long = format!("{}.example.com", "a".repeat(250));
        assert!(AdvertisedEndpoint::new(long, 51820).is_err());
        assert!(AdvertisedEndpoint::new("vpn.example.com", 0).is_err());
        assert!(AdvertisedEndpoint::new("vpn.example.com", 65535).is_ok());
    }

    #[test]
    fn accepts_ordinary_unicode_labels_and_refuses_line_breakers() {
        assert_eq!(ClientLabel::new("Laptop").unwrap().as_str(), "Laptop");
        assert_eq!(ClientLabel::new("  Phone  ").unwrap().as_str(), "Phone");
        assert_eq!(
            ClientLabel::new("Bureau – MacBook").unwrap().as_str(),
            "Bureau – MacBook"
        );
        for bad in [
            "",
            "   ",
            "\n",
            "a\nb",
            "a\rb",
            "a\u{2028}b",
            "a\u{85}b",
            "a\u{0}b",
        ] {
            assert!(ClientLabel::new(bad).is_err(), "must reject {bad:?}");
        }
        let long = "x".repeat(MAX_CLIENT_LABEL_BYTES + 1);
        assert!(ClientLabel::new(long).is_err());
        assert!(ClientLabel::new("x".repeat(MAX_CLIENT_LABEL_BYTES)).is_ok());
    }

    #[test]
    fn derived_labels_are_stable_and_bounded() {
        let id = ClientId::new();
        let first = ClientLabel::derived_from_client_id(id);
        let second = ClientLabel::derived_from_client_id(id);
        assert_eq!(first, second, "the same client derives the same label");
        assert_ne!(first, ClientLabel::derived_from_client_id(ClientId::new()));
        assert!(first.as_str().starts_with("client-"));
        assert!(first.as_str().len() <= MAX_CLIENT_LABEL_BYTES);
    }

    #[test]
    fn a_receipt_keeps_the_committed_generation_when_enforcement_degrades() {
        let receipt = ProductMutationReceipt::degraded(
            DesiredGeneration::new(7).unwrap(),
            DegradedCategory::BackendUnreachable,
        );
        assert_eq!(receipt.generation, DesiredGeneration::new(7).unwrap());
        assert!(!receipt.is_enforced());
        assert_eq!(
            receipt.enforcement.degraded_category(),
            Some(DegradedCategory::BackendUnreachable)
        );
        assert!(ProductMutationReceipt::converged(receipt.generation).is_enforced());
    }
}
