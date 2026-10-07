//! Management HTTP configuration and the explicit bounds it publishes.
//!
//! Every bound an HTTP surface can be attacked with is written down here as a
//! named constant rather than inherited silently from a framework default. That
//! has two purposes: the limits are reviewable as product intent, and a test can
//! assert that the EggServe [`RuntimeConfig`] actually received them.
//!
//! # Defaults are management-surface defaults
//!
//! These are deliberately small. This is an appliance administration surface on
//! a loopback listener, not a public web service:
//!
//! * 64 concurrent connections and 128 in-flight requests.
//! * 32 request headers totalling 8 KiB, and a 1 KiB request target.
//! * 16 KiB maximum request body — enough for the M003 credential payloads and
//!   nothing else.
//! * No file streaming and no CONNECT tunnelling: those are unbounded by nature
//!   and have no place on an administration surface.
//! * Independent header, body, handler, write, and idle deadlines, plus a total
//!   connection lifetime so a keep-alive client cannot hold a slot forever.

use eggserve_server::{config::RuntimeConfig, ServerError};
use std::{fmt, net::SocketAddr, time::Duration};

/// Maximum concurrent connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 64;

/// Maximum concurrent in-flight requests.
pub const DEFAULT_MAX_IN_FLIGHT_REQUESTS: usize = 128;

/// Maximum request headers.
pub const DEFAULT_MAX_HEADERS: usize = 32;

/// Maximum total request header bytes.
pub const DEFAULT_MAX_HEADER_BYTES: usize = 8 * 1024;

/// Maximum request target bytes.
pub const DEFAULT_MAX_REQUEST_TARGET_BYTES: usize = 1024;

/// Maximum request body bytes, across the whole surface.
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: u64 = 16 * 1024;

/// Parser/read buffer floor. EggServe delegates to Hyper, which panics below 8 KiB.
pub const MIN_BUF_SIZE: usize = 8 * 1024;

/// The smallest capacity EggServe accepts for file streaming or tunnelling.
///
/// The management surface needs neither, but the runtime rejects a capacity of
/// zero, so the surface pins the floor and relies on having no route that could
/// consume it. Asserting a *zero* here would be a claim the transport cannot
/// express, so the claim this crate can actually make — and tests — is that the
/// floor is pinned and that nothing routes to it.
pub const MIN_FEATURE_CAPACITY: usize = 1;

/// The default loopback management listener.
pub const DEFAULT_BIND: &str = "127.0.0.1:8000";

/// How long a client may take to send its request headers.
pub const DEFAULT_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a client may take to finish a request body.
pub const DEFAULT_BODY_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// How long one handler invocation may run before it is cut off.
pub const DEFAULT_HANDLER_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a response write may block.
pub const DEFAULT_RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long an idle keep-alive connection is held.
pub const DEFAULT_KEEP_ALIVE_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// Total lifetime ceiling for a single connection, across all its requests.
pub const DEFAULT_CONNECTION_TOTAL_TIMEOUT: Duration = Duration::from_secs(60);

/// Grace period offered to in-flight requests during shutdown.
pub const DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Requests allowed on one connection before it is closed.
pub const DEFAULT_MAX_REQUESTS_PER_CONNECTION: u64 = 256;

/// The product's own statement of the management surface's bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpLimits {
    /// Address the management listener binds to.
    pub bind: SocketAddr,
    /// Maximum concurrent connections.
    pub max_connections: usize,
    /// Maximum concurrent in-flight requests.
    pub max_in_flight_requests: usize,
    /// Maximum request headers.
    pub max_headers: usize,
    /// Maximum total request header bytes.
    pub max_header_bytes: usize,
    /// Maximum request target bytes.
    pub max_request_target_bytes: usize,
    /// Maximum request body bytes, across the whole surface.
    pub max_request_body_bytes: u64,
    /// Parser/read buffer size.
    pub buf_size: usize,
    /// How long a client may take to send its request headers.
    pub header_read_timeout: Duration,
    /// How long a client may take to finish a request body.
    pub body_read_timeout: Duration,
    /// How long one handler invocation may run.
    pub handler_timeout: Duration,
    /// How long a response write may block.
    pub response_write_timeout: Duration,
    /// How long an idle keep-alive connection is held.
    pub keep_alive_idle_timeout: Duration,
    /// Total lifetime ceiling for one connection.
    pub connection_total_timeout: Duration,
    /// Grace period offered to in-flight requests during shutdown.
    pub graceful_shutdown_timeout: Duration,
    /// Requests allowed on one connection.
    pub max_requests_per_connection: u64,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            bind: DEFAULT_BIND
                .parse()
                .expect("a literal socket address parses"),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_in_flight_requests: DEFAULT_MAX_IN_FLIGHT_REQUESTS,
            max_headers: DEFAULT_MAX_HEADERS,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_request_target_bytes: DEFAULT_MAX_REQUEST_TARGET_BYTES,
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            buf_size: MIN_BUF_SIZE,
            header_read_timeout: DEFAULT_HEADER_READ_TIMEOUT,
            body_read_timeout: DEFAULT_BODY_READ_TIMEOUT,
            handler_timeout: DEFAULT_HANDLER_TIMEOUT,
            response_write_timeout: DEFAULT_RESPONSE_WRITE_TIMEOUT,
            keep_alive_idle_timeout: DEFAULT_KEEP_ALIVE_IDLE_TIMEOUT,
            connection_total_timeout: DEFAULT_CONNECTION_TOTAL_TIMEOUT,
            graceful_shutdown_timeout: DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT,
            max_requests_per_connection: DEFAULT_MAX_REQUESTS_PER_CONNECTION,
        }
    }
}

/// Why a management HTTP configuration could not be built.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// A limit was zero or otherwise below what the transport can support.
    #[error("the HTTP limit `{0}` must be greater than zero")]
    NonPositiveLimit(&'static str),
    /// The read buffer is below the transport floor.
    #[error("the HTTP read buffer must be at least {minimum} bytes, got {actual}")]
    BufferTooSmall { minimum: usize, actual: usize },
    /// The bind address could not be parsed.
    #[error("`{0}` is not a valid bind address")]
    InvalidBind(String),
    /// EggServe rejected the assembled configuration.
    #[error("the HTTP runtime configuration is invalid: {0}")]
    Runtime(#[from] ServerError),
    /// A routable bind was requested without the acknowledgement that says the
    /// operator meant it.
    ///
    /// A routable listener with no canonical origin leaves nothing to check
    /// `Host` against, and accepting any `Host` is precisely the DNS-rebinding
    /// hole the origin policy exists to close. So the default refuses rather
    /// than falling back to a permissive policy.
    #[error(
        "a routable bind serves the management surface to the network; \
             pass --allow-non-loopback together with --canonical-origin to say so"
    )]
    OffHostNeedsAcknowledgement,
}

impl HttpLimits {
    /// Checks the limits that EggServe would otherwise reject at build time.
    pub fn validate(&self) -> Result<(), HttpError> {
        let positive = [
            ("max_connections", self.max_connections),
            ("max_in_flight_requests", self.max_in_flight_requests),
            ("max_headers", self.max_headers),
            ("max_header_bytes", self.max_header_bytes),
            ("max_request_target_bytes", self.max_request_target_bytes),
        ];
        for (name, value) in positive {
            if value == 0 {
                return Err(HttpError::NonPositiveLimit(name));
            }
        }
        if self.buf_size < MIN_BUF_SIZE {
            return Err(HttpError::BufferTooSmall {
                minimum: MIN_BUF_SIZE,
                actual: self.buf_size,
            });
        }
        Ok(())
    }

    /// Assembles the EggServe runtime configuration these limits describe.
    ///
    /// Note what is *not* set: no `Server` header (so the product does not
    /// advertise its stack), no PROXY protocol, no trusted proxy (so forwarded
    /// headers cannot influence the observed client), no file-stream capacity,
    /// and no CONNECT tunnels.
    pub fn to_runtime_config(&self) -> Result<RuntimeConfig, HttpError> {
        self.validate()?;
        RuntimeConfig::builder()
            .bind(self.bind)
            .max_connections(self.max_connections)
            .max_in_flight_requests(self.max_in_flight_requests)
            .max_headers(self.max_headers)
            .max_header_bytes(self.max_header_bytes)
            .max_request_target_bytes(self.max_request_target_bytes)
            .max_request_body_bytes(self.max_request_body_bytes)
            .max_buf_size(self.buf_size)
            .header_read_timeout(self.header_read_timeout)
            .body_read_timeout(self.body_read_timeout)
            .handler_timeout(self.handler_timeout)
            .response_write_timeout(self.response_write_timeout)
            .keep_alive_idle_timeout(self.keep_alive_idle_timeout)
            .connection_total_timeout(self.connection_total_timeout)
            .graceful_shutdown_timeout(self.graceful_shutdown_timeout)
            .max_requests_per_connection(Some(self.max_requests_per_connection))
            // An administration surface streams no files and tunnels nothing.
            // EggServe requires these to be at least 1, so the surface pins the
            // floor and relies on having no route that could use either.
            .max_file_streams(MIN_FEATURE_CAPACITY)
            .max_active_tunnels(MIN_FEATURE_CAPACITY)
            .stream_chunk_size(MIN_BUF_SIZE)
            // Forwarded headers are meaningless without a trusted proxy, and
            // trusting them would let a client forge its observed address.
            .proxy_protocol_enabled(false)
            .forwarded_standard(false)
            .forwarded_legacy(false)
            .build()
            .map_err(HttpError::from)
    }
}

/// The management HTTP configuration as the service sees it.
#[derive(Clone, Debug, Default)]
pub struct ManagementHttpConfig {
    /// The bounds published by this surface.
    pub limits: HttpLimits,
}

impl ManagementHttpConfig {
    /// Builds the default loopback management configuration.
    pub fn new(bind: impl fmt::Display) -> Result<Self, HttpError> {
        let bind = bind.to_string();
        let bind: SocketAddr = bind
            .parse()
            .map_err(|_| HttpError::InvalidBind(bind.clone()))?;
        let limits = HttpLimits {
            bind,
            ..HttpLimits::default()
        };
        limits.validate()?;
        Ok(Self { limits })
    }

    /// Builds the configuration from explicit limits.
    pub fn from_limits(limits: HttpLimits) -> Result<Self, HttpError> {
        limits.validate()?;
        Ok(Self { limits })
    }

    /// Assembles the EggServe runtime configuration.
    pub fn runtime_config(&self) -> Result<RuntimeConfig, HttpError> {
        self.limits.to_runtime_config()
    }

    /// The address the listener will bind.
    pub fn bind(&self) -> SocketAddr {
        self.limits.bind
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_limits_reach_the_runtime_config() {
        let limits = HttpLimits::default();
        let runtime = limits.to_runtime_config().expect("valid defaults");

        assert_eq!(runtime.max_connections, limits.max_connections);
        assert_eq!(runtime.max_headers, limits.max_headers);
        assert_eq!(runtime.max_header_bytes, limits.max_header_bytes);
        assert_eq!(
            runtime.max_request_target_bytes,
            limits.max_request_target_bytes
        );
        assert_eq!(
            runtime.max_request_body_bytes,
            limits.max_request_body_bytes
        );
        assert_eq!(
            runtime.max_in_flight_requests,
            limits.max_in_flight_requests
        );
        assert_eq!(runtime.max_buf_size, limits.buf_size);
        assert_eq!(runtime.handler_timeout, limits.handler_timeout);
        assert_eq!(
            runtime.graceful_shutdown_timeout,
            limits.graceful_shutdown_timeout
        );
    }

    #[test]
    fn the_surface_advertises_no_stack_and_no_tunnels() {
        let runtime = HttpLimits::default().to_runtime_config().unwrap();
        // Not setting a Server header must survive assembly: the product does
        // not hand an attacker its stack for free.
        assert_eq!(runtime.server_header_value(), None);
        // The transport floor, pinned: nothing may raise it, and no M001 route
        // can consume either capability.
        assert_eq!(runtime.max_file_streams, MIN_FEATURE_CAPACITY);
        assert_eq!(runtime.max_active_tunnels, MIN_FEATURE_CAPACITY);
    }

    #[test]
    fn the_default_bind_is_loopback_only() {
        let bind = HttpLimits::default().bind;
        assert!(bind.ip().is_loopback(), "{bind} must not be routable");
    }

    #[test]
    fn a_zero_limit_is_refused_rather_than_becoming_unbounded() {
        let limits = HttpLimits {
            max_connections: 0,
            ..HttpLimits::default()
        };
        assert!(matches!(
            limits.to_runtime_config(),
            Err(HttpError::NonPositiveLimit("max_connections"))
        ));

        let limits = HttpLimits {
            max_in_flight_requests: 0,
            ..HttpLimits::default()
        };
        assert!(limits.to_runtime_config().is_err());
    }

    #[test]
    fn an_unbounded_body_ceiling_is_refused() {
        // `u64::MAX` is the classic "no limit" spelling; the surface has no
        // unbounded body route, so it must not be expressible.
        let limits = HttpLimits {
            max_request_body_bytes: u64::MAX,
            ..HttpLimits::default()
        };
        assert!(limits.to_runtime_config().is_err());
    }

    #[test]
    fn a_read_buffer_below_the_transport_floor_is_refused() {
        let limits = HttpLimits {
            buf_size: MIN_BUF_SIZE - 1,
            ..HttpLimits::default()
        };
        assert!(matches!(
            limits.to_runtime_config(),
            Err(HttpError::BufferTooSmall { .. })
        ));
    }

    #[test]
    fn a_configuration_names_one_ephemeral_port_for_tests() {
        let config = ManagementHttpConfig::new("127.0.0.1:0").expect("port 0 is valid");
        assert_eq!(config.bind().port(), 0);
        // Port 0 asks the kernel for a free port, which is how the integration
        // tests bind without racing for a fixed number.
        assert!(config.runtime_config().is_ok());
    }

    #[test]
    fn an_unparseable_bind_address_is_rejected_with_the_input() {
        let error = ManagementHttpConfig::new("not-an-address").expect_err("must reject");
        assert!(matches!(error, HttpError::InvalidBind(ref text) if text == "not-an-address"));
    }
}
