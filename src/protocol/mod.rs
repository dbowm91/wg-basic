//! The bounded, versioned, local Unix-domain privileged protocol.
//!
//! Ownership is split across units plus the wire vocabulary:
//!
//! - [`auth`] holds the peer-credential authorization policy (portable; Darwin
//!   peer identity gains its `getpeereid` backend in M002);
//! - [`socket`] owns bind, stale-path handling, and shutdown lifecycle
//!   (Linux; Darwin IPC lands in M002 and M001 netd fails closed);
//! - [`dispatch`] owns operation routing and domain-error projection (Linux;
//!   Darwin stubs in M001 report unsupported through the typed errors);
//! - [`client`] is the one-shot request helper (portable).
//!
//! [`framing`] owns the four-byte big-endian length frame and [`wire`] owns the
//! JSON envelope. [`capability`] owns the read-only capability snapshot
//! (portable shape; Darwin observation reports unsupported/unknown, never
//! Linux `/proc` values).
//!
//! There is no generic exec, file-write, raw-netlink, or raw-nft operation.
//! Requests are handled one at a time and every connection carries one request.

#[cfg(unix)]
mod auth;
#[cfg(windows)]
mod auth_windows;
mod capability;
#[cfg(unix)]
mod client;
#[cfg(windows)]
mod client_windows;
mod dispatch;
mod framing;
#[cfg(unix)]
mod socket;
#[cfg(windows)]
mod socket_windows;
mod wire;

#[cfg(unix)]
pub use auth::AuthorizationPolicy;
#[cfg(windows)]
pub use auth_windows::AuthorizationPolicy;
pub use capability::{CapabilityState, NetworkCapabilitySnapshot};
#[cfg(unix)]
pub use client::request;
#[cfg(windows)]
pub use client_windows::request;
pub use framing::{read_frame, write_frame, MAX_FRAME_SIZE};
#[cfg(unix)]
pub use socket::SocketServer;
#[cfg(windows)]
pub use socket_windows::SocketServer;
pub use wire::{
    InstallationNetworkApplyBody, InstallationNetworkPlanBody, ProtocolError, RequestEnvelope,
    RequestOperation, ResponseBody, ResponseEnvelope, PROTOCOL_VERSION,
};
