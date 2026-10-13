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

mod auth;
mod capability;
mod client;
#[cfg(target_os = "linux")]
mod dispatch;
mod framing;
#[cfg(target_os = "linux")]
mod socket;
mod wire;

pub use auth::AuthorizationPolicy;
pub use capability::{CapabilityState, NetworkCapabilitySnapshot};
pub use client::request;
pub use framing::{read_frame, write_frame, MAX_FRAME_SIZE};
#[cfg(target_os = "linux")]
pub use socket::SocketServer;
pub use wire::{
    InstallationNetworkApplyBody, InstallationNetworkPlanBody, ProtocolError, RequestEnvelope,
    RequestOperation, ResponseBody, ResponseEnvelope, PROTOCOL_VERSION,
};
