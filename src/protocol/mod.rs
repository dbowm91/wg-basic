//! The bounded, versioned, local Unix-domain privileged protocol.
//!
//! Ownership is split across four units plus the wire vocabulary:
//!
//! - [`auth`] holds the peer-credential authorization policy;
//! - [`socket`] owns bind, stale-path handling, and shutdown lifecycle;
//! - [`dispatch`] owns operation routing and domain-error projection;
//! - [`client`] is the one-shot request helper.
//!
//! [`framing`] owns the four-byte big-endian length frame and [`wire`] owns the
//! JSON envelope. [`capability`] owns the read-only capability snapshot.
//!
//! There is no generic exec, file-write, raw-netlink, or raw-nft operation.
//! Requests are handled one at a time and every connection carries one request.

mod auth;
mod capability;
mod client;
mod dispatch;
mod framing;
mod socket;
mod wire;

pub use auth::AuthorizationPolicy;
pub use capability::{CapabilityState, NetworkCapabilitySnapshot};
pub use client::request;
pub use framing::{read_frame, write_frame, MAX_FRAME_SIZE};
pub use socket::SocketServer;
pub use wire::{
    InstallationNetworkApplyBody, InstallationNetworkPlanBody, ProtocolError, RequestEnvelope,
    RequestOperation, ResponseBody, ResponseEnvelope, PROTOCOL_VERSION,
};
