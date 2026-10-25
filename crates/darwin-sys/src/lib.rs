//! Audited Darwin kernel control surface for wg-basic.
//!
//! This crate is the single OS boundary where `unsafe` is allowed. It exists
//! because the wg-basic Darwin backend has to talk to the Darwin kernel
//! directly (interface and address observation, routing-table observation, link
//! and address control, route mutation) and the main crate deliberately keeps
//! `#![forbid(unsafe_code)]`.
//!
//! The M002 implementation plan anticipated exactly this shape: "If FFI unsafe
//! is unavoidable, isolate audited unsafe in a tiny OS boundary via explicit
//! ADR/lint exception rather than weakening crate-wide forbid(unsafe_code)."
//! Concretely:
//!
//! - this crate is `#![deny(unsafe_code)]` and enables `unsafe` in exactly one
//!   module, [`ffi`];
//! - the public API is fully typed and safe: no raw pointers, file descriptors,
//!   or `errno` escape into the caller;
//! - the request numbers, struct layouts, and message shapes come from the
//!   macOS SDK headers (`sys/sockio.h`, `net/route.h`, `ifaddrs.h`) and from
//!   Apple's own `route(8)` implementation, so the wire shapes are the
//!   platform's supported interface rather than a hand-rolled approximation;
//! - nothing here parses a human-readable tool's output, and nothing here
//!   executes a subprocess.
//!
//! Every operation is scoped to a named interface or an explicit address and
//! route. No function in this crate enumerates "all interfaces to mutate" or
//! touches a default route.

#![cfg(target_os = "macos")]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::undocumented_unsafe_blocks)]

/// The single audited unsafe OS boundary. Every `unsafe` block in this
/// workspace member lives in this module and nowhere else.
#[allow(unsafe_code)]
mod ffi;

use std::fmt;
use std::net::IpAddr;

use ipnet::IpNet;

/// The classification of a Darwin kernel failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SysErrorKind {
    /// The caller lacks the privilege this operation requires.
    PermissionDenied,
    /// The named interface, address, or route does not exist.
    NotFound,
    /// The address or route already exists.
    AlreadyExists,
    /// The kernel rejected the request as malformed.
    InvalidArgument,
    /// Any other kernel-reported failure, carrying the raw `errno`.
    Os(i32),
}

/// A Darwin kernel operation failure.
///
/// The `operation` field names the syscall family that failed so operators get
/// an actionable message without the caller having to guess.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SysError {
    /// The failure classification.
    pub kind: SysErrorKind,
    /// The Darwin operation that failed.
    pub operation: &'static str,
}

impl fmt::Display for SysError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Darwin {} failed: ", self.operation)?;
        match self.kind {
            SysErrorKind::PermissionDenied => formatter.write_str("insufficient privilege"),
            SysErrorKind::NotFound => formatter.write_str("not found"),
            SysErrorKind::AlreadyExists => formatter.write_str("already exists"),
            SysErrorKind::InvalidArgument => formatter.write_str("rejected as invalid"),
            SysErrorKind::Os(code) => write!(formatter, "os error {code}"),
        }
    }
}

impl std::error::Error for SysError {}

/// One observed network interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceInfo {
    /// The kernel interface name, for example `utun4`.
    pub name: String,
    /// The kernel interface index.
    pub index: u32,
    /// The raw `IFF_*` interface flags.
    pub flags: u16,
    /// The interface MTU in bytes, or zero when it could not be read.
    pub mtu: u32,
    /// Every address configured on the interface.
    pub addresses: Vec<IpNet>,
}

impl InterfaceInfo {
    /// Whether the interface is administratively up.
    pub fn is_up(&self) -> bool {
        self.flags & ffi::IFF_UP != 0
    }
}

/// One observed route in the main routing table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteInfo {
    /// The route destination, including its prefix length.
    pub destination: IpNet,
    /// The next hop, when this is a gateway route.
    pub gateway: Option<IpAddr>,
    /// The output interface index.
    pub interface_index: u32,
    /// The output interface name.
    pub interface_name: String,
    /// The raw `RTF_*` route flags.
    pub flags: u32,
}

impl RouteInfo {
    /// Whether the route is a gateway route (it forwards through a next hop).
    pub fn is_gateway(&self) -> bool {
        self.gateway.is_some()
    }
}

/// Lists every network interface with its addresses, flags, and MTU.
///
/// Observation only: this never mutates host state.
pub fn interfaces() -> Result<Vec<InterfaceInfo>, SysError> {
    ffi::list_interfaces()
}

/// Whether the host has global IPv4 forwarding enabled.
///
/// This is host-global state this product does not own. It is read to prove
/// the host-only posture and is never changed.
pub fn ipv4_forwarding_enabled() -> Option<bool> {
    ffi::sysctl_bool("net.inet.ip.forwarding")
}

/// Whether the host has global IPv6 forwarding enabled.
pub fn ipv6_forwarding_enabled() -> Option<bool> {
    ffi::sysctl_bool("net.inet6.ip6.forwarding")
}

/// Lists every route in the main routing table.
///
/// Observation only: this never mutates host state.
pub fn routes() -> Result<Vec<RouteInfo>, SysError> {
    ffi::list_routes()
}

/// Returns the kernel index of a named interface, or `None` when it does not
/// exist.
pub fn interface_index(name: &str) -> Option<u32> {
    ffi::interface_index(name)
}

/// Returns the absolute path of the executable a process is running.
///
/// This is the Darwin replacement for reading `/proc/<pid>/exe`: macOS has no
/// `/proc`, and a process name is not proof of identity. A reused pid or a
/// renamed binary is reported as a different path, never as the same one.
pub fn process_executable_path(pid: u32) -> Option<std::path::PathBuf> {
    let bytes = ffi::process_executable_path(pid)?;
    let text = String::from_utf8(bytes).ok()?;
    let trimmed = text.trim_end_matches('\0');
    if trimmed.is_empty() {
        return None;
    }
    Some(std::path::PathBuf::from(trimmed))
}

/// Brings a named interface administratively up or down.
///
/// The flags word is read first and only the `IFF_UP` bit is changed, so no
/// other interface flag is disturbed.
pub fn set_link_up(name: &str, up: bool) -> Result<(), SysError> {
    ffi::set_link_up(name, up)
}

/// Adds an address to a named interface.
pub fn add_address(name: &str, address: IpNet) -> Result<(), SysError> {
    ffi::add_address(name, address)
}

/// Removes an address from a named interface.
pub fn remove_address(name: &str, address: IpNet) -> Result<(), SysError> {
    ffi::remove_address(name, address)
}

/// Adds a route for an explicit destination through a named interface.
///
/// A route without a gateway is a direct (interface-bound) route. A route with
/// a gateway forwards through that next hop. Neither form touches a default
/// route, and the destination is always an explicit prefix.
pub fn add_route(
    destination: IpNet,
    gateway: Option<IpAddr>,
    interface: &str,
) -> Result<(), SysError> {
    ffi::add_route(destination, gateway, interface)
}

/// Removes a route for an explicit destination through a named interface.
pub fn remove_route(
    destination: IpNet,
    gateway: Option<IpAddr>,
    interface: &str,
) -> Result<(), SysError> {
    ffi::remove_route(destination, gateway, interface)
}
