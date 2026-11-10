//! Audited Windows control surface for wg-basic.
//!
//! Unsafe is confined to [`ffi`]. Every public function is safe, borrows no
//! caller-supplied command line, and refuses a path or a name that is not the
//! one this product derived.

#![cfg(windows)]
#![deny(unsafe_code)]

mod ffi;

use std::fs::File;
use std::io;
use std::net::SocketAddr;
use std::path::Path;

pub use ffi::{OsFacts, SysError};

/// Canonical SID string, for example `S-1-5-21-...`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sid(String);

impl Sid {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Rebuilds a SID this process already resolved. The string is not a path
    /// and is not taken from a protocol request.
    pub fn from_canonical(value: &str) -> Result<Self, SysError> {
        if !value.starts_with("S-1-") || value.len() > 184 || value.contains('\\') {
            return Err(SysError::invalid("sid"));
        }
        Ok(Self(value.to_string()))
    }
}

impl std::fmt::Display for Sid {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The user SID of this process.
pub fn current_user_sid() -> Result<Sid, SysError> {
    ffi::current_user_sid().map(Sid)
}

/// Resolves a local account name to its user SID. The name is a host lookup,
/// never a value taken from a protocol request.
pub fn lookup_account_sid(account: &str) -> Result<Sid, SysError> {
    if account.is_empty() || account.contains('\\') || account.contains('/') || account.len() > 64 {
        return Err(SysError::invalid("account name"));
    }
    ffi::lookup_account_sid(account).map(Sid)
}

/// A named-pipe listener this process created.
pub struct PipeListener {
    inner: ffi::PipeHandle,
}

/// One accepted connection plus the kernel peer identity.
pub struct AcceptedPipe {
    pub io: File,
    pub peer_sid: Sid,
    /// High or system integrity. Medium fails closed.
    pub high_integrity: bool,
}

impl PipeListener {
    /// Binds `name` so only `serve` and this process's user can open it.
    ///
    /// `FILE_FLAG_FIRST_PIPE_INSTANCE` makes a pipe someone else already
    /// created a conflict. This function does not close that pipe.
    pub fn bind(name: &str, serve: &Sid) -> Result<Self, SysError> {
        if !crate_pipe_name_ok(name) {
            return Err(SysError::invalid("pipe name"));
        }
        let own = current_user_sid()?;
        Ok(Self {
            inner: ffi::create_pipe(name, serve.as_str(), own.as_str())?,
        })
    }

    pub fn disconnect(&self) {
        ffi::disconnect_pipe(&self.inner);
    }

    pub fn accept(&self) -> Result<AcceptedPipe, SysError> {
        let accepted = ffi::accept_pipe(&self.inner)?;
        Ok(AcceptedPipe {
            io: accepted.io,
            peer_sid: Sid(accepted.peer_sid),
            high_integrity: accepted.high_integrity,
        })
    }
}

impl Drop for PipeListener {
    fn drop(&mut self) {
        ffi::close_pipe(&mut self.inner);
    }
}

fn crate_pipe_name_ok(name: &str) -> bool {
    let Some(segment) = name.strip_prefix(r"\\.\pipe\wg-basic-") else {
        return false;
    };
    !segment.is_empty()
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Connects to a pipe this product is allowed to name.
pub fn connect_pipe(name: &str) -> io::Result<File> {
    if !crate_pipe_name_ok(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pipe name is outside the wg-basic prefix",
        ));
    }
    ffi::connect_pipe(name)
}

/// True when a pipe instance already exists. Does not close it.
pub fn pipe_exists(name: &str) -> Result<bool, SysError> {
    if !crate_pipe_name_ok(name) {
        return Err(SysError::invalid("pipe name"));
    }
    ffi::pipe_exists(name)
}

/// Replaces a file or directory DACL with one ACE: the current user, full
/// control, inheritance off. A NULL or inherited DACL is not left in place.
pub fn restrict_to_current_user(path: &Path) -> Result<(), SysError> {
    let path = path_string(path)?;
    ffi::restrict_to_current_user(&path)
}

/// Replaces the DACL with one allow ACE for `sid`. The SID is a host identity,
/// never a protocol field.
pub fn restrict_to_sid(path: &Path, sid: &Sid) -> Result<(), SysError> {
    let path = path_string(path)?;
    ffi::restrict_to_sid(&path, sid.as_str())
}

/// A non-reparse file or directory whose DACL admits only the current user.
pub fn is_private(path: &Path) -> Result<bool, SysError> {
    let path = path_string(path)?;
    ffi::is_private(&path)
}

/// Creates a new file and restricts it before returning the handle.
pub fn create_private_file(path: &Path) -> io::Result<File> {
    let path =
        path_string(path).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    ffi::create_private_file(&path)
}

fn path_string(path: &Path) -> Result<String, SysError> {
    let text = path
        .to_str()
        .ok_or_else(|| SysError::invalid("path is not valid Unicode"))?;
    if text.is_empty() || text.len() > 32_000 {
        return Err(SysError::invalid("path"));
    }
    Ok(text.to_owned())
}

/// Advisory lock that the kernel releases when the handle closes, including
/// on process death.
pub struct FileLock {
    _file: File,
}

impl FileLock {
    pub fn try_exclusive(file: File) -> Result<Self, LockError> {
        ffi::lock_exclusive(&file).map_err(LockError::from_ffi)?;
        Ok(Self { _file: file })
    }

    pub fn try_shared(file: File) -> Result<Self, LockError> {
        ffi::lock_shared(&file).map_err(LockError::from_ffi)?;
        Ok(Self { _file: file })
    }
}

pub enum LockError {
    Busy,
    Io,
}

impl LockError {
    fn from_ffi(busy: bool) -> Self {
        if busy {
            Self::Busy
        } else {
            Self::Io
        }
    }
}

/// OS facts used for the SKU check and doctor. Read-only.
pub fn os_facts() -> Result<OsFacts, SysError> {
    ffi::os_facts()
}

/// Loads `wireguard.dll` from an absolute path.
///
/// The search flags are fixed: the DLL's own directory and System32. The
/// process working directory is not searched.
pub fn load_wireguard(path: &Path) -> Result<(), SysError> {
    let path = path_string(path)?;
    let file_name = Path::new(&path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if file_name != "wireguard.dll" || !Path::new(&path).is_absolute() {
        return Err(SysError::invalid("wireguard.dll path"));
    }
    ffi::load_wireguard(&path)
}

#[derive(Clone, Debug)]
pub struct DeviceConfig {
    pub private_key: Option<[u8; 32]>,
    pub public_key: Option<[u8; 32]>,
    pub listen_port: u16,
    pub peers: Vec<PeerConfig>,
}

#[derive(Clone, Debug)]
pub struct PeerConfig {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub persistent_keepalive: u16,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<(std::net::IpAddr, u8)>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    /// 100ns intervals since 1601-01-01 UTC. Zero means no handshake.
    pub last_handshake: u64,
}

pub struct Adapter {
    /// Integer form of the driver handle so the value can move between threads.
    /// The pointer is only passed back into the driver.
    handle: usize,
    pub luid: u64,
    pub guid: [u8; 16],
}

impl Adapter {
    pub fn create(name: &str, guid: &[u8; 16]) -> Result<Self, SysError> {
        validate_adapter_name(name)?;
        let (handle, luid) = ffi::create_adapter(name, guid)?;
        Ok(Self {
            handle: handle as usize,
            luid,
            guid: *guid,
        })
    }

    pub fn open(name: &str) -> Result<Self, SysError> {
        validate_adapter_name(name)?;
        let (handle, luid, guid) = ffi::open_adapter(name)?;
        Ok(Self {
            handle: handle as usize,
            luid,
            guid,
        })
    }

    fn raw(&self) -> ffi::AdapterHandle {
        self.handle as ffi::AdapterHandle
    }

    pub fn set_config(&self, config: &DeviceConfig) -> Result<(), SysError> {
        ffi::set_config(self.raw(), config)
    }

    pub fn get_config(&self) -> Result<DeviceConfig, SysError> {
        ffi::get_config(self.raw())
    }

    pub fn set_up(&self, up: bool) -> Result<(), SysError> {
        ffi::set_adapter_state(self.raw(), up)
    }

    pub fn is_up(&self) -> Result<bool, SysError> {
        ffi::get_adapter_state(self.raw())
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        ffi::close_adapter(self.handle as ffi::AdapterHandle);
    }
}

fn validate_adapter_name(name: &str) -> Result<(), SysError> {
    if name.is_empty()
        || name.len() > 40
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(SysError::invalid("adapter name"));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostAddress {
    pub addr: std::net::IpAddr,
    pub prefix_len: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostRoute {
    pub destination: std::net::IpAddr,
    pub prefix_len: u8,
    pub gateway: Option<std::net::IpAddr>,
    pub luid: u64,
    pub metric: u32,
}

pub fn addresses_on(luid: u64) -> Result<Vec<HostAddress>, SysError> {
    ffi::addresses_on(luid)
}

pub fn add_address(luid: u64, address: &HostAddress) -> Result<(), SysError> {
    ffi::add_address(luid, address)
}

pub fn delete_address(luid: u64, address: &HostAddress) -> Result<(), SysError> {
    ffi::delete_address(luid, address)
}

pub fn routes_on(luid: u64) -> Result<Vec<HostRoute>, SysError> {
    ffi::routes_on(luid)
}

pub fn add_route(route: &HostRoute) -> Result<(), SysError> {
    if route.prefix_len == 0 {
        return Err(SysError::invalid(
            "a default route is not an owned tunnel route",
        ));
    }
    ffi::add_route(route)
}

pub fn delete_route(route: &HostRoute) -> Result<(), SysError> {
    if route.prefix_len == 0 {
        return Err(SysError::invalid(
            "a default route is not an owned tunnel route",
        ));
    }
    ffi::delete_route(route)
}

pub fn ipv4_forwarding_enabled() -> Result<bool, SysError> {
    ffi::ipv4_forwarding_enabled()
}

pub fn set_ipv4_forwarding(enabled: bool) -> Result<(), SysError> {
    ffi::set_ipv4_forwarding(enabled)
}

pub fn ipv6_forwarding_enabled() -> Result<Option<bool>, SysError> {
    ffi::ipv6_forwarding_enabled()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NatObject {
    pub name: String,
    pub internal_prefix: String,
}

pub fn list_nats() -> Result<Vec<NatObject>, SysError> {
    ffi::list_nats()
}

pub fn create_nat(name: &str, prefix: &str) -> Result<(), SysError> {
    owned_name(name)?;
    if !prefix_ok(prefix) {
        return Err(SysError::invalid("nat prefix"));
    }
    ffi::create_nat(name, prefix)
}

pub fn delete_nat(name: &str) -> Result<(), SysError> {
    owned_name(name)?;
    ffi::delete_nat(name)
}

pub fn install_filter(name: &str, listen_port: u16) -> Result<(), SysError> {
    owned_name(name)?;
    ffi::install_filter(name, listen_port)
}

pub fn delete_filter(name: &str) -> Result<(), SysError> {
    owned_name(name)?;
    ffi::delete_filter(name)
}

fn owned_name(name: &str) -> Result<(), SysError> {
    let Some(rest) = name.strip_prefix("wg-basic-") else {
        return Err(SysError::invalid("object name"));
    };
    if rest.is_empty()
        || rest.contains('"')
        || rest.contains('\\')
        || rest.contains(' ')
        || !rest
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(SysError::invalid("object name"));
    }
    Ok(())
}

fn prefix_ok(prefix: &str) -> bool {
    let Some((addr, len)) = prefix.split_once('/') else {
        return false;
    };
    addr.parse::<std::net::Ipv4Addr>().is_ok()
        && len.parse::<u8>().ok().is_some_and(|len| len <= 32)
}

pub fn default_route_luids() -> Result<Vec<u64>, SysError> {
    ffi::default_route_luids()
}

#[derive(Clone, Debug)]
pub struct ServiceSpec {
    pub name: &'static str,
    pub display: &'static str,
    pub command: String,
    /// `None` runs as LocalSystem. `Some` is an unprivileged account.
    pub account: Option<(String, String)>,
}

pub fn install_service(spec: &ServiceSpec) -> Result<(), SysError> {
    if spec.name != "wg-basic" && spec.name != "wg-basic-netd" {
        return Err(SysError::invalid("service name"));
    }
    ffi::install_service(spec)
}

pub fn service_exists(name: &str) -> Result<bool, SysError> {
    if name != "wg-basic" && name != "wg-basic-netd" {
        return Err(SysError::invalid("service name"));
    }
    ffi::service_exists(name)
}

pub fn delete_service(name: &str) -> Result<(), SysError> {
    if name != "wg-basic" && name != "wg-basic-netd" {
        return Err(SysError::invalid("service name"));
    }
    ffi::delete_service(name)
}

pub fn start_service(name: &str) -> Result<(), SysError> {
    if name != "wg-basic" && name != "wg-basic-netd" {
        return Err(SysError::invalid("service name"));
    }
    ffi::start_service(name)
}

pub fn stop_service(name: &str) -> Result<(), SysError> {
    if name != "wg-basic" && name != "wg-basic-netd" {
        return Err(SysError::invalid("service name"));
    }
    ffi::stop_service(name)
}

/// Creates a local user that is not added to Administrators.
pub fn create_local_user(name: &str, password: &str) -> Result<(), SysError> {
    if name != "wg-basic" || password.len() < 16 || password.len() > 64 {
        return Err(SysError::invalid("local user"));
    }
    ffi::create_local_user(name, password)
}

pub fn delete_local_user(name: &str) -> Result<(), SysError> {
    if name != "wg-basic" {
        return Err(SysError::invalid("local user"));
    }
    ffi::delete_local_user(name)
}

pub fn account_in_administrators(account: &str) -> Result<bool, SysError> {
    ffi::account_in_administrators(account)
}
