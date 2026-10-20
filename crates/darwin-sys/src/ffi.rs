//! The single audited `unsafe` boundary of the wg-basic Darwin backend.
//!
//! Everything here is a thin, typed wrapper over one Darwin kernel
//! interface. The request numbers and struct layouts were taken from the macOS
//! SDK headers (`sys/sockio.h`, `net/if.h`, `netinet6/in6_var.h`,
//! `net/route.h`, `ifaddrs.h`) and from Apple's own `route(8)` and
//! `ifconfig(8)` implementations:
//!
//! - interface and address observation: `getifaddrs(3)`;
//! - routing-table observation: `sysctl(CTL_NET, PF_ROUTE, ..., NET_RT_DUMP)`,
//!   the same dump `route print` uses;
//! - link flags and MTU: `ioctl(SIOCGIFFLAGS/SIOCSIFFLAGS/SIOCGIFMTU)`;
//! - IPv4 addresses: `ioctl(SIOCAIFADDR/SIOCDIFADDR)` with `struct ifaliasreq`
//!   and `struct ifreq`, exactly as `ifconfig inet` sends them;
//! - IPv6 addresses: `ioctl(SIOCAIFADDR_IN6/SIOCDIFADDR_IN6)` with
//!   `struct in6_aliasreq` and `struct in6_ifreq`, exactly as
//!   `ifconfig inet6` sends them;
//! - route mutation: an `AF_ROUTE` socket carrying `RTM_ADD`/`RTM_DELETE`
//!   messages, the same wire shape `route add`/`route delete` send.
//!
//! No subprocess is executed, no human-readable tool output is parsed, and no
//! function mutates a default route or an unnamed interface.

use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::{c_char, c_int, c_uchar, c_ushort, c_void};
use std::sync::atomic::{AtomicI32, Ordering};

use ipnet::IpNet;

use super::{InterfaceInfo, RouteInfo, SysError, SysErrorKind};

// --- macOS ABI constants (verified against the macOS SDK headers) ---------

/// `IFF_UP` from `<net/if.h>`.
pub(crate) const IFF_UP: u16 = 0x1;

const SIOCGIFFLAGS: libc::c_ulong = 0xc020_6911;
const SIOCSIFFLAGS: libc::c_ulong = 0x8020_6910;
const SIOCGIFMTU: libc::c_ulong = 0xc020_6933;
const SIOCAIFADDR: libc::c_ulong = 0x8040_691a;
const SIOCDIFADDR: libc::c_ulong = 0x8020_6919;
const SIOCAIFADDR_IN6: libc::c_ulong = 0x8080_691a;
const SIOCDIFADDR_IN6: libc::c_ulong = 0x8120_6919;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 30;
const AF_LINK: u8 = 18;

const CTL_NET: c_int = 4;
const PF_ROUTE: c_int = 17;
const NET_RT_DUMP: c_int = 1;

const RTM_ADD: u8 = 0x1;
const RTM_DELETE: u8 = 0x2;
const RTM_VERSION: u8 = 5;

const RTF_UP: i32 = 0x1;
const RTF_GATEWAY: i32 = 0x2;
const RTF_HOST: i32 = 0x4;
const RTF_STATIC: i32 = 0x800;

const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
const RTA_NETMASK: i32 = 0x4;
const RTA_GENMASK: i32 = 0x8;
const RTA_IFP: i32 = 0x10;
const RTA_IFA: i32 = 0x20;

/// `struct ifaliasreq` from `<net/if.h>`: a name plus three sockets.
#[repr(C)]
struct IfAliasReq {
    ifra_name: [c_char; 16],
    ifra_addr: libc::sockaddr,
    ifra_broadaddr: libc::sockaddr,
    ifra_mask: libc::sockaddr,
}

/// `struct in6_addrlifetime` from `<netinet6/in6_var.h>`.
#[repr(C)]
struct In6AddrLifetime {
    ia6t_expire: i64,
    ia6t_preferred: i64,
    ia6t_vltime: u32,
    ia6t_pltime: u32,
}

/// `struct in6_aliasreq` from `<netinet6/in6_var.h>`.
#[repr(C)]
struct In6AliasReq {
    ifra_name: [c_char; 16],
    ifra_addr: libc::sockaddr_in6,
    ifra_dstaddr: libc::sockaddr_in6,
    ifra_prefixmask: libc::sockaddr_in6,
    ifra_flags: c_int,
    ifra_lifetime: In6AddrLifetime,
}

/// The `in6_ifreq` union; only `ifru_addr` is used here.
#[repr(C)]
union In6IfReqUnion {
    ifru_addr: libc::sockaddr_in6,
    padding: [u8; 272],
}

/// `struct in6_ifreq` from `<net/if.h>`.
#[repr(C)]
struct In6IfReq {
    ifr_name: [c_char; 16],
    ifr_ifru: In6IfReqUnion,
}

/// Monotonic sequence number for route socket messages.
static ROUTE_SEQUENCE: AtomicI32 = AtomicI32::new(1);

fn next_sequence() -> i32 {
    ROUTE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

fn last_error(operation: &'static str) -> SysError {
    let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let kind = match code {
        libc::EPERM | libc::EACCES => SysErrorKind::PermissionDenied,
        libc::ENOENT | libc::ENXIO | libc::ENODEV | libc::ESRCH => SysErrorKind::NotFound,
        libc::EEXIST | libc::EADDRINUSE => SysErrorKind::AlreadyExists,
        libc::EINVAL | libc::EAFNOSUPPORT | libc::EADDRNOTAVAIL | libc::ENOPROTOOPT => {
            SysErrorKind::InvalidArgument
        }
        _ => SysErrorKind::Os(code),
    };
    SysError { kind, operation }
}

fn bytes_of<T>(value: &T) -> Vec<u8> {
    let mut out = vec![0u8; std::mem::size_of::<T>()];
    // SAFETY: `out` is exactly `size_of::<T>()` bytes long and `value` is a
    // live, initialised `T`, so the copy is in bounds and cannot overlap.
    unsafe {
        std::ptr::copy_nonoverlapping(
            value as *const T as *const u8,
            out.as_mut_ptr(),
            std::mem::size_of::<T>(),
        );
    }
    out
}

/// Copies the family-specific body of a `sockaddr_in` into a `sockaddr`'s
/// data area. The body starts after `sa_len`/`sa_family`, so it is exactly the
/// `sin_port`/`sin_addr`/`sin_zero` bytes in network order.
fn write_sockaddr_in_body(target: &mut [c_char], source: &libc::sockaddr_in) {
    let bytes = bytes_of(source);
    for (slot, byte) in target.iter_mut().zip(bytes[2..].iter()) {
        *slot = *byte as c_char;
    }
}

fn fill_name(slot: &mut [c_char], name: &str) {
    let raw = name.as_bytes();
    for (target, byte) in slot.iter_mut().zip(raw.iter()) {
        *target = *byte as c_char;
    }
}

fn prefix_len_v4(mask: Ipv4Addr) -> u8 {
    (!u32::from(mask)).leading_zeros() as u8
}

fn prefix_len_v6(mask: Ipv6Addr) -> u8 {
    (!u128::from(mask)).leading_zeros() as u8
}

fn max_prefix_len(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn netmask_of(network: IpNet) -> IpAddr {
    match network {
        IpNet::V4(v4) => {
            let bits = IpNet::V4(v4).prefix_len();
            let mask = if bits == 0 {
                0u32
            } else {
                u32::MAX << (32 - bits)
            };
            IpAddr::V4(Ipv4Addr::from(mask))
        }
        IpNet::V6(v6) => {
            let bits = IpNet::V6(v6).prefix_len();
            let mask = if bits == 0 {
                0u128
            } else {
                u128::MAX << (128 - bits)
            };
            IpAddr::V6(Ipv6Addr::from(mask))
        }
    }
}

/// Builds the `sockaddr_in` bytes for one IPv4 address.
fn sockaddr_in_for(address: Ipv4Addr) -> libc::sockaddr_in {
    // SAFETY: every field of this kernel structure is a plain integer or a
    // byte array, so an all-zero bit pattern is a valid, fully initialised
    // value for it.
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sin.sin_len = std::mem::size_of::<libc::sockaddr_in>() as c_uchar;
    sin.sin_family = AF_INET as libc::sa_family_t;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = u32::from_ne_bytes(address.octets());
    sin
}

/// Builds the `sockaddr_in6` bytes for one IPv6 address.
fn sockaddr_in6_for(address: Ipv6Addr) -> libc::sockaddr_in6 {
    // SAFETY: every field of this kernel structure is a plain integer or a
    // byte array, so an all-zero bit pattern is a valid, fully initialised
    // value for it.
    let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sin6.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as c_uchar;
    sin6.sin6_family = AF_INET6 as libc::sa_family_t;
    sin6.sin6_port = 0;
    sin6.sin6_flowinfo = 0;
    sin6.sin6_addr.s6_addr = address.octets();
    sin6.sin6_scope_id = 0;
    sin6
}

/// Builds the `sockaddr_in`/`sockaddr_in6` bytes for one address.
fn sockaddr_for(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(v4) => bytes_of(&sockaddr_in_for(v4)),
        IpAddr::V6(v6) => bytes_of(&sockaddr_in6_for(v6)),
    }
}

/// Builds the `sockaddr_dl` bytes naming an interface.
fn sockaddr_dl_for(name: &str, index: u32) -> Vec<u8> {
    // SAFETY: every field of this kernel structure is a plain integer or a
    // byte array, so an all-zero bit pattern is a valid, fully initialised
    // value for it.
    let mut sdl: libc::sockaddr_dl = unsafe { std::mem::zeroed() };
    sdl.sdl_len = std::mem::size_of::<libc::sockaddr_dl>() as c_uchar;
    sdl.sdl_family = AF_LINK as c_uchar;
    sdl.sdl_index = index as c_ushort;
    sdl.sdl_type = 0;
    let raw = name.as_bytes();
    let length = raw.len().min(sdl.sdl_data.len());
    sdl.sdl_nlen = length as c_uchar;
    for (slot, byte) in sdl.sdl_data.iter_mut().zip(raw.iter()) {
        *slot = *byte as c_char;
    }
    bytes_of(&sdl)
}

/// Builds a zeroed `ifreq` carrying the interface name.
fn ifreq_for(name: &str) -> libc::ifreq {
    // SAFETY: every field of this kernel structure is a plain integer or a
    // byte array, so an all-zero bit pattern is a valid, fully initialised
    // value for it.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    fill_name(&mut request.ifr_name, name);
    request
}

/// Builds a `struct ifaliasreq` for one IPv4 address.
fn ifaliasreq_for(name: &str, address: IpNet) -> Option<IfAliasReq> {
    let IpAddr::V4(ip) = address.addr() else {
        return None;
    };
    let IpAddr::V4(mask) = netmask_of(address) else {
        return None;
    };
    let mut request = IfAliasReq {
        ifra_name: [0; 16],
        // SAFETY: every field of this kernel structure is a plain integer or a
        // byte array, so an all-zero bit pattern is a valid, fully initialised
        // value for it.
        ifra_addr: unsafe { std::mem::zeroed() },
        // SAFETY: every field of this kernel structure is a plain integer or a
        // byte array, so an all-zero bit pattern is a valid, fully initialised
        // value for it.
        ifra_broadaddr: unsafe { std::mem::zeroed() },
        // SAFETY: every field of this kernel structure is a plain integer or a
        // byte array, so an all-zero bit pattern is a valid, fully initialised
        // value for it.
        ifra_mask: unsafe { std::mem::zeroed() },
    };
    fill_name(&mut request.ifra_name, name);
    let address_in = sockaddr_in_for(ip);
    request.ifra_addr.sa_len = address_in.sin_len;
    request.ifra_addr.sa_family = address_in.sin_family;
    write_sockaddr_in_body(&mut request.ifra_addr.sa_data, &address_in);
    let mask_in = sockaddr_in_for(mask);
    request.ifra_mask.sa_len = mask_in.sin_len;
    request.ifra_mask.sa_family = mask_in.sin_family;
    write_sockaddr_in_body(&mut request.ifra_mask.sa_data, &mask_in);
    Some(request)
}

/// Builds a `struct in6_aliasreq` for one IPv6 address.
fn in6_aliasreq_for(name: &str, address: IpNet) -> Option<In6AliasReq> {
    let IpAddr::V6(ip) = address.addr() else {
        return None;
    };
    let IpAddr::V6(mask) = netmask_of(address) else {
        return None;
    };
    let mut request = In6AliasReq {
        ifra_name: [0; 16],
        // SAFETY: every field of this kernel structure is a plain integer or a
        // byte array, so an all-zero bit pattern is a valid, fully initialised
        // value for it.
        ifra_addr: unsafe { std::mem::zeroed() },
        // SAFETY: every field of this kernel structure is a plain integer or a
        // byte array, so an all-zero bit pattern is a valid, fully initialised
        // value for it.
        ifra_dstaddr: unsafe { std::mem::zeroed() },
        // SAFETY: every field of this kernel structure is a plain integer or a
        // byte array, so an all-zero bit pattern is a valid, fully initialised
        // value for it.
        ifra_prefixmask: unsafe { std::mem::zeroed() },
        ifra_flags: 0,
        ifra_lifetime: In6AddrLifetime {
            ia6t_expire: 0,
            ia6t_preferred: 0,
            ia6t_vltime: u32::MAX,
            ia6t_pltime: u32::MAX,
        },
    };
    fill_name(&mut request.ifra_name, name);
    request.ifra_addr = sockaddr_in6_for(ip);
    request.ifra_prefixmask = sockaddr_in6_for(mask);
    Some(request)
}

/// Builds a `struct in6_ifreq` for one IPv6 address.
fn in6_ifreq_for(name: &str, address: IpNet) -> Option<In6IfReq> {
    let IpAddr::V6(ip) = address.addr() else {
        return None;
    };
    let mut request = In6IfReq {
        ifr_name: [0; 16],
        ifr_ifru: In6IfReqUnion { padding: [0; 272] },
    };
    fill_name(&mut request.ifr_name, name);
    request.ifr_ifru.ifru_addr = sockaddr_in6_for(ip);
    Some(request)
}

/// Reads one address from an `ifaddrs` entry, with its prefix length.
fn address_of(entry: &libc::ifaddrs) -> Option<IpNet> {
    let address = entry.ifa_addr;
    if address.is_null() {
        return None;
    }
    // SAFETY: `ifa_addr` points at a live `sockaddr` owned by the list
    // returned by `getifaddrs`; we only read its family byte here.
    let family = unsafe { (*address).sa_family };
    let netmask = entry.ifa_netmask;
    match family {
        AF_INET => {
            // SAFETY: an `AF_INET` socket address is a `sockaddr_in`.
            let sin = unsafe { &*(address as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_be());
            let prefix = if netmask.is_null() {
                32
            } else {
                // SAFETY: an `AF_INET` netmask is a `sockaddr_in`.
                let mask = unsafe { &*(netmask as *const libc::sockaddr_in) };
                prefix_len_v4(Ipv4Addr::from(mask.sin_addr.s_addr.to_be()))
            };
            IpNet::new(IpAddr::V4(ip), prefix).ok()
        }
        AF_INET6 => {
            // SAFETY: an `AF_INET6` socket address is a `sockaddr_in6`.
            let sin6 = unsafe { &*(address as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let prefix = if netmask.is_null() {
                128
            } else {
                // SAFETY: an `AF_INET6` netmask is a `sockaddr_in6`.
                let mask6 = unsafe { &*(netmask as *const libc::sockaddr_in6) };
                prefix_len_v6(Ipv6Addr::from(mask6.sin6_addr.s6_addr))
            };
            IpNet::new(IpAddr::V6(ip), prefix).ok()
        }
        _ => None,
    }
}

pub(crate) fn list_interfaces() -> Result<Vec<InterfaceInfo>, SysError> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` fills `head` with a linked list that this function
    // releases with `freeifaddrs` on every path, including the error path.
    let status = unsafe { libc::getifaddrs(&mut head) };
    if status != 0 {
        return Err(last_error("getifaddrs"));
    }
    let mut raw: Vec<RawInterface> = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: `cursor` is a live node of the list returned by
        // `getifaddrs`; reading it and advancing to `ifa_next` stays in bounds.
        let entry = unsafe { &*cursor };
        // SAFETY: `ifa_name` is a NUL-terminated string owned by the list.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let flags = entry.ifa_flags as u16;
        let addresses = address_of(entry).into_iter().collect();
        raw.push(RawInterface {
            name,
            flags,
            addresses,
        });
        cursor = entry.ifa_next;
    }
    // SAFETY: `head` came from `getifaddrs` and is released exactly once.
    unsafe { libc::freeifaddrs(head) };
    let mut interfaces = group_interfaces(raw);
    for interface in &mut interfaces {
        interface.index = interface_index(&interface.name).unwrap_or(0);
        interface.mtu = interface_mtu(&interface.name).unwrap_or(0);
    }
    Ok(interfaces)
}

/// One raw `getifaddrs` observation: an interface name, its flag word, and the
/// addresses reported alongside it.
struct RawInterface {
    name: String,
    flags: u16,
    addresses: Vec<IpNet>,
}

/// Groups raw per-address observations into one record per interface.
///
/// `getifaddrs` reports one entry per interface/address pair, and the
/// link-level entry of an interface carries no address at all. An interface
/// that has no configured address is still an interface: a freshly created
/// tunnel is exactly that, and an interface missing from the inventory is an
/// interface this product cannot see, prove, or manage.
fn group_interfaces(raw: Vec<RawInterface>) -> Vec<InterfaceInfo> {
    let mut interfaces: Vec<InterfaceInfo> = Vec::new();
    for entry in raw {
        let position = match interfaces
            .iter()
            .position(|interface| interface.name == entry.name)
        {
            Some(position) => position,
            None => {
                interfaces.push(InterfaceInfo {
                    index: 0,
                    name: entry.name.clone(),
                    flags: entry.flags,
                    mtu: 0,
                    addresses: Vec::new(),
                });
                interfaces.len() - 1
            }
        };
        let interface = &mut interfaces[position];
        // A later entry for the same interface carries the authoritative flag
        // word; the link-level entry may come first.
        interface.flags = entry.flags;
        interface.addresses.extend(entry.addresses);
    }
    interfaces
}

pub(crate) fn interface_index(name: &str) -> Option<u32> {
    let c_name = CString::new(name).ok()?;
    // SAFETY: `if_nametoindex` reads a NUL-terminated name and returns zero
    // when the interface does not exist.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    (index != 0).then_some(index)
}

/// Reads a boolean `sysctl` by its dotted name.
///
/// macOS exposes the host's global forwarding state through
/// `net.inet.ip.forwarding` and `net.inet6.ip6.forwarding`. Reading them
/// proves the host-only posture; it never changes them.
pub(crate) fn sysctl_bool(name: &str) -> Option<bool> {
    extern "C" {
        fn sysctlbyname(
            name: *const c_char,
            oldp: *mut c_void,
            oldlenp: *mut usize,
            newp: *mut c_void,
            newlen: usize,
        ) -> c_int;
    }
    let c_name = std::ffi::CString::new(name).ok()?;
    let mut value: c_int = 0;
    let mut length = std::mem::size_of::<c_int>();
    // SAFETY: `sysctlbyname` writes an `int` into the buffer we own when
    // `oldlenp` says how many bytes are available.
    let status = unsafe {
        sysctlbyname(
            c_name.as_ptr(),
            &mut value as *mut c_int as *mut c_void,
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return None;
    }
    Some(value != 0)
}

/// Resolves the executable path of a running process.
///
/// This is the `proc_pidpath(3)` call from `<libproc.h>`: the only supported
/// Darwin way to learn which executable a pid is running, because macOS has
/// no `/proc`. It is what lets the backend prove that a recorded helper pid
/// still refers to the pinned helper binary rather than to a reused pid.
pub(crate) fn process_executable_path(pid: u32) -> Option<Vec<u8>> {
    extern "C" {
        fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
    }
    let mut buffer = vec![0u8; 4096];
    // SAFETY: `proc_pidpath` writes at most `buffer.len()` bytes into the
    // buffer we own and returns the number of bytes written, or zero on
    // failure.
    let written = unsafe {
        proc_pidpath(
            pid as c_int,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
        )
    };
    if written <= 0 {
        return None;
    }
    buffer.truncate(written as usize);
    Some(buffer)
}

fn ioctl_socket() -> Result<c_int, SysError> {
    // SAFETY: `socket` is a plain syscall wrapper; the descriptor is closed by
    // the caller on every path.
    let descriptor = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if descriptor < 0 {
        return Err(last_error("socket"));
    }
    Ok(descriptor)
}

pub(crate) fn interface_mtu(name: &str) -> Result<u32, SysError> {
    let descriptor = ioctl_socket()?;
    let mut request = ifreq_for(name);
    // SAFETY: `SIOCGIFMTU` writes an `int` into the `ifru_mtu` member of the
    // `ifreq` we own; the pointer is valid for the duration of the call.
    let status = unsafe { libc::ioctl(descriptor, SIOCGIFMTU, &mut request as *mut libc::ifreq) };
    // SAFETY: `descriptor` was opened by `ioctl_socket` and is not used again.
    unsafe { libc::close(descriptor) };
    if status < 0 {
        return Err(last_error("SIOCGIFMTU"));
    }
    // SAFETY: `SIOCGIFMTU` wrote the `ifru_mtu` member of the `ifreq` we
    // own, so reading that member is initialised.
    let mtu = unsafe { request.ifr_ifru.ifru_mtu };
    Ok(mtu as u32)
}

pub(crate) fn set_link_up(name: &str, up: bool) -> Result<(), SysError> {
    let descriptor = ioctl_socket()?;
    let mut request = ifreq_for(name);
    // SAFETY: `SIOCGIFFLAGS` fills the `ifru_flags` member of the `ifreq` we
    // own; the pointer is valid for the duration of the call.
    let status = unsafe { libc::ioctl(descriptor, SIOCGIFFLAGS, &mut request as *mut libc::ifreq) };
    if status < 0 {
        // SAFETY: `descriptor` was opened by `ioctl_socket` and is not used again.
        unsafe { libc::close(descriptor) };
        return Err(last_error("SIOCGIFFLAGS"));
    }
    // SAFETY: `SIOCGIFFLAGS` wrote the `ifru_flags` member of the `ifreq` we
    // own, so reading that member is initialised.
    let mut flags = unsafe { request.ifr_ifru.ifru_flags };
    if up {
        flags |= IFF_UP as libc::c_short;
    } else {
        flags &= !(IFF_UP as libc::c_short);
    }
    request.ifr_ifru.ifru_flags = flags;
    // SAFETY: `SIOCSIFFLAGS` reads the `ifru_flags` member we just set.
    let status = unsafe { libc::ioctl(descriptor, SIOCSIFFLAGS, &mut request as *mut libc::ifreq) };
    // SAFETY: `descriptor` was opened by `ioctl_socket` and is not used again.
    unsafe { libc::close(descriptor) };
    if status < 0 {
        return Err(last_error("SIOCSIFFLAGS"));
    }
    Ok(())
}

pub(crate) fn add_address(name: &str, address: IpNet) -> Result<(), SysError> {
    let descriptor = ioctl_socket()?;
    let outcome = match address.addr() {
        IpAddr::V4(_) => {
            let Some(mut request) = ifaliasreq_for(name, address) else {
                // SAFETY: `descriptor` was opened by `ioctl_socket` and is not
                // used again.
                unsafe { libc::close(descriptor) };
                return Err(SysError {
                    kind: SysErrorKind::InvalidArgument,
                    operation: "SIOCAIFADDR",
                });
            };
            // SAFETY: `SIOCAIFADDR` reads the `struct ifaliasreq` we built; the
            // pointer is valid and correctly sized for the duration of the
            // call.
            let status =
                unsafe { libc::ioctl(descriptor, SIOCAIFADDR, &mut request as *mut IfAliasReq) };
            if status < 0 {
                Err(last_error("SIOCAIFADDR"))
            } else {
                Ok(())
            }
        }
        IpAddr::V6(_) => {
            let Some(mut request) = in6_aliasreq_for(name, address) else {
                // SAFETY: `descriptor` was opened by `ioctl_socket` and is not
                // used again.
                unsafe { libc::close(descriptor) };
                return Err(SysError {
                    kind: SysErrorKind::InvalidArgument,
                    operation: "SIOCAIFADDR_IN6",
                });
            };
            // SAFETY: `SIOCAIFADDR_IN6` reads the `struct in6_aliasreq` we
            // built; the pointer is valid and correctly sized for the duration
            // of the call.
            let status = unsafe {
                libc::ioctl(
                    descriptor,
                    SIOCAIFADDR_IN6,
                    &mut request as *mut In6AliasReq,
                )
            };
            if status < 0 {
                Err(last_error("SIOCAIFADDR_IN6"))
            } else {
                Ok(())
            }
        }
    };
    // SAFETY: `descriptor` was opened by `ioctl_socket` and is not used again.
    unsafe { libc::close(descriptor) };
    outcome
}

pub(crate) fn remove_address(name: &str, address: IpNet) -> Result<(), SysError> {
    let descriptor = ioctl_socket()?;
    let outcome = match address.addr() {
        IpAddr::V4(ip) => {
            let mut request = ifreq_for(name);
            let address_in = sockaddr_in_for(ip);
            request.ifr_ifru.ifru_addr.sa_len = address_in.sin_len;
            request.ifr_ifru.ifru_addr.sa_family = address_in.sin_family;
            // SAFETY: the `ifreq` was zeroed before use and the union member
            // is written through the same `ifreq` below; taking the mutable
            // reference here only borrows the union storage we own.
            let slot = unsafe { &mut request.ifr_ifru.ifru_addr };
            write_sockaddr_in_body(&mut slot.sa_data, &address_in);
            // SAFETY: `SIOCDIFADDR` reads the `ifru_addr` member of the
            // `ifreq` we own; the pointer is valid for the duration of the
            // call.
            let status =
                unsafe { libc::ioctl(descriptor, SIOCDIFADDR, &mut request as *mut libc::ifreq) };
            if status < 0 {
                Err(last_error("SIOCDIFADDR"))
            } else {
                Ok(())
            }
        }
        IpAddr::V6(ip) => {
            let Some(mut request) = in6_ifreq_for(name, address) else {
                // SAFETY: `descriptor` was opened by `ioctl_socket` and is not
                // used again.
                unsafe { libc::close(descriptor) };
                return Err(SysError {
                    kind: SysErrorKind::InvalidArgument,
                    operation: "SIOCDIFADDR_IN6",
                });
            };
            request.ifr_ifru.ifru_addr = sockaddr_in6_for(ip);
            // SAFETY: `SIOCDIFADDR_IN6` reads the `struct in6_ifreq` we built;
            // the pointer is valid and correctly sized for the duration of the
            // call.
            let status =
                unsafe { libc::ioctl(descriptor, SIOCDIFADDR_IN6, &mut request as *mut In6IfReq) };
            if status < 0 {
                Err(last_error("SIOCDIFADDR_IN6"))
            } else {
                Ok(())
            }
        }
    };
    // SAFETY: `descriptor` was opened by `ioctl_socket` and is not used again.
    unsafe { libc::close(descriptor) };
    outcome
}

/// Reads the `sockaddr` at `cursor`, returning its bytes and padded length.
fn take_sockaddr(payload: &[u8], cursor: usize) -> Option<(&[u8], usize)> {
    let length = *payload.get(cursor)? as usize;
    if length < 2 || cursor + length > payload.len() {
        return None;
    }
    Some((&payload[cursor..cursor + length], (length + 3) & !3))
}

fn sockaddr_ip(bytes: &[u8]) -> Option<IpAddr> {
    let family = *bytes.get(1)?;
    match family {
        AF_INET if bytes.len() >= std::mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: an `AF_INET` socket address is a `sockaddr_in` and the
            // slice is at least that long.
            let sin = unsafe { &*(bytes.as_ptr() as *const libc::sockaddr_in) };
            Some(IpAddr::V4(Ipv4Addr::from(sin.sin_addr.s_addr.to_be())))
        }
        AF_INET6 if bytes.len() >= std::mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: an `AF_INET6` socket address is a `sockaddr_in6` and the
            // slice is at least that long.
            let sin6 = unsafe { &*(bytes.as_ptr() as *const libc::sockaddr_in6) };
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

fn sockaddr_prefix(bytes: &[u8]) -> Option<u8> {
    let family = *bytes.get(1)?;
    match family {
        AF_INET if bytes.len() >= std::mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: an `AF_INET` netmask is a `sockaddr_in` and the slice is
            // at least that long.
            let sin = unsafe { &*(bytes.as_ptr() as *const libc::sockaddr_in) };
            Some(prefix_len_v4(Ipv4Addr::from(sin.sin_addr.s_addr.to_be())))
        }
        AF_INET6 if bytes.len() >= std::mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: an `AF_INET6` netmask is a `sockaddr_in6` and the slice is
            // at least that long.
            let sin6 = unsafe { &*(bytes.as_ptr() as *const libc::sockaddr_in6) };
            Some(prefix_len_v6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

fn sockaddr_link(bytes: &[u8]) -> Option<(String, u32)> {
    let family = *bytes.get(1)?;
    if family != AF_LINK || bytes.len() < std::mem::size_of::<libc::sockaddr_dl>() {
        return None;
    }
    // SAFETY: an `AF_LINK` socket address is a `sockaddr_dl` and the slice is
    // at least that long.
    let sdl = unsafe { &*(bytes.as_ptr() as *const libc::sockaddr_dl) };
    let length = (sdl.sdl_nlen as usize).min(sdl.sdl_data.len());
    let name = sdl.sdl_data[..length]
        .iter()
        .map(|byte| *byte as u8 as char)
        .collect::<String>();
    Some((name, sdl.sdl_index as u32))
}

fn parse_route(header: &libc::rt_msghdr, payload: &[u8]) -> Option<RouteInfo> {
    let mut cursor = 0usize;
    let mut destination: Option<IpAddr> = None;
    let mut gateway: Option<IpAddr> = None;
    let mut prefix: Option<u8> = None;
    let mut interface_name: Option<String> = None;
    let mut interface_index_value = 0u32;
    // The socket addresses appear in `RTAX_*` order, which is the order this
    // loop walks.
    for which in [
        RTA_DST,
        RTA_GATEWAY,
        RTA_NETMASK,
        RTA_GENMASK,
        RTA_IFP,
        RTA_IFA,
    ] {
        if header.rtm_addrs & which == 0 {
            continue;
        }
        let Some((bytes, consumed)) = take_sockaddr(payload, cursor) else {
            break;
        };
        cursor += consumed;
        match which {
            RTA_DST => destination = sockaddr_ip(bytes),
            RTA_GATEWAY => gateway = sockaddr_ip(bytes),
            RTA_NETMASK => prefix = sockaddr_prefix(bytes),
            RTA_IFP => {
                if let Some((name, index)) = sockaddr_link(bytes) {
                    interface_name = Some(name);
                    interface_index_value = index;
                }
            }
            _ => {}
        }
    }
    let address = destination?;
    let network = IpNet::new(address, prefix.unwrap_or(max_prefix_len(address))).ok()?;
    Some(RouteInfo {
        destination: network,
        gateway,
        interface_index: interface_index_value,
        interface_name: interface_name.unwrap_or_default(),
        flags: header.rtm_flags as u32,
    })
}

fn parse_route_dump(buffer: &[u8]) -> Vec<RouteInfo> {
    let header_size = std::mem::size_of::<libc::rt_msghdr>();
    let mut routes = Vec::new();
    let mut offset = 0usize;
    while offset + header_size <= buffer.len() {
        // SAFETY: the dump is a sequence of `rt_msghdr` messages; the header at
        // `offset` is read unaligned because the buffer is byte-addressed.
        let header = unsafe {
            std::ptr::read_unaligned(buffer.as_ptr().add(offset) as *const libc::rt_msghdr)
        };
        let length = header.rtm_msglen as usize;
        if length < header_size || offset + length > buffer.len() {
            break;
        }
        if header.rtm_type == RTM_ADD {
            if let Some(route) =
                parse_route(&header, &buffer[offset + header_size..offset + length])
            {
                routes.push(route);
            }
        }
        offset += length;
    }
    routes
}

pub(crate) fn list_routes() -> Result<Vec<RouteInfo>, SysError> {
    let mut mib: [c_int; 6] = [CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0];
    let mut needed: usize = 0;
    // SAFETY: querying the size of a sysctl buffer is the documented first
    // call; `oldp` is null and `oldlenp` receives the required length.
    let status = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return Err(last_error("sysctl route dump"));
    }
    if needed == 0 {
        return Ok(Vec::new());
    }
    let mut buffer = vec![0u8; needed];
    // SAFETY: `buffer` is exactly the number of bytes the kernel reported for
    // this query, and `needed` is updated in place by the kernel.
    let status = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buffer.as_mut_ptr() as *mut c_void,
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return Err(last_error("sysctl route dump"));
    }
    let length = needed.min(buffer.len());
    Ok(parse_route_dump(&buffer[..length]))
}

/// Assembles one routing message for the `AF_ROUTE` socket.
///
/// This is pure: it builds the exact bytes `route add`/`route delete` send.
fn build_route_message(
    command: u8,
    destination: IpNet,
    gateway: Option<IpAddr>,
    interface: &str,
    interface_index: u32,
    sequence: i32,
) -> Vec<u8> {
    let mut addresses = RTA_DST | RTA_NETMASK | RTA_IFP;
    let mut flags = RTF_UP | RTF_STATIC;
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&sockaddr_for(destination.addr()));
    if let Some(next_hop) = gateway {
        addresses |= RTA_GATEWAY;
        flags |= RTF_GATEWAY;
        payload.extend_from_slice(&sockaddr_for(next_hop));
    }
    payload.extend_from_slice(&sockaddr_for(netmask_of(destination)));
    payload.extend_from_slice(&sockaddr_dl_for(interface, interface_index));
    if destination.prefix_len() == max_prefix_len(destination.addr()) {
        flags |= RTF_HOST;
    }

    let header_size = std::mem::size_of::<libc::rt_msghdr>();
    // SAFETY: every field of this kernel structure is a plain integer or a
    // byte array, so an all-zero bit pattern is a valid, fully initialised
    // value for it.
    let mut header: libc::rt_msghdr = unsafe { std::mem::zeroed() };
    header.rtm_msglen = (header_size + payload.len()) as libc::c_ushort;
    header.rtm_version = RTM_VERSION;
    header.rtm_type = command;
    header.rtm_index = 0;
    header.rtm_flags = flags;
    header.rtm_addrs = addresses;
    header.rtm_seq = sequence;

    let mut message = vec![0u8; header_size];
    // SAFETY: `message` is exactly `size_of::<rt_msghdr>()` bytes long and
    // `header` is a live, initialised value, so the copy is in bounds.
    unsafe {
        std::ptr::copy_nonoverlapping(
            &header as *const libc::rt_msghdr as *const u8,
            message.as_mut_ptr(),
            header_size,
        );
    }
    message.extend_from_slice(&payload);
    message
}

fn write_route(
    command: u8,
    destination: IpNet,
    gateway: Option<IpAddr>,
    interface: &str,
) -> Result<(), SysError> {
    let index = interface_index(interface).ok_or(SysError {
        kind: SysErrorKind::NotFound,
        operation: "route",
    })?;
    let message = build_route_message(
        command,
        destination,
        gateway,
        interface,
        index,
        next_sequence(),
    );
    // SAFETY: an `AF_ROUTE` socket is the documented transport for routing
    // messages; the descriptor is closed on every path below.
    let descriptor = unsafe { libc::socket(libc::AF_ROUTE, libc::SOCK_RAW, 0) };
    if descriptor < 0 {
        return Err(last_error("route socket"));
    }
    // SAFETY: `message` is a fully initialised routing message of exactly
    // `rtm_msglen` bytes and stays alive for the duration of the call.
    let written =
        unsafe { libc::write(descriptor, message.as_ptr() as *const c_void, message.len()) };
    // SAFETY: `descriptor` was opened above and is not used again.
    unsafe { libc::close(descriptor) };
    if written < 0 {
        return Err(last_error("route write"));
    }
    if written as usize != message.len() {
        return Err(SysError {
            kind: SysErrorKind::Os(libc::EIO),
            operation: "route write",
        });
    }
    Ok(())
}

pub(crate) fn add_route(
    destination: IpNet,
    gateway: Option<IpAddr>,
    interface: &str,
) -> Result<(), SysError> {
    write_route(RTM_ADD, destination, gateway, interface)
}

pub(crate) fn remove_route(
    destination: IpNet,
    gateway: Option<IpAddr>,
    interface: &str,
) -> Result<(), SysError> {
    write_route(RTM_DELETE, destination, gateway, interface)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The NUL-terminated name in a fixed-size kernel name field.
    fn name_bytes(slot: &[c_char]) -> Vec<u8> {
        let bytes: Vec<u8> = slot.iter().map(|byte| *byte as u8).collect();
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        bytes[..end].to_vec()
    }

    fn sign_bytes(slot: &[c_char]) -> Vec<u8> {
        slot.iter().map(|byte| *byte as u8).collect()
    }

    /// A raw observation of one interface that carries no address at all.
    fn raw_without_addresses(name: &str, flags: u16) -> RawInterface {
        RawInterface {
            name: name.to_owned(),
            flags,
            addresses: Vec::new(),
        }
    }

    #[test]
    fn an_interface_without_an_address_is_still_listed() {
        // A freshly created tunnel has no configured address yet. If the
        // inventory dropped it, the product could neither see nor prove the
        // device it just created.
        let grouped = group_interfaces(vec![raw_without_addresses("utun7", 0x1)]);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].name, "utun7");
        assert!(grouped[0].addresses.is_empty());
    }

    #[test]
    fn the_link_level_and_address_entries_group_into_one_interface() {
        let address: IpNet = "192.0.2.1/24".parse().expect("a test address");
        let grouped = group_interfaces(vec![
            raw_without_addresses("en0", 0x1),
            RawInterface {
                name: "en0".to_owned(),
                flags: 0x1,
                addresses: vec![address],
            },
        ]);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].name, "en0");
        assert_eq!(grouped[0].addresses, vec![address]);
    }

    #[test]
    fn prefix_lengths_follow_the_netmask() {
        assert_eq!(prefix_len_v4(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(prefix_len_v4(Ipv4Addr::new(255, 255, 255, 255)), 32);
        assert_eq!(prefix_len_v4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        assert_eq!(prefix_len_v6(Ipv6Addr::UNSPECIFIED), 0);
        assert_eq!(
            prefix_len_v6(Ipv6Addr::new(0xffff, 0xffff, 0, 0, 0, 0, 0, 0)),
            32
        );
    }

    #[test]
    fn netmask_matches_the_prefix_length() {
        let network: IpNet = "10.0.0.4/24".parse().unwrap();
        assert_eq!(
            netmask_of(network),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))
        );
        let network: IpNet = "2001:db8::1/64".parse().unwrap();
        assert_eq!(
            netmask_of(network),
            IpAddr::V6(Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0))
        );
    }

    #[test]
    fn route_message_carries_the_expected_socket_addresses() {
        let destination: IpNet = "10.0.0.2/32".parse().unwrap();
        let message = build_route_message(RTM_ADD, destination, None, "utun7", 19, 42);
        let header_size = std::mem::size_of::<libc::rt_msghdr>();
        assert!(message.len() > header_size);
        // SAFETY: the message was built by this module and is at least a
        // header long.
        let header =
            unsafe { std::ptr::read_unaligned(message.as_ptr() as *const libc::rt_msghdr) };
        assert_eq!(header.rtm_type, RTM_ADD);
        assert_eq!(header.rtm_version, RTM_VERSION);
        assert_eq!(header.rtm_seq, 42);
        assert_eq!(header.rtm_msglen as usize, message.len());
        assert_eq!(header.rtm_addrs, RTA_DST | RTA_NETMASK | RTA_IFP);
        assert_eq!(header.rtm_flags & RTF_UP, RTF_UP);
        assert_eq!(header.rtm_flags & RTF_HOST, RTF_HOST);
        assert_eq!(header.rtm_flags & RTF_GATEWAY, 0);

        // The destination socket address is first, then the netmask, then the
        // interface name.
        let payload = &message[header_size..];
        let (destination_bytes, consumed) = take_sockaddr(payload, 0).unwrap();
        assert_eq!(
            sockaddr_ip(destination_bytes),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
        let (mask_bytes, consumed) = take_sockaddr(payload, consumed).unwrap();
        assert_eq!(
            sockaddr_prefix(mask_bytes),
            Some(32),
            "a /32 destination carries a full netmask"
        );
        let (link_bytes, _) = take_sockaddr(payload, consumed * 2).unwrap();
        assert_eq!(sockaddr_link(link_bytes), Some(("utun7".to_owned(), 19)));
    }

    #[test]
    fn gateway_routes_set_the_gateway_flag_and_carry_the_next_hop() {
        let destination: IpNet = "10.0.0.0/24".parse().unwrap();
        let gateway: IpAddr = "10.0.0.1".parse().unwrap();
        let message = build_route_message(RTM_ADD, destination, Some(gateway), "utun7", 19, 7);
        let header_size = std::mem::size_of::<libc::rt_msghdr>();
        // SAFETY: the message was built by this module and is at least a
        // header long.
        let header =
            unsafe { std::ptr::read_unaligned(message.as_ptr() as *const libc::rt_msghdr) };
        assert_eq!(
            header.rtm_addrs,
            RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_IFP
        );
        assert_eq!(header.rtm_flags & RTF_GATEWAY, RTF_GATEWAY);
        assert_eq!(header.rtm_flags & RTF_HOST, 0);
        let payload = &message[header_size..];
        let (_, consumed) = take_sockaddr(payload, 0).unwrap();
        let (gateway_bytes, _) = take_sockaddr(payload, consumed).unwrap();
        assert_eq!(
            sockaddr_ip(gateway_bytes),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }

    #[test]
    fn request_structs_match_the_macos_sdk_layouts() {
        assert_eq!(std::mem::size_of::<IfAliasReq>(), 64);
        assert_eq!(std::mem::size_of::<In6AliasReq>(), 128);
        assert_eq!(std::mem::size_of::<In6IfReq>(), 288);
        assert_eq!(std::mem::size_of::<libc::rt_msghdr>(), 92);
        assert_eq!(std::mem::size_of::<libc::sockaddr_dl>(), 20);
    }

    #[test]
    fn ipv4_alias_requests_carry_the_address_and_its_netmask() {
        let address: IpNet = "10.8.0.1/24".parse().unwrap();
        let request = ifaliasreq_for("utun7", address).unwrap();
        assert_eq!(name_bytes(&request.ifra_name), b"utun7".to_vec());
        assert_eq!(request.ifra_addr.sa_family, AF_INET as libc::sa_family_t);
        let body = &request.ifra_addr.sa_data[2..6];
        assert_eq!(sign_bytes(body), vec![10, 8, 0, 1]);
        let mask = &request.ifra_mask.sa_data[2..6];
        assert_eq!(sign_bytes(mask), vec![255, 255, 255, 0]);
    }

    #[test]
    fn ipv6_alias_requests_carry_the_address_and_its_prefix_mask() {
        let address: IpNet = "2001:db8::1/64".parse().unwrap();
        let request = in6_aliasreq_for("utun7", address).unwrap();
        assert_eq!(name_bytes(&request.ifra_name), b"utun7".to_vec());
        assert_eq!(request.ifra_addr.sin6_len, 28);
        assert_eq!(
            Ipv6Addr::from(request.ifra_addr.sin6_addr.s6_addr),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
        );
        assert_eq!(
            Ipv6Addr::from(request.ifra_prefixmask.sin6_addr.s6_addr),
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0)
        );
        assert_eq!(request.ifra_lifetime.ia6t_vltime, u32::MAX);
    }
}
