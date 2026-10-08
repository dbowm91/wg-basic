//! Deterministic IPv4 client-address allocation.
//!
//! A pure function of product state. It performs no I/O, holds no state, and
//! cannot race: the caller supplies the prefix, the reserved server addresses,
//! and every assigned client address, and gets back either a specific address
//! or a bounded error. The same inputs always produce the same answer, which is
//! what makes "the lowest usable free address" a testable claim rather than a
//! hopeful one.
//!
//! The algorithm is a sorted gap scan over `u32` space, never a walk of the
//! address space. A /8 has sixteen million addresses and allocation must be
//! independent of that number.

use ipnet::{IpNet, Ipv4Net};
use std::net::{IpAddr, Ipv4Addr};

/// What allocation was asked for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressRequest {
    /// Take the lowest usable address not already reserved.
    Automatic,
    /// Take exactly this address, or explain why it cannot be used.
    Requested(Ipv4Addr),
}

/// Everything the allocator needs to know, gathered by the caller inside the
/// mutation transaction.
///
/// Note that `reserved_clients` deliberately includes *disabled* clients: a
/// disabled client keeps its address, so its address must not be handed to
/// somebody else and then collide when the first client is re-enabled.
#[derive(Clone, Debug)]
pub struct AllocationContext {
    prefix: Ipv4Addr,
    prefix_len: u8,
    /// Server/interface addresses inside the prefix.
    server_addresses: Vec<Ipv4Addr>,
    /// Every managed client's address, enabled or not.
    reserved_clients: Vec<Ipv4Addr>,
}

impl AllocationContext {
    /// Builds a context from the selected IPv4 tunnel prefix.
    pub fn new(prefix: IpNet) -> Result<Self, AllocationError> {
        let addr = prefix.addr();
        if !addr.is_ipv4() {
            return Err(AllocationError::NotIpv4);
        }
        let IpNet::V4(v4) = prefix else {
            return Err(AllocationError::NotIpv4);
        };
        let (network, prefix_len) = (v4.network(), v4.prefix_len());
        if prefix_len > 30 {
            // A /31 has no usable host, and /32 is a single address rather than
            // a pool. Treating either as a pool would hand out the network
            // address or produce a range whose bounds cross.
            return Err(AllocationError::PrefixTooSmall(prefix_len));
        }
        Ok(Self {
            prefix: network,
            prefix_len,
            server_addresses: Vec::new(),
            reserved_clients: Vec::new(),
        })
    }

    pub fn with_server_addresses(mut self, addresses: impl IntoIterator<Item = Ipv4Addr>) -> Self {
        self.server_addresses.extend(addresses);
        self
    }

    pub fn with_reserved_clients(mut self, addresses: impl IntoIterator<Item = Ipv4Addr>) -> Self {
        self.reserved_clients.extend(addresses);
        self
    }

    /// The lowest and highest address this prefix may allocate.
    ///
    /// Network and broadcast are excluded wherever the prefix is wide enough to
    /// have them: a /30 is exactly network, two hosts, broadcast.
    ///
    /// Computed in `u64` because a /0 spans all 2^32 addresses, whose last
    /// address is `u32::MAX`. Doing this arithmetic in `u32` wraps a prefix
    /// whose size is a multiple of 2^32 down to an empty one.
    fn usable_bounds(&self) -> Result<(u32, u32), AllocationError> {
        let size = 1u64 << (32 - u32::from(self.prefix_len));
        let base = u64::from(u32::from(self.prefix));
        let last = base
            .checked_add(size - 1)
            .filter(|last| *last <= u64::from(u32::MAX))
            .ok_or(AllocationError::PrefixTooSmall(self.prefix_len))? as u32;

        if size <= 2 {
            // /31 or /32: no distinct network/broadcast pair exists to reserve.
            return Ok((u32::from(self.prefix), last));
        }
        Ok((base as u32 + 1, last - 1))
    }

    /// Allocates an address according to `request`.
    pub fn allocate(&self, request: AddressRequest) -> Result<Ipv4Addr, AllocationError> {
        let (low, high) = self.usable_bounds()?;
        if low > high {
            return Err(AllocationError::Exhausted);
        }

        let used = self.used_set();
        match request {
            AddressRequest::Requested(address) => {
                let value = u32::from(address);
                if value < low || value > high {
                    return Err(AllocationError::OutsidePrefix(address));
                }
                if used.contains(&value) {
                    return Err(AllocationError::AlreadyUsed(address));
                }
                Ok(address)
            }
            AddressRequest::Automatic => {
                let mut candidate = low;
                for value in used.range(low..).copied() {
                    if value > high {
                        break;
                    }
                    if value > candidate {
                        // Everything between `candidate` and `value` is free, so
                        // the first gap wins without walking the addresses in it.
                        return Ok(Ipv4Addr::from(candidate));
                    }
                    // `value == candidate`: this address is taken, step over it.
                    candidate = value + 1;
                }
                if candidate > high {
                    return Err(AllocationError::Exhausted);
                }
                Ok(Ipv4Addr::from(candidate))
            }
        }
    }

    /// Every unusable address inside the pool, sorted and deduplicated.
    ///
    /// Built from the product state the caller supplied, so it is exactly the
    /// set the gap scan has to step over. `BTreeSet` gives the sorted iteration
    /// the scan relies on for free, and deduplicates an address that is both a
    /// server address and a client address.
    fn used_set(&self) -> std::collections::BTreeSet<u32> {
        let mut used = std::collections::BTreeSet::new();
        let Ok((low, high)) = self.usable_bounds() else {
            return used;
        };
        // The network address sits below the usable bounds, so it is reserved
        // explicitly rather than being relied upon to fall outside the scan.
        used.insert(u32::from(self.prefix));
        for address in self.server_addresses.iter().chain(&self.reserved_clients) {
            let value = u32::from(*address);
            if (low.saturating_sub(1)..=high.saturating_add(1)).contains(&value) {
                used.insert(value);
            }
        }
        used
    }

    /// The prefix this context allocates inside.
    pub fn prefix(&self) -> IpNet {
        IpNet::V4(Ipv4Net::new(self.prefix, self.prefix_len).expect("a validated prefix"))
    }
}

/// Allocates one IPv4 client address inside `prefix`.
///
/// Convenience over [`AllocationContext::allocate`] for the common case.
pub fn allocate_ipv4(
    prefix: IpNet,
    request: AddressRequest,
    server_addresses: impl IntoIterator<Item = Ipv4Addr>,
    reserved_clients: impl IntoIterator<Item = Ipv4Addr>,
) -> Result<Ipv4Addr, AllocationError> {
    let context = AllocationContext::new(prefix)?
        .with_server_addresses(server_addresses)
        .with_reserved_clients(reserved_clients);
    context.allocate(request)
}

/// Narrows any address column to IPv4, which is the only family M001 allocates.
pub fn ipv4_of(address: IpAddr) -> Option<Ipv4Addr> {
    match address {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AllocationError {
    #[error("Phase 8 M001 allocates IPv4 addresses only")]
    NotIpv4,
    #[error("prefix length /{0} is too small to allocate a client address")]
    PrefixTooSmall(u8),
    #[error("every usable address inside the prefix is already assigned")]
    Exhausted,
    #[error("address {0} is outside the selected prefix")]
    OutsidePrefix(Ipv4Addr),
    #[error("address {0} is already assigned or reserved")]
    AlreadyUsed(Ipv4Addr),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(value: &str) -> IpNet {
        value.parse().unwrap()
    }

    fn context(value: &str) -> AllocationContext {
        AllocationContext::new(net(value)).unwrap()
    }

    #[test]
    fn allocates_the_lowest_usable_free_address() {
        let allocated = context("10.8.0.0/24").allocate(AddressRequest::Automatic);
        assert_eq!(allocated, Ok(Ipv4Addr::new(10, 8, 0, 1)));
    }

    #[test]
    fn skips_the_network_address_and_a_leading_server_address() {
        let allocated = context("10.8.0.0/24")
            .with_server_addresses([Ipv4Addr::new(10, 8, 0, 1)])
            .allocate(AddressRequest::Automatic);
        assert_eq!(allocated, Ok(Ipv4Addr::new(10, 8, 0, 2)));
    }

    #[test]
    fn skips_the_broadcast_address_at_the_top_of_the_pool() {
        // A /29 is .0 (network), .1 .. .6 (hosts), .7 (broadcast). With every
        // usable host taken, allocation must report exhaustion rather than hand
        // out the network or broadcast address.
        let context = self::context("10.8.0.0/29").with_reserved_clients([
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(10, 8, 0, 2),
            Ipv4Addr::new(10, 8, 0, 3),
            Ipv4Addr::new(10, 8, 0, 4),
            Ipv4Addr::new(10, 8, 0, 5),
            Ipv4Addr::new(10, 8, 0, 6),
        ]);
        assert_eq!(
            context.allocate(AddressRequest::Automatic),
            Err(AllocationError::Exhausted)
        );

        // With one host free, that host -- not the broadcast -- is what comes back.
        let one_free = self::context("10.8.0.0/29").with_reserved_clients([
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(10, 8, 0, 2),
            Ipv4Addr::new(10, 8, 0, 3),
            Ipv4Addr::new(10, 8, 0, 4),
            Ipv4Addr::new(10, 8, 0, 5),
        ]);
        assert_eq!(
            one_free.allocate(AddressRequest::Automatic),
            Ok(Ipv4Addr::new(10, 8, 0, 6))
        );
    }

    #[test]
    fn fills_the_first_gap_not_merely_the_next_integer() {
        // 10 is taken, 11 is free: the allocator must notice the gap rather
        // than marching upward one address at a time.
        let allocated = context("10.8.0.0/24")
            .with_reserved_clients([
                Ipv4Addr::new(10, 8, 0, 1),
                Ipv4Addr::new(10, 8, 0, 2),
                Ipv4Addr::new(10, 8, 0, 10),
                Ipv4Addr::new(10, 8, 0, 11),
            ])
            .allocate(AddressRequest::Automatic);
        assert_eq!(allocated, Ok(Ipv4Addr::new(10, 8, 0, 3)));
    }

    #[test]
    fn a_server_address_in_the_middle_is_reserved() {
        let allocated = context("10.8.0.0/24")
            .with_server_addresses([Ipv4Addr::new(10, 8, 0, 100)])
            .with_reserved_clients([
                Ipv4Addr::new(10, 8, 0, 1),
                Ipv4Addr::new(10, 8, 0, 99),
                Ipv4Addr::new(10, 8, 0, 101),
            ])
            .allocate(AddressRequest::Automatic);
        assert_eq!(
            allocated,
            Ok(Ipv4Addr::new(10, 8, 0, 2)),
            ".100 is the server's and must be stepped over"
        );
    }

    #[test]
    fn a_disabled_client_keeps_its_address_reserved() {
        let allocated = context("10.8.0.0/24")
            .with_reserved_clients([Ipv4Addr::new(10, 8, 0, 1), Ipv4Addr::new(10, 8, 0, 2)])
            .allocate(AddressRequest::Automatic);
        assert_eq!(
            allocated,
            Ok(Ipv4Addr::new(10, 8, 0, 3)),
            "a disabled client still holds .2, so a new client must not take it"
        );
    }

    #[test]
    fn handles_a_slash_30_pool_exactly() {
        let allocated = context("10.8.0.0/30").allocate(AddressRequest::Automatic);
        assert_eq!(allocated, Ok(Ipv4Addr::new(10, 8, 0, 1)));
        let exhausted = context("10.8.0.0/30")
            .with_server_addresses([Ipv4Addr::new(10, 8, 0, 1)])
            .with_reserved_clients([Ipv4Addr::new(10, 8, 0, 2)])
            .allocate(AddressRequest::Automatic);
        assert_eq!(exhausted, Err(AllocationError::Exhausted));
    }

    #[test]
    fn handles_slash_24_and_slash_16_prefixes() {
        assert_eq!(
            context("10.8.0.0/24").allocate(AddressRequest::Automatic),
            Ok(Ipv4Addr::new(10, 8, 0, 1))
        );
        assert_eq!(
            context("172.16.0.0/16").allocate(AddressRequest::Automatic),
            Ok(Ipv4Addr::new(172, 16, 0, 1))
        );
    }

    #[test]
    fn handles_the_largest_prefix_without_scanning_it() {
        // 0.0.0.0/0 is four billion addresses; a linear scan would be unusable.
        let allocated = context("0.0.0.0/0")
            .with_reserved_clients([Ipv4Addr::new(0, 0, 0, 1), Ipv4Addr::new(0, 0, 0, 2)])
            .allocate(AddressRequest::Automatic);
        assert_eq!(allocated, Ok(Ipv4Addr::new(0, 0, 0, 3)));
    }

    #[test]
    fn a_requested_address_fails_on_reservation_and_out_of_prefix() {
        let ctx = context("10.8.0.0/24")
            .with_server_addresses([Ipv4Addr::new(10, 8, 0, 1)])
            .with_reserved_clients([Ipv4Addr::new(10, 8, 0, 2)]);
        assert_eq!(
            ctx.allocate(AddressRequest::Requested(Ipv4Addr::new(10, 8, 0, 2))),
            Err(AllocationError::AlreadyUsed(Ipv4Addr::new(10, 8, 0, 2)))
        );
        assert_eq!(
            ctx.allocate(AddressRequest::Requested(Ipv4Addr::new(10, 8, 0, 1))),
            Err(AllocationError::AlreadyUsed(Ipv4Addr::new(10, 8, 0, 1))),
            "a server address is reserved"
        );
        assert_eq!(
            ctx.allocate(AddressRequest::Requested(Ipv4Addr::new(10, 8, 0, 0))),
            Err(AllocationError::OutsidePrefix(Ipv4Addr::new(10, 8, 0, 0))),
            "the network address is not allocatable"
        );
        assert_eq!(
            ctx.allocate(AddressRequest::Requested(Ipv4Addr::new(10, 8, 0, 255))),
            Err(AllocationError::OutsidePrefix(Ipv4Addr::new(10, 8, 0, 255))),
            "the broadcast address is not allocatable"
        );
        assert_eq!(
            ctx.allocate(AddressRequest::Requested(Ipv4Addr::new(192, 168, 1, 1))),
            Err(AllocationError::OutsidePrefix(Ipv4Addr::new(
                192, 168, 1, 1
            )))
        );
        assert_eq!(
            ctx.allocate(AddressRequest::Requested(Ipv4Addr::new(10, 8, 0, 7))),
            Ok(Ipv4Addr::new(10, 8, 0, 7))
        );
    }

    #[test]
    fn allocation_is_deterministic_across_repeated_calls() {
        let ctx = context("10.8.0.0/24")
            .with_reserved_clients([Ipv4Addr::new(10, 8, 0, 1), Ipv4Addr::new(10, 8, 0, 5)]);
        let first = ctx.allocate(AddressRequest::Automatic);
        for _ in 0..16 {
            assert_eq!(ctx.allocate(AddressRequest::Automatic), first);
        }
        assert_eq!(first, Ok(Ipv4Addr::new(10, 8, 0, 2)));
    }

    #[test]
    fn duplicate_reservations_do_not_disturb_the_gap_scan() {
        let ctx = context("10.8.0.0/24").with_reserved_clients([
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(10, 8, 0, 1),
        ]);
        assert_eq!(
            ctx.allocate(AddressRequest::Automatic),
            Ok(Ipv4Addr::new(10, 8, 0, 2))
        );
    }

    #[test]
    fn refuses_ipv6_and_prefixes_with_no_usable_hosts() {
        assert!(matches!(
            AllocationContext::new(net("2001:db8::/64")),
            Err(AllocationError::NotIpv4)
        ));
        assert!(matches!(
            AllocationContext::new(net("10.8.0.0/31")),
            Err(AllocationError::PrefixTooSmall(31))
        ));
        assert!(matches!(
            AllocationContext::new(net("10.8.0.1/32")),
            Err(AllocationError::PrefixTooSmall(32))
        ));
    }

    #[test]
    fn a_non_zero_network_octet_is_normalised_before_allocation() {
        let ctx = context("10.8.0.77/24");
        assert_eq!(ctx.prefix(), net("10.8.0.0/24"));
        assert_eq!(
            ctx.allocate(AddressRequest::Automatic),
            Ok(Ipv4Addr::new(10, 8, 0, 1))
        );
    }
}
