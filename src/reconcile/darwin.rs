//! Darwin interface/address/route observation and deterministic planning (M004).
//!
//! Safe modeling scope only: typed observation shapes, pure plan cases, and
//! fail-closed conflict rules. The privileged route-socket/`getifaddrs`
//! backend that fills these observations lands with M003's live helper on a
//! disposable privileged host; this module performs no I/O, spawns nothing,
//! and never deletes by prefix+device guess.
//!
//! Researched Darwin surface (primary sources in ADR-008 §7; `route(8)` and
//! `route` socket `PF_ROUTE` semantics):
//! - addresses are interface-scoped (`ifscope`/`ifa_scope`), IPv6 link-locals
//!   carry `%utunN` scope and must not be mistaken for global tunnel routes;
//! - routes carry destination family, gateway, `ifscope`, and flags; the
//!   `utunN` number is ephemeral (renumbering changes it, never the logical
//!   [`InterfaceId`]);
//! - global default-route takeover is out of scope: only tunnel-scoped
//!   prefixes route via the managed `utun`; anything wider is refused.
//!
//! Invariants (all enforced by the pure planner below):
//! - no deletion solely because prefix+device match; exact installation
//!   resource identity (owner tag + route attributes) or conflict;
//! - all unowned routes/addresses/physical interfaces/upstream defaults
//!   preserved verbatim;
//! - failed apply never marks a newer generation converged (callers retry
//!   with fresh observation; this planner is side-effect free);
//! - IPv6 link-local/scoped families handled intentionally, never routed.

use std::net::IpAddr;

/// One observed Darwin address on the managed `utun`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DarwinAddress {
    pub address: ipnet::IpNet,
    /// Interface scope (`ifa_scope`/`ifscope`); tunnel addresses are scoped
    /// to the managed `utun`, link-locals carry `%utunN`.
    pub scope: AddressScope,
    /// Whether this address was installed by this installation (exact owner
    /// tag match at observation time).
    pub owned: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressScope {
    /// Global tunnel address on the managed `utun`.
    Tunnel,
    /// Link-local or otherwise scoped (`%utunN`); never routed as tunnel traffic.
    LinkLocal,
    /// Observed on another interface (foreign by definition).
    Foreign,
}

/// One observed Darwin route that may involve the managed `utun`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DarwinRoute {
    pub destination: crate::domain::NetworkPrefix,
    pub gateway: Option<IpAddr>,
    /// Scope the route is bound to (`ifscope`), when reported.
    pub ifscope: Option<String>,
    /// Whether this route was installed by this installation.
    pub owned: bool,
}

/// What the privileged backend observed for one managed tunnel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DarwinObservation {
    /// Ephemeral kernel name (`utunN`), if the device exists.
    pub utun_name: Option<String>,
    pub addresses: Vec<DarwinAddress>,
    pub routes: Vec<DarwinRoute>,
}

/// Desired Darwin state for one managed tunnel (projected, portable).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DarwinDesired {
    pub addresses: Vec<ipnet::IpNet>,
    pub routes: Vec<crate::domain::NetworkPrefix>,
}

/// Deterministic Darwin mutation (planned, not applied here).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DarwinAction {
    AddAddress(ipnet::IpNet),
    RemoveAddress(ipnet::IpNet),
    AddRoute(crate::domain::NetworkPrefix),
    RemoveRoute(crate::domain::NetworkPrefix),
}

/// Why planning refused instead of guessing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DarwinPlanError {
    #[error("managed utun is absent; addresses/routes cannot converge without it")]
    InterfaceAbsent,
    #[error("duplicate desired prefix")]
    DuplicateDesired,
    #[error("an unowned route conflicts with desired state; operator cleanup required")]
    Conflict,
    #[error("desired state would take over global routing; refused")]
    GlobalTakeoverRefused,
}

/// Pure observe→plan for one Darwin managed tunnel.
///
/// - idempotent: converged observations plan nothing;
/// - foreign addresses/routes (unowned, unlisted) are preserved, never deleted;
/// - owned-but-unlisted entries plan removal (exact identity only);
/// - duplicate desired prefixes, conflicting unowned routes, absent `utun`,
///   and global (`0.0.0.0/0`, `::/0`) desires are refused, never guessed.
pub fn plan_darwin(
    desired: &DarwinDesired,
    observed: &DarwinObservation,
) -> Result<Vec<DarwinAction>, DarwinPlanError> {
    let Some(_utun) = observed.utun_name.as_deref() else {
        // No device: desired tunnel state cannot converge, but nothing may be
        // deleted elsewhere either. Empty desired plans nothing; non-empty is
        // reported (the caller surfaces it as degraded, not converged).
        if desired.addresses.is_empty() && desired.routes.is_empty() {
            return Ok(Vec::new());
        }
        return Err(DarwinPlanError::InterfaceAbsent);
    };

    // Global takeover is never plannable through this backend.
    for prefix in desired
        .addresses
        .iter()
        .map(|address| address.to_string())
        .chain(desired.routes.iter().map(|prefix| prefix.to_string()))
    {
        if prefix == "0.0.0.0/0" || prefix == "::/0" {
            return Err(DarwinPlanError::GlobalTakeoverRefused);
        }
    }

    // Duplicate desired entries are a caller bug, not a merge.
    {
        let mut seen = std::collections::HashSet::new();
        for address in &desired.addresses {
            if !seen.insert(address.to_string()) {
                return Err(DarwinPlanError::DuplicateDesired);
            }
        }
        let mut seen_routes = std::collections::HashSet::new();
        for route in &desired.routes {
            if !seen_routes.insert(route.to_string()) {
                return Err(DarwinPlanError::DuplicateDesired);
            }
        }
    }

    let mut actions = Vec::new();

    // Addresses: add missing tunnel desires; remove owned-but-unlisted tunnel
    // addresses; preserve link-local and foreign entries verbatim.
    for address in &desired.addresses {
        let present = observed.addresses.iter().any(|observed_address| {
            observed_address.address == *address
                && matches!(observed_address.scope, AddressScope::Tunnel)
        });
        if !present {
            actions.push(DarwinAction::AddAddress(*address));
        }
    }
    for observed_address in &observed.addresses {
        if !matches!(observed_address.scope, AddressScope::Tunnel) {
            continue;
        }
        // Unowned + unlisted = foreign: preserved (no action).
        if !desired.addresses.contains(&observed_address.address) && observed_address.owned {
            actions.push(DarwinAction::RemoveAddress(observed_address.address));
        }
    }

    // Routes: add missing desires unless an unowned route already covers the
    // same destination (conflict, never silent adoption); remove
    // owned-but-unlisted routes; preserve foreign routes.
    for route in &desired.routes {
        let present_owned = observed.routes.iter().any(|observed_route| {
            observed_route.destination.to_string() == route.to_string() && observed_route.owned
        });
        if present_owned {
            continue;
        }
        let conflicting_unowned = observed.routes.iter().any(|observed_route| {
            observed_route.destination.to_string() == route.to_string() && !observed_route.owned
        });
        if conflicting_unowned {
            return Err(DarwinPlanError::Conflict);
        }
        actions.push(DarwinAction::AddRoute(route.clone()));
    }
    for observed_route in &observed.routes {
        if observed_route.owned
            && !desired
                .routes
                .iter()
                .any(|route| route.to_string() == observed_route.destination.to_string())
        {
            actions.push(DarwinAction::RemoveRoute(
                observed_route.destination.clone(),
            ));
        }
    }

    Ok(actions)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(text: &str) -> crate::domain::NetworkPrefix {
        text.parse().unwrap()
    }

    fn tunnel(address: &str, owned: bool) -> DarwinAddress {
        DarwinAddress {
            address: address.parse().unwrap(),
            scope: AddressScope::Tunnel,
            owned,
        }
    }

    fn route(destination: &str, owned: bool) -> DarwinRoute {
        DarwinRoute {
            destination: prefix(destination),
            gateway: None,
            ifscope: Some("utun4".into()),
            owned,
        }
    }

    fn observed_empty_utun() -> DarwinObservation {
        DarwinObservation {
            utun_name: Some("utun4".into()),
            addresses: Vec::new(),
            routes: Vec::new(),
        }
    }

    #[test]
    fn converged_state_plans_nothing() {
        let desired = DarwinDesired {
            addresses: vec!["10.8.0.1/24".parse().unwrap()],
            routes: vec![prefix("10.9.0.0/16")],
        };
        let observed = DarwinObservation {
            utun_name: Some("utun4".into()),
            addresses: vec![tunnel("10.8.0.1/24", true)],
            routes: vec![route("10.9.0.0/16", true)],
        };
        assert_eq!(plan_darwin(&desired, &observed).unwrap(), Vec::new());
    }

    #[test]
    fn missing_entries_plan_adds_and_owned_extras_plan_removal() {
        let desired = DarwinDesired {
            addresses: vec!["10.8.0.1/24".parse().unwrap()],
            routes: Vec::new(),
        };
        let observed = DarwinObservation {
            utun_name: Some("utun7".into()),
            addresses: vec![
                tunnel("10.8.0.1/24", true),
                tunnel("10.8.0.99/24", true),
                DarwinAddress {
                    address: "fe80::1/64".parse().unwrap(),
                    scope: AddressScope::LinkLocal,
                    owned: false,
                },
            ],
            routes: vec![route("10.9.0.0/16", true)],
        };
        let actions = plan_darwin(&desired, &observed).unwrap();
        assert!(actions.contains(&DarwinAction::RemoveRoute(prefix("10.9.0.0/16"))));
        assert!(!actions.iter().any(|action| matches!(
            action,
            DarwinAction::RemoveAddress(address) if address.to_string() == "fe80::1/64"
        )));
    }

    #[test]
    fn foreign_state_is_preserved_never_deleted() {
        let desired = DarwinDesired {
            addresses: Vec::new(),
            routes: Vec::new(),
        };
        let observed = DarwinObservation {
            utun_name: Some("utun4".into()),
            addresses: vec![tunnel("10.8.0.9/24", false)],
            routes: vec![route("10.9.0.0/16", false)],
        };
        assert_eq!(plan_darwin(&desired, &observed).unwrap(), Vec::new());
    }

    #[test]
    fn conflicting_unowned_route_is_a_conflict_not_an_adoption() {
        let desired = DarwinDesired {
            addresses: Vec::new(),
            routes: vec![prefix("10.9.0.0/16")],
        };
        let observed = DarwinObservation {
            utun_name: Some("utun4".into()),
            addresses: Vec::new(),
            routes: vec![route("10.9.0.0/16", false)],
        };
        assert_eq!(
            plan_darwin(&desired, &observed).unwrap_err(),
            DarwinPlanError::Conflict
        );
    }

    #[test]
    fn absent_utun_global_takeover_and_duplicates_refuse() {
        let desired = DarwinDesired {
            addresses: vec!["10.8.0.1/24".parse().unwrap()],
            routes: Vec::new(),
        };
        let absent = DarwinObservation {
            utun_name: None,
            addresses: Vec::new(),
            routes: Vec::new(),
        };
        assert_eq!(
            plan_darwin(&desired, &absent).unwrap_err(),
            DarwinPlanError::InterfaceAbsent
        );
        let global = DarwinDesired {
            addresses: Vec::new(),
            routes: vec![prefix("0.0.0.0/0")],
        };
        assert_eq!(
            plan_darwin(&global, &observed_empty_utun()).unwrap_err(),
            DarwinPlanError::GlobalTakeoverRefused
        );
        let duplicate = DarwinDesired {
            addresses: vec![
                "10.8.0.1/24".parse().unwrap(),
                "10.8.0.1/24".parse().unwrap(),
            ],
            routes: Vec::new(),
        };
        assert_eq!(
            plan_darwin(&duplicate, &observed_empty_utun()).unwrap_err(),
            DarwinPlanError::DuplicateDesired
        );
    }

    #[test]
    fn renumbered_utun_reapplies_under_the_same_logical_identity() {
        // utun4 → utun7 with the same desired state: the plan re-adds under
        // the live name; no foreign deletion is ever planned by number.
        let desired = DarwinDesired {
            addresses: vec!["10.8.0.1/24".parse().unwrap()],
            routes: Vec::new(),
        };
        let renumbered = DarwinObservation {
            utun_name: Some("utun7".into()),
            addresses: Vec::new(),
            routes: Vec::new(),
        };
        let actions = plan_darwin(&desired, &renumbered).unwrap();
        assert!(actions.contains(&DarwinAction::AddAddress("10.8.0.1/24".parse().unwrap())));
    }
}
