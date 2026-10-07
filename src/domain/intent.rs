//! Network intent value types shared by the application model and the kernel
//! backends.
//!
//! These are pure vocabulary: they describe what the operator wants to exist,
//! never what the kernel currently reports. They live here rather than in a
//! Linux-gated module so the unprivileged management side can persist and
//! reconstruct them without depending on a network backend.

use crate::domain::NetworkPrefix;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Whether wg-basic claims management of a link.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipDeclaration {
    /// wg-basic owns the link and may create or delete it.
    Managed,
    /// wg-basic observes the link and never mutates its lifecycle.
    ObserveOnly,
}

/// Whether a link should exist.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkLifecycle {
    Present,
    Absent,
}

/// Whether a single managed address or route should exist.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourcePresence {
    Present,
    Absent,
}

/// One exactly managed interface address.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredAddress {
    pub address: IpNet,
    pub presence: ResourcePresence,
}

/// One exactly managed route in the main unicast table.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRoute {
    pub destination: NetworkPrefix,
    pub gateway: Option<IpAddr>,
    pub presence: ResourcePresence,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_vocabulary_serializes_in_snake_case() {
        assert_eq!(
            serde_json::to_string(&OwnershipDeclaration::ObserveOnly).unwrap(),
            "\"observe_only\""
        );
        assert_eq!(
            serde_json::to_string(&LinkLifecycle::Present).unwrap(),
            "\"present\""
        );
        assert_eq!(
            serde_json::to_string(&ResourcePresence::Absent).unwrap(),
            "\"absent\""
        );
    }

    #[test]
    fn managed_route_round_trips_with_and_without_a_gateway() {
        let routed: ManagedRoute = serde_json::from_str(
            r#"{"destination":"10.1.0.0/16","gateway":"192.0.2.1","presence":"present"}"#,
        )
        .unwrap();
        assert_eq!(routed.gateway, Some(IpAddr::from([192, 0, 2, 1])));

        let direct: ManagedRoute = serde_json::from_str(
            r#"{"destination":"10.1.0.0/16","gateway":null,"presence":"absent"}"#,
        )
        .unwrap();
        assert_eq!(direct.gateway, None);
        assert_eq!(direct.presence, ResourcePresence::Absent);
    }
}
