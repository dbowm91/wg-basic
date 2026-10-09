use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr, str::FromStr};

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct NetworkPrefix(IpNet);

impl NetworkPrefix {
    pub fn new(network: IpNet) -> Self {
        Self(network.trunc())
    }
    pub fn network(&self) -> IpNet {
        self.0
    }
    pub fn contains(&self, address: IpAddr) -> bool {
        self.0.contains(&address)
    }
    pub fn family_matches(&self, address: IpAddr) -> bool {
        self.0.addr().is_ipv4() == address.is_ipv4()
    }
}
impl From<IpNet> for NetworkPrefix {
    fn from(network: IpNet) -> Self {
        Self::new(network)
    }
}
impl<'de> Deserialize<'de> for NetworkPrefix {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        IpNet::deserialize(deserializer).map(Self::new)
    }
}
impl FromStr for NetworkPrefix {
    type Err = ipnet::AddrParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse::<IpNet>().map(Self::new)
    }
}
impl std::fmt::Display for NetworkPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClientRoutePolicy {
    pub prefixes: Vec<NetworkPrefix>,
}

pub const MAX_CLIENT_ROUTE_PREFIXES: usize = 64;

impl ClientRoutePolicy {
    pub fn validate(&self) -> Result<(), RoutePolicyValidationError> {
        if self.prefixes.len() > MAX_CLIENT_ROUTE_PREFIXES {
            return Err(RoutePolicyValidationError::TooManyPrefixes);
        }
        let mut seen = HashSet::new();
        for prefix in &self.prefixes {
            let network = prefix.network();
            let full_tunnel = network.prefix_len() == 0;
            if (network.addr().is_unspecified() || network.addr().is_multicast()) && !full_tunnel {
                return Err(RoutePolicyValidationError::InvalidPrefix);
            }
            if !seen.insert(prefix) {
                return Err(RoutePolicyValidationError::DuplicatePrefix);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RoutePolicyValidationError {
    #[error("client route policy exceeds the 64-prefix limit")]
    TooManyPrefixes,
    #[error("client routes must be unicast prefixes or the explicit family default route")]
    InvalidPrefix,
    #[error("client route policy contains a duplicate prefix")]
    DuplicatePrefix,
}

pub fn validate_unique_client_addresses<'a>(
    addresses: impl IntoIterator<Item = &'a IpNet>,
) -> Result<(), NetworkValidationError> {
    let mut seen = HashSet::new();
    for prefix in addresses {
        if prefix.prefix_len() != if prefix.addr().is_ipv4() { 32 } else { 128 } {
            return Err(NetworkValidationError::ClientAddressMustBeHostPrefix);
        }
        if !seen.insert(prefix.addr()) {
            return Err(NetworkValidationError::DuplicateClientAddress(
                prefix.addr(),
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NetworkValidationError {
    #[error("client assignments must be host prefixes (/32 or /128)")]
    ClientAddressMustBeHostPrefix,
    #[error("client address {0} is assigned more than once")]
    DuplicateClientAddress(IpAddr),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_prefixes_and_rejects_invalid_client_assignments() {
        let prefix: NetworkPrefix = "10.8.0.7/24".parse().unwrap();
        assert_eq!(prefix.to_string(), "10.8.0.0/24");
        assert!("10.8.0.0/33".parse::<NetworkPrefix>().is_err());
        let first: IpNet = "10.8.0.2/32".parse().unwrap();
        let duplicate = first;
        assert!(matches!(
            validate_unique_client_addresses([&first, &duplicate]),
            Err(NetworkValidationError::DuplicateClientAddress(_))
        ));
        let subnet: IpNet = "10.8.0.0/24".parse().unwrap();
        assert_eq!(
            validate_unique_client_addresses([&subnet]),
            Err(NetworkValidationError::ClientAddressMustBeHostPrefix)
        );
    }

    #[test]
    fn route_policy_accepts_explicit_family_defaults_and_unique_split_routes() {
        let policy = ClientRoutePolicy {
            prefixes: vec![
                "0.0.0.0/0".parse().unwrap(),
                "::/0".parse().unwrap(),
                "192.0.2.0/24".parse().unwrap(),
                "2001:db8:1::/48".parse().unwrap(),
            ],
        };
        assert_eq!(policy.validate(), Ok(()));
    }

    #[test]
    fn route_policy_rejects_duplicates_bad_prefixes_and_overflow() {
        let duplicate = ClientRoutePolicy {
            prefixes: vec![
                "192.0.2.0/24".parse().unwrap(),
                "192.0.2.1/24".parse().unwrap(),
            ],
        };
        assert_eq!(
            duplicate.validate(),
            Err(RoutePolicyValidationError::DuplicatePrefix)
        );
        for value in ["0.0.0.0/32", "224.0.0.0/4", "::/64", "ff00::/8"] {
            assert_eq!(
                ClientRoutePolicy {
                    prefixes: vec![value.parse().unwrap()]
                }
                .validate(),
                Err(RoutePolicyValidationError::InvalidPrefix)
            );
        }
        let too_many = ClientRoutePolicy {
            prefixes: (0..=MAX_CLIENT_ROUTE_PREFIXES)
                .map(|i| format!("10.{}.0.0/16", i).parse().unwrap())
                .collect(),
        };
        assert_eq!(
            too_many.validate(),
            Err(RoutePolicyValidationError::TooManyPrefixes)
        );
    }

    #[test]
    fn serde_normalizes_prefixes_before_route_validation() {
        let policy: ClientRoutePolicy =
            serde_json::from_str(r#"{"prefixes":["192.0.2.7/24","192.0.2.99/24"]}"#).unwrap();
        assert_eq!(policy.prefixes[0].to_string(), "192.0.2.0/24");
        assert_eq!(
            policy.validate(),
            Err(RoutePolicyValidationError::DuplicatePrefix)
        );
    }
}
