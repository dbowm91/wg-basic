use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr, str::FromStr};

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
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
}
