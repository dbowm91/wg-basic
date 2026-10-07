use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use uuid::Uuid;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
        impl FromStr for $name {
            type Err = uuid::Error;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self)
            }
        }
    };
}

id_type!(InterfaceId);
id_type!(PeerId);
id_type!(ClientId);

id_type!(PrincipalId);
id_type!(SessionId);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_round_trip_and_are_type_distinct() {
        let interface = InterfaceId::new();
        assert_eq!(
            interface.to_string().parse::<InterfaceId>().unwrap(),
            interface
        );
        assert_ne!(interface.to_string(), PeerId::new().to_string());
        assert_ne!(interface.to_string(), ClientId::new().to_string());
    }
}
