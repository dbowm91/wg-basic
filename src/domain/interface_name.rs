use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// Linux interface locator (IFNAMSIZ includes the terminating NUL).
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct InterfaceName(String);

impl InterfaceName {
    pub fn new(value: impl Into<String>) -> Result<Self, InterfaceNameError> {
        let value = value.into();
        if value.is_empty() {
            return Err(InterfaceNameError::Empty);
        }
        if value.len() > 15 {
            return Err(InterfaceNameError::TooLong);
        }
        if value.bytes().any(|b| {
            b == 0 || b.is_ascii_control() || b == b'/' || b == b':' || b.is_ascii_whitespace()
        }) {
            return Err(InterfaceNameError::InvalidCharacter);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for InterfaceName {
    type Error = InterfaceNameError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl From<InterfaceName> for String {
    fn from(value: InterfaceName) -> Self {
        value.0
    }
}
impl FromStr for InterfaceName {
    type Err = InterfaceNameError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}
impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InterfaceNameError {
    #[error("interface name must not be empty")]
    Empty,
    #[error("interface name exceeds Linux IFNAMSIZ limit of 15 bytes")]
    TooLong,
    #[error(
        "interface name contains a forbidden control, whitespace, slash, colon, or NUL character"
    )]
    InvalidCharacter,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_linux_name_bounds_and_characters() {
        assert!(InterfaceName::new("wg0").is_ok());
        assert!(InterfaceName::new("123456789012345").is_ok());
        assert_eq!(
            InterfaceName::new("1234567890123456"),
            Err(InterfaceNameError::TooLong)
        );
        for invalid in [
            "",
            "bad/name",
            "bad:name",
            "bad name",
            "bad\0name",
            "bad\nname",
        ] {
            assert!(InterfaceName::new(invalid).is_err(), "{invalid:?}");
        }
    }
}
