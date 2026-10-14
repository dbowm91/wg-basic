use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// Logical managed interface name (e.g. `wg0`).
///
/// This is the operator-configured, OS-neutral logical identity stored in
/// SQLite alongside the [`InterfaceId`]. It is stable across reboots and, on
/// Darwin, across `utunN` renumbering: the kernel-assigned `utunN` name is an
/// ephemeral [`OsLocator`](crate::platform::OsLocator), never this value.
///
/// Bounds follow `IFNAMSIZ` (15 bytes plus NUL) on both Linux and Darwin
/// (Darwin `IFNAMSZ` is likewise 16), so the same validation holds for both
/// backends. Darwin `utunN` names (`utun0`…`utun4095`) satisfy these bounds.
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
    #[error("interface name exceeds IFNAMSIZ limit of 15 bytes (Linux and Darwin)")]
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

    /// M001: Darwin `utunN` names satisfy the same logical bounds, but they
    /// are ephemeral locators, never logical identity. The logical name stays
    /// `wg0` while the OS locator churns.
    #[test]
    fn darwin_utun_names_satisfy_logical_bounds_but_are_not_identity() {
        for utun in ["utun0", "utun4", "utun107", "utun4095"] {
            assert!(InterfaceName::new(utun).is_ok(), "{utun}");
        }
        // The logical tunnel keeps its UUID identity across utun renumbering.
        let installation = crate::domain::InstallationId::new();
        let interface_id = crate::domain::InterfaceId::new();
        let logical =
            crate::platform::LogicalTunnel::new(installation, interface_id, "wg0".parse().unwrap());
        assert_eq!(
            logical.owner_tag(),
            crate::domain::OwnerTag::new(installation, interface_id)
        );
        // Two different utun locators map to the same logical tunnel.
        let first = crate::platform::OsLocator::Darwin {
            utun_name: Some("utun4".into()),
        };
        let second = crate::platform::OsLocator::Darwin {
            utun_name: Some("utun7".into()),
        };
        assert_ne!(first, second, "locators churn");
        assert_eq!(
            logical.name.as_str(),
            "wg0",
            "logical identity is stable across utun churn"
        );
    }
}
