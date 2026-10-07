//! Durable interface ownership tags.
//!
//! An [`OwnerTag`] is a bounded, deterministic, ASCII-safe string written into
//! the kernel as the link's `IFLA_IFALIAS`. It is the durable proof that a link
//! belongs to this wg-basic installation and interface.
//!
//! Properties that make it safe:
//!
//! - it is derived only from a format version, the `InstallationId`, and the
//!   `InterfaceId` — never from a user-supplied name or label;
//! - it is not a secret and carries no private key material;
//! - it round-trips back into the installation and interface identity;
//! - a foreign or unknown version is rejected rather than guessed at.
//!
//! Ownership is proven by an exact tag match. A missing tag, a tag belonging to
//! another installation or interface, or an unrelated alias is a conflict —
//! ownership is never inferred from the public key or from the interface name.

use crate::domain::{InstallationId, InterfaceId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

/// The owner-tag format prefix, including the version marker and separator.
const OWNER_TAG_PREFIX: &str = "wg-basic:v1:";

/// Linux `IFALIASZ` is 256 bytes including the terminating NUL, so a usable
/// alias is at most 255 characters. The longest tag this format produces is
/// 85 characters, which leaves ample headroom.
pub const MAX_OWNER_TAG_LENGTH: usize = 255;

/// A bounded, deterministic interface ownership tag.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OwnerTag {
    installation_id: InstallationId,
    interface_id: InterfaceId,
}

/// A tag that could not be parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OwnerTagError {
    #[error("owner tag does not use the supported wg-basic:v1 format")]
    UnknownFormat,

    #[error("owner tag does not carry both an installation and an interface identity")]
    Incomplete,

    #[error("owner tag carries an invalid identity")]
    InvalidIdentity,

    #[error("owner tag is longer than the kernel interface-alias maximum")]
    TooLong,
}

impl OwnerTag {
    /// Derives the tag for one interface of one installation.
    pub fn new(installation_id: InstallationId, interface_id: InterfaceId) -> Self {
        Self {
            installation_id,
            interface_id,
        }
    }

    /// The installation this tag proves ownership for.
    pub fn installation_id(&self) -> InstallationId {
        self.installation_id
    }

    /// The interface this tag proves ownership for.
    pub fn interface_id(&self) -> InterfaceId {
        self.interface_id
    }

    /// Returns the tag when this identity matches both parts of `self`.
    ///
    /// Ownership requires an exact match; a partial match is not ownership.
    pub fn matches(&self, installation_id: InstallationId, interface_id: InterfaceId) -> bool {
        self.installation_id == installation_id && self.interface_id == interface_id
    }

    /// Classifies an observed alias against this expected tag.
    pub fn classify(&self, observed: Option<&str>) -> AliasMatch {
        match observed {
            None => AliasMatch::Absent,
            Some(alias) => match alias.parse::<Self>() {
                Ok(tag) if tag == *self => AliasMatch::Owned,
                Ok(tag) if tag.installation_id == self.installation_id => {
                    AliasMatch::ForeignInterface
                }
                Ok(_) => AliasMatch::ForeignInstallation,
                Err(_) => AliasMatch::Unrelated,
            },
        }
    }

    /// The canonical wire form: `wg-basic:v1:<installation-uuid>:<interface-uuid>`.
    pub fn as_str(&self) -> String {
        format!(
            "{OWNER_TAG_PREFIX}{}:{}",
            self.installation_id, self.interface_id
        )
    }
}

impl TryFrom<String> for OwnerTag {
    type Error = OwnerTagError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<OwnerTag> for String {
    fn from(tag: OwnerTag) -> Self {
        tag.as_str()
    }
}

impl Serialize for OwnerTag {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_str())
    }
}

impl<'de> Deserialize<'de> for OwnerTag {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for OwnerTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

impl FromStr for OwnerTag {
    type Err = OwnerTagError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() > MAX_OWNER_TAG_LENGTH {
            return Err(OwnerTagError::TooLong);
        }
        let rest = value
            .strip_prefix(OWNER_TAG_PREFIX)
            .ok_or(OwnerTagError::UnknownFormat)?;
        let mut parts = rest.split(':');
        let installation = parts.next().ok_or(OwnerTagError::Incomplete)?;
        let interface = parts.next().ok_or(OwnerTagError::Incomplete)?;
        if parts.next().is_some() {
            return Err(OwnerTagError::UnknownFormat);
        }
        Ok(Self {
            installation_id: installation
                .parse()
                .map_err(|_| OwnerTagError::InvalidIdentity)?,
            interface_id: interface
                .parse()
                .map_err(|_| OwnerTagError::InvalidIdentity)?,
        })
    }
}

/// How an observed interface alias compares with the expected owner tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AliasMatch {
    /// The link carries exactly the expected owner tag.
    Owned,
    /// The link carries no alias at all.
    Absent,
    /// The alias is a wg-basic tag from this installation but a different interface.
    ForeignInterface,
    /// The alias is a wg-basic tag from a different installation.
    ForeignInstallation,
    /// The alias is something wg-basic did not write.
    Unrelated,
}

impl AliasMatch {
    /// Only an exact match proves ownership of an existing link.
    pub fn proves_ownership(self) -> bool {
        matches!(self, AliasMatch::Owned)
    }

    /// Every other case must fail closed for authoritative mutation or destruction.
    pub fn is_conflict(self) -> bool {
        !self.proves_ownership()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag() -> OwnerTag {
        OwnerTag::new(InstallationId::new(), InterfaceId::new())
    }

    #[test]
    fn owner_tag_is_deterministic_ascii_and_well_under_the_kernel_limit() {
        let installation = InstallationId::new();
        let interface = InterfaceId::new();
        let first = OwnerTag::new(installation, interface);
        let second = OwnerTag::new(installation, interface);
        assert_eq!(
            first.as_str(),
            second.as_str(),
            "derivation is deterministic"
        );

        let rendered = first.as_str();
        assert!(rendered.len() <= MAX_OWNER_TAG_LENGTH, "{rendered}");
        assert_eq!(rendered.len(), 85, "the v1 format has a fixed length");
        assert!(rendered.is_ascii(), "the tag must be ASCII-safe");
        assert!(rendered.starts_with(OWNER_TAG_PREFIX));
        assert!(rendered.contains(&installation.to_string()));
        assert!(rendered.contains(&interface.to_string()));
    }

    #[test]
    fn owner_tag_round_trips_into_installation_and_interface_identity() {
        let installation = InstallationId::new();
        let interface = InterfaceId::new();
        let original = OwnerTag::new(installation, interface);

        let parsed: OwnerTag = original.as_str().parse().expect("round trip");
        assert_eq!(parsed, original);
        assert_eq!(parsed.installation_id(), installation);
        assert_eq!(parsed.interface_id(), interface);
        assert_eq!(parsed, original.to_string().parse().unwrap());
    }

    #[test]
    fn a_distinct_installation_or_interface_yields_a_distinct_tag() {
        let installation = InstallationId::new();
        let interface = InterfaceId::new();
        let base = OwnerTag::new(installation, interface);

        assert_ne!(base, OwnerTag::new(InstallationId::new(), interface));
        assert_ne!(base, OwnerTag::new(installation, InterfaceId::new()));
    }

    #[test]
    fn invalid_and_foreign_formats_are_rejected_rather_than_guessed() {
        assert!(matches!(
            "wg-basic:v2:x:y".parse::<OwnerTag>(),
            Err(OwnerTagError::UnknownFormat)
        ));
        assert!(matches!(
            "someone-elses-tag".parse::<OwnerTag>(),
            Err(OwnerTagError::UnknownFormat)
        ));
        assert!(matches!(
            "wg-basic:v1:only-one-part".parse::<OwnerTag>(),
            Err(OwnerTagError::Incomplete)
        ));
        assert!(matches!(
            "wg-basic:v1:not-a-uuid:also-not".parse::<OwnerTag>(),
            Err(OwnerTagError::InvalidIdentity)
        ));
        assert!(matches!(
            "wg-basic:v1:a:b:c".parse::<OwnerTag>(),
            Err(OwnerTagError::UnknownFormat)
        ));
        assert!("".parse::<OwnerTag>().is_err());

        let too_long = format!("wg-basic:v1:{}:{}", "a".repeat(200), "b".repeat(200));
        assert!(matches!(
            too_long.parse::<OwnerTag>(),
            Err(OwnerTagError::TooLong)
        ));
    }

    #[test]
    fn classification_distinguishes_owned_absent_foreign_and_unrelated_aliases() {
        let expected = tag();
        let rendered = expected.as_str();

        assert_eq!(expected.classify(Some(&rendered)), AliasMatch::Owned);
        assert_eq!(expected.classify(None), AliasMatch::Absent);
        assert_eq!(expected.classify(Some("")), AliasMatch::Unrelated);
        assert_eq!(
            expected.classify(Some("my laptop uplink")),
            AliasMatch::Unrelated
        );

        let same_install_other_interface =
            OwnerTag::new(expected.installation_id(), InterfaceId::new()).as_str();
        assert_eq!(
            expected.classify(Some(&same_install_other_interface)),
            AliasMatch::ForeignInterface
        );

        let other_install = OwnerTag::new(InstallationId::new(), expected.interface_id()).as_str();
        assert_eq!(
            expected.classify(Some(&other_install)),
            AliasMatch::ForeignInstallation
        );
    }

    #[test]
    fn only_an_exact_match_proves_ownership() {
        let expected = tag();
        assert!(expected
            .classify(Some(&expected.as_str()))
            .proves_ownership());
        for case in [None, Some(""), Some("wg-quick"), Some("other")] {
            assert!(expected.classify(case).is_conflict());
        }
        // A tag from this installation but another interface is still a conflict.
        let sibling = OwnerTag::new(expected.installation_id(), InterfaceId::new()).as_str();
        assert!(expected.classify(Some(&sibling)).is_conflict());
    }

    #[test]
    fn ownership_never_relaxes_to_a_partial_identity_match() {
        let installation = InstallationId::new();
        let interface = InterfaceId::new();
        let tag = OwnerTag::new(installation, interface);
        assert!(!tag.matches(installation, InterfaceId::new()));
        assert!(!tag.matches(InstallationId::new(), interface));
        assert!(tag.matches(installation, interface));
    }
}
