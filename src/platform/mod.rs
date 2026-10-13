//! Portable platform boundary for Linux and Darwin (macOS) server targets.
//!
//! M001 establishes the rule the later macOS milestones build on: the
//! authoritative identity of a managed tunnel is logical and OS-neutral, while
//! every OS-assigned locator is ephemeral observation metadata that can never
//! prove ownership on its own.
//!
//! - Logical identity: [`LogicalTunnel`] (`InstallationId` + `InterfaceId` +
//!   managed [`InterfaceName`]). Stable across reboots, utun renumbering, and
//!   helper restarts. This is what the SQLite desired state stores and what
//!   [`OwnerTag`] binds.
//! - OS locator: [`OsLocator`]. The kernel-assigned name (`wg0` on Linux,
//!   `utunN` on Darwin), an ifindex where the backend reports one, or nothing
//!   when the link is absent. Ephemeral, never serialized as ownership proof.
//!
//! Linux-only observation fields that already exist on the wire
//! (`ObservedManagedInterface::ifindex` and `interface_alias`) are backend
//! metadata in this vocabulary: they are useful for Linux reconciliation but
//! are not universal ownership proof. Darwin backends must not fabricate them.
//!
//! [`BackendCapability`] keeps three states distinct: a backend that is
//! installed and usable, one that is known-unsupported on this OS, and one
//! whose support has not been qualified yet. M001 reports the Darwin network
//! backends as unsupported/unknown, never as available.

use crate::domain::{InstallationId, InterfaceId, InterfaceName, OwnerTag};

/// The OS this binary was compiled for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Platform {
    Linux,
    Darwin,
    Unsupported,
}

impl Platform {
    /// The platform of the running binary.
    pub fn current() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::Linux
        }
        #[cfg(target_os = "macos")]
        {
            Self::Darwin
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Self::Unsupported
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Darwin => "macos",
            Self::Unsupported => "unsupported",
        }
    }

    /// Whether the privileged network backends are implemented on this OS.
    ///
    /// M001: only Linux. Darwin reports unsupported until M002–M005 close.
    pub fn has_native_network_backend(self) -> bool {
        matches!(self, Self::Linux)
    }
}

/// OS-neutral logical tunnel identity.
///
/// The triple is stable while the OS-assigned device name churns underneath:
/// a reboot that moves `utun4` to `utun7` does not change the logical tunnel,
/// the persisted desired state, or any exported client configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalTunnel {
    pub installation_id: InstallationId,
    pub interface_id: InterfaceId,
    pub name: InterfaceName,
}

impl LogicalTunnel {
    pub fn new(
        installation_id: InstallationId,
        interface_id: InterfaceId,
        name: InterfaceName,
    ) -> Self {
        Self {
            installation_id,
            interface_id,
            name,
        }
    }

    /// The durable ownership proof derived from the logical identity.
    pub fn owner_tag(&self) -> OwnerTag {
        OwnerTag::new(self.installation_id, self.interface_id)
    }
}

/// Ephemeral OS-assigned locator. Never authoritative, never persisted as
/// desired state, never sufficient to authorize deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OsLocator {
    /// Linux kernel device name plus the backend-reported ifindex, when known.
    Linux {
        name: InterfaceName,
        ifindex: Option<u32>,
    },
    /// Darwin utun device name as assigned by the kernel (`utunN`), when known.
    Darwin { utun_name: Option<String> },
    /// No link observed.
    Absent { name: InterfaceName },
}

impl OsLocator {
    /// The logical managed name this locator was observed for.
    pub fn logical_name(&self) -> &InterfaceName {
        match self {
            Self::Linux { name, .. } => name,
            Self::Darwin { .. } => {
                // Darwin locators carry only the ephemeral utun name; the
                // logical name lives in `LogicalTunnel`. This branch is
                // unreachable in practice and exists so the enum stays
                // exhaustive without inventing a name.
                unreachable!("Darwin utun locators do not carry the logical name")
            }
            Self::Absent { name } => name,
        }
    }
}

/// Support state for one host capability.
///
/// Three states, never two: supported backends can be used, unsupported ones
/// must fail closed with an actionable error, and unknown ones must not be
/// presented as either.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendCapability {
    Supported,
    Unsupported(&'static str),
    Unknown(&'static str),
}

impl BackendCapability {
    pub fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

pub mod darwin;
pub mod linux;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{RequestOperation, PROTOCOL_VERSION};

    #[test]
    fn current_platform_matches_compile_target() {
        #[cfg(target_os = "linux")]
        assert_eq!(Platform::current(), Platform::Linux);
        #[cfg(target_os = "macos")]
        assert_eq!(Platform::current(), Platform::Darwin);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert_eq!(Platform::current(), Platform::Unsupported);
    }

    #[test]
    fn only_linux_reports_a_native_network_backend_in_m001() {
        assert!(Platform::Linux.has_native_network_backend());
        assert!(!Platform::Darwin.has_native_network_backend());
        assert!(!Platform::Unsupported.has_native_network_backend());
    }

    #[test]
    fn capability_states_stay_distinct() {
        assert!(BackendCapability::Supported.is_supported());
        assert!(!BackendCapability::Unsupported("m001").is_supported());
        assert!(!BackendCapability::Unknown("m002").is_supported());
        assert_ne!(
            BackendCapability::Unsupported("a"),
            BackendCapability::Unknown("a"),
            "unsupported (known-absent) and unknown (unqualified) must not collapse"
        );
    }

    #[test]
    fn logical_identity_is_stable_while_os_locators_churn() {
        let installation = InstallationId::new();
        let interface_id = crate::domain::InterfaceId::new();
        let logical = LogicalTunnel::new(installation, interface_id, "wg0".parse().unwrap());
        assert_eq!(
            logical.owner_tag(),
            OwnerTag::new(installation, interface_id)
        );

        // Linux locator carries name + optional ifindex; Darwin carries
        // ephemeral utun; neither enters the owner tag.
        let linux = OsLocator::Linux {
            name: "wg0".parse().unwrap(),
            ifindex: Some(42),
        };
        let darwin_first = OsLocator::Darwin {
            utun_name: Some("utun4".into()),
        };
        let darwin_second = OsLocator::Darwin {
            utun_name: Some("utun7".into()),
        };
        assert_ne!(darwin_first, darwin_second);
        assert_ne!(format!("{linux:?}"), format!("{darwin_first:?}"));
        // The owner tag derives only from the logical UUIDs.
        assert_eq!(
            logical.owner_tag(),
            OwnerTag::new(installation, interface_id)
        );
    }

    #[test]
    fn darwin_target_floor_is_declared_and_supported_targets_are_both_darwin() {
        assert_eq!(darwin::MIN_MACOS_MAJOR, 13);
        assert_eq!(darwin::MIN_MACOS_VERSION, "13.0");
        assert_eq!(
            darwin::SUPPORTED_TARGETS,
            &["aarch64-apple-darwin", "x86_64-apple-darwin"]
        );
    }

    #[test]
    fn wire_protocol_stays_pinned_through_the_portability_refactor() {
        // M001 changes no wire bytes: version stays 1 and the two operations
        // pinned by the architecture guard keep their snake_case tags.
        assert_eq!(PROTOCOL_VERSION, 1);
        let ping = serde_json::to_string(&RequestOperation::Ping).unwrap();
        assert!(ping.contains("\"ping\""), "{ping}");
        // Old Linux receipts with ifindex/alias still decode: the fields are
        // backend metadata, not removed or renamed.
        let old = r#"{"interface":"wg0","ifindex":7,"link_kind":"wire_guard","admin_up":true,"addresses":[],"routes":[],"unsupported_route_count":0,"interface_alias":"wg-basic:v1:test","duplicate_owner_tag":false,"wireguard":null}"#;
        let observed: crate::reconcile::ObservedManagedInterface =
            serde_json::from_str(old).unwrap();
        assert_eq!(observed.ifindex, Some(7));
        assert_eq!(
            observed.interface_alias.as_deref(),
            Some("wg-basic:v1:test")
        );
    }
}
