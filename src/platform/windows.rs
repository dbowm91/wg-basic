//! Windows Server platform facts for the headless server (ADR-011).
//!
//! The qualified target is Windows Server, amd64, build family 10.0.26100.
//! These types are pure: they decide ownership and refusal. They do not call
//! Win32. The privileged crate applies a decision only after this module has
//! already refused an uncertain one.

use crate::domain::{InstallationId, InterfaceId};
use sha2::{Digest, Sha256};

/// Pipe the privileged service listens on.
///
/// Win32 pipe names cannot contain a backslash (`CreateNamedPipe`). The
/// hierarchical name in the milestone is therefore this single pipe, still
/// under the `wg-basic` prefix and not WireGuard's own pipe.
pub const DEFAULT_PIPE: &str = r"\\.\pipe\wg-basic-netd";

/// Prefix every accepted `--socket` value must use.
pub const PIPE_PREFIX: &str = r"\\.\pipe\wg-basic-";

/// State directory created by the installer. Tests pass an explicit path.
pub const STATE_DIR: &str = r"C:\ProgramData\wg-basic\state";

/// Default state database. Not a schema change; Linux keeps its own constant.
pub const DEFAULT_STATE_PATH: &str = r"C:\ProgramData\wg-basic\state\state.db";

/// Binaries, `wireguard.dll`, and the prebuilt-binary license.
pub const BIN_DIR: &str = r"C:\ProgramData\wg-basic\bin";

/// Runtime receipts. Desired state does not live here.
pub const RUNTIME_DIR: &str = r"C:\ProgramData\wg-basic\netd";

/// Service that runs unprivileged `serve`.
pub const SERVE_SERVICE: &str = "wg-basic";

/// Service that runs privileged `netd`.
pub const NETD_SERVICE: &str = "wg-basic-netd";

/// Local account `serve` runs as. It is not a member of Administrators.
pub const SERVE_ACCOUNT: &str = "wg-basic";

/// Pinned `wireguard-nt` archive. A mismatch is a stop.
pub const WIREGUARD_NT_URL: &str =
    "https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip";

/// SHA-256 of the pinned zip, the same digest WireGuard for Windows pins.
pub const WIREGUARD_NT_ARCHIVE_SHA256: &str =
    "dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace";

/// SHA-256 of `wireguard-nt/bin/amd64/wireguard.dll` inside that zip.
pub const WIREGUARD_NT_DLL_SHA256: &str =
    "b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3";

/// Build family of Windows Server 2025. Windows 11 shares it and is refused
/// by installation type, not by this number alone.
pub const SERVER_2025_BUILD: u32 = 26100;

/// The only support sentence this line is allowed to make, and only after the
/// `windows-2025` job has shown translated traffic.
pub const SUPPORT_SENTENCE: &str = "\
wg-basic runs as a headless WireGuard server with an IPv4 NAT gateway on \
Windows Server 2025 x64. That behavior is qualified on the GitHub-hosted \
windows-2025 runner. Reboot survival, inbound reachability from the public \
internet, IPv6 egress, and every other Windows edition are not part of this claim.";

/// Why a Windows SKU is not this product's target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkuRefusal {
    /// Installation type was Client, or anything other than Server.
    NotServer,
    /// Not amd64.
    Architecture,
    /// Build family was not 10.0.26100.
    BuildFamily,
}

impl SkuRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotServer => "installation type is not Server",
            Self::Architecture => "architecture is not amd64",
            Self::BuildFamily => "build family is not 10.0.26100",
        }
    }
}

/// Accepts only Windows Server, amd64, build 26100.
pub fn sku_allowed(installation_type: &str, arch: &str, build: u32) -> Result<(), SkuRefusal> {
    if !arch.eq_ignore_ascii_case("amd64") && arch != "x86_64" {
        return Err(SkuRefusal::Architecture);
    }
    if !installation_type.eq_ignore_ascii_case("Server") {
        return Err(SkuRefusal::NotServer);
    }
    if build != SERVER_2025_BUILD {
        return Err(SkuRefusal::BuildFamily);
    }
    Ok(())
}

/// A pipe path this product is willing to bind.
///
/// The value must be `\\.\pipe\wg-basic-` plus one segment of letters, digits,
/// and hyphens. Anything else, including a foreign pipe prefix, is refused.
pub fn pipe_name_allowed(name: &str) -> bool {
    let Some(segment) = name.strip_prefix(PIPE_PREFIX) else {
        return false;
    };
    !segment.is_empty()
        && !segment.contains('\\')
        && !segment.contains('/')
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Whether the peer SID is the serve account. Administrators are not a bypass.
pub fn peer_is_serve(serve_sid: &str, peer_sid: &str) -> bool {
    !serve_sid.is_empty() && serve_sid == peer_sid
}

/// True when `path` is the pinned amd64 DLL and the sidecar digest matches.
pub fn dll_matches_pin(path: &std::path::Path) -> bool {
    use sha2::{Digest, Sha256};
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    let digest = Sha256::digest(&bytes);
    let encoded = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if encoded != WIREGUARD_NT_DLL_SHA256 {
        return false;
    }
    let Ok(sidecar) = std::fs::read_to_string(path.with_extension("dll.sha256")) else {
        return false;
    };
    sidecar.trim().eq_ignore_ascii_case(WIREGUARD_NT_DLL_SHA256)
}

/// Adapter GUID requested from `wireguard-nt`.
///
/// Derived from the installation and the interface id so a recreate keeps the
/// same NLA profile. It is not written to SQLite.
pub fn adapter_guid(installation: InstallationId, interface: InterfaceId) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"wg-basic wireguard-nt adapter guid v1\0");
    hasher.update(installation.to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(interface.to_string().as_bytes());
    let digest = hasher.finalize();
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&digest[..16]);
    guid[6] = (guid[6] & 0x0f) | 0x50;
    guid[8] = (guid[8] & 0x3f) | 0x80;
    guid
}

/// NetNAT object this installation owns. The caller does not choose the name.
pub fn owned_nat_name(installation: InstallationId) -> String {
    format!("wg-basic-{installation}")
}

/// One NetNAT row observed on the host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedNat {
    pub name: String,
    pub internal_prefix: String,
}

/// What gateway apply is allowed to do to WinNAT.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NatDecision {
    /// No NAT exists. Create the owned one.
    Create { name: String, prefix: String },
    /// The only NAT is the one this installation recorded, with the same prefix.
    Adopt { name: String },
    /// A NAT this installation does not own is present. Create nothing.
    Refuse { reason: &'static str },
}

/// Decides the single-NetNAT rule. Never deletes a foreign object.
pub fn decide_nat(existing: &[ObservedNat], owned_name: &str, tunnel_prefix: &str) -> NatDecision {
    match existing {
        [] => NatDecision::Create {
            name: owned_name.to_owned(),
            prefix: tunnel_prefix.to_owned(),
        },
        [only] if only.name == owned_name && only.internal_prefix == tunnel_prefix => {
            NatDecision::Adopt {
                name: owned_name.to_owned(),
            }
        }
        _ => NatDecision::Refuse {
            reason: "a NetNAT this installation does not own is already present",
        },
    }
}

/// Recorded IPv4 forwarding ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForwardingRecord {
    /// Value observed before this installation changed anything.
    pub previous_enabled: bool,
    /// This installation is what turned the toggle on.
    pub changed_by_us: bool,
}

/// Gateway apply enables forwarding and records whether it had to.
pub fn forwarding_on_apply(previous_enabled: bool) -> ForwardingRecord {
    ForwardingRecord {
        previous_enabled,
        changed_by_us: !previous_enabled,
    }
}

/// Teardown restores the previous value only when this installation changed it
/// and the live value is still the one it set.
pub fn forwarding_restore(record: ForwardingRecord, live_enabled: bool) -> Option<bool> {
    if record.changed_by_us && live_enabled {
        Some(record.previous_enabled)
    } else {
        None
    }
}

/// Default route selection for the NAT egress. The tunnel adapter is never egress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefaultRoute {
    pub interface_luid: u64,
    pub is_tunnel: bool,
}

pub fn select_egress(routes: &[DefaultRoute]) -> Result<u64, &'static str> {
    let candidates: Vec<u64> = routes
        .iter()
        .filter(|route| !route.is_tunnel)
        .map(|route| route.interface_luid)
        .collect();
    match candidates.as_slice() {
        [only] => Ok(*only),
        [] => Err("no IPv4 default route"),
        _ => Err("more than one IPv4 default route"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (InstallationId, InterfaceId) {
        (
            "00000000-0000-4000-8000-0000000000a1".parse().unwrap(),
            "00000000-0000-4000-8000-0000000000b2".parse().unwrap(),
        )
    }

    #[test]
    fn only_server_2025_amd64_is_accepted() {
        assert_eq!(sku_allowed("Server", "amd64", 26100), Ok(()));
        assert_eq!(sku_allowed("Server", "x86_64", 26100), Ok(()));
        assert_eq!(
            sku_allowed("Client", "amd64", 26100),
            Err(SkuRefusal::NotServer)
        );
        assert_eq!(
            sku_allowed("Server", "arm64", 26100),
            Err(SkuRefusal::Architecture)
        );
        assert_eq!(
            sku_allowed("Server", "amd64", 20348),
            Err(SkuRefusal::BuildFamily)
        );
    }

    #[test]
    fn pipe_names_stay_inside_the_product_prefix() {
        assert!(pipe_name_allowed(DEFAULT_PIPE));
        assert!(pipe_name_allowed(r"\\.\pipe\wg-basic-test"));
        assert!(!pipe_name_allowed(r"\\.\pipe\wg-basic\netd"));
        assert!(!pipe_name_allowed(r"\\.\pipe\Other\netd"));
        assert!(!pipe_name_allowed(r"\\.\pipe\wg-basic-a\b"));
        assert!(!pipe_name_allowed(r"C:\pipe\wg-basic-netd"));
    }

    #[test]
    fn administrators_are_not_an_implicit_allow() {
        let serve = "S-1-5-21-1-2-3-1000";
        let other_admin = "S-1-5-21-1-2-3-500";
        assert!(peer_is_serve(serve, serve));
        assert!(!peer_is_serve(serve, other_admin));
        assert!(!peer_is_serve(serve, "S-1-5-32-544"));
        assert!(!peer_is_serve("", serve));
    }

    #[test]
    fn adapter_guid_is_stable_and_rfc_shaped() {
        let (installation, interface) = ids();
        let first = adapter_guid(installation, interface);
        let second = adapter_guid(installation, interface);
        assert_eq!(first, second);
        assert_eq!(first[6] >> 4, 5);
        assert_eq!(first[8] & 0xc0, 0x80);
        let other = adapter_guid(InstallationId::new(), interface);
        assert_ne!(first, other);
    }

    #[test]
    fn foreign_nat_is_a_refusal_and_never_a_second_create() {
        let owned = "wg-basic-1";
        assert!(matches!(
            decide_nat(&[], owned, "10.8.0.0/24"),
            NatDecision::Create { .. }
        ));
        assert!(matches!(
            decide_nat(
                &[ObservedNat {
                    name: owned.into(),
                    internal_prefix: "10.8.0.0/24".into(),
                }],
                owned,
                "10.8.0.0/24"
            ),
            NatDecision::Adopt { .. }
        ));
        let foreign = decide_nat(
            &[ObservedNat {
                name: "Wsl".into(),
                internal_prefix: "172.20.0.0/20".into(),
            }],
            owned,
            "10.8.0.0/24",
        );
        assert!(matches!(foreign, NatDecision::Refuse { .. }));
        let both = decide_nat(
            &[
                ObservedNat {
                    name: owned.into(),
                    internal_prefix: "10.8.0.0/24".into(),
                },
                ObservedNat {
                    name: "Other".into(),
                    internal_prefix: "172.20.0.0/20".into(),
                },
            ],
            owned,
            "10.8.0.0/24",
        );
        assert!(matches!(both, NatDecision::Refuse { .. }));
    }

    #[test]
    fn forwarding_restore_only_undoes_our_own_change() {
        let already = forwarding_on_apply(true);
        assert!(!already.changed_by_us);
        assert_eq!(forwarding_restore(already, true), None);
        let turned_on = forwarding_on_apply(false);
        assert!(turned_on.changed_by_us);
        assert_eq!(forwarding_restore(turned_on, true), Some(false));
        assert_eq!(forwarding_restore(turned_on, false), None);
    }

    #[test]
    fn egress_refuses_zero_or_several_default_routes_and_skips_the_tunnel() {
        assert!(select_egress(&[]).is_err());
        assert_eq!(
            select_egress(&[
                DefaultRoute {
                    interface_luid: 1,
                    is_tunnel: true,
                },
                DefaultRoute {
                    interface_luid: 2,
                    is_tunnel: false,
                },
            ]),
            Ok(2)
        );
        assert!(select_egress(&[
            DefaultRoute {
                interface_luid: 2,
                is_tunnel: false,
            },
            DefaultRoute {
                interface_luid: 3,
                is_tunnel: false,
            },
        ])
        .is_err());
    }

    #[test]
    fn support_sentence_names_the_sku_and_does_not_generalize() {
        assert!(SUPPORT_SENTENCE.contains("Windows Server 2025 x64"));
        assert!(SUPPORT_SENTENCE.contains("windows-2025"));
        assert!(!SUPPORT_SENTENCE.contains("Windows support"));
        assert!(SUPPORT_SENTENCE.contains("not part of this claim"));
    }
}
