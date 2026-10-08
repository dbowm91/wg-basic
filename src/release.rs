//! Stable release identity, target selection, and detached authenticity checks.
//!
//! This module deliberately has no acquisition or filesystem mutation path.

use eggup_eggpack::ManifestProjection;
use minisign_verify::{PublicKey, Signature};
use sha2::{Digest, Sha256};

pub const PRODUCT_ID: &str = "wg-basic";
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Production release trust root. Maintainers provision this public key only
/// after verifying a signed draft; fixture keys must never be substituted.
pub const PRODUCTION_PUBLIC_KEY: Option<&str> = None;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxTarget {
    X86_64,
    Aarch64,
}

impl LinuxTarget {
    pub const ALL: [Self; 2] = [Self::Aarch64, Self::X86_64];

    pub const fn triple(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64-unknown-linux-gnu",
            Self::Aarch64 => "aarch64-unknown-linux-gnu",
        }
    }

    pub fn from_host(os: &str, arch: &str) -> Result<Self, &'static str> {
        if os != "linux" {
            return Err("wg-basic releases support Linux only");
        }
        match arch {
            "x86_64" | "amd64" => Ok(Self::X86_64),
            "aarch64" | "arm64" => Ok(Self::Aarch64),
            _ => {
                Err("unsupported Linux architecture; supported targets are x86_64 and aarch64 GNU")
            }
        }
    }
}

/// Parse the restricted Phase 10 stable SemVer subset (exactly X.Y.Z).
pub fn parse_stable_version(value: &str) -> Result<(u64, u64, u64), &'static str> {
    let mut components = value.split('.');
    let major = parse_component(components.next().ok_or("invalid stable version")?)?;
    let minor = parse_component(components.next().ok_or("invalid stable version")?)?;
    let patch = parse_component(components.next().ok_or("invalid stable version")?)?;
    if components.next().is_some() {
        return Err("Phase 10 accepts stable X.Y.Z versions only");
    }
    Ok((major, minor, patch))
}

fn parse_component(value: &str) -> Result<u64, &'static str> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("invalid stable version component");
    }
    value
        .parse()
        .map_err(|_| "stable version component is out of range")
}

pub fn require_newer(current: &str, candidate: &str) -> Result<(), &'static str> {
    if parse_stable_version(candidate)? > parse_stable_version(current)? {
        Ok(())
    } else {
        Err("release must be strictly newer than the installed version")
    }
}

/// Keep SHA-256 integrity verification separate from signature authenticity.
pub fn verify_artifact_bytes(
    bytes: &[u8],
    expected_size: u64,
    expected_sha256: &[u8; 32],
) -> Result<(), &'static str> {
    if bytes.len() as u64 != expected_size {
        return Err("release artifact size does not match signed manifest");
    }
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if &actual != expected_sha256 {
        return Err("release artifact digest does not match signed manifest");
    }
    Ok(())
}

/// Verify exact manifest bytes before any parser or policy consumes them.
pub fn verify_manifest(
    manifest: &[u8],
    signature_text: &str,
    public_key_text: &str,
) -> Result<(), &'static str> {
    let public_key =
        PublicKey::decode(public_key_text).map_err(|_| "invalid release public key")?;
    let signature = Signature::decode(signature_text).map_err(|_| "invalid release signature")?;
    public_key
        .verify(manifest, &signature, false)
        .map_err(|_| "release manifest signature verification failed")
}

/// Authenticate, parse, and enforce product/release/target policy in that order.
pub fn authenticate_release_manifest(
    manifest: &[u8],
    signature_text: &str,
    public_key_text: &str,
    expected_release: &str,
    current_version: &str,
    target: LinuxTarget,
) -> Result<ManifestProjection, &'static str> {
    verify_manifest(manifest, signature_text, public_key_text)?;
    let projection = eggup_eggpack::project_json(manifest, target.triple())
        .map_err(|_| "signed release manifest has no valid selected target")?;
    validate_authenticated_projection(projection, expected_release, current_version, target)
}

/// Apply product policy to a projection obtained only after authenticity checks.
fn validate_authenticated_projection(
    projection: ManifestProjection,
    expected_release: &str,
    current_version: &str,
    target: LinuxTarget,
) -> Result<ManifestProjection, &'static str> {
    let (product, release) = eggup_eggpack::install_ids(&projection)
        .map_err(|_| "release manifest layout is not a direct installable artifact")?;
    if product.as_str() != PRODUCT_ID {
        return Err("release manifest product does not match wg-basic");
    }
    if release.as_str() != expected_release {
        return Err("release manifest identity does not match selected release");
    }
    require_newer(current_version, expected_release)?;
    match &projection {
        ManifestProjection::Installable {
            target: selected,
            artifacts,
            ..
        } if selected == target.triple()
            && artifacts.len() == 1
            && artifacts[0].artifact_name == format!("wg-basic-{}", target.triple())
            && artifacts[0].destination == "wg-basic" =>
        {
            Ok(projection)
        }
        _ => Err("release manifest does not contain the exact wg-basic target artifact"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_PUBLIC_KEY: &str = "untrusted comment: minisign public key\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
    const FIXTURE_SIGNATURE: &str = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1633700835\tfile:test\tprehashed\nwLMDjy9FLAuxZ3q4NlEvkgtyhrr0gtTu6KC4KBJdITbbOeAi1zBIYo0v4iTgt8jJpIidRJnp94ABQkJAgAooBQ==";
    const RELEASE_FIXTURE: &str =
        include_str!("../tests/fixtures/release-auth/release-manifest.json");
    const RELEASE_SIGNATURE: &str =
        include_str!("../tests/fixtures/release-auth/release-manifest.json.minisig");
    const RELEASE_PUBLIC_KEY: &str =
        include_str!("../tests/fixtures/release-auth/minisign.fixture.pub");
    const WRONG_PRODUCT_FIXTURE: &str =
        include_str!("../tests/fixtures/release-auth/release-manifest-wrong-product.json");
    const WRONG_PRODUCT_SIGNATURE: &str =
        include_str!("../tests/fixtures/release-auth/release-manifest-wrong-product.json.minisig");
    const MISMATCHED_RELEASE_FIXTURE: &str =
        include_str!("../tests/fixtures/release-auth/release-manifest-mismatched-release.json");
    const MISMATCHED_RELEASE_SIGNATURE: &str = include_str!(
        "../tests/fixtures/release-auth/release-manifest-mismatched-release.json.minisig"
    );
    const MISSING_TARGET_FIXTURE: &str =
        include_str!("../tests/fixtures/release-auth/release-manifest-missing-target.json");
    const MISSING_TARGET_SIGNATURE: &str =
        include_str!("../tests/fixtures/release-auth/release-manifest-missing-target.json.minisig");

    #[test]
    fn stable_version_policy_is_strict_and_monotonic() {
        assert!(parse_stable_version(PACKAGE_VERSION).is_ok());
        assert_eq!(parse_stable_version("1.20.300"), Ok((1, 20, 300)));
        for invalid in [
            "",
            "1",
            "1.2",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2.3-rc1",
            "1.2.3+build",
            "1.2.3.4",
            "x.2.3",
        ] {
            assert!(parse_stable_version(invalid).is_err(), "{invalid}");
        }
        assert!(require_newer("1.2.3", "1.2.4").is_ok());
        assert!(require_newer("1.2.3", "1.2.3").is_err());
        assert!(require_newer("1.2.3", "1.2.2").is_err());
    }

    #[test]
    fn only_canonical_linux_targets_are_selectable() {
        assert_eq!(
            LinuxTarget::from_host("linux", "amd64"),
            Ok(LinuxTarget::X86_64)
        );
        assert_eq!(
            LinuxTarget::from_host("linux", "arm64"),
            Ok(LinuxTarget::Aarch64)
        );
        assert_eq!(
            LinuxTarget::ALL.map(LinuxTarget::triple),
            ["aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"]
        );
        for (os, arch) in [
            ("linux", "arm"),
            ("linux", "armv7"),
            ("linux", "x86_64-musl"),
            ("darwin", "x86_64"),
        ] {
            assert!(LinuxTarget::from_host(os, arch).is_err());
        }
    }

    #[test]
    fn minisign_verification_accepts_fixture_and_fails_closed_without_echoing_bytes() {
        assert!(verify_manifest(b"test", FIXTURE_SIGNATURE, FIXTURE_PUBLIC_KEY).is_ok());
        let secret_document = b"secret-release-manifest-content";
        let error = verify_manifest(secret_document, "truncated", FIXTURE_PUBLIC_KEY).unwrap_err();
        assert!(!error.contains("secret-release-manifest-content"));
        assert!(verify_manifest(b"test", "truncated", FIXTURE_PUBLIC_KEY).is_err());
        assert!(verify_manifest(b"test", FIXTURE_SIGNATURE, "bad key").is_err());
        assert!(verify_manifest(b"changed", FIXTURE_SIGNATURE, FIXTURE_PUBLIC_KEY).is_err());
        let wrong_key = FIXTURE_PUBLIC_KEY.replace("RWQf6LRC", "RWQf6LRA");
        assert!(verify_manifest(b"test", FIXTURE_SIGNATURE, &wrong_key).is_err());
    }

    #[test]
    fn signed_manifest_is_verified_before_projection_and_policy() {
        let projection = authenticate_release_manifest(
            RELEASE_FIXTURE.as_bytes(),
            RELEASE_SIGNATURE,
            RELEASE_PUBLIC_KEY,
            "0.2.0",
            "0.1.0",
            LinuxTarget::X86_64,
        )
        .expect("fixture release is signed and policy-compliant");
        assert!(
            matches!(projection, ManifestProjection::Installable { ref artifacts, .. } if artifacts.len() == 1 && artifacts[0].exact_size == 4)
        );
        for (manifest, signature, expected_release, current) in [
            (RELEASE_FIXTURE, RELEASE_SIGNATURE, "0.2.0", "0.2.0"),
            (RELEASE_FIXTURE, RELEASE_SIGNATURE, "0.2.0", "0.3.0"),
            (
                WRONG_PRODUCT_FIXTURE,
                WRONG_PRODUCT_SIGNATURE,
                "0.2.0",
                "0.1.0",
            ),
            (
                MISMATCHED_RELEASE_FIXTURE,
                MISMATCHED_RELEASE_SIGNATURE,
                "0.2.0",
                "0.1.0",
            ),
            (
                MISSING_TARGET_FIXTURE,
                MISSING_TARGET_SIGNATURE,
                "0.2.0",
                "0.1.0",
            ),
        ] {
            assert!(authenticate_release_manifest(
                manifest.as_bytes(),
                signature,
                RELEASE_PUBLIC_KEY,
                expected_release,
                current,
                LinuxTarget::X86_64,
            )
            .is_err());
        }

        let mut changed = RELEASE_FIXTURE.as_bytes().to_vec();
        changed[0] ^= 1;
        assert!(authenticate_release_manifest(
            &changed,
            RELEASE_SIGNATURE,
            RELEASE_PUBLIC_KEY,
            "0.2.0",
            "0.1.0",
            LinuxTarget::X86_64,
        )
        .is_err());

        let wrong_product = RELEASE_FIXTURE.replace(
            "\"product_id\":\"wg-basic\"",
            "\"product_id\":\"other-product\"",
        );
        let projection =
            eggup_eggpack::project_json(wrong_product.as_bytes(), LinuxTarget::X86_64.triple())
                .unwrap();
        assert!(validate_authenticated_projection(
            projection,
            "0.2.0",
            "0.1.0",
            LinuxTarget::X86_64
        )
        .is_err());

        let wrong_release =
            RELEASE_FIXTURE.replace("\"release_id\":\"0.2.0\"", "\"release_id\":\"0.3.0\"");
        let projection =
            eggup_eggpack::project_json(wrong_release.as_bytes(), LinuxTarget::X86_64.triple())
                .unwrap();
        assert!(validate_authenticated_projection(
            projection,
            "0.2.0",
            "0.1.0",
            LinuxTarget::X86_64
        )
        .is_err());

        let wrong_artifact =
            RELEASE_FIXTURE.replace("\"install\":\"wg-basic\"", "\"install\":\"other-binary\"");
        let projection =
            eggup_eggpack::project_json(wrong_artifact.as_bytes(), LinuxTarget::X86_64.triple())
                .unwrap();
        assert!(validate_authenticated_projection(
            projection,
            "0.2.0",
            "0.1.0",
            LinuxTarget::X86_64
        )
        .is_err());

        let no_aarch64 = RELEASE_FIXTURE.replace(
            "{\"target\":\"aarch64-unknown-linux-gnu\",\"form\":{\"kind\":\"direct\",\"artifact\":{\"name\":\"wg-basic-aarch64-unknown-linux-gnu\",\"size\":4,\"sha256\":\"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"},\"install\":\"wg-basic\"}},",
            "",
        );
        assert!(
            eggup_eggpack::project_json(no_aarch64.as_bytes(), LinuxTarget::Aarch64.triple())
                .is_err()
        );
        assert!(authenticate_release_manifest(
            RELEASE_FIXTURE.as_bytes(),
            &RELEASE_SIGNATURE[..RELEASE_SIGNATURE.len() - 5],
            RELEASE_PUBLIC_KEY,
            "0.2.0",
            "0.1.0",
            LinuxTarget::X86_64,
        )
        .is_err());
        assert!(authenticate_release_manifest(
            RELEASE_FIXTURE.as_bytes(),
            RELEASE_SIGNATURE,
            "bad key",
            "0.2.0",
            "0.1.0",
            LinuxTarget::X86_64,
        )
        .is_err());
        assert!(authenticate_release_manifest(
            RELEASE_FIXTURE.as_bytes(),
            RELEASE_SIGNATURE,
            RELEASE_PUBLIC_KEY,
            "0.2.0",
            "0.2.0",
            LinuxTarget::X86_64,
        )
        .is_err());
    }

    #[test]
    fn artifact_integrity_requires_exact_size_and_digest() {
        let bytes = include_bytes!("../tests/fixtures/release-auth/wg-basic-test-artifact");
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        assert!(verify_artifact_bytes(bytes, 4, &digest).is_ok());
        assert!(verify_artifact_bytes(bytes, 3, &digest).is_err());
        let wrong_digest = [0u8; 32];
        assert!(verify_artifact_bytes(bytes, 4, &wrong_digest).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn eggup_adapter_rejects_symlink_and_nonregular_acquired_paths() {
        use eggup_core::PermissionsIntent;
        use std::collections::HashMap;
        use std::os::unix::fs::symlink;

        let projection =
            eggup_eggpack::project_json(RELEASE_FIXTURE.as_bytes(), LinuxTarget::X86_64.triple())
                .unwrap();
        let ManifestProjection::Installable { artifacts, .. } = &projection else {
            panic!("fixture is direct-installable");
        };
        let requirement = &artifacts[0];
        let root = std::env::temp_dir().join(format!(
            "wg-basic-release-adapter-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let regular = root.join("artifact");
        std::fs::write(&regular, b"test").unwrap();
        let linked = root.join("linked-artifact");
        symlink(&regular, &linked).unwrap();

        let materialize = |path| {
            projection.materialize_artifact_set_with_destinations(
                HashMap::from([(requirement.artifact_name.clone(), path)]),
                HashMap::from([(requirement.member_id.clone(), "wg-basic".to_owned())]),
                HashMap::from([(requirement.member_id.clone(), PermissionsIntent::Executable)]),
            )
        };
        assert!(materialize(regular).is_ok());
        assert!(materialize(linked).is_err());
        assert!(materialize(root.clone()).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
