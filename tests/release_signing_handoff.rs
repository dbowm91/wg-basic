//! Fixture-only signing mechanics for the detached M003 manifest/installer handoff.

use std::io::Cursor;

const MANIFEST: &[u8] = include_bytes!("fixtures/release-auth/release-manifest.json");
const WRONG_PRODUCT: &[u8] =
    include_bytes!("fixtures/release-auth/release-manifest-wrong-product.json");
const INSTALLER: &[u8] = include_bytes!("../release/eggpack/install.sh");

#[test]
fn fixture_signatures_verify_exact_manifest_and_installer_bytes() {
    let minisign::KeyPair { pk, sk } = minisign::KeyPair::generate_unencrypted_keypair()
        .expect("generate an ephemeral test-only key pair");
    let public_key = pk
        .to_box()
        .expect("serialize ephemeral public key")
        .into_string();
    let minisign::KeyPair { pk: wrong_pk, .. } = minisign::KeyPair::generate_unencrypted_keypair()
        .expect("generate an unrelated test-only key pair");
    let wrong_public_key = wrong_pk
        .to_box()
        .expect("serialize unrelated public key")
        .into_string();

    for bytes in [MANIFEST, INSTALLER] {
        let signature = minisign::sign(
            Some(&pk),
            &sk,
            Cursor::new(bytes),
            Some("wg-basic fixture handoff"),
            Some("wg-basic test fixture only"),
        )
        .expect("fixture key signs exact bytes")
        .to_string();
        assert!(wg_basic::release::verify_manifest(bytes, &signature, &public_key).is_ok());
        assert!(wg_basic::release::verify_manifest(bytes, &signature, &wrong_public_key).is_err());
        assert!(wg_basic::release::verify_manifest(
            bytes,
            "untrusted comment: truncated",
            &public_key
        )
        .is_err());

        let mut tampered = bytes.to_vec();
        tampered[0] ^= 1;
        assert!(wg_basic::release::verify_manifest(&tampered, &signature, &public_key).is_err());
    }

    let wrong_product_signature = minisign::sign(
        Some(&pk),
        &sk,
        Cursor::new(WRONG_PRODUCT),
        Some("wg-basic wrong-product fixture"),
        Some("test only"),
    )
    .expect("fixture key signs the wrong-product control")
    .to_string();
    assert!(wg_basic::release::authenticate_release_manifest(
        WRONG_PRODUCT,
        &wrong_product_signature,
        &public_key,
        "0.2.0",
        "0.1.0",
        wg_basic::release::LinuxTarget::X86_64,
    )
    .is_err());
    assert!(wg_basic::release::authenticate_release_manifest(
        MANIFEST,
        &minisign::sign(
            Some(&pk),
            &sk,
            Cursor::new(MANIFEST),
            Some("wg-basic fixture handoff"),
            Some("wg-basic test fixture only"),
        )
        .expect("fixture key signs the manifest")
        .to_string(),
        &public_key,
        "0.3.0",
        "0.1.0",
        wg_basic::release::LinuxTarget::X86_64,
    )
    .is_err());
}
