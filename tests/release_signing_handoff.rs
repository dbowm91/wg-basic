//! Fixture-only signing mechanics for the detached M003 manifest/installer handoff.

use std::io::Cursor;

const MANIFEST: &[u8] = include_bytes!("fixtures/release-auth/release-manifest.json");
const INSTALLER: &[u8] = include_bytes!("../release/eggpack/install.sh");

#[test]
fn fixture_signatures_verify_exact_manifest_and_installer_bytes() {
    let minisign::KeyPair { pk, sk } = minisign::KeyPair::generate_unencrypted_keypair()
        .expect("generate an ephemeral test-only key pair");
    let public_key = pk
        .to_box()
        .expect("serialize ephemeral public key")
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

        let mut tampered = bytes.to_vec();
        tampered[0] ^= 1;
        assert!(wg_basic::release::verify_manifest(&tampered, &signature, &public_key).is_err());
    }
}
