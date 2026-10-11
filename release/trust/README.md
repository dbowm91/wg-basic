# Release trust root and installer bootstrap

By maintainer decision (2026-10-11) there is no production Minisign public
key and none is planned: releases are checksums-only. No placeholder key
is committed or trusted by production code. Release verification tests inject a
separate fixture public key. Production self-update is permanently
unavailable; every release requires a fresh install.

The generated `install-exact.sh` is an integrity bootstrap: it is bound to one
release tag and verifies the selected binary's exact size and SHA-256. The
product `install.sh --version` path downloads that exact-version bootstrap over
HTTPS and runs it as root. It is a lower-assurance convenience path; HTTPS and
an embedded checksum do not authenticate the script or manifest. The wrapper
prints this limitation and uses a fixed system `PATH` and private `/tmp`
staging directory.

Without a trust root there is no signature-authenticated installation path.
The strongest available installation checks the live tag/source and artifact
identity and passes the selected artifact's exact size and SHA-256 to the
wrapper with a local candidate. The copy staged for root execution is
root-owned and verified again. Follow the complete procedure in
`docs/installation.md`. The signed procedure below is retained reference for
a future trust root under a new plan, not current practice. The key in
`tests/fixtures/release-auth/` is test-only and must never be used for a public
release.

After independently verifying the script and manifest signatures and
downloading the selected manifest artifact, the high-assurance form is:

```sh
chmod 700 ./wg-basic
sudo sh ./install.sh --version X.Y.Z --candidate ./wg-basic \
  --sha256 '<selected artifact SHA-256 from the verified manifest>' \
  --size '<selected artifact size from the verified manifest>'
```

The wrapper copies the candidate into a private root-owned directory, checks
its exact size, digest, and version there, then delegates to
`wg-basic system install`. It makes no network request in this mode. The
operator must take the digest and size from the target record in the verified
manifest.

## Maintainer verification handoff (reference — signing waived)

The release workflow uploads an `eggpack-staging-receipt` Actions artifact
after staging a draft. A separate read-only workflow binds that receipt to the
source run and attempt. Download both receipts from their exact Actions runs,
download all live draft assets into a private directory, and verify the run,
live tag, draft asset inventory, and bytes before signing:

```sh
python3 scripts/verify-release-signing-bundle.py \
  ./eggpack-staging-receipt.json ./release-provenance.json ./draft-assets \
  --public-key /etc/wg-basic/release.pub
```

The verifier checks the exact repository/tag/release/source identity, the two
target inventory, every downloaded asset's size and SHA-256, the manifest's
artifact bindings, and each checksum sidecar. Only after it succeeds, sign the
exact downloaded bytes in the trusted maintainer environment:

```sh
minisign -S -s "$MINISIGN_SECRET_KEY" -m ./draft-assets/release-manifest.json \
  -x ./draft-assets/release-manifest.json.minisig
minisign -S -s "$MINISIGN_SECRET_KEY" -m ./draft-assets/install.sh \
  -x ./draft-assets/install.sh.minisig
minisign -V -p production.pub -m ./draft-assets/release-manifest.json \
  -x ./draft-assets/release-manifest.json.minisig
minisign -V -p production.pub -m ./draft-assets/install.sh \
  -x ./draft-assets/install.sh.minisig
```

Upload both detached signatures to the same draft without replacing any
existing asset, then download and verify them again. Keep the private key out
of the repository and GitHub Actions. No production signing key exists by
maintainer decision, so this procedure is retained reference only; signing has
not been performed and is not planned.
