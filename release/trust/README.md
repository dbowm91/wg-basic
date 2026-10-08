# Release trust root and installer bootstrap

The production Minisign public key is not provisioned yet. No placeholder key
is committed or trusted by production code. Release verification tests inject a
separate fixture public key. Production self-update must remain unavailable
until a maintainer provisions the real public trust root and its fingerprint.

The generated `install-exact.sh` is an integrity bootstrap: it is bound to one
release tag and verifies the selected binary's exact size and SHA-256. The
product `install.sh` downloads that exact-version bootstrap over HTTPS and then
delegates system setup to `wg-basic system install`. The convenience path trusts
the downloaded script bytes; HTTPS and an embedded checksum do not authenticate
the script or manifest.

A high-assurance installation must obtain the production public key
independently, download `install.sh` and its detached `.minisig`, verify the
signature before execution, then verify the signed release manifest before
using its artifact metadata. That path is not available until the production
trust root has been provisioned and a production-signed draft has been
qualified. The key in `tests/fixtures/release-auth/` is test-only and must never
be used for a public release.

## Maintainer signing handoff

The release workflow uploads an `eggpack-staging-receipt` Actions artifact
after staging a draft. Download all assets from that exact draft into a private
directory and verify them against the receipt before signing:

```sh
python3 scripts/verify-signing-request.py signing-receipt.json ./draft-assets
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
of the repository and GitHub Actions. No production signing key is provisioned
at present, so this procedure is specified but production signing has not been
performed.
