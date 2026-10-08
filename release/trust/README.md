# Release trust root

The production Minisign public key is not provisioned yet. No placeholder key
is committed or trusted by production code. Release verification tests inject a
separate fixture public key. Production self-update must remain unavailable
until a maintainer provisions the real public trust root and its fingerprint.
