# Deployment status

A supported production installer and system-service setup are not implemented.
Do not use development commands as a production deployment procedure.

The local demo in the [README](../README.md) runs only the management service on
loopback. It does not start `netd` or create a VPN. The
[development guide](development.md) describes local service and test workflows.

## Releases and updates

Releases are checksums-only. There is no production signing key or independently
distributed trust root. A SHA-256 match detects corruption, but it does not
authenticate a publisher. The production update commands fail closed, and no
supported self-update path is available.

No macOS release is supported. Linux is the canonical platform.

For the maintainer's release policy and retained signing reference, see
[release signing](release-signing.md). For the current planning disposition,
see the [planning registry](../plans/registry.md).
