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

Linux is the canonical platform. Apple silicon (`aarch64-apple-darwin`) headless
server publication is maintainer-authorized under
[ADR-014](../plans/adr/014-macos-apple-silicon-release-authorization.md)
(checksums-only; gateway advanced-administrator-only; no Darwin self-update).
A published “macOS supported” claim waits on C015 controlled-host teardown
evidence and C005 packaging/docs closure. Until then, treat macOS as
authorized-pending. Intel Macs are refused at install time.

### Apple silicon support matrix (ADR-014)

| Mode | Arch | Floor | Claim today | Operator prerequisites |
|---|---|---|---|---|
| Host-only | `aarch64-apple-darwin` | macOS 13.0+ aspirational; qualified on macOS 15.x hosted and macOS 26.6.2 controlled-host arm64 | Authorized-pending publication | Install + pinned helper |
| Routed LAN | same | same | Authorized-pending publication | Admin enables forwarding; installs matching PF filter; upstream return routes |
| Gateway (IPv4 NAT, IPv6 routed, no NAT66) | same | same | Authorized-pending as **advanced-administrator-only** | Admin attaches parent PF lines; product owns scoped anchor only |
| Darwin self-update | — | — | **Not authorized** | Fresh install per release |
| Intel Mac | — | — | **Refused** | — |

Darwin install uses `wg-basic system install --helper PATH` with the
hash-pinned `wireguard-go` companion built from
`helper/wireguard-go.provenance.json` (see
`scripts/package-darwin-release-helper.py`). Package release-shaped helper
assets with `python3 scripts/package-darwin-release-helper.py --output-dir DIR`.

For the maintainer's release policy and retained signing reference, see
[release signing](release-signing.md). For the current planning disposition,
see the [planning registry](../plans/registry.md).
