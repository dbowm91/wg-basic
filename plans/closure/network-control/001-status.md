# M001 Closure — Repository, Domain, and Runtime-Role Foundation

Disposition: **closed**

Implementation plan: `plans/implementation/network-control/001-repository-domain-runtime-foundation.md`

Repository baseline: `206cb1c` (planning-only repository immediately before implementation)

Implementation commit: `e27034ef404912e6f8206588ddcf7be59d5c48da`

Final implementation head: `e27034ef404912e6f8206588ddcf7be59d5c48da`

## Requirement-to-evidence matrix

| Requirement | Evidence | Result |
|---|---|---|
| Minimal Rust 2021 package, lockfile, MIT metadata, Rust 1.89 MSRV, unsafe denied | `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `LICENSE`, `src/lib.rs` | Pass |
| Single executable exposes default/help/version and `serve`, `netd`, `doctor` roles without network mutation | `src/main.rs`; manual `--help`, `doctor`, `serve`, `netd`, and default invocations | Pass; service roles truthfully report unimplemented |
| Distinct stable IDs; bounded Linux interface names | `src/domain/identifiers.rs`, `src/domain/interface_name.rs` | Pass; unit coverage |
| Prefix values, client assignment membership/uniqueness, and separated server/client route fields | `src/domain/network.rs`, `src/domain/state.rs` | Pass; unit coverage |
| WireGuard key parsing and secret-safe formatting | `src/domain/secret.rs` | Pass; validates 32-byte base64 keys, redaction test passes, owned secret strings zeroize on drop |
| Typed application error categories | `src/error.rs` | Pass |
| Linux platform boundary; no backend mutation code | `src/lib.rs`, `src/platform/linux` module boundary | Pass; no kernel or host-network operations are implemented |
| Formatting, check, Clippy, unit suite, and MSRV check | Local commands listed below; hosted CI run [37579869469](https://github.com/dbowm91/wg-basic/actions/runs/37579869469) | Pass |
| No generic production command execution | `rg -n 'std::process::Command|Command::new|\bCommandExt\b' src` | No matches |
| Architecture, development, and planning docs reflect actual behavior | `README.md`, `architecture/overview.md`, `docs/development.md`, `AGENTS.md`, registry and roadmap | Pass |

## Verification actually run

All local commands exited successfully:

```text
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked                         # 6 passed
cargo +1.89.0 check --all-targets --locked
```

Manual CLI checks confirmed help and default output work, `doctor` reports a read-only unimplemented placeholder, and `serve`/`netd` fail with explicit not-implemented messages and nonzero status.

Hosted CI on Ubuntu with Rust 1.89.0 completed successfully. It ran formatting, locked all-target check, Clippy with warnings denied, and unit tests.

No network-namespace or real-kernel evidence was required: M001 introduces no networking behavior or host mutation.

## Dependency inventory

| Dependency | Purpose |
|---|---|
| `clap` | Small, maintained CLI parser and help/version behavior |
| `serde` | Stable typed serialization boundary for domain values |
| `ipnet` | Mature IP network/prefix parsing and containment |
| `uuid` | Random, locator-independent typed IDs |
| `zeroize` | Clears owned private/preshared key strings on drop |
| `base64` | Validates WireGuard's base64-encoded 32-byte key representation |
| `thiserror` | Typed application/domain error display |

No TLS, database, netlink, logging subscriber, or process-execution dependency was added.

## Security and ownership evidence

- The CLI has no networking side effect; production source has no process execution API.
- Private and preshared key `Debug`/`Display` output is redacted. `PublicKey` may be displayed because it is public material.
- Key wrappers are not `Clone`; private/preshared key wrappers zeroize their owned allocation on drop. This does not claim that compiler/runtime or downstream copies cannot exist.
- Desired server-side peer `allowed_ips` and client-side `route_policy` are separate fields.
- Interface names are locators and IDs are independent UUID newtypes.

## Limitations and unresolved findings

Known limitations are intentional M001 scope: `serve`, `netd`, and diagnostic checks are placeholders; there is no IPC, persistence, WireGuard backend, route/firewall control, or host mutation. Secret bytes are serialized as strings when a caller explicitly serializes them; storage/encryption policy belongs to later work.

Unresolved findings: none identified in M001 scope. No high/medium ownership or privilege finding applies because no privileged operation exists.

## Readiness recommendation

M001 is strictly closed. Promote M002 to **ready**. M002 can reuse the package/domain/error boundaries and executable roles. M003–M005 remain blocked by their declared hard dependencies and must still provide their required real-kernel namespace evidence.
