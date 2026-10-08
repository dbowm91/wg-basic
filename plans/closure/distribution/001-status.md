# Distribution M001 Closure — Release Identity, Authenticity, and Targets

Status: closed

Source plan: `plans/implementation/distribution/001-release-identity-authenticity-and-targets.md`

Roadmap: `plans/subsystems/distribution-install-update-roadmap.md`

Implementation commits:

- `7f4e49f` — release identity, verifier, producer contracts, native CI lanes
- `c4d4e87` — emit exact artifact size and SHA-256 in native qualification evidence

Repository baseline: `e3a4d3f18b12deab69c73e1c9eaeab5871c1b24c`

Implementation head: `c4d4e87`.

## Requirement-to-evidence matrix

| Requirement | Evidence | Result |
|---|---|---|
| Stable release identity and strict stable SemVer policy | `src/release.rs`; Clap `--version` reads `PACKAGE_VERSION`; malformed/leading-zero/prerelease/build-metadata, equal, older, and newer cases in release unit tests | Pass |
| Exactly two canonical Linux GNU targets and host aliases | `LinuxTarget`; `release/eggpack/distribution.toml`; rejection tests cover non-Linux, ARMv7, musl, and unknown architectures | Pass |
| Native x86_64 release build and smoke | Distribution foundation CI run [37782271310](https://github.com/dbowm91/wg-basic/actions/runs/37782271310), job `native-release-candidate (x86_64-unknown-linux-gnu, ubuntu-24.04, ...)`; exact artifact: 9,199,560 bytes, SHA-256 `ba4f2487b0c9455ad80a13a8bfab8af02fa5be590b0fcb63b93315e400730057` | Pass |
| Native aarch64 release build and smoke | Distribution foundation CI run [37782271310](https://github.com/dbowm91/wg-basic/actions/runs/37782271310), job `native-release-candidate (aarch64-unknown-linux-gnu, ubuntu-24.04-arm, ...)`; exact artifact: 8,480,880 bytes, SHA-256 `8d67d837eb7a5c6b1645648ebd84425304206f52dab1ecc13cec386446e44309` | Pass |
| glibc compatibility floor is evidenced | Both native jobs build with cargo-zigbuild 0.23.3 and Zig 0.14.1 at 2.17, then `readelf --version-info` verifies max required `GLIBC_2.17`; the same runner executes version/help/doctor, checks ELF host identity and dynamic dependency resolution, and records size/hash/dependency inventory | Pass |
| Eggpack producer contract validates | Pinned Eggpack `e5c81f28bd328d4aea41c3f061a0ed9944306262` resolver accepted both selected aliases and all contract inputs in CI run [37782271310](https://github.com/dbowm91/wg-basic/actions/runs/37782271310), `release-contract` job | Pass |
| Verify-only Minisign path is qualified on Rust 1.89 | `minisign-verify 0.3.0`, MIT licensed, no transitive dependencies; `cargo +1.89.0 check --all-targets --locked`; signed manifest fixture verifies before Eggpack parsing/projection | Pass |
| Signature failure matrix and diagnostic secrecy | Valid fixture signature; one-byte mutation, truncated signature, malformed signature/public key, wrong key, malformed payload, and error-redaction tests; fixture private-key source guard in `tests/architecture_guards.rs` | Pass |
| Signed manifest product/release/target/version policy | Signed fixture coverage: strict newer accepted; same/older refused; wrong product, selected release mismatch, missing selected target refused; artifact selection/layout validated after authentication | Pass |
| Exact Eggup/Eggpack registry graph | External fixture at `/tmp/wg-basic-phase10-graph` resolved and compiled on Rust 1.89 with registry-only pins: `eggpack-manifest 0.1.0`, `eggup-core 0.1.3`, `eggup-acquisition 0.1.3`, `eggup-curl 0.1.2`, `eggup-eggpack 0.1.3`, `eggup-service 0.1.2`, `minisign-verify 0.3.0`; all are MIT licensed | Pass |
| Artifact size/SHA-256 and unsafe acquired paths | Exact size/hash tests; Eggup adapter test rejects symlink and non-regular acquired paths while accepting the regular fixture | Pass |
| M001 introduces no installation/update mutation | No install/update CLI or service/root-path write was added; the release module is verify/project/integrity policy only | Pass |
| Existing Phase 6–9 CI remains green | Full CI run [37782271299](https://github.com/dbowm91/wg-basic/actions/runs/37782271299) succeeded, including ordinary Rust, advisory audit, rootful network/state/service suites, and both upgrade rehearsals | Pass |

## Verification commands and results

Local repository gates on the implementation source:

```text
cargo fmt --all -- --check                         passed
cargo check --all-targets --locked                 passed
cargo clippy --all-targets --locked -- -D warnings passed
cargo test --locked                                passed (533 passed, 1 ignored)
cargo +1.89.0 check --all-targets --locked         passed
```

The focused release tests passed (6 tests), the private-key architecture guard
passed, the exact x86_64 release smoke passed, and Eggpack's pinned resolver
accepted the full two-target contract. CI run `37782271299` completed every
existing job successfully; `37782271310` completed the producer contract and
both native release target jobs successfully.

## Security, ownership, and compatibility

- The verifier receives explicit key text and verifies exact manifest bytes
  before parsing or projecting them. Release authenticity is distinct from the
  separate exact-size/SHA-256 artifact integrity check.
- Fixture private signing material exists only under
  `tests/fixtures/release-auth/`; tests assert its payload is absent from
  shipped source. The runtime dependency set has no signing API.
- No production public key or fingerprint was fabricated. The production trust
  root remains unprovisioned, so public-release signing/update readiness remains
  unavailable. This is an operational release prerequisite, not a blocker to
  M002 implementation.
- The artifact contract remains exactly x86_64/aarch64 GNU Linux. No installer,
  service mutation, release discovery, or self-update capability was added.

## Known limitations and findings

- The real production signing trust root must be provisioned before a public
  signed release or production self-update can be enabled.
- No high, medium, or low implementation finding remains open for M001.
- No real-kernel evidence applies to this verifier/target milestone; native
  binary qualification was performed on the required Linux runners.

Disposition: **closed**. Distribution M002 is unblocked and ready.
